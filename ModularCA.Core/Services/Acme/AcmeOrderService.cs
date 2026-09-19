using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Manages ACME order lifecycle including creation, finalization, and certificate issuance.
/// </summary>
/// <remarks>
/// <para>
/// Only finalization runs on the shared enrollment middle. ACME is accounts, orders,
/// authorizations, challenges and nonces — a state machine the other protocols do not have — and
/// generalising that would describe nothing. What the pipeline owns here is the middle between
/// "this order is ready and here is its CSR" and "here is the issued certificate": the CA, the
/// protocol's enablement on it, the profiles, the name validation, the request row and the
/// issuance. Everything either side of that stays ACME's, including the order state machine that
/// reads the outcome.
/// </para>
/// <para>
/// The checks ACME makes for itself still run before the pipeline, in the order they always have:
/// the CSR must carry only identifiers the order authorized, and CAA must permit this CA to issue
/// for each of them. Neither is a question about the CA's policy, and both refuse in ACME's own
/// rendering.
/// </para>
/// </remarks>
public class AcmeOrderService(
    ModularCADbContext db,
    IProtocolAuditService protocolAudit,
    IEnrollmentPipeline pipeline,
    ICaaCheckService caaCheckService) : IAcmeOrderService, IEnrollmentProtocol
{
    /// <summary>The protocol name as per-CA protocol configuration and audit rows record it.</summary>
    public const string Protocol = "ACME";

    /// <inheritdoc />
    string IEnrollmentProtocol.Name => Protocol;

    /// <summary>
    /// What ACME offers here: issuance through an order, and revocation (RFC 8555 §7.6).
    /// </summary>
    /// <remarks>
    /// Not <see cref="EnrollmentCapabilities.ReEnroll"/> or
    /// <see cref="EnrollmentCapabilities.Renew"/>: an ACME client renews by placing another order
    /// and validating the identifiers again, so a renewal is not a distinct operation carrying
    /// evidence of the certificate it replaces. Not <see cref="EnrollmentCapabilities.Poll"/> or
    /// <see cref="EnrollmentCapabilities.Collect"/> either — the order resource is polled, but no
    /// request taken under submission can be asked after, which is what those two name. No
    /// server-side key generation; ACME has none.
    /// </remarks>
    EnrollmentCapabilities IEnrollmentProtocol.Capabilities =>
        EnrollmentCapabilities.Enroll | EnrollmentCapabilities.Revoke;

    private readonly ModularCADbContext _db = db;
    private readonly IProtocolAuditService _protocolAudit = protocolAudit;
    private readonly IEnrollmentPipeline _pipeline = pipeline;
    private readonly ICaaCheckService _caaCheckService = caaCheckService;

    /// <summary>
    /// Creates a new ACME order. The caller can pass the
    /// <paramref name="caLabel"/> resolved from the route so finalize can select
    /// the same CA the client originally targeted. The label is persisted on the
    /// order row.
    /// </summary>
    public async Task<AcmeOrderDto> CreateAsync(Guid accountId, CreateAcmeOrderRequest request, string baseUrl, string? caLabel = null)
    {
        // Deduplicate identifiers before creating authorizations. ACME clients may repeat
        // a name in the order (e.g. the same domain passed twice, or a CN that is also a
        // SAN). One authorization was previously created per entry, so the duplicate's
        // authorization stayed Pending forever — the client validates each unique name
        // only once — and the order never reached Ready (finalize then 403'd with
        // orderNotReady). Match on type + case/trailing-dot-insensitive value, keeping the
        // first occurrence's original form. Wildcard (*.x) and apex (x) stay distinct.
        var identifiers = request.Identifiers
            .GroupBy(i => (Type: (i.Type ?? string.Empty).ToLowerInvariant(),
                           Value: (i.Value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant()))
            .Select(g => g.First())
            .ToList();

        var order = new AcmeOrderEntity
        {
            AccountId = accountId,
            Status = nameof(AcmeOrderStatus.Pending),
            IdentifiersJson = JsonSerializer.Serialize(identifiers),
            NotBefore = request.NotBefore,
            NotAfter = request.NotAfter,
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            CreatedAt = DateTime.UtcNow,
            CaLabel = string.IsNullOrWhiteSpace(caLabel) ? null : caLabel
        };

        _db.AcmeOrders.Add(order);
        await _db.SaveChangesAsync();

        // The per-CA AcmeAllowedChallengeTypes setting was stored and never read; every
        // authorization offered http-01 and dns-01 regardless. Resolved once per order.
        var allowedChallengeTypes = await GetAllowedChallengeTypesAsync(order.CaLabel);

        // Previously this loop called SaveChangesAsync twice per identifier,
        // producing 2N round-trips on ACME order creation with N SANs. Now we stage every
        // authorization + its challenges in the change tracker and commit once after the loop.
        // AcmeAuthorizationEntity.Id is Guid-generated in the entity default, so challenges
        // can reference authz.Id without a flush.
        foreach (var identifier in identifiers)
        {
            var authz = AcmeAuthorizationService.CreateAuthorizationWithChallenges(order.Id, identifier);
            _db.AcmeAuthorizations.Add(authz);

            var challenges = AcmeAuthorizationService.CreateChallengesForAuthorization(authz.Id, authz.IsWildcard, allowedChallengeTypes);
            _db.AcmeChallenges.AddRange(challenges);
        }

        await _db.SaveChangesAsync();
        return await BuildOrderDto(order, baseUrl);
    }

    public async Task<AcmeOrderDto?> GetByIdAsync(Guid orderId, string baseUrl)
    {
        var order = await _db.AcmeOrders.FindAsync(orderId);
        if (order == null) return null;
        return await BuildOrderDto(order, baseUrl);
    }

    public async Task<List<AcmeOrderDto>> GetByAccountAsync(Guid accountId, string baseUrl)
    {
        var orders = await _db.AcmeOrders
            .Where(o => o.AccountId == accountId)
            .OrderByDescending(o => o.CreatedAt)
            .ToListAsync();

        var result = new List<AcmeOrderDto>();
        foreach (var order in orders)
            result.Add(await BuildOrderDto(order, baseUrl));
        return result;
    }

    /// <summary>
    /// Finalizes an ACME order: decodes the CSR, holds it to the identifiers the order
    /// authorized, checks CAA, runs the shared enrollment middle, and moves the order to valid or
    /// invalid on what came back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The CA label is taken from the order's stored value, which is authoritative;
    /// <paramref name="caLabel"/> from the route may only confirm it. The label is handed to the
    /// pipeline, which resolves the CA, refuses a CA that is gone or has ACME switched off, and
    /// reads that CA's ACME profiles — the work <see cref="ICaResolverService"/> used to be asked
    /// for here.
    /// </para>
    /// <para>
    /// Every refusal below reaches the client as one RFC 8555 problem document, because that is
    /// what the controller has always rendered a failed finalize as: 403 with type
    /// <c>urn:ietf:params:acme:error:orderNotReady</c> and a fixed detail. The sentence a refusal
    /// carries is for the log and the ACME audit tab, and the order state machine is what the
    /// client reads instead.
    /// </para>
    /// </remarks>
    public async Task<AcmeOrderDto> FinalizeAsync(Guid orderId, string csrBase64Url, string baseUrl, string? caLabel = null)
    {
        var order = await _db.AcmeOrders.FindAsync(orderId)
            ?? throw new InvalidOperationException("Order not found.");

        if (order.Status != nameof(AcmeOrderStatus.Ready))
            throw new InvalidOperationException($"Order is not ready for finalization. Current status: {order.Status}");

        order.Status = nameof(AcmeOrderStatus.Processing);
        await _db.SaveChangesAsync();

        try
        {
            // Decode the base64url CSR to DER, then convert to PEM
            var csrDer = Base64UrlDecode(csrBase64Url);
            var csrPem = CertificateUtil.ConvertDerToPem(csrDer, "CERTIFICATE REQUEST");
            var parsedCsr = CertificateUtil.ParseCsr(csrPem);

            // The ORDER's CA is authoritative. The route label may only confirm it.
            //
            // This used to prefer the route-supplied label over the order's, so a client could
            // create and validate an order under one CA and then finalize it against another:
            // POST /acme/lab/new-order (where AcmeAllowPrivateAddressValidation is on), then
            // POST /acme/prod/order/{id}/finalize, and the production CA signs an authorization
            // that was only ever permitted under the lab CA's relaxed policy. Ownership was
            // checked by account id alone, which does not constrain which CA acts.
            if (!string.IsNullOrWhiteSpace(caLabel)
                && !string.IsNullOrWhiteSpace(order.CaLabel)
                && !string.Equals(caLabel, order.CaLabel, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Order belongs to CA '{order.CaLabel}' and cannot be finalized against CA '{caLabel}'.");
            }

            var effectiveCaLabel = !string.IsNullOrWhiteSpace(order.CaLabel) ? order.CaLabel : caLabel;

            // Validate that the CSR identifiers match the order identifiers
            var orderIdentifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(order.IdentifiersJson) ?? [];
            ValidateCsrAgainstOrder(parsedCsr, orderIdentifiers);

            // CAA record check (RFC 8659 / RFC 8555 §7.4.2)
            foreach (var identifier in orderIdentifiers)
            {
                var isWildcard = identifier.Value.StartsWith("*.");
                var baseDomain = isWildcard ? identifier.Value[2..] : identifier.Value;
                var allowed = await _caaCheckService.IsIssuanceAllowedAsync(baseDomain, isWildcard);
                if (!allowed)
                    throw new InvalidOperationException(
                        $"CAA record for '{identifier.Value}' does not authorize this CA to issue certificates.");
            }

            // The middle: the CA, its ACME configuration, the profiles, the names, the request row
            // and the issuance. ACME resolves no CA of its own - the order carries a label and
            // nothing more - so the pipeline resolves it, and the refusals it can make for a CA
            // that is gone or has ACME switched off are the refusals ResolveAsync used to throw.
            var submission = new EnrollmentSubmission
            {
                Protocol = Protocol,
                CaLabel = effectiveCaLabel,
                Correlation = order.Id.ToString(),
                RequestedNotBefore = order.NotBefore,
                RequestedNotAfter = order.NotAfter,
                Caller = new EnrollmentCaller(
                    Principal: $"acme-account:{order.AccountId}",
                    AuthMethod: EnrollmentAuthMethod.MessageSignature,
                    IsVerified: true),
                Request = new EnrollmentRequestMaterial
                {
                    CsrPem = csrPem,
                    Subject = parsedCsr.SubjectName,
                    SubjectAlternativeNames = parsedCsr.SubjectAlternativeNames,
                    KeyAlgorithm = parsedCsr.KeyAlgorithm,
                    KeySize = parsedCsr.KeySize,
                    SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
                },
                Audit = record => WriteAcmeAuditAsync(record, order, effectiveCaLabel),
            };

            var outcome = await _pipeline.SubmitAsync(submission);
            switch (outcome)
            {
                case EnrollmentOutcome.Issued issued:
                    order.FinalizedCsrId = issued.RequestId;
                    var issuedCertificateId = await _db.CertificateRequests
                        .Where(c => c.Id == issued.RequestId)
                        .Select(c => c.IssuedCertificateId)
                        .FirstOrDefaultAsync();
                    if (issuedCertificateId != null)
                        order.CertificateId = issuedCertificateId;
                    break;

                // An ACME order has no state for "waiting for a human". RFC 8555 lets finalize
                // leave the order processing and have the client poll, but nothing links an
                // approval made days later back to the order, so the client would poll an order
                // that never moves and an approver would issue a certificate nobody can fetch.
                // The finalize is refused instead, and the row the middle wrote is closed so the
                // approval queue does not fill with ACME requests that can never be collected.
                //
                // This is the one place where migrating changes what a CA does: an approval-gated
                // request profile on an ACME-enabled CA used to be ignored here and the
                // certificate issued without an approver. Refusing is the direction that fails
                // closed, and it is what the gate was configured to mean.
                case EnrollmentOutcome.Pending pending:
                    await CloseUncollectableRequestAsync(pending.RequestId);
                    throw new InvalidOperationException(
                        "The request profile for this CA requires approval, which ACME cannot wait for.");

                // Already audited, by the writer above and in the shape the ACME tab has. The
                // controller renders every one of these as the same RFC 8555 problem document, so
                // the sentence reaches the log and never the client.
                case EnrollmentOutcome.Refused refused:
                    throw new InvalidOperationException(refused.Message);

                case EnrollmentOutcome.Failed failed:
                    throw new InvalidOperationException(failed.Message);

                default:
                    throw new InvalidOperationException("Unrecognised enrollment outcome.");
            }

            order.Status = nameof(AcmeOrderStatus.Valid);
            await _db.SaveChangesAsync();
        }
        catch (Exception)
        {
            order.Status = nameof(AcmeOrderStatus.Invalid);
            await _db.SaveChangesAsync();
            throw;
        }

        return await BuildOrderDto(order, baseUrl);
    }

    /// <summary>
    /// Writes the shared audit fields the pipeline supplies as an ACME row, against the order the
    /// request finalizes.
    /// </summary>
    /// <remarks>
    /// An issued certificate keeps the row it has always had, down to the signing and certificate
    /// profile ids that let post-incident forensics trace a certificate back to the policy that
    /// issued it; those are read off the request row the middle wrote, so they are the profiles it
    /// actually used rather than the ones a second resolution would pick. A refusal is a new row:
    /// finalize refusals were audited nowhere before, so an operator saw a client failing and had
    /// only the application log to read.
    /// </remarks>
    /// <param name="record">The shared fields; see <see cref="EnrollmentAuditRecord"/>.</param>
    /// <param name="order">The order being finalized, which names the account and the identifiers.</param>
    /// <param name="caLabel">The CA label as the order carries it, which may be null for the default CA.</param>
    private async Task WriteAcmeAuditAsync(EnrollmentAuditRecord record, AcmeOrderEntity order, string? caLabel)
    {
        if (record.Event == EnrollmentAuditEvent.Issued)
        {
            var profiles = record.RequestId == null ? null : await _db.CertificateRequests
                .AsNoTracking()
                .Where(c => c.Id == record.RequestId.Value)
                .Select(c => new { c.SigningProfileId, c.CertProfileId })
                .FirstOrDefaultAsync();

            await _protocolAudit.LogAcmeAsync("CertificateIssued", order.AccountId, order.Id,
                record.Subject, record.SerialNumber,
                order.IdentifiersJson, null, null,
                caLabel: caLabel,
                signingProfileId: profiles?.SigningProfileId,
                certProfileId: profiles?.CertProfileId);
            return;
        }

        // Pending arrives here too, and is recorded as the refusal it becomes: the finalize is
        // turned down below rather than left waiting, so a row saying otherwise would describe an
        // order that does not exist.
        var reason = record.Event == EnrollmentAuditEvent.Pending
            ? "The request profile for this CA requires approval, which ACME cannot wait for."
            : record.Message ?? "Finalization refused.";

        await _protocolAudit.LogAcmeAsync("FinalizeRefused", order.AccountId, order.Id,
            record.Subject, null, order.IdentifiersJson, null, null,
            success: false, errorMessage: reason, caLabel: caLabel);
    }

    /// <summary>
    /// Closes a request row the middle took under submission for an order that cannot wait for an
    /// approver, so the approval queue does not accumulate ACME requests whose certificate nobody
    /// could ever collect.
    /// </summary>
    /// <param name="requestId">The row the pipeline wrote.</param>
    private async Task CloseUncollectableRequestAsync(Guid requestId)
    {
        var request = await _db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == requestId);
        if (request == null) return;
        request.Status = "Rejected";
        await _db.SaveChangesAsync();
    }

    /// <summary>
    /// Retrieves the account ID that owns the specified order.
    /// </summary>
    public async Task<Guid?> GetAccountIdForOrderAsync(Guid orderId)
    {
        var order = await _db.AcmeOrders.FindAsync(orderId);
        return order?.AccountId;
    }

    /// <summary>
    /// Retrieves the account ID that owns the ACME order associated with the given certificate
    /// serial number. Returns null if no ACME order is linked to that serial, or if the serial
    /// is linked to more than one order.
    /// <para>
    /// This is the ownership gate for ACME revocation, so an ambiguous serial must not resolve to
    /// an arbitrary order. A serial is unique only within an issuer, and picking either candidate
    /// would mean authorizing the revocation against a different certificate than the caller
    /// presented. Returning null denies, which is the correct answer when ownership cannot be
    /// established.
    /// </para>
    /// </summary>
    public async Task<Guid?> GetAccountIdForCertificateSerialAsync(string serialNumber, byte[]? presentedDer = null)
    {
        var orders = await _db.AcmeOrders
            .Include(o => o.Certificate)
            .Where(o => o.CertificateId != null
                && o.Certificate != null
                && o.Certificate.SerialNumber == serialNumber)
            .Take(2)
            .ToListAsync();

        if (orders.Count != 1) return null;

        // Bind the decision to the exact certificate the caller presented.
        //
        // RFC 8555 §7.6 has the client send the whole certificate, but matching only its serial
        // means the check answers "some certificate with this serial belongs to you" rather than
        // "this certificate belongs to you". A serial is unique only within an issuer, so those
        // are not the same question. Comparing the DER closes the gap for free — a legitimate
        // client is presenting the very bytes we issued.
        if (presentedDer is { Length: > 0 })
        {
            var stored = orders[0].Certificate?.RawCertificate;
            if (stored == null || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(stored, presentedDer))
                return null;
        }

        return orders[0].AccountId;
    }

    /// <summary>
    /// Audit findings #28: returns the issued certificate serial associated with the ACME
    /// order, or null if none has been issued yet. Used by the controller to populate the
    /// <c>AcmeOrderFinalized</c> audit detail without coupling controllers to the DbContext.
    /// </summary>
    public async Task<string?> GetIssuedCertificateSerialForOrderAsync(Guid orderId)
    {
        var order = await _db.AcmeOrders
            .Include(o => o.Certificate)
            .AsNoTracking()
            .FirstOrDefaultAsync(o => o.Id == orderId);
        return order?.Certificate?.SerialNumber;
    }

    /// <summary>
    /// Builds the PEM chain for an ACME order's issued certificate.
    /// Previously walked the CA hierarchy with one query per hop — replaced with a single
    /// materialisation of CA certificates into a Dictionary and an in-memory walk keyed on
    /// CertificateId. One DB round-trip regardless of chain depth.
    /// </summary>
    public async Task<string?> DownloadCertificateAsync(Guid orderId)
    {
        var order = await _db.AcmeOrders.FindAsync(orderId);
        if (order == null || order.Status != nameof(AcmeOrderStatus.Valid) || order.CertificateId == null)
            return null;

        var leafCert = await _db.Certificates
            .AsNoTracking()
            .Include(c => c.SigningProfile)
            .FirstOrDefaultAsync(c => c.CertificateId == order.CertificateId.Value);
        if (leafCert == null)
            return null;

        var chain = new StringBuilder();
        chain.AppendLine(leafCert.Pem.Trim());

        // Single-shot fetch of every CA-bearing certificate + its signing profile, keyed by id
        // for an O(1) parent lookup. This is small (number of CAs in the system, not number
        // of leaf certs), so the memory cost is negligible.
        var caCerts = await _db.Certificates
            .AsNoTracking()
            .Where(c => c.IsCA)
            .Include(c => c.SigningProfile)
            .ToDictionaryAsync(c => c.CertificateId);

        var issuerId = leafCert.SigningProfile?.IssuerId;
        var visited = new HashSet<Guid>();
        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            if (!caCerts.TryGetValue(issuerId.Value, out var issuer))
                break;
            chain.AppendLine(issuer.Pem.Trim());
            issuerId = issuer.SigningProfile?.IssuerId;
        }

        return chain.ToString();
    }

    /// <summary>
    /// Expires stale ACME orders and authorizations. Set-based
    /// ExecuteUpdateAsync instead of materialising every stale row into memory. Each call
    /// now issues exactly two UPDATE round-trips regardless of backlog size.
    /// </summary>
    public async Task ExpireStaleOrdersAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var invalid = nameof(AcmeOrderStatus.Invalid);
        var pending = nameof(AcmeOrderStatus.Pending);
        var ready = nameof(AcmeOrderStatus.Ready);

        await _db.AcmeOrders
            .Where(o => o.ExpiresAt <= now &&
                        (o.Status == pending || o.Status == ready))
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, _ => invalid), cancellationToken);

        var authzPending = nameof(AcmeAuthorizationStatus.Pending);
        var authzExpired = nameof(AcmeAuthorizationStatus.Expired);

        await _db.AcmeAuthorizations
            .Where(a => a.ExpiresAt <= now && a.Status == authzPending)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, _ => authzExpired), cancellationToken);
    }

    public async Task<bool> HasStaleOrdersAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        return await _db.AcmeOrders.AnyAsync(o => o.ExpiresAt <= now &&
            (o.Status == nameof(AcmeOrderStatus.Pending) || o.Status == nameof(AcmeOrderStatus.Ready)), cancellationToken)
            || await _db.AcmeAuthorizations.AnyAsync(a => a.ExpiresAt <= now && a.Status == nameof(AcmeAuthorizationStatus.Pending), cancellationToken);
    }

    /// <summary>
    /// Exact wildcard-aware CSR identifier comparison. The
    /// previous implementation called <c>TrimStart('*', '.')</c> on both sides,
    /// which collapsed <c>*.example.com</c> to <c>example.com</c> and let a
    /// non-wildcard SAN pass through an order that only authorized the wildcard
    /// (and vice versa). We now normalize by lower-casing + IDN-to-ASCII and
    /// compare verbatim so <c>*.example.com</c> must appear in the order
    /// exactly, and a bare <c>example.com</c> in the CSR requires <c>example.com</c>
    /// in the order. Also enforces that the CSR CN (if present) equals one of
    /// the SAN values per BR 7.1.4.
    /// </summary>
    private static void ValidateCsrAgainstOrder(CertificateUtil.ParsedCsrInfo parsedCsr, List<AcmeIdentifier> orderIdentifiers)
    {
        var idn = new IdnMapping();

        static string? ExtractCommonName(string? subjectDn)
        {
            if (string.IsNullOrEmpty(subjectDn)) return null;
            foreach (var part in subjectDn.Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed[3..];
            }
            return null;
        }

        string NormalizeDomain(string raw)
        {
            var trimmed = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (trimmed.StartsWith("*.", StringComparison.Ordinal))
            {
                var rest = trimmed[2..];
                if (rest.Length == 0) return trimmed;
                try { rest = idn.GetAscii(rest); } catch (ArgumentException) { /* leave as-is */ }
                return "*." + rest;
            }
            try { return idn.GetAscii(trimmed); } catch (ArgumentException) { return trimmed; }
        }

        var orderDomains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in orderIdentifiers.Where(i => i.Type == "dns"))
            orderDomains.Add(NormalizeDomain(id.Value));

        // Collect CSR SAN dNSName values with wildcards preserved.
        var csrSans = new HashSet<string>(StringComparer.Ordinal);
        foreach (var san in parsedCsr.SubjectAlternativeNames)
        {
            if (!san.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
            {
                // Non-DNS SANs are not permitted in ACME DNS-identifier orders.
                var type = san.Contains(':') ? san[..san.IndexOf(':')] : "<raw>";
                throw new InvalidOperationException($"CSR contains non-DNS SAN of type '{type}', which is not permitted for ACME orders.");
            }
            var value = san[(san.IndexOf(':') + 1)..];
            if (!string.IsNullOrWhiteSpace(value))
                csrSans.Add(NormalizeDomain(value));
        }

        // Every CSR SAN must appear verbatim in the order identifier set.
        foreach (var sanDomain in csrSans)
        {
            if (!orderDomains.Contains(sanDomain))
                throw new InvalidOperationException($"CSR SAN '{sanDomain}' is not present in the order identifier list.");
        }

        // BR 7.1.4.2: if a CN is present, it must equal one of the SANs exactly
        // (after the same normalization).
        var cn = ExtractCommonName(parsedCsr.SubjectName);
        if (!string.IsNullOrEmpty(cn))
        {
            var cnNormalized = NormalizeDomain(cn);
            if (csrSans.Count > 0 && !csrSans.Contains(cnNormalized))
                throw new InvalidOperationException($"CSR CN '{cnNormalized}' does not match any SAN.");
            if (!orderDomains.Contains(cnNormalized))
                throw new InvalidOperationException($"CSR CN '{cnNormalized}' is not present in the order identifier list.");
        }
    }

    private async Task<AcmeOrderDto> BuildOrderDto(AcmeOrderEntity order, string baseUrl)
    {
        var identifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(order.IdentifiersJson) ?? [];

        var authzIds = await _db.AcmeAuthorizations
            .Where(a => a.OrderId == order.Id)
            .Select(a => a.Id)
            .ToListAsync();

        var dto = new AcmeOrderDto
        {
            Id = order.Id,
            Status = order.Status.ToLowerInvariant(),
            Identifiers = identifiers,
            NotBefore = order.NotBefore,
            NotAfter = order.NotAfter,
            ExpiresAt = order.ExpiresAt,
            Authorizations = authzIds.Select(id => $"{baseUrl}/api/v1/acme/authz/{id}").ToList(),
            Finalize = $"{baseUrl}/api/v1/acme/order/{order.Id}/finalize"
        };

        if (order.Status == nameof(AcmeOrderStatus.Valid) && order.CertificateId != null)
            dto.Certificate = $"{baseUrl}/api/v1/acme/cert/{order.Id}";

        return dto;
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    /// <summary>
    /// Reads the challenge types the addressed CA permits, or null for no restriction.
    /// </summary>
    private async Task<IReadOnlyCollection<string>?> GetAllowedChallengeTypesAsync(string? caLabel)
    {
        var cas = _db.CertificateAuthorities.AsNoTracking().Where(c => c.IsEnabled);
        cas = string.IsNullOrWhiteSpace(caLabel)
            ? cas.OrderByDescending(c => c.IsDefault)
            : cas.Where(c => c.Label == caLabel);
        var caId = await cas.Select(c => (Guid?)c.Id).FirstOrDefaultAsync();
        if (caId == null)
            return null;

        var raw = await _db.CaProtocolConfigs.AsNoTracking()
            .Where(c => c.CaId == caId && c.Protocol == "ACME")
            .Select(c => c.AcmeAllowedChallengeTypes)
            .FirstOrDefaultAsync();
        return AcmeChallengeTypePolicy.Parse(raw);
    }
}
