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
    /// Creates a new ACME order at <paramref name="ca"/>, the CA the account is bound to. The
    /// CA's label is persisted on the order row, so finalize issues from the same CA, and the
    /// order's challenges follow that CA's challenge-type policy.
    /// </summary>
    public async Task<AcmeOrderDto> CreateAsync(Guid accountId, CreateAcmeOrderRequest request, string baseUrl, CertificateAuthorityEntity ca)
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
            CaLabel = string.IsNullOrWhiteSpace(ca.Label) ? null : ca.Label
        };

        _db.AcmeOrders.Add(order);
        await _db.SaveChangesAsync();

        // The per-CA AcmeAllowedChallengeTypes setting was stored and never read; every
        // authorization offered http-01 and dns-01 regardless. Resolved once per order.
        var allowedChallengeTypes = await GetAllowedChallengeTypesAsync(ca.Id);

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
    /// <paramref name="addressedCa"/> is the CA the request addresses, which is the CA the
    /// account is bound to. An order placed at any other CA is refused, on every route,
    /// label-less ones included. The CA's label is handed to the pipeline, which resolves the CA,
    /// refuses a CA that is gone or has ACME switched off, and reads that CA's ACME profiles;
    /// a label that would resolve to a different CA (a CA without a label that is not the
    /// default) is refused rather than issued from elsewhere.
    /// </para>
    /// <para>
    /// Every refusal below reaches the client as one RFC 8555 problem document, because that is
    /// what the controller has always rendered a failed finalize as: 403 with type
    /// <c>urn:ietf:params:acme:error:orderNotReady</c> and a fixed detail. The sentence a refusal
    /// carries is for the log and the ACME audit tab, and the order state machine is what the
    /// client reads instead.
    /// </para>
    /// </remarks>
    public async Task<AcmeOrderDto> FinalizeAsync(Guid orderId, string csrBase64Url, string baseUrl, CertificateAuthorityEntity addressedCa)
    {
        ArgumentNullException.ThrowIfNull(addressedCa);
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

            // The order must have been placed at the CA that finalizes it, so an authorization
            // validated under one CA's policy (say a lab CA allowing private addresses) is never
            // signed by another. This used to be skipped on the label-less routes.
            if (!string.Equals(order.CaLabel, addressedCa.Label, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Order belongs to CA '{order.CaLabel ?? "(no label)"}' and cannot be finalized at CA '{addressedCa.Label ?? addressedCa.Name}'.");
            }
            if ((await CaResolverService.FindAddressedCaAsync(_db, addressedCa.Label))?.Id != addressedCa.Id)
            {
                throw new InvalidOperationException(
                    $"CA '{addressedCa.Label ?? addressedCa.Name}' cannot be addressed by its label, so its orders cannot be finalized.");
            }

            var effectiveCaLabel = addressedCa.Label;

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
                CommonNameIfProfileRequiresOne = CommonNameFromSans(parsedCsr.SubjectAlternativeNames),
                Audit = record => WriteAcmeAuditAsync(record, order, addressedCa),
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
    /// <param name="ca">The CA the order is finalized at, the account's bound CA, whose label, id and space the row carries.</param>
    private async Task WriteAcmeAuditAsync(EnrollmentAuditRecord record, AcmeOrderEntity order, CertificateAuthorityEntity ca)
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
                caLabel: ca.Label, certificateAuthorityId: ca.Id, spaceId: ca.SpaceId,
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
            success: false, errorMessage: reason,
            caLabel: ca.Label, certificateAuthorityId: ca.Id, spaceId: ca.SpaceId);
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
    /// The first DNS name of a certification request, when it can stand as a common name: 64
    /// characters or fewer (the limit on a common name) and made only of the characters a
    /// hostname or wildcard uses. Null otherwise. It is the first name and no other because that
    /// is the name issuance gives a certificate whose request has no subject
    /// (<c>CertificateBuilderService.ResolveSubjectDn</c>), so what the request profile is asked
    /// about is what the certificate will carry. The names have already been checked against
    /// the order (<see cref="ValidateCsrAgainstOrder"/>).
    /// </summary>
    internal static string? CommonNameFromSans(IEnumerable<string> subjectAlternativeNames)
    {
        var first = subjectAlternativeNames.FirstOrDefault(s => s.StartsWith("dns:", StringComparison.OrdinalIgnoreCase));
        if (first == null) return null;
        var value = first[4..].Trim();
        return value.Length is > 0 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '*')
            ? value
            : null;
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

    /// <summary>
    /// The order object (RFC 8555 §7.1.3). Its authorization, finalize and certificate URLs are
    /// under the path of the CA the order was placed at (<see cref="AcmeCaPolicy.PathPrefix"/>),
    /// which is the account's bound CA, so they keep working whichever route the client used and
    /// whatever the default CA becomes.
    /// </summary>
    private async Task<AcmeOrderDto> BuildOrderDto(AcmeOrderEntity order, string baseUrl)
    {
        var identifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(order.IdentifiersJson) ?? [];

        var authzIds = await _db.AcmeAuthorizations
            .Where(a => a.OrderId == order.Id)
            .Select(a => a.Id)
            .ToListAsync();

        var acmeBase = baseUrl + AcmeCaPolicy.PathPrefix(order.CaLabel);
        var dto = new AcmeOrderDto
        {
            Id = order.Id,
            Status = order.Status.ToLowerInvariant(),
            Identifiers = identifiers,
            NotBefore = order.NotBefore,
            NotAfter = order.NotAfter,
            ExpiresAt = order.ExpiresAt,
            Authorizations = authzIds.Select(id => $"{acmeBase}/authz/{id}").ToList(),
            Finalize = $"{acmeBase}/order/{order.Id}/finalize"
        };

        if (order.Status == nameof(AcmeOrderStatus.Valid) && order.CertificateId != null)
            dto.Certificate = $"{acmeBase}/cert/{order.Id}";

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
    /// Reads the challenge types CA <paramref name="caId"/>, the order's CA, permits, or null for
    /// no restriction.
    /// </summary>
    private async Task<IReadOnlyCollection<string>?> GetAllowedChallengeTypesAsync(Guid caId)
    {
        var raw = await _db.CaProtocolConfigs.AsNoTracking()
            .Where(c => c.CaId == caId && c.Protocol == "ACME")
            .Select(c => c.AcmeAllowedChallengeTypes)
            .FirstOrDefaultAsync();
        return AcmeChallengeTypePolicy.Parse(raw);
    }
}
