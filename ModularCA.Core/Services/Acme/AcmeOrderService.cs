using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Manages ACME order lifecycle including creation, finalization, and certificate issuance.
/// </summary>
public class AcmeOrderService(
    ModularCADbContext db,
    ICertificateIssuanceService issuanceService,
    ICertificateStore certStore,
    ICaResolverService caResolver,
    IProtocolAuditService protocolAudit,
    RequestProfileValidationService requestProfileValidation,
    ICaaCheckService caaCheckService) : IAcmeOrderService
{
    private readonly ModularCADbContext _db = db;
    private readonly ICertificateIssuanceService _issuanceService = issuanceService;
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICaResolverService _caResolver = caResolver;
    private readonly IProtocolAuditService _protocolAudit = protocolAudit;
    private readonly RequestProfileValidationService _requestProfileValidation = requestProfileValidation;
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

        // Previously this loop called SaveChangesAsync twice per identifier,
        // producing 2N round-trips on ACME order creation with N SANs. Now we stage every
        // authorization + its challenges in the change tracker and commit once after the loop.
        // AcmeAuthorizationEntity.Id is Guid-generated in the entity default, so challenges
        // can reference authz.Id without a flush.
        foreach (var identifier in identifiers)
        {
            var authz = AcmeAuthorizationService.CreateAuthorizationWithChallenges(order.Id, identifier);
            _db.AcmeAuthorizations.Add(authz);

            var challenges = AcmeAuthorizationService.CreateChallengesForAuthorization(authz.Id, authz.IsWildcard);
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
    /// Finalizes an ACME order by decoding the CSR, validating it against the
    /// order identifiers, issuing the certificate via the configured cert and
    /// signing profiles, and updating the order status.
    /// The CA label is plumbed from the order's stored value (or optionally
    /// from <paramref name="caLabel"/> if the caller wants to override) into
    /// <see cref="ICaResolverService"/> so the right CA signs the cert.
    /// </summary>
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

            // Resolve CA using the order's stored CA label
            // (captured at new-order time) rather than the hard-coded null that
            // always picked the protocol-level default.
            var effectiveCaLabel = !string.IsNullOrWhiteSpace(caLabel) ? caLabel : order.CaLabel;
            var caContext = await _caResolver.ResolveAsync(effectiveCaLabel, "ACME");
            var signingProfileId = caContext.SigningProfileId;

            // Resolve cert profile: ACME doesn't support requester choice → protocol default → request profile default
            var (resolvedCertProfileId, certProfileError) = await _requestProfileValidation
                .ResolveCertProfileIdAsync(null, caContext.CertProfileId, caContext.RequestProfileId);
            if (resolvedCertProfileId == null)
                throw new InvalidOperationException(certProfileError ?? "No certificate profile available for ACME");
            var certProfileId = resolvedCertProfileId.Value;

            var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId)
                ?? throw new InvalidOperationException("Configured ACME signing profile not found.");
            var certProfile = await _db.CertProfiles.FindAsync(certProfileId)
                ?? throw new InvalidOperationException("Configured ACME certificate profile not found.");

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

            // Create the CSR entity for the issuance pipeline
            var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);
            var subject = parsedCsr.SubjectName;

            // Validate against request profile if one is configured for this protocol
            if (caContext.RequestProfileId != null)
            {
                var (isValid, error, modifiedSubject) = await _requestProfileValidation
                    .ValidateAsync(caContext.RequestProfileId.Value, subject, sanJson);
                if (!isValid)
                    throw new InvalidOperationException(error ?? "Request profile validation failed");
                if (modifiedSubject != null)
                    subject = modifiedSubject;
            }

            var csrEntity = new CertRequestEntity
            {
                Subject = subject,
                SubjectAlternativeNames = sanJson,
                CSR = csrPem,
                KeyAlgorithm = parsedCsr.KeyAlgorithm,
                KeySize = parsedCsr.KeySize,
                SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
                SubmittedAt = DateTime.UtcNow,
                Status = "Pending",
                CertProfileId = certProfileId,
                CertProfile = certProfile,
                SigningProfileId = signingProfileId,
                SigningProfile = signingProfile
            };

            _db.CertificateRequests.Add(csrEntity);
            await _db.SaveChangesAsync();

            order.FinalizedCsrId = csrEntity.Id;

            // Default validity dates from signing profile when certbot omits them
            var issuanceNotBefore = order.NotBefore ?? DateTime.UtcNow;
            var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
            var issuanceNotAfter = order.NotAfter ?? issuanceNotBefore.Add(maxValidity);

            // Issue the certificate
            var result = await _issuanceService.IssueCertificateAsync(
                csrEntity.Id,
                issuanceNotBefore,
                issuanceNotAfter);
            var certPem = result.Pem;

            // Parse the issued cert for audit details
            var issuedCert = CertificateUtil.ParseFromPem(certPem);

            var identifiersJson = order.IdentifiersJson;
            // Include signing/cert profile ids and caLabel so
            // post-incident forensics can trace the cert back to the policy
            // that issued it.
            await _protocolAudit.LogAcmeAsync("CertificateIssued", order.AccountId, order.Id,
                csrEntity.Subject, CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
                identifiersJson, null, null,
                caLabel: effectiveCaLabel,
                signingProfileId: signingProfileId,
                certProfileId: certProfileId);

            // Find the issued certificate entity
            var csrWithCert = await _db.CertificateRequests
                .Include(c => c.IssuedCertificate)
                .FirstOrDefaultAsync(c => c.Id == csrEntity.Id);

            if (csrWithCert?.IssuedCertificateId != null)
            {
                order.CertificateId = csrWithCert.IssuedCertificateId;
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
    /// Retrieves the account ID that owns the specified order.
    /// </summary>
    public async Task<Guid?> GetAccountIdForOrderAsync(Guid orderId)
    {
        var order = await _db.AcmeOrders.FindAsync(orderId);
        return order?.AccountId;
    }

    /// <summary>
    /// Retrieves the account ID that owns the ACME order associated with the given certificate serial number.
    /// Returns null if no ACME order is linked to that serial.
    /// </summary>
    public async Task<Guid?> GetAccountIdForCertificateSerialAsync(string serialNumber)
    {
        var order = await _db.AcmeOrders
            .Include(o => o.Certificate)
            .FirstOrDefaultAsync(o => o.CertificateId != null
                && o.Certificate != null
                && o.Certificate.SerialNumber == serialNumber);
        return order?.AccountId;
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
}
