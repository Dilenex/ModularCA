using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Text.Json;

namespace ModularCA.Core.Services.Est;

/// <summary>
/// Thrown when an EST enrollment request requires manual approval before issuance.
/// The controller should catch this and return HTTP 202 Accepted.
/// </summary>
public class EstPendingApprovalException : Exception
{
    public EstPendingApprovalException(string message) : base(message) { }
}

/// <summary>
/// Implements the EST (Enrollment over Secure Transport) protocol for certificate enrollment and renewal.
/// </summary>
public class EstService : IEstService
{
    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ICertificateIssuanceService _issuanceService;
    private readonly ICaResolverService _caResolver;
    private readonly IProtocolAuditService _protocolAudit;
    private readonly IEnrollmentAuthorizationService _enrollmentAuth;
    private readonly RequestProfileValidationService _requestProfileValidation;
    private readonly INotificationService _notifications;
    private readonly ILogger<EstService> _logger;

    public EstService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ICertificateIssuanceService issuanceService,
        ICaResolverService caResolver,
        IProtocolAuditService protocolAudit,
        IEnrollmentAuthorizationService enrollmentAuth,
        RequestProfileValidationService requestProfileValidation,
        INotificationService notifications,
        ILogger<EstService> logger)
    {
        _db = db;
        _keystore = keystore;
        _issuanceService = issuanceService;
        _caResolver = caResolver;
        _protocolAudit = protocolAudit;
        _enrollmentAuth = enrollmentAuth;
        _requestProfileValidation = requestProfileValidation;
        _notifications = notifications;
        _logger = logger;
    }

    public async Task<byte[]> GetCaCertsAsync(string? caLabel = null)
    {
        var context = await _caResolver.ResolveAsync(caLabel, "EST");
        var signingProfile = await _db.SigningProfiles.FindAsync(context.SigningProfileId);

        if (signingProfile?.IssuerId == null)
        {
            // No signing profile or issuer configured — fall back to all trusted authorities
            var allCerts = _keystore.GetTrustedAuthorities();
            return BuildCertsOnlyPkcs7(allCerts);
        }

        // Walk the issuer chain from the signing profile to collect only
        // the CA certificates in the actual issuance path, excluding any
        // unrelated certificates such as the system signing cert.
        var caCerts = new List<X509Certificate>();
        var visited = new HashSet<Guid>();
        var issuerId = signingProfile.IssuerId;

        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuerEntity = await _db.Certificates
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
            if (issuerEntity == null) break;

            var issuerCert = CertificateUtil.ParseFromPem(issuerEntity.Pem);
            caCerts.Add(issuerCert);
            issuerId = issuerEntity.SigningProfile?.IssuerId;
        }

        return BuildCertsOnlyPkcs7(caCerts);
    }

    /// <summary>
    /// Performs EST simple enrollment by decoding the base64-encoded CSR, resolving the CA context
    /// and certificate/signing profiles, issuing the certificate, and returning the result as PKCS#7.
    /// </summary>
    public async Task<byte[]> SimpleEnrollAsync(string base64Csr, string? caLabel = null, string? sourceIp = null,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert = null, bool isAuthenticated = false,
        string? callerUsername = null)
    {
        var csrPem = DecodeCsrFromBase64(base64Csr);

        // Enrollment authorization check
        var (allowed, authError) = await _enrollmentAuth.ValidateAsync("EST", caLabel, csrPem, clientCert, isAuthenticated);
        if (!allowed)
        {
            // Surface authorization denials on the EST audit tab — previously these threw
            // without any protocol audit row, leaving rejected enrollments invisible.
            await _protocolAudit.LogEstAsync("EstEnrollRejected", null, null,
                null, null, caLabel, sourceIp,
                success: false, errorMessage: authError ?? "Enrollment not authorized",
                callerPrincipal: clientCert != null ? $"mtls:{clientCert.Subject}"
                    : (!string.IsNullOrEmpty(callerUsername) ? $"basic:{callerUsername}" : null));
            throw new InvalidOperationException(authError ?? "Enrollment not authorized");
        }

        var parsedCsr = CertificateUtil.ParseCsr(csrPem);

        // Cross-check CSR subject/SAN against caller identity. A client
        // authenticated as "alice" must NOT be able to submit a CSR with subject
        // CN=root-admin and receive it. The request profile can still override patterns
        // downstream, but the caller-identity binding is enforced here so privilege
        // escalation via EST is closed by default.
        if (clientCert != null)
        {
            var csrSanValues = parsedCsr.SubjectAlternativeNames
                .Select(s => s.Contains(':') ? s.Split(':', 2)[1] : s)
                .ToList();

            // Gather the client cert's subject CN + SANs. Any parse failure in these
            // extractors fails closed (they throw InvalidOperationException) — we emit
            // the EstEnrollRejected audit before propagating so the operator can trace
            // the rejection.
            string? clientCn;
            List<string> clientSans;
            string? csrCn;
            try
            {
                clientCn = ExtractCommonName(clientCert.Subject);
                clientSans = ExtractClientCertSans(clientCert);
                csrCn = ExtractCommonName(parsedCsr.SubjectName);
            }
            catch (InvalidOperationException ex)
            {
                await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                    parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                    success: false, errorMessage: $"Malformed identity input: {ex.Message}",
                    callerPrincipal: $"mtls:{clientCert.Subject ?? "?"}");
                throw;
            }

            bool subjectOk = string.IsNullOrEmpty(csrCn)
                || (clientCn != null && string.Equals(csrCn, clientCn, StringComparison.OrdinalIgnoreCase));

            bool sansOk = csrSanValues.Count == 0 ||
                csrSanValues.All(csrSan =>
                    clientSans.Any(cs => string.Equals(cs, csrSan, StringComparison.OrdinalIgnoreCase)));

            if (!subjectOk || !sansOk)
            {
                await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                    parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                    success: false, errorMessage: "CSR subject/SAN does not match mTLS client identity",
                    callerPrincipal: $"mtls:{clientCn ?? "?"}");
                throw new InvalidOperationException(
                    "CSR subject or SANs do not match the authenticated mTLS client identity.");
            }
        }
        else if (isAuthenticated && !string.IsNullOrEmpty(callerUsername))
        {
            // HTTP Basic / bearer path: CSR CN must match the authenticated username.
            string? csrCn;
            try
            {
                csrCn = ExtractCommonName(parsedCsr.SubjectName);
            }
            catch (InvalidOperationException ex)
            {
                await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                    parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                    success: false, errorMessage: $"Malformed CSR DN: {ex.Message}",
                    callerPrincipal: $"basic:{callerUsername}");
                throw;
            }
            if (!string.IsNullOrEmpty(csrCn) &&
                !string.Equals(csrCn, callerUsername, StringComparison.OrdinalIgnoreCase))
            {
                await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                    parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                    success: false, errorMessage: "CSR CN does not match authenticated username",
                    callerPrincipal: $"basic:{callerUsername}");
                throw new InvalidOperationException(
                    "CSR CN does not match the authenticated caller username.");
            }
        }

        var context = await _caResolver.ResolveAsync(caLabel, "EST");
        var signingProfileId = context.SigningProfileId;

        // Resolve cert profile: requester's choice (EST doesn't support this) → protocol default → request profile default
        var (resolvedCertProfileId, certProfileError) = await _requestProfileValidation
            .ResolveCertProfileIdAsync(null, context.CertProfileId, context.RequestProfileId);
        if (resolvedCertProfileId == null)
            throw new InvalidOperationException(certProfileError ?? "No certificate profile available for EST");
        var certProfileId = resolvedCertProfileId.Value;

        var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId)
            ?? throw new InvalidOperationException("Configured EST signing profile not found.");
        var certProfile = await _db.CertProfiles.FindAsync(certProfileId)
            ?? throw new InvalidOperationException("Configured EST certificate profile not found.");

        var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);
        var subject = parsedCsr.SubjectName;

        // Validate against request profile if one is configured for this protocol
        bool requireApproval = false;
        if (context.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await _requestProfileValidation
                .ValidateAsync(context.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
            {
                await _protocolAudit.LogEstAsync("EstEnrollRejected", subject, null,
                    parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                    success: false, errorMessage: error ?? "Request profile validation failed");
                throw new InvalidOperationException(error ?? "Request profile validation failed");
            }
            if (modifiedSubject != null)
                subject = modifiedSubject;

            // Check if the request profile requires manual approval
            var requestProfile = await _db.RequestProfiles.FindAsync(context.RequestProfileId.Value);
            if (requestProfile?.RequireApproval == true)
                requireApproval = true;
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
            Status = requireApproval ? "PendingApproval" : "Pending",
            CertProfileId = certProfileId,
            CertProfile = certProfile,
            SigningProfileId = signingProfileId,
            SigningProfile = signingProfile
        };

        _db.CertificateRequests.Add(csrEntity);
        await _db.SaveChangesAsync();

        // If approval is required, skip issuance and return 202 Accepted
        if (requireApproval)
        {
            await _protocolAudit.LogEstAsync("SimpleEnroll-PendingApproval", subject,
                null, parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp);

            // Notify administrators that a CSR requires manual approval
            _ = _notifications.NotifyCsrPendingApprovalAsync(subject, "EST");

            throw new EstPendingApprovalException("Certificate request requires approval");
        }

        var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.Add(maxValidity);

        var issuanceResult = await _issuanceService.IssueCertificateAsync(
            csrEntity.Id, notBefore, notAfter);
        var certPem = issuanceResult.Pem;

        // Audit the enrollment
        var issuedCert = await _db.CertificateRequests
            .Where(c => c.Id == csrEntity.Id)
            .Select(c => c.IssuedCertificate)
            .FirstOrDefaultAsync();
        await _protocolAudit.LogEstAsync("SimpleEnroll", subject,
            issuedCert?.SerialNumber, parsedCsr.KeyAlgorithm, parsedCsr.KeySize,
            caLabel, sourceIp);

        return await BuildCertResponsePkcs7(certPem, csrEntity);
    }

    /// <summary>
    /// Performs EST simple re-enrollment (RFC 7030 §4.2.2). Validates the presenting client
    /// certificate is not expired, not revoked, was issued by the target CA, is within the
    /// configurable renewal window (last 30% of validity), and that the CSR subject matches
    /// the original certificate subject before delegating to the enrollment pipeline.
    /// </summary>
    public async Task<byte[]> SimpleReenrollAsync(string base64Csr, string? caLabel = null, string? sourceIp = null,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert = null, bool isAuthenticated = false,
        string? callerUsername = null)
    {
        // RFC 7030 §4.2.2: The client certificate from mTLS authenticates the renewal.
        if (clientCert != null)
        {
            // 1. Verify the client certificate is not expired
            var now = DateTime.UtcNow;
            if (now > clientCert.NotAfter)
                await ThrowReenrollRejectedAsync("Client certificate has expired and cannot be used for re-enrollment.", caLabel, sourceIp, clientCert);
            if (now < clientCert.NotBefore)
                await ThrowReenrollRejectedAsync("Client certificate is not yet valid.", caLabel, sourceIp, clientCert);

            // 2. Verify the client certificate is not revoked (check our DB)
            var clientSerialHex = clientCert.SerialNumber?.ToUpperInvariant();
            if (!string.IsNullOrEmpty(clientSerialHex))
            {
                var certEntity = await _db.Certificates
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.SerialNumber == clientSerialHex);
                if (certEntity != null && certEntity.Revoked)
                    await ThrowReenrollRejectedAsync("Client certificate has been revoked and cannot be used for re-enrollment.", caLabel, sourceIp, clientCert);
            }

            // 3. Verify the client cert was issued by the target CA
            var context = await _caResolver.ResolveAsync(caLabel, "EST");
            var signingProfile = await _db.SigningProfiles.FindAsync(context.SigningProfileId);
            if (signingProfile?.IssuerId != null)
            {
                var caCertEntity = await _db.Certificates
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId);
                if (caCertEntity != null)
                {
                    // Compare issuer DN: the client cert's Issuer must match the CA cert's Subject
                    var caSubjectDn = caCertEntity.SubjectDN;
                    var clientIssuerDn = clientCert.Issuer;
                    if (!string.IsNullOrEmpty(caSubjectDn) && !string.IsNullOrEmpty(clientIssuerDn))
                    {
                        // Normalize for comparison: both may use different RDN orderings
                        var normalizedCaSubject = NormalizeDn(caSubjectDn);
                        var normalizedClientIssuer = NormalizeDn(clientIssuerDn);
                        if (!string.Equals(normalizedCaSubject, normalizedClientIssuer, StringComparison.OrdinalIgnoreCase))
                            await ThrowReenrollRejectedAsync(
                                "Client certificate was not issued by the CA being re-enrolled against.", caLabel, sourceIp, clientCert);
                    }
                }
            }

            // 4. Only allow re-enrollment within the last 30% of the validity period
            var totalValidity = clientCert.NotAfter - clientCert.NotBefore;
            var renewalWindowStart = clientCert.NotBefore + TimeSpan.FromTicks((long)(totalValidity.Ticks * 0.70));
            if (now < renewalWindowStart)
                await ThrowReenrollRejectedAsync(
                    $"Re-enrollment is only allowed within the renewal window (last 30% of validity). " +
                    $"Renewal opens on {renewalWindowStart:u}.", caLabel, sourceIp, clientCert);

            // 5. Verify the CSR subject matches the original certificate subject
            var csrPem = DecodeCsrFromBase64(base64Csr);
            var parsedCsr = CertificateUtil.ParseCsr(csrPem);
            var csrSubject = NormalizeDn(parsedCsr.SubjectName);
            var clientSubject = NormalizeDn(clientCert.Subject);
            if (!string.Equals(csrSubject, clientSubject, StringComparison.OrdinalIgnoreCase))
                await ThrowReenrollRejectedAsync(
                    "CSR subject must match the original certificate subject for re-enrollment.", caLabel, sourceIp, clientCert);
        }

        return await SimpleEnrollAsync(base64Csr, caLabel, sourceIp, clientCert, isAuthenticated, callerUsername);
    }

    /// <summary>
    /// Records an EST re-enrollment rejection on the protocol audit tab, then throws.
    /// The renewal-gating checks in <see cref="SimpleReenrollAsync"/> previously threw with
    /// no audit row, so rejected renewals never appeared on the EST tab. Always throws.
    /// </summary>
    private async Task ThrowReenrollRejectedAsync(string reason, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2 clientCert)
    {
        await _protocolAudit.LogEstAsync("EstReenrollRejected", clientCert.Subject, null,
            null, null, caLabel, sourceIp, success: false, errorMessage: reason,
            callerPrincipal: $"mtls:{clientCert.Subject}");
        throw new InvalidOperationException(reason);
    }

    /// <summary>
    /// RFC 2253 canonical form via BouncyCastle's <see cref="X509Name"/>
    /// equivalence. The old heuristic (split-on-comma, upper, sort) broke on escaped commas
    /// (<c>CN=Doe\, Jane</c>) and multi-value RDNs (<c>CN=a+OU=b</c>). Falling back to the
    /// old behaviour on parse failure keeps renewal working for malformed inputs rather than
    /// rejecting with a confusing error. Equivalence check via <see cref="X509Name.Equivalent(X509Name, bool)"/>
    /// from the caller.
    /// </summary>
    private static string NormalizeDn(string dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return string.Empty;
        try
        {
            var x500 = new X509Name(dn);
            return x500.ToString(reverse: true, X509Name.RFC2253Symbols).ToUpperInvariant();
        }
        catch
        {
            // Defensive fallback for malformed DNs
            var parts = dn.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().ToUpperInvariant())
                .OrderBy(p => p)
                .ToArray();
            return string.Join(",", parts);
        }
    }

    /// <summary>
    /// Extract CN from an X.500 DN string. Returns null when no CN is present.
    /// Prefers BouncyCastle's <see cref="X509Name"/> parser so escaped commas survive.
    /// Now throws <see cref="InvalidOperationException"/> on
    /// malformed DN input rather than silently returning null. A swallowed parse failure
    /// allowed CSR CN-subset checks to pass trivially (string.IsNullOrEmpty(csrCn) -> true),
    /// which was a subject-binding bypass under the EST mTLS identity check.
    /// </summary>
    private string? ExtractCommonName(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return null;
        try
        {
            var x500 = new X509Name(dn);
            var oids = x500.GetOidList();
            var values = x500.GetValueList();
            for (int i = 0; i < oids.Count; i++)
            {
                if (((Org.BouncyCastle.Asn1.DerObjectIdentifier)oids[i]!).Id == X509Name.CN.Id)
                    return values[i]?.ToString();
            }
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "EST ExtractCommonName failed to parse DN '{Dn}'; rejecting enrollment to fail closed on subject-binding check.",
                dn);
            throw new InvalidOperationException(
                "Malformed X.500 DN; cannot verify subject-binding for EST enrollment.", ex);
        }
    }

    /// <summary>
    /// Extract DNS/email/IP SAN values from a .NET <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/>
    /// by walking the Subject Alternative Name extension.
    /// Now throws <see cref="InvalidOperationException"/> on
    /// malformed SAN parsing rather than silently returning an empty list. An empty list
    /// from a swallowed failure allowed CSR SAN-subset checks to enforce against an empty
    /// allow-list, weakening the mTLS client-identity binding.
    /// </summary>
    private List<string> ExtractClientCertSans(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        var result = new List<string>();
        try
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value != "2.5.29.17") continue;
                // Parse the SAN extension via BC for type-agnostic traversal.
                var asn1 = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(ext.RawData);
                var gns = Org.BouncyCastle.Asn1.X509.GeneralNames.GetInstance(asn1);
                foreach (var gn in gns.GetNames())
                {
                    var val = gn.Name?.ToString();
                    if (!string.IsNullOrEmpty(val)) result.Add(val);
                }
            }
            // Also include the cert's subject CN as a trivial SAN candidate so callers
            // submitting CSRs where the SAN == the CN still pass the subset check.
            var subjectCn = ExtractCommonName(cert.Subject);
            if (subjectCn != null) result.Add(subjectCn);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            _logger.LogWarning(ex,
                "EST ExtractClientCertSans failed to parse SAN extension for client cert subject '{Subject}' thumbprint '{Thumbprint}'; rejecting enrollment.",
                cert.Subject, cert.Thumbprint);
            throw new InvalidOperationException(
                "Malformed Subject Alternative Name extension on mTLS client cert; cannot verify SAN-binding for EST enrollment.", ex);
        }
        return result;
    }

    /// <summary>
    /// CSR attributes advertised to EST clients. Previously this
    /// advertised <c>Pkcs9AtChallengePassword</c> but EST never extracted/validated it —
    /// misleading clients into embedding a credential the server silently discarded. Now
    /// the response only advertises the extension-request attribute so clients know to
    /// include SAN/EKU extensions in the PKCS#10.
    /// </summary>
    public byte[] GetCsrAttributes()
    {
        var attrs = new Asn1EncodableVector();
        attrs.Add(new DerSequence(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest));
        var seq = new DerSequence(attrs);
        return seq.GetDerEncoded();
    }

    private static string DecodeCsrFromBase64(string base64Body)
    {
        // EST sends the CSR as base64-encoded DER (no PEM armor)
        var trimmed = base64Body.Trim();
        byte[] derBytes;
        try
        {
            derBytes = Convert.FromBase64String(trimmed);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("Invalid base64 encoding in EST request body.");
        }

        return CertificateUtil.ConvertDerToPem(derBytes, "CERTIFICATE REQUEST");
    }

    private async Task<byte[]> BuildCertResponsePkcs7(string certPem, CertRequestEntity csrEntity)
    {
        // Reload the CSR to get the issued certificate reference
        var csr = await _db.CertificateRequests
            .Include(c => c.IssuedCertificate)
            .Include(c => c.SigningProfile)
            .FirstOrDefaultAsync(c => c.Id == csrEntity.Id)
            ?? throw new InvalidOperationException("CSR entity not found after issuance.");

        var certs = new List<X509Certificate>();

        // Parse the issued leaf certificate
        var leafCert = CertificateUtil.ParseFromPem(certPem);
        certs.Add(leafCert);

        // Walk the issuer chain to include intermediates + root
        if (csr.SigningProfile?.IssuerId != null)
        {
            var visited = new HashSet<Guid>();
            var issuerId = csr.SigningProfile.IssuerId;
            while (issuerId.HasValue && visited.Add(issuerId.Value))
            {
                var issuerEntity = await _db.Certificates
                    .Include(c => c.SigningProfile)
                    .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
                if (issuerEntity == null) break;

                var issuerCert = CertificateUtil.ParseFromPem(issuerEntity.Pem);
                certs.Add(issuerCert);
                issuerId = issuerEntity.SigningProfile?.IssuerId;
            }
        }

        return BuildCertsOnlyPkcs7(certs);
    }

    private static byte[] BuildCertsOnlyPkcs7(IList<X509Certificate> certificates)
    {
        // Build a degenerate SignedData (certs-only) per RFC 2315 / RFC 5652.
        // SignedData ::= SEQUENCE {
        //   version          INTEGER (1),
        //   digestAlgorithms SET OF (empty),
        //   contentInfo      ContentInfo { id-data, absent },
        //   certificates [0] IMPLICIT SET OF Certificate,
        //   signerInfos      SET OF (empty)
        // }
        var certAsn1 = new Asn1EncodableVector();
        foreach (var cert in certificates)
            certAsn1.Add(Asn1Object.FromByteArray(cert.GetEncoded()));

        var signedData = new DerSequence(
            new DerInteger(1),                                       // version
            new DerSet(),                                            // digestAlgorithms (empty)
            new DerSequence(new DerObjectIdentifier("1.2.840.113549.1.7.1")), // contentInfo (id-data)
            new DerTaggedObject(false, 0, new DerSet(certAsn1)),     // certificates [0]
            new DerSet()                                             // signerInfos (empty)
        );

        var contentInfo = new DerSequence(
            new DerObjectIdentifier("1.2.840.113549.1.7.2"),         // id-signedData
            new DerTaggedObject(true, 0, signedData)
        );

        return contentInfo.GetDerEncoded();
    }
}
