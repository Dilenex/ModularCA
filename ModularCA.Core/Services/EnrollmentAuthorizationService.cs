using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services;

/// <summary>
/// Validates enrollment authorization based on protocol, client certificates, and enrollment tokens.
/// </summary>
public interface IEnrollmentAuthorizationService
{
    Task<(bool Allowed, string? Error)> ValidateAsync(
        string protocol, string? caLabel, string? csrPem,
        X509Certificate2? clientCert, bool isAuthenticated);
}

public class EnrollmentAuthorizationService : IEnrollmentAuthorizationService
{
    private readonly ModularCADbContext _db;
    private readonly IEnrollmentTokenService _tokenService;
    private readonly ILogger<EnrollmentAuthorizationService> _logger;

    public EnrollmentAuthorizationService(
        ModularCADbContext db,
        IEnrollmentTokenService tokenService,
        ILogger<EnrollmentAuthorizationService> logger)
    {
        _db = db;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task<(bool Allowed, string? Error)> ValidateAsync(
        string protocol, string? caLabel, string? csrPem,
        X509Certificate2? clientCert, bool isAuthenticated)
    {
        var protocolConfig = await _db.CaProtocolConfigs
            .Include(c => c.Ca)
            .FirstOrDefaultAsync(c =>
                c.Protocol == protocol &&
                (caLabel == null || c.Ca.Label == caLabel));

        if (protocolConfig == null)
            return (false, "No protocol configuration found for this CA. EST enrollment is not enabled.");

        return protocol.ToUpperInvariant() switch
        {
            "EST" => ValidateEst(protocolConfig, clientCert, isAuthenticated),
            "SCEP" => await ValidateScep(protocolConfig, csrPem),
            "CMP" => ValidateCmp(protocolConfig, clientCert, isAuthenticated),
            "ACME" => (true, null), // ACME handles its own authorization via challenges
            "OCSP" => (true, null), // OCSP is a query protocol, no enrollment
            _ => (true, null),
        };
    }

    /// <summary>
    /// Validates EST enrollment authorization. When both client certificate and HTTP authentication
    /// are configured, both must be satisfied. When only one is configured, only that one is required.
    /// </summary>
    private static (bool, string?) ValidateEst(
        CaProtocolConfigEntity config, X509Certificate2? clientCert, bool isAuthenticated)
    {
        // If both auth methods are required, both must be present
        if (config.EstRequireClientCert && config.EstHttpAuthEnabled)
        {
            if (clientCert != null && isAuthenticated)
                return (true, null);
            return (false, "EST enrollment requires both client certificate AND HTTP authentication");
        }

        // If only client cert required
        if (config.EstRequireClientCert)
            return clientCert != null ? (true, null) : (false, "EST enrollment requires a client certificate (mTLS)");

        // If only HTTP auth required
        if (config.EstHttpAuthEnabled)
            return isAuthenticated ? (true, null) : (false, "EST enrollment requires HTTP authentication");

        // Neither required — SECURITY: refuse to issue to anonymous callers.
        // A misconfigured EST protocol config with both EstRequireClientCert=false
        // AND EstHttpAuthEnabled=false must not allow unauthenticated certificate
        // issuance. The controller-level precondition is the primary guard; this
        // service-level refusal is defense-in-depth if that check is ever bypassed.
        return (false, "no authentication method enabled");
    }

    private async Task<(bool, string?)> ValidateScep(
        CaProtocolConfigEntity config, string? csrPem)
    {
        if (!config.ScepChallengeRequired)
            return (true, null);

        if (string.IsNullOrWhiteSpace(csrPem))
            return (false, "CSR required for SCEP challenge password validation");

        var challengePassword = CertificateUtil.ExtractChallengePassword(csrPem);
        if (string.IsNullOrWhiteSpace(challengePassword))
            return (false, "SCEP challenge password required but not found in CSR");

        // Pass the CSR's SANs, not just its subject.
        //
        // ValidateAndConsumeAsync takes `sans` as an OPTIONAL parameter and skips the
        // SANRestriction check entirely when it is null (EnrollmentTokenService: `if (sans !=
        // null && !SansSatisfy(...))`). This call omitted it, and it is the only caller that
        // reaches that check — the public enrollment controller runs SansSatisfy itself. So the
        // restriction was dead code on the SCEP path: a client holding a challenge password
        // scoped to example.com could put DNS:evil.attacker.net in the CSR's SAN extension and
        // be issued it, because only the CN was ever compared. The comment on the check itself
        // says SCEP is "where it is the ONLY name check", which is exactly what made the gap
        // invisible.
        var (subject, sans) = TryExtractSubjectAndSans(csrPem);
        return await _tokenService.ValidateAndConsumeAsync(challengePassword, subject, "SCEP", sans);
    }

    /// <summary>
    /// Authorizes a CMP enrollment. CMP carries its identity inside the PKIMessage protection,
    /// which <c>CmpService</c> has already verified by the time this runs — so
    /// <paramref name="isAuthenticated"/> is the signal, and it is the only one available here.
    /// <para>
    /// This method previously ignored <paramref name="isAuthenticated"/> entirely and branched on
    /// <paramref name="clientCert"/>, which <c>CmpService</c> always passes as <c>null</c>. That
    /// made CMP unusable in both directions: with <c>CmpRequireSignature = false</c> (the default)
    /// it returned success unconditionally, including for a message with no protection at all;
    /// with it set to <c>true</c> every request failed, even one that had just passed full
    /// signature verification. There was no working secure configuration.
    /// </para>
    /// <para>
    /// The <c>CmpRequireSignature</c> distinction between signature and PBMAC protection is
    /// enforced in <c>CmpService</c>, where the concrete protection mode is known.
    /// </para>
    /// </summary>
    private static (bool, string?) ValidateCmp(
        CaProtocolConfigEntity config, X509Certificate2? clientCert, bool isAuthenticated)
    {
        if (!isAuthenticated)
            return (false, "CMP requires verified message protection (RFC 4210 5.1.3).");

        return (true, null);
    }

    /// <summary>
    /// Extracts the subject DN and SAN list from a PEM CSR for enrollment-token name checks.
    /// </summary>
    /// <remarks>
    /// Returns <c>(null, null)</c> if the CSR cannot be parsed. A null SAN list means "could not
    /// determine", and <c>ValidateAndConsumeAsync</c> treats that as "no SAN check" — which is
    /// safe here only because an unparseable CSR fails later in issuance anyway. An empty list
    /// is different and is checked normally.
    /// </remarks>
    private static (string? Subject, IEnumerable<string>? Sans) TryExtractSubjectAndSans(string csrPem)
    {
        try
        {
            var parsed = CertificateUtil.ParseCsr(csrPem);
            return (parsed.SubjectName, parsed.SubjectAlternativeNames);
        }
        catch { return (null, null); }
    }
}
