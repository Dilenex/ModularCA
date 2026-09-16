using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services;

/// <summary>
/// Validates enrollment authorization based on protocol, client certificates, and enrollment tokens.
/// </summary>
public interface IEnrollmentAuthorizationService
{
    /// <summary>
    /// Decides whether an enrollment request is authorized for the CA it addresses.
    /// </summary>
    /// <param name="protocol">Protocol name, e.g. "EST".</param>
    /// <param name="caLabel">CA label from the route, or null for the default CA.</param>
    /// <param name="csrPem">The CSR, where the protocol carries its credential inside it (SCEP).</param>
    /// <param name="clientCert">The TLS client certificate, if one was presented.</param>
    /// <param name="isAuthenticated">Whether the request carries a verified HTTP or message-level credential.</param>
    /// <param name="callerUsername">
    /// The username behind <paramref name="isAuthenticated"/>, when the credential names one.
    /// Required for EST HTTP authentication so the caller's entitlement on the target CA can be
    /// checked; a password proves identity, not membership.
    /// </param>
    Task<(bool Allowed, string? Error)> ValidateAsync(
        string protocol, string? caLabel, string? csrPem,
        X509Certificate2? clientCert, bool isAuthenticated, string? callerUsername = null);
}

public class EnrollmentAuthorizationService : IEnrollmentAuthorizationService
{
    private readonly ModularCADbContext _db;
    private readonly IEnrollmentTokenService _tokenService;
    private readonly ICaResolverService _caResolver;
    private readonly IEnrollmentPrincipalAuthorizer _principalAuthorizer;
    private readonly ILogger<EnrollmentAuthorizationService> _logger;

    public EnrollmentAuthorizationService(
        ModularCADbContext db,
        IEnrollmentTokenService tokenService,
        ICaResolverService caResolver,
        IEnrollmentPrincipalAuthorizer principalAuthorizer,
        ILogger<EnrollmentAuthorizationService> logger)
    {
        _db = db;
        _tokenService = tokenService;
        _caResolver = caResolver;
        _principalAuthorizer = principalAuthorizer;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<(bool Allowed, string? Error)> ValidateAsync(
        string protocol, string? caLabel, string? csrPem,
        X509Certificate2? clientCert, bool isAuthenticated, string? callerUsername = null)
    {
        // Resolve the CA first, through the same selection the issuance path uses, and only then
        // read that CA's protocol row. This used to be one query: FirstOrDefault over every
        // protocol row matching the label, with no ordering and no IsEnabled filter. For a
        // label-less request that returned whichever CA's row the database listed first, disabled
        // or not, while CaResolverService independently issued from the default CA. A lab CA's
        // "Basic is enough" policy could authorise issuance from the production CA that required
        // a client certificate, and the two lookups could disagree on which CA was even meant.
        var ca = await _caResolver.ResolveCaEntityAsync(caLabel);
        if (ca == null)
        {
            return (false, caLabel != null
                ? $"CA '{caLabel}' not found or disabled."
                : "No enabled Certificate Authority found.");
        }

        var protocolUpper = protocol.ToUpperInvariant();
        var protocolConfig = await _db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == protocolUpper);

        if (protocolConfig == null || !protocolConfig.IsEnabled)
            return (false, $"{protocolUpper} is not enabled for CA '{ca.Label}'.");

        return protocolUpper switch
        {
            "EST" => await ValidateEstAsync(protocolConfig, ca, clientCert, isAuthenticated, callerUsername),
            "SCEP" => await ValidateScep(protocolConfig, csrPem),
            "CMP" => ValidateCmp(protocolConfig, clientCert, isAuthenticated),
            "MSAE" => await ValidateMsaeAsync(ca, isAuthenticated, callerUsername),
            "ACME" => (true, null), // ACME handles its own authorization via challenges
            "OCSP" => (true, null), // OCSP is a query protocol, no enrollment
            _ => (true, null),
        };
    }

    /// <summary>
    /// Validates Windows autoenrollment (MS-WSTEP) authorization: the caller must have
    /// authenticated with a username, and that account must hold the enrollment capability on
    /// the CA that will issue.
    /// </summary>
    /// <remarks>
    /// There is no certificate branch and no "either credential" policy here, unlike EST. The
    /// only credential the MSAE endpoint accepts today is a username and password, so an
    /// unauthenticated or nameless caller has nothing to check membership for and is refused
    /// outright. Membership is the same check EST HTTP authentication uses: a password proves who
    /// is asking, not whether they may ask here.
    /// </remarks>
    private async Task<(bool, string?)> ValidateMsaeAsync(
        CertificateAuthorityEntity ca, bool isAuthenticated, string? callerUsername)
    {
        if (!isAuthenticated || string.IsNullOrWhiteSpace(callerUsername))
            return (false, "MSAE enrollment requires an authenticated username.");

        if (await _principalAuthorizer.MayEnrollAsync(callerUsername, ca.Id))
            return (true, null);

        _logger.LogWarning(
            "MSAE enrollment refused: user {Username} lacks {Capability} on CA {CaLabel}.",
            callerUsername, Shared.Authorization.Capabilities.CertRequest, ca.Label);
        return (false, $"User '{callerUsername}' is not permitted to enroll at CA '{ca.Label}'.");
    }

    /// <summary>
    /// Validates EST enrollment authorization against the CA that will issue. When both client
    /// certificate and HTTP authentication are configured, both must be satisfied; when only one
    /// is configured, only that one is required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HTTP authentication is satisfied only when the authenticated account holds the enrollment
    /// capability on <paramref name="ca"/>. Before this, the check was <c>isAuthenticated</c>
    /// alone, which the default bearer scheme sets for every valid session token: any user in any
    /// tenant could enroll at any EST-enabled CA. A password proves who is asking, not whether they
    /// may ask here.
    /// </para>
    /// <para>
    /// The client-certificate branch checks only presence. Whether the certificate chains to
    /// <paramref name="ca"/> and is unrevoked is proven by <c>EstService</c> before issuance;
    /// that needs the CA's certificate and a chain build, which do not belong in a policy switch.
    /// </para>
    /// </remarks>
    private async Task<(bool, string?)> ValidateEstAsync(
        CaProtocolConfigEntity config, CertificateAuthorityEntity ca,
        X509Certificate2? clientCert, bool isAuthenticated, string? callerUsername)
    {
        var httpAuthSatisfied = false;
        if (isAuthenticated)
        {
            if (string.IsNullOrWhiteSpace(callerUsername))
            {
                // Authenticated but nameless: nothing to check membership for. Refuse rather than
                // fall through. This is the shape of a mis-wired scheme, and the controller's own
                // CN binding already refuses the same case for the same reason.
                _logger.LogWarning("EST HTTP authentication for CA {CaLabel} carried no username; refusing.", ca.Label);
            }
            else if (await _principalAuthorizer.MayEnrollAsync(callerUsername, ca.Id))
            {
                httpAuthSatisfied = true;
            }
            else
            {
                _logger.LogWarning(
                    "EST HTTP authentication refused: user {Username} lacks {Capability} on CA {CaLabel}.",
                    callerUsername, Shared.Authorization.Capabilities.CertRequest, ca.Label);
            }
        }

        if (config.EstRequireClientCert && config.EstHttpAuthEnabled)
        {
            if (clientCert != null && httpAuthSatisfied)
                return (true, null);
            return (false, "EST enrollment requires both client certificate AND HTTP authentication");
        }

        if (config.EstRequireClientCert)
            return clientCert != null ? (true, null) : (false, "EST enrollment requires a client certificate (mTLS)");

        if (config.EstHttpAuthEnabled)
        {
            if (httpAuthSatisfied)
                return (true, null);
            return isAuthenticated
                ? (false, "EST enrollment refused: the authenticated account is not entitled to request certificates from this CA")
                : (false, "EST enrollment requires HTTP authentication");
        }

        // Neither required. SECURITY: refuse to issue to anonymous callers.
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
