using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Text.Json;
using ModularCA.Shared.Errors;

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
public class EstService : IEstService, IEnrollmentProtocol
{
    /// <summary>The protocol name as per-CA protocol configuration and audit rows record it.</summary>
    public const string Protocol = "EST";

    /// <inheritdoc />
    string IEnrollmentProtocol.Name => Protocol;

    /// <summary>
    /// What EST offers here: first issuance, and re-enrollment on the certificate the client
    /// already holds (RFC 7030 4.2.1 and 4.2.2).
    /// </summary>
    /// <remarks>
    /// Not <see cref="EnrollmentCapabilities.Poll"/> or <see cref="EnrollmentCapabilities.Collect"/>:
    /// an approval-gated EST request is answered 202 and RFC 7030 has the client retry the whole
    /// enrollment rather than ask after the one it made. Not
    /// <see cref="EnrollmentCapabilities.ServerKeyGeneration"/> either; <c>/serverkeygen</c> is not
    /// implemented.
    /// </remarks>
    EnrollmentCapabilities IEnrollmentProtocol.Capabilities =>
        EnrollmentCapabilities.Enroll | EnrollmentCapabilities.ReEnroll;

    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ICaResolverService _caResolver;
    private readonly IProtocolAuditService _protocolAudit;
    private readonly RequestProfileValidationService _requestProfileValidation;
    private readonly ISecurityPolicyService _securityPolicy;
    private readonly IEnrollmentPipeline _pipeline;
    private readonly ILogger<EstService> _logger;

    /// <summary>
    /// Constructs the EST protocol service. Takes <see cref="ISecurityPolicyService"/> so
    /// re-enrollment's client-certificate chain build honours the same
    /// <see cref="ModularCA.Shared.Entities.SecurityPolicyEntity.RequireMtlsOcspCheck"/> switch
    /// the mTLS login path uses, instead of EST having its own implicit revocation policy.
    /// <para>
    /// Takes <see cref="IEnrollmentPipeline"/> rather than issuance, authorization and profile
    /// resolution separately: the middle of an enrollment is the same work in every protocol, and
    /// this service now supplies only what is EST's own — decoding the request, binding it to the
    /// credential that was presented, and rendering PKCS#7.
    /// </para>
    /// </summary>
    public EstService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ICaResolverService caResolver,
        IProtocolAuditService protocolAudit,
        RequestProfileValidationService requestProfileValidation,
        ISecurityPolicyService securityPolicy,
        IEnrollmentPipeline pipeline,
        ILogger<EstService> logger)
    {
        _db = db;
        _keystore = keystore;
        _caResolver = caResolver;
        _protocolAudit = protocolAudit;
        _requestProfileValidation = requestProfileValidation;
        _securityPolicy = securityPolicy;
        _pipeline = pipeline;
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
            return Pkcs7Util.BuildCertsOnly(allCerts);
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

        return Pkcs7Util.BuildCertsOnly(caCerts);
    }

    /// <summary>
    /// Performs EST simple enrollment by decoding the base64-encoded CSR, resolving the CA context
    /// and certificate/signing profiles, issuing the certificate, and returning the result as PKCS#7.
    /// </summary>
    public Task<byte[]> SimpleEnrollAsync(string base64Csr, string? caLabel = null, string? sourceIp = null,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert = null, bool isAuthenticated = false,
        string? callerUsername = null)
        => SimpleEnrollCoreAsync(base64Csr, caLabel, sourceIp, clientCert, isAuthenticated, callerUsername,
            presentedCertVerified: false);

    /// <summary>
    /// The EST half of an enrollment, shared by <see cref="SimpleEnrollAsync"/> and
    /// <see cref="SimpleReenrollAsync"/>: decode the request, bind it to the credential that was
    /// presented, hand it to <see cref="IEnrollmentPipeline"/>, and render what comes back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything between authorization and issuance — resolving the CA, refusing a disabled
    /// protocol, authorizing the caller, resolving the profiles, validating the names, recording
    /// the request, issuing it or taking it under submission, and auditing the outcome — is the
    /// pipeline's, and is the same sequence every protocol runs. What stays here is what is EST's
    /// own: base64 and PKCS#10 decoding, the identity binding below, the SAN binding once the
    /// profile is known, the EST audit shape, and PKCS#7 rendering.
    /// </para>
    /// <para>
    /// The CSR is parsed before the submission is built, but a parse failure is held and raised
    /// from the post-authorization check rather than thrown here. EST has always authorized before
    /// it read the request, so an unauthorized caller is told they are unauthorized whatever their
    /// CSR contains — and that refusal is the one that reaches the EST audit tab.
    /// </para>
    /// </remarks>
    /// <param name="presentedCertVerified">
    /// True when the caller has already proven that <paramref name="clientCert"/> chains to the
    /// target CA and is unrevoked, as re-enrollment does before it gets here. False for a direct
    /// enrollment, which must prove it itself. Before this flag existed, direct enrollment never
    /// proved it at all: the TLS handshake had validated the certificate against <em>some</em>
    /// trust anchor, and this method trusted that a certificate was present. A human login
    /// certificate satisfied <c>EstRequireClientCert</c>; a device certificate from one CA
    /// enrolled at another; a revoked certificate enrolled a replacement for itself.
    /// </param>
    private async Task<byte[]> SimpleEnrollCoreAsync(string base64Csr, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert, bool isAuthenticated,
        string? callerUsername, bool presentedCertVerified)
    {
        var csrPem = DecodeCsrFromBase64(base64Csr);

        var parsedCsr = new CertificateUtil.ParsedCsrInfo();
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? parseFailure = null;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception ex)
        {
            parseFailure = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex);
        }

        // Set by the identity binding when the caller authenticated with a username; the SAN
        // binding below needs it, and it is only known once the binding has run.
        string? basicBoundUsername = null;

        var submission = new EnrollmentSubmission
        {
            Protocol = Protocol,
            CaLabel = caLabel,
            SourceIp = sourceIp,
            Caller = new EnrollmentCaller(
                Principal: AuditPrincipal(clientCert, callerUsername),
                AuthMethod: clientCert != null
                    ? EnrollmentAuthMethod.ClientCertificate
                    : isAuthenticated ? EnrollmentAuthMethod.HttpCredential : EnrollmentAuthMethod.None,
                IsVerified: isAuthenticated,
                Username: callerUsername,
                ClientCertificate: clientCert),
            Request = new EnrollmentRequestMaterial
            {
                CsrPem = csrPem,
                Subject = parsedCsr.SubjectName,
                SubjectAlternativeNames = parsedCsr.SubjectAlternativeNames,
                KeyAlgorithm = parsedCsr.KeyAlgorithm,
                KeySize = parsedCsr.KeySize,
                SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            },
            AfterAuthorization = async authorized =>
            {
                parseFailure?.Throw();
                basicBoundUsername = await BindCallerIdentityAsync(
                    parsedCsr, caLabel, sourceIp, clientCert, isAuthenticated, callerUsername, presentedCertVerified);
                // EST binds the request to the credential; it never replaces what the request says,
                // so what it was given is what the middle goes on with.
                return authorized;
            },
            AfterProfileValidation = async policy =>
            {
                if (basicBoundUsername != null)
                {
                    await EnforceBasicAuthSanBindingAsync(
                        parsedCsr, basicBoundUsername, policy.RequestProfileId, caLabel, sourceIp);
                }
            },
            Audit = record => WriteEstAuditAsync(record, caLabel, sourceIp, clientCert, callerUsername),
        };

        var outcome = await _pipeline.SubmitAsync(submission);
        return outcome switch
        {
            EnrollmentOutcome.Issued issued => BuildCertResponsePkcs7(issued),
            // RFC 7030 4.2.3: the controller turns this into 202 Accepted.
            EnrollmentOutcome.Pending => throw new EstPendingApprovalException("Certificate request requires approval"),
            EnrollmentOutcome.Refused refused => throw new InvalidOperationException(refused.Message),
            EnrollmentOutcome.Failed failed => throw new InvalidOperationException(failed.Message),
            _ => throw new InvalidOperationException("Unrecognised enrollment outcome."),
        };
    }

    /// <summary>
    /// Cross-checks the CSR's subject and SANs against the identity the caller authenticated as,
    /// and returns the username the SAN binding should later hold the request to, or null when the
    /// caller authenticated with a certificate instead.
    /// </summary>
    /// <remarks>
    /// A client authenticated as "alice" must NOT be able to submit a CSR with subject
    /// CN=root-admin and receive it. The request profile can still override patterns downstream,
    /// but the caller-identity binding is enforced here so privilege escalation via EST is closed
    /// by default. Every refusal writes its own EST audit row before throwing, which is why this
    /// runs as the protocol's own check rather than as part of the shared middle.
    /// </remarks>
    private async Task<string?> BindCallerIdentityAsync(
        CertificateUtil.ParsedCsrInfo parsedCsr, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert,
        bool isAuthenticated, string? callerUsername, bool presentedCertVerified)
    {
        if (clientCert != null)
        {
            // The identity binding below trusts this certificate's CN and SANs. That trust is only
            // warranted once the certificate is known to have been issued by the CA being enrolled
            // against, and not since revoked. The handshake cannot establish either: it validates
            // against an anchor set, not a target, and runs revocation Offline with unknown status
            // tolerated.
            if (!presentedCertVerified)
            {
                await VerifyPresentedCertificateAsync(clientCert, caLabel,
                    reason => ThrowEnrollRejectedAsync(reason, caLabel, sourceIp, clientCert));
            }

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
            catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
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

            return null;
        }

        if (isAuthenticated && !string.IsNullOrEmpty(callerUsername))
        {
            // HTTP Basic / bearer path: CSR CN must match the authenticated username.
            // The SANs are bound further down, once the request profile is known.
            string? csrCn;
            try
            {
                csrCn = ExtractCommonName(parsedCsr.SubjectName);
            }
            catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
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
            return callerUsername;
        }

        if (isAuthenticated)
        {
            // Authenticated, no client certificate, and no username could be resolved. There is
            // nothing to bind the CSR to, so the subject and SAN checks above would be skipped
            // entirely and the caller could enroll any identity.
            //
            // This is the shape of the original defect: the caller name arrived null because the
            // controller read a claim the token never carried, and the binding quietly did not
            // apply. Refuse rather than fall through, so a future mis-wiring fails visibly
            // instead of silently disabling the control.
            await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                success: false, errorMessage: "Authenticated caller has no resolvable username to bind the CSR to",
                callerPrincipal: "unknown");
            throw new InvalidOperationException(
                "Authenticated EST caller could not be identified; enrollment refused.");
        }

        return null;
    }

    /// <summary>
    /// How the EST audit tab names the caller: the mTLS subject when a certificate was presented,
    /// otherwise the authenticated username, otherwise nothing.
    /// </summary>
    private static string? AuditPrincipal(
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert, string? callerUsername)
        => clientCert != null ? $"mtls:{clientCert.Subject}"
            : !string.IsNullOrEmpty(callerUsername) ? $"basic:{callerUsername}" : null;

    /// <summary>
    /// Writes the pipeline's shared audit fields as an EST row, in EST's own operation names.
    /// </summary>
    /// <remarks>
    /// The audit tables are per protocol, so the pipeline supplies the facts and this decides the
    /// shape. A refusal reached before the request was read — an unknown CA, a disabled protocol,
    /// an unauthorized caller — carries no subject or key detail, because EST authorizes before it
    /// parses and has never claimed to know what such a request asked for. A refusal after that
    /// carries the request's own details and no principal, which is the row a rejected enrollment
    /// has always produced.
    /// </remarks>
    private Task WriteEstAuditAsync(EnrollmentAuditRecord record, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert, string? callerUsername)
        => record.Event switch
        {
            EnrollmentAuditEvent.Issued => _protocolAudit.LogEstAsync("SimpleEnroll", record.Subject,
                record.SerialNumber, record.KeyAlgorithm, record.KeySize, caLabel, sourceIp),

            EnrollmentAuditEvent.Pending => _protocolAudit.LogEstAsync("SimpleEnroll-PendingApproval",
                record.Subject, null, record.KeyAlgorithm, record.KeySize, caLabel, sourceIp),

            _ when RefusedBeforeTheRequestWasRead(record.Reason) => _protocolAudit.LogEstAsync(
                "EstEnrollRejected", null, null, null, null, caLabel, sourceIp,
                success: false, errorMessage: record.Message ?? "Enrollment not authorized",
                callerPrincipal: AuditPrincipal(clientCert, callerUsername)),

            _ => _protocolAudit.LogEstAsync("EstEnrollRejected", record.Subject, null,
                record.KeyAlgorithm, record.KeySize, caLabel, sourceIp,
                success: false, errorMessage: record.Message ?? "Enrollment refused"),
        };

    /// <summary>
    /// Whether a refusal reason is one the pipeline reaches before the request itself is looked
    /// at, and whose audit row therefore names the caller rather than the request.
    /// </summary>
    private static bool RefusedBeforeTheRequestWasRead(EnrollmentRefusalReason? reason)
        => reason is EnrollmentRefusalReason.CaNotFound
            or EnrollmentRefusalReason.ProtocolDisabledOnCa
            or EnrollmentRefusalReason.CredentialMissing
            or EnrollmentRefusalReason.CredentialInvalid
            or EnrollmentRefusalReason.CallerNotAuthorized;

    /// <summary>
    /// Performs EST simple re-enrollment (RFC 7030 4.2.2). The presenting mTLS client
    /// certificate must be currently valid, must cryptographically chain to the CA being
    /// re-enrolled against, must not be revoked, must be inside the renewal window (last 30% of
    /// validity), and its Subject must match the CSR Subject - only then is the request handed to
    /// the normal enrollment pipeline.
    /// <para>
    /// The issuer check used to be a DN <em>string</em> comparison: it loaded the CA
    /// certificate row, normalized <c>caCert.SubjectDN</c> and <c>clientCert.Issuer</c>, and
    /// compared the two strings. Nothing about that proves issuance - the Issuer field is
    /// attacker-controlled text in a certificate the attacker generates. Anyone who could
    /// complete the TLS handshake could present a self-signed certificate carrying a victim's
    /// Subject and the CA's Subject copied into its Issuer field and pass every gate below
    /// (expiry, revocation-by-serial, "issuer", renewal window, CSR subject match), and the CA
    /// would then mint a genuine certificate for an identity the caller does not control. Worse,
    /// the check silently fell through to success whenever the signing profile had no
    /// <c>IssuerId</c>, the CA row was missing, or either DN string was empty. It is now a real
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Chain"/> build against the CA
    /// certificate as the sole trust anchor, and every one of those former skip-paths is a hard
    /// reject audited on the EST protocol tab.
    /// </para>
    /// </summary>
    public async Task<byte[]> SimpleReenrollAsync(string base64Csr, string? caLabel = null, string? sourceIp = null,
        System.Security.Cryptography.X509Certificates.X509Certificate2? clientCert = null, bool isAuthenticated = false,
        string? callerUsername = null)
    {
        // RFC 7030 4.2.2: the client's existing certificate is what authenticates a renewal.
        // EstController already answers 401 when no client certificate is on the connection, but
        // the service must not lean on its caller for that: every renewal gate below used to sit
        // inside `if (clientCert != null)`, so a null certificate meant *all* of them were
        // skipped and the request fell straight through to SimpleEnrollAsync. Fail closed here so
        // the guarantee belongs to the service, not to one controller.
        if (clientCert == null)
        {
            await _protocolAudit.LogEstAsync("EstReenrollRejected", null, null,
                null, null, caLabel, sourceIp, success: false,
                errorMessage: "Re-enrollment attempted without an mTLS client certificate.",
                callerPrincipal: !string.IsNullOrEmpty(callerUsername) ? $"basic:{callerUsername}" : null);
            throw new InvalidOperationException(
                "EST re-enrollment requires an mTLS client certificate (RFC 7030 4.2.2).");
        }

        // 1. Verify the client certificate is not expired
        var now = DateTime.UtcNow;
        if (now > clientCert.NotAfter)
            await ThrowReenrollRejectedAsync("Client certificate has expired and cannot be used for re-enrollment.", caLabel, sourceIp, clientCert);
        if (now < clientCert.NotBefore)
            await ThrowReenrollRejectedAsync("Client certificate is not yet valid.", caLabel, sourceIp, clientCert);

        // 2-3. Prove the target CA issued this certificate, and that it has not been revoked.
        //       Shared with direct enrollment; see VerifyPresentedCertificateAsync.
        await VerifyPresentedCertificateAsync(clientCert, caLabel,
            reason => ThrowReenrollRejectedAsync(reason, caLabel, sourceIp, clientCert));

        // 4. Only allow re-enrollment within the last 30% of the validity period
        var totalValidity = clientCert.NotAfter - clientCert.NotBefore;
        var renewalWindowStart = clientCert.NotBefore + TimeSpan.FromTicks((long)(totalValidity.Ticks * 0.70));
        if (now < renewalWindowStart)
            await ThrowReenrollRejectedAsync(
                $"Re-enrollment is only allowed within the renewal window (last 30% of validity). " +
                $"Renewal opens on {renewalWindowStart:u}.", caLabel, sourceIp, clientCert);

        // 5. Verify the CSR subject matches the original certificate subject.
        //    Compared as parsed ASN.1 names, not as normalized strings: this is the gate that
        //    decides what identity the renewed certificate carries, so it must not rest on a
        //    text heuristic. See TryParseCsrSubject for what the old string path allowed.
        var csrPem = DecodeCsrFromBase64(base64Csr);
        var csrSubject = TryParseCsrSubject(csrPem);
        var certSubject = TryParseCertificateSubject(clientCert.RawData);
        if (csrSubject == null || certSubject == null)
            await ThrowReenrollRejectedAsync(
                "The subject DN of the CSR or of the presented certificate could not be parsed; re-enrollment cannot verify identity.",
                caLabel, sourceIp, clientCert);
        // inOrder: true - RDN sequence order is part of a DN's identity; a reordered DN is a
        // different name and must not be accepted as "the same subject".
        if (!csrSubject!.Equivalent(certSubject!, true))
            await ThrowReenrollRejectedAsync(
                "CSR subject must match the original certificate subject for re-enrollment.", caLabel, sourceIp, clientCert);

        return await SimpleEnrollCoreAsync(base64Csr, caLabel, sourceIp, clientCert, isAuthenticated, callerUsername,
            presentedCertVerified: true);
    }

    /// <summary>
    /// Bounds the SANs a username-authenticated EST caller may ask for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The mTLS branch of <see cref="SimpleEnrollAsync"/> requires every CSR SAN to be a name the
    /// client certificate already carries. The HTTP-auth branch checked only the CN, so the two
    /// paths to the same endpoint were not equally bound: an account with nothing but enrollment
    /// rights could submit <c>CN=&lt;its own username&gt;</c> — passing the CN check exactly — with
    /// <c>DNS:vpn.example.com</c> in the SAN extension and be issued a server certificate for a
    /// host it has no relationship to. The CN is not where a TLS certificate's identity lives.
    /// </para>
    /// <para>A SAN is accepted when it is:</para>
    /// <list type="bullet">
    /// <item>the caller's own username, or the CN that was already pinned to it — so the ordinary
    /// <c>CN=printer1, DNS:printer1</c> shape keeps working; or</item>
    /// <item>of a type whose values the protocol's request profile pins with an explicit pattern —
    /// the operator has then declared the namespace, and
    /// <c>RequestProfileValidationService.ValidateAsync</c> has already held this value to it.</item>
    /// </list>
    /// <para>
    /// Anything else is refused. That is deliberately stricter than "a profile exists": a profile
    /// that allows the DNS type without pinning its values permits every hostname there is, which
    /// is the state a default install is in.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Whether a SAN value is one the authenticated caller has already been pinned to — its own
    /// username, or the CSR CN that had to equal that username to get this far.
    /// </summary>
    /// <remarks>
    /// Keeping the ordinary <c>CN=printer1</c> plus <c>DNS:printer1</c> shape working is the whole
    /// reason this is not simply "the SAN must equal the username": a CSR that repeats its own
    /// subject in the SAN extension is asserting nothing new.
    /// </remarks>
    internal static bool SanIsBoundToCaller(string sanValue, string callerUsername, string? csrCn)
    {
        if (string.IsNullOrWhiteSpace(sanValue)) return false;
        if (string.Equals(sanValue, callerUsername, StringComparison.OrdinalIgnoreCase)) return true;
        return !string.IsNullOrEmpty(csrCn)
            && string.Equals(sanValue, csrCn, StringComparison.OrdinalIgnoreCase);
    }

    private async Task EnforceBasicAuthSanBindingAsync(
        CertificateUtil.ParsedCsrInfo parsedCsr, string callerUsername, Guid? requestProfileId,
        string? caLabel, string? sourceIp)
    {
        if (parsedCsr.SubjectAlternativeNames.Count == 0)
            return;

        string? csrCn;
        try
        {
            csrCn = ExtractCommonName(parsedCsr.SubjectName);
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            csrCn = null;
        }

        foreach (var entry in parsedCsr.SubjectAlternativeNames)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;

            var separator = entry.IndexOf(':');
            var sanType = separator > 0 ? entry[..separator].Trim() : "DNS";
            var sanValue = separator > 0 ? entry[(separator + 1)..].Trim() : entry.Trim();

            if (SanIsBoundToCaller(sanValue, callerUsername, csrCn))
                continue;

            if (requestProfileId != null &&
                await _requestProfileValidation.ConstrainsSanValuesAsync(requestProfileId.Value, sanType))
            {
                continue;
            }

            await _protocolAudit.LogEstAsync("EstEnrollRejected", parsedCsr.SubjectName, null,
                parsedCsr.KeyAlgorithm, parsedCsr.KeySize, caLabel, sourceIp,
                success: false,
                errorMessage: $"SAN '{entry}' is not bound to the authenticated caller",
                callerPrincipal: $"basic:{callerUsername}");
            throw new InvalidOperationException(
                $"SAN '{entry}' is not bound to the authenticated caller and no request profile " +
                $"constrains SAN values of type '{sanType}'.");
        }
    }

    /// <summary>
    /// Records an EST re-enrollment rejection on the protocol audit tab, then throws.
    /// The renewal-gating checks in <see cref="SimpleReenrollAsync"/> previously threw with
    /// no audit row, so rejected renewals never appeared on the EST tab. Always throws.
    /// </summary>
    /// <summary>
    /// Proves that a presented client certificate was issued by the CA being enrolled against and
    /// has not been revoked. Calls <paramref name="reject"/> (which must throw) on any failure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the certificate-side counterpart of the username membership check in
    /// <c>EnrollmentAuthorizationService</c>: possession of a certificate proves who is asking,
    /// and chaining to the target CA proves they may ask here. Extracted from re-enrollment,
    /// which had always done this, so that direct enrollment does it too.
    /// </para>
    /// <para>
    /// Chain validation runs before the revocation lookup on purpose: a serial number is unique
    /// only per issuer, so the revocation query is meaningful only once the issuer is known.
    /// </para>
    /// <para>
    /// RFC 7030 section 3.3.2 does allow a client to authenticate initial enrollment with a
    /// certificate from a third party, such as a manufacturer-installed identity. That is a
    /// deliberately narrower policy here: a third-party certificate is accepted only where an
    /// operator has made that CA an EST-enabled CA of this system. Deployments that need
    /// manufacturer certificates bootstrap with HTTP Basic or an enrollment token instead.
    /// </para>
    /// </remarks>
    /// <returns>The <c>CertificateId</c> of the verified issuing CA certificate.</returns>
    private async Task<Guid> VerifyPresentedCertificateAsync(
        System.Security.Cryptography.X509Certificates.X509Certificate2 clientCert,
        string? caLabel,
        Func<string, Task> reject)
    {
        var context = await _caResolver.ResolveAsync(caLabel, "EST");
        var signingProfile = await _db.SigningProfiles.FindAsync(context.SigningProfileId);
        if (signingProfile?.IssuerId == null)
            await reject("The EST signing profile has no issuing CA configured, so the presenting certificate's issuer cannot be verified.");

        var caCertEntity = await _db.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == signingProfile!.IssuerId);
        if (caCertEntity == null)
            await reject("The issuing CA certificate configured for this EST signing profile is missing, so issuance cannot be verified.");

        System.Security.Cryptography.X509Certificates.X509Certificate2? caCert = null;
        try
        {
            caCert = LoadIssuerCertificate(caCertEntity!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "EST could not load the issuing CA certificate {CertificateId}; rejecting the request.",
                caCertEntity!.CertificateId);
        }
        if (caCert == null)
            await reject("The issuing CA certificate could not be parsed, so issuance cannot be verified.");

        using (var anchorCert = caCert!)
        {
            // Honour the same operator switch the mTLS login path uses. When OCSP is not
            // required, revocation is still caught by the database gate immediately below.
            var requireRevocationCheck = (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck;
            if (!X509ChainValidationUtil.ValidateAgainstAnchor(
                    clientCert, anchorCert, requireRevocationCheck, out var chainErrors))
            {
                _logger.LogWarning(
                    "EST chain validation failed for subject '{Subject}' against CA '{CaSubject}': {ChainErrors}",
                    clientCert.Subject, caCertEntity!.SubjectDN, chainErrors);
                await reject("Client certificate does not chain to the CA being enrolled against.");
            }
        }
        var verifiedIssuerCertificateId = caCertEntity!.CertificateId;

        // Scoped to the issuer just verified: serial numbers are unique only within one issuer's
        // namespace. Rows with no IssuerCertificateId (legacy, pre-FK) are still considered so the
        // check fails closed for them. The serial is normalised to the stored form; a miss here
        // means "not revoked", so a formatting mismatch would be a revocation bypass.
        var clientSerialHex = CertificateUtil.NormalizeSerialForLookup(clientCert.SerialNumber);
        if (!string.IsNullOrEmpty(clientSerialHex))
        {
            var serialMatches = await _db.Certificates
                .AsNoTracking()
                .Where(c => c.SerialNumber == clientSerialHex)
                .Select(c => new { c.IssuerCertificateId, c.Revoked })
                .ToListAsync();
            if (serialMatches.Any(c => c.Revoked
                    && (c.IssuerCertificateId == null || c.IssuerCertificateId == verifiedIssuerCertificateId)))
                await reject("Client certificate has been revoked and cannot be used for enrollment.");
        }

        return verifiedIssuerCertificateId;
    }

    /// <summary>
    /// Audits a rejected direct enrollment on the EST protocol tab and throws. Always throws.
    /// </summary>
    private async Task ThrowEnrollRejectedAsync(string reason, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2 clientCert)
    {
        await _protocolAudit.LogEstAsync("EstEnrollRejected", clientCert.Subject, null,
            null, null, caLabel, sourceIp, success: false, errorMessage: reason,
            callerPrincipal: $"mtls:{clientCert.Subject}");
        throw new InvalidOperationException(reason);
    }

    private async Task ThrowReenrollRejectedAsync(string reason, string? caLabel, string? sourceIp,
        System.Security.Cryptography.X509Certificates.X509Certificate2 clientCert)
    {
        await _protocolAudit.LogEstAsync("EstReenrollRejected", clientCert.Subject, null,
            null, null, caLabel, sourceIp, success: false, errorMessage: reason,
            callerPrincipal: $"mtls:{clientCert.Subject}");
        throw new InvalidOperationException(reason);
    }

    /// <summary>
    /// Materializes a stored CA certificate row as an
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/> for use as a
    /// chain trust anchor. Prefers the stored DER (<c>RawCertificate</c>) and falls back to the
    /// PEM column for rows written before DER was persisted. Throws when the row carries neither,
    /// so the caller rejects the renewal rather than silently skipping the issuer check.
    /// Callers own the returned instance and must dispose it.
    /// </summary>
    private static System.Security.Cryptography.X509Certificates.X509Certificate2 LoadIssuerCertificate(
        CertificateEntity entity)
    {
        if (entity.RawCertificate is { Length: > 0 } der)
            return System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(der);
        if (!string.IsNullOrWhiteSpace(entity.Pem))
            return System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(entity.Pem);
        throw new InvalidOperationException(
            $"CA certificate row {entity.CertificateId} contains neither DER nor PEM certificate data.");
    }

    /// <summary>
    /// Parses a PKCS#10 CSR and returns its subject as a BouncyCastle
    /// <see cref="X509Name"/>, or <c>null</c> when the CSR cannot be parsed.
    /// <para>
    /// Re-enrollment compares subjects as parsed ASN.1 names rather than as normalized DN
    /// strings. The previous <c>NormalizeDn</c> helper rendered both sides to text and, when
    /// BouncyCastle's parser threw, fell back to "split on comma, upper-case, sort" - a heuristic
    /// that discards RDN order, treats an escaped comma inside a value as a separator, and cannot
    /// see multi-valued RDNs. That fallback was tolerable while it only had to keep renewal
    /// convenient, but it is now load-bearing for identity, so both sides are parsed properly and
    /// an unparseable name is a rejection instead of a guess.
    /// </para>
    /// </summary>
    private static X509Name? TryParseCsrSubject(string csrPem)
    {
        try
        {
            using var reader = new StringReader(csrPem);
            var request = new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject()
                as Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest;
            return request?.GetCertificationRequestInfo().Subject;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses DER certificate bytes and returns the subject as a BouncyCastle
    /// <see cref="X509Name"/>, or <c>null</c> when the certificate cannot be parsed. Reading the
    /// name from the certificate's own ASN.1 rather than from
    /// <c>X509Certificate2.Subject</c> also removes a format mismatch: .NET and BouncyCastle
    /// render some attribute types differently (for example <c>S=</c> versus <c>ST=</c>), which
    /// made a text comparison between a .NET-rendered certificate subject and a
    /// BouncyCastle-rendered CSR subject unreliable.
    /// </summary>
    private static X509Name? TryParseCertificateSubject(byte[] der)
    {
        try
        {
            var parsed = new X509CertificateParser().ReadCertificate(der);
            return parsed?.SubjectDN;
        }
        catch
        {
            return null;
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

    /// <summary>
    /// Renders an issued certificate and its issuer chain as a certs-only PKCS#7, which is what
    /// an EST client expects in answer to /simpleenroll and /simplereenroll.
    /// </summary>
    /// <remarks>
    /// The chain comes from the pipeline, which walked the signing profile's issuer links while it
    /// still had the profile in hand; this used to be a second walk of the same links from a
    /// reloaded request row.
    /// </remarks>
    private static byte[] BuildCertResponsePkcs7(EnrollmentOutcome.Issued issued)
    {
        var certs = new List<X509Certificate> { CertificateUtil.ParseFromPem(issued.CertificatePem) };
        foreach (var issuerPem in issued.ChainPem)
            certs.Add(CertificateUtil.ParseFromPem(issuerPem));
        return Pkcs7Util.BuildCertsOnly(certs);
    }

}
