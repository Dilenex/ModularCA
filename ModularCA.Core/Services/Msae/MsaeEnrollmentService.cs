using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Issues a certificate for a Windows autoenrollment (MS-WSTEP) request that has already been
/// parsed off the wire and whose caller has already been authenticated.
/// </summary>
public interface IMsaeEnrollmentService
{
    /// <summary>
    /// Enrolls <paramref name="pkcs10Der"/> on behalf of <paramref name="callerUsername"/> and
    /// returns the issued certificate and its chain as a certs-only PKCS#7 (DER).
    /// </summary>
    /// <param name="pkcs10Der">The DER-encoded PKCS#10 from the request's BinarySecurityToken.</param>
    /// <param name="callerUsername">The username the credential service verified. Never null or blank.</param>
    /// <param name="sourceIp">Caller address, for the audit record.</param>
    /// <param name="caLabel">CA label from the route, or null for the default CA.</param>
    /// <exception cref="MsaeEnrollmentException">
    /// The request was refused for a reason safe to tell the client: unknown template, policy
    /// refusal, disabled protocol, malformed CSR. Anything else propagates and is reported to the
    /// client generically.
    /// </exception>
    Task<byte[]> EnrollAsync(byte[] pkcs10Der, string callerUsername, string? sourceIp, string? caLabel);
}

/// <summary>
/// An enrollment refusal whose message is safe to return to the client as a SOAP fault reason.
/// </summary>
public sealed class MsaeEnrollmentException(string message) : Exception(message);

/// <summary>
/// The MS-WSTEP enrollment pipeline: template resolution, authorization, request-profile policy,
/// persistence, issuance and chain assembly.
/// </summary>
/// <remarks>
/// <para>
/// This is the same pipeline EST's simple enrollment runs, written for the Windows case rather
/// than shared with it, because the two differ in what identifies the caller and in how the
/// target profile is chosen. EST binds the CSR subject to the authenticated username; a Windows
/// client enrolls for the machine or user it is running as and the credential it presents is
/// an enrollment credential, not the subject's own, so no such binding is applied here. Naming
/// policy is the request profile's job. Identity-derived subjects arrive with Kerberos
/// authentication in a later phase.
/// </para>
/// <para>
/// Profile selection follows the template the client named in its CSR, when it named one and a
/// ModularCA certificate template of that name exists; the template's CA, signing profile,
/// certificate profile and request profile are then used. A request that names a template this
/// CA does not have is refused rather than silently issued from a default: the client asked for
/// something specific and would otherwise receive a certificate that does not do what it
/// expects. A request naming no template falls back to the CA's MSAE protocol configuration.
/// </para>
/// <para>
/// Approval-gated request profiles are refused before anything is persisted. MS-WSTEP has a
/// pending disposition that a client polls on, but the polling half is not implemented yet, so
/// creating a pending request the client could never collect would only leave orphans.
/// Renewals are likewise handled at the controller, which refuses them before reaching here.
/// </para>
/// </remarks>
public class MsaeEnrollmentService(
    ModularCADbContext db,
    ICertificateIssuanceService issuance,
    ICaResolverService caResolver,
    IEnrollmentAuthorizationService enrollmentAuth,
    RequestProfileValidationService requestProfileValidation,
    IProfileResolutionService profileResolution,
    IProtocolAuditService protocolAudit,
    ILogger<MsaeEnrollmentService> logger) : IMsaeEnrollmentService
{
    /// <summary>The protocol name as it appears in per-CA protocol configuration and audit rows.</summary>
    public const string Protocol = "MSAE";

    /// <summary>Audit operation recorded for an issued certificate.</summary>
    public const string EnrollOperation = "Enroll";

    /// <summary>Audit operation recorded for a refused request.</summary>
    public const string RejectOperation = "EnrollRejected";

    /// <inheritdoc />
    public async Task<byte[]> EnrollAsync(byte[] pkcs10Der, string callerUsername, string? sourceIp, string? caLabel)
    {
        ArgumentNullException.ThrowIfNull(pkcs10Der);
        if (pkcs10Der.Length == 0)
            throw new ArgumentException("PKCS#10 is empty.", nameof(pkcs10Der));
        ArgumentException.ThrowIfNullOrWhiteSpace(callerUsername);

        var csrPem = CertificateUtil.ConvertDerToPem(pkcs10Der, "CERTIFICATE REQUEST");

        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "MSAE request from {Username} carried an unreadable PKCS#10.", callerUsername);
            var reason = "The request does not contain a readable PKCS#10.";
            await protocolAudit.LogMsaeAsync(RejectOperation, null, null, null, null, null, caLabel, sourceIp,
                success: false, errorMessage: reason, callerPrincipal: Principal(callerUsername));
            throw new MsaeEnrollmentException(reason);
        }

        // Which CA and profiles: the named template if there is one, else the CA's MSAE defaults.
        var template = MsaeCsrTemplate.TryRead(pkcs10Der);
        var audit = new AuditContext(callerUsername, sourceIp, parsedCsr, template?.Name ?? template?.Oid);
        var (context, resolvedTemplateName) = await ResolveContextAsync(template, caLabel, audit);
        if (resolvedTemplateName != null)
            audit = audit with { TemplateName = resolvedTemplateName };

        // The membership check runs against the CA the request actually resolved to, which for a
        // template request may differ from the route label; the two are reconciled above.
        var (allowed, authError) = await enrollmentAuth.ValidateAsync(
            Protocol, context.Ca.Label, csrPem, clientCert: null, isAuthenticated: true, callerUsername);
        if (!allowed)
            throw await RefuseAsync(audit, context.Ca, authError ?? "Enrollment not authorized.");

        var (resolvedCertProfileId, certProfileError) = await requestProfileValidation
            .ResolveCertProfileIdAsync(null, context.CertProfileId, context.RequestProfileId);
        if (resolvedCertProfileId == null)
            throw await RefuseAsync(audit, context.Ca, certProfileError ?? "No certificate profile is available for MSAE enrollment.");

        var signingProfile = await db.SigningProfiles.FindAsync(context.SigningProfileId)
            ?? throw new InvalidOperationException("Configured MSAE signing profile not found.");
        var certProfile = await db.CertProfiles.FindAsync(resolvedCertProfileId.Value)
            ?? throw new InvalidOperationException("Configured MSAE certificate profile not found.");

        var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);
        var subject = parsedCsr.SubjectName;

        if (context.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await requestProfileValidation
                .ValidateAsync(context.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
                throw await RefuseAsync(audit, context.Ca, error ?? "Request profile validation failed.");
            if (modifiedSubject != null)
                subject = modifiedSubject;

            // Read from the resolved profile so an inheriting child cannot relax a parent's
            // approval requirement, the same way EST does.
            var effective = await profileResolution.ResolveRequestProfileAsync(context.RequestProfileId.Value);
            if (effective.RequireApproval)
                throw await RefuseAsync(audit, context.Ca,
                    "This request profile requires approval, which MSAE enrollment does not support yet.");
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
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
        };
        db.CertificateRequests.Add(csrEntity);
        await db.SaveChangesAsync();

        var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var notAfter = notBefore.Add(maxValidity);

        var issued = await issuance.IssueCertificateAsync(csrEntity.Id, notBefore, notAfter);

        var serial = await db.CertificateRequests
            .Where(c => c.Id == csrEntity.Id)
            .Select(c => c.IssuedCertificate!.SerialNumber)
            .FirstOrDefaultAsync();

        await protocolAudit.LogMsaeAsync(EnrollOperation, subject, serial,
            parsedCsr.KeyAlgorithm, parsedCsr.KeySize, audit.TemplateName, context.Ca.Label, sourceIp,
            certificateAuthorityId: context.Ca.Id, tenantId: context.Ca.TenantId,
            callerPrincipal: Principal(callerUsername));

        return await BuildChainPkcs7Async(issued.Pem, signingProfile);
    }

    /// <summary>What every audit row for one request has in common.</summary>
    private sealed record AuditContext(
        string CallerUsername, string? SourceIp, CertificateUtil.ParsedCsrInfo Csr, string? TemplateName);

    /// <summary>
    /// Chooses the CA and profiles for a request: by the named template when one is named, else
    /// by the CA's MSAE protocol configuration. Refuses a named template that does not exist,
    /// and a template whose CA is not the one the route addressed. Returns the resolved
    /// template's name, or null when the CA's defaults were used, so the audit row can carry it.
    /// </summary>
    private async Task<(ResolvedCaContext Context, string? TemplateName)> ResolveContextAsync(
        MsaeCsrTemplate.TemplateReference? template, string? caLabel, AuditContext audit)
    {
        // A client that fetched policy names the template by the OID the policy service gave
        // it; a hand-built request names it by name. The OID wins when both are present and it
        // is known, because it is the identifier the policy service promised. An OID this CA
        // never issued, with no name to fall back on, is refused.
        var templateName = template?.Name;
        if (template?.Oid != null)
        {
            var byOid = await db.CertificateTemplates.AsNoTracking()
                .Where(t => t.MsaeTemplateOid == template.Oid)
                .Select(t => t.Name)
                .FirstOrDefaultAsync();
            if (byOid != null)
                templateName = byOid;
            else if (templateName == null)
                throw await RefuseAsync(audit, null, $"Certificate template OID '{template.Oid}' is not available.", caLabel);
        }

        if (templateName != null)
        {
            ResolvedCaContext byTemplate;
            try
            {
                byTemplate = await caResolver.ResolveByTemplateAsync(templateName);
            }
            catch (InvalidOperationException ex)
            {
                logger.LogInformation("MSAE request named template {Template}, refused: {Reason}", templateName, ex.Message);
                throw await RefuseAsync(audit, null, $"Certificate template '{templateName}' is not available.", caLabel);
            }

            if (!string.IsNullOrWhiteSpace(caLabel)
                && !string.Equals(byTemplate.Ca.Label, caLabel, StringComparison.OrdinalIgnoreCase))
            {
                throw await RefuseAsync(audit, byTemplate.Ca,
                    $"Certificate template '{templateName}' does not belong to CA '{caLabel}'.");
            }
            return (byTemplate, templateName);
        }

        try
        {
            return (await caResolver.ResolveAsync(caLabel, Protocol), null);
        }
        catch (InvalidOperationException ex)
        {
            // The resolver's messages name the CA and say the protocol is off or unconfigured;
            // that is exactly what an operator testing the endpoint needs to see.
            throw await RefuseAsync(audit, null, ex.Message, caLabel);
        }
    }

    /// <summary>
    /// Records a refusal on the MSAE audit tab and returns the exception to throw, so every
    /// refusal path reads as one line and none can forget the audit row.
    /// </summary>
    private async Task<MsaeEnrollmentException> RefuseAsync(
        AuditContext audit, CertificateAuthorityEntity? ca, string reason, string? caLabel = null)
    {
        await protocolAudit.LogMsaeAsync(RejectOperation, audit.Csr.SubjectName, null,
            audit.Csr.KeyAlgorithm, audit.Csr.KeySize, audit.TemplateName, ca?.Label ?? caLabel, audit.SourceIp,
            success: false, errorMessage: reason,
            certificateAuthorityId: ca?.Id, tenantId: ca?.TenantId,
            callerPrincipal: Principal(audit.CallerUsername));
        return new MsaeEnrollmentException(reason);
    }

    private static string Principal(string username) => $"user:{username}";

    /// <summary>
    /// Wraps the issued leaf and its issuer chain, walked through the signing profile's issuer
    /// links, as a certs-only PKCS#7.
    /// </summary>
    private async Task<byte[]> BuildChainPkcs7Async(string leafPem, SigningProfileEntity signingProfile)
    {
        var certs = new List<X509Certificate> { CertificateUtil.ParseFromPem(leafPem) };

        var visited = new HashSet<Guid>();
        var issuerId = signingProfile.IssuerId;
        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuer = await db.Certificates
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
            if (issuer == null) break;
            certs.Add(CertificateUtil.ParseFromPem(issuer.Pem));
            issuerId = issuer.SigningProfile?.IssuerId;
        }

        return Pkcs7Util.BuildCertsOnly(certs);
    }
}
