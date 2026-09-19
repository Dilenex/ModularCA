using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Models;
using ModularCA.Shared.Interfaces;
using ModularCA.Core.Services.Msae.Kerberos;
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
    /// Enrolls <paramref name="pkcs10Der"/> on behalf of <paramref name="caller"/> and returns the
    /// issued certificate and its chain as a certs-only PKCS#7 (DER), or the id of a request left
    /// waiting for approval when the request profile requires one.
    /// </summary>
    /// <param name="pkcs10Der">The DER-encoded PKCS#10 from the request's BinarySecurityToken.</param>
    /// <param name="caller">Who is asking and as whom they act; see <see cref="MsaeCaller"/>.</param>
    /// <param name="sourceIp">Caller address, for the audit record.</param>
    /// <param name="caLabel">CA label from the route, or null for the default CA.</param>
    /// <exception cref="MsaeEnrollmentException">
    /// The request was refused for a reason safe to tell the client: unknown template, policy
    /// refusal, disabled protocol, malformed CSR. Anything else propagates and is reported to the
    /// client generically.
    /// </exception>
    Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, MsaeCaller caller, string? sourceIp, string? caLabel);

    /// <summary>
    /// As <see cref="EnrollAsync(byte[], MsaeCaller, string?, string?)"/>, with the renewal evidence
    /// a CMC request carried. A renewal is issued only when the wrapper was signed by the
    /// certificate being renewed, that certificate was issued by the route's CA, is neither
    /// revoked nor expired, and belongs to the same template; the new request is linked to it.
    /// </summary>
    Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, MsaeCaller caller, string? sourceIp, string? caLabel, MsaeRenewal? renewal);

    /// <summary>
    /// Answers a client asking after a request it submitted earlier (MS-WSTEP QueryTokenStatus).
    /// Only the identity that submitted the request may collect it, and only at the CA the route
    /// names; anyone else, and an unknown id, is told the request is denied without learning
    /// whether it exists.
    /// </summary>
    Task<MsaeStatusResult> QueryStatusAsync(string requestId, MsaeCaller caller, string? sourceIp, string? caLabel);

    /// <summary>Enrolls on behalf of a caller that signed in with a username.</summary>
    Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, string callerUsername, string? sourceIp, string? caLabel)
        => EnrollAsync(pkcs10Der, MsaeCaller.Credential(callerUsername), sourceIp, caLabel);
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
/// The middle of an enrollment - the CA, the protocol's enablement on it, the caller's
/// authorization, the effective profiles, the names against the request profile, the request row,
/// issuance or submission for approval, and the audit row - is
/// <see cref="IEnrollmentPipeline"/>, and is the same sequence every protocol runs. What stays
/// here is what is Windows own: reading the CMC and the PKCS#10, resolving the template a client
/// named, building the subject from a Kerberos identity, proving renewal evidence, answering a
/// status query, and rendering PKCS#7. EST binds the CSR subject to the authenticated username; a
/// Windows client enrolls for the machine or user it is running as and the credential it presents
/// is an enrollment credential, not the subject own, so no such binding is applied here.
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
/// An approval-gated request profile leaves the request waiting for an approver, in the status
/// the console's approval queue works from, and the client is told it is taken under submission.
/// The client then asks after it by id (<see cref="QueryStatusAsync"/>) until an operator has
/// approved and issued it, or rejected it. Renewals arrive as CMC requests signed by the
/// certificate being renewed; see <see cref="MsaeRenewal"/>.
/// </para>
/// </remarks>
public class MsaeEnrollmentService(
    ModularCADbContext db,
    ICaResolverService caResolver,
    IProtocolAuditService protocolAudit,
    IEnrollmentPipeline pipeline,
    ILogger<MsaeEnrollmentService> logger) : IMsaeEnrollmentService, IEnrollmentProtocol
{
    /// <summary>The protocol name as it appears in per-CA protocol configuration and audit rows.</summary>
    public const string Protocol = "MSAE";

    /// <inheritdoc />
    string IEnrollmentProtocol.Name => Protocol;

    /// <summary>
    /// What Windows autoenrollment offers here: enrollment, CMC renewal against the certificate
    /// being replaced, and a status query a client asks after an approval-gated request with and
    /// collects the certificate from.
    /// </summary>
    /// <remarks>
    /// Not <see cref="EnrollmentCapabilities.ReEnroll"/>: a Windows renewal is not a request
    /// authenticated by the old certificate at the transport, it is a CMC wrapper signed by it, and
    /// that distinction is what <see cref="EnrollmentCapabilities.Renew"/> names. Revocation and
    /// server-side key generation are not offered by these two web services.
    /// </remarks>
    EnrollmentCapabilities IEnrollmentProtocol.Capabilities =>
        EnrollmentCapabilities.Enroll | EnrollmentCapabilities.Renew
        | EnrollmentCapabilities.Poll | EnrollmentCapabilities.Collect;

    /// <summary>Audit operation recorded for an issued certificate.</summary>
    public const string EnrollOperation = "Enroll";

    /// <summary>Audit operation recorded for a refused request.</summary>
    public const string RejectOperation = "EnrollRejected";

    /// <summary>Audit operation for an issued renewal; the request row links to the certificate renewed.</summary>
    public const string RenewOperation = "Renew";

    /// <summary>Audit operation for a request taken under submission, awaiting approval.</summary>
    public const string PendingOperation = "EnrollPending";

    /// <summary>Audit operation for a certificate collected by a status query after approval.</summary>
    public const string CollectOperation = "Collect";

    /// <summary>Request status while an approver owns it; the cleanup job never touches it.</summary>
    public const string PendingApprovalStatus = "PendingApproval";

    /// <summary>Enrolls on behalf of a caller that signed in with a username.</summary>
    public Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, string callerUsername, string? sourceIp, string? caLabel)
        => EnrollAsync(pkcs10Der, MsaeCaller.Credential(callerUsername), sourceIp, caLabel);

    /// <inheritdoc />
    public Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, MsaeCaller caller, string? sourceIp, string? caLabel)
        => EnrollAsync(pkcs10Der, caller, sourceIp, caLabel, renewal: null);

    /// <inheritdoc />
    /// <remarks>
    /// The order of the refusals below is the order this service has always refused in, because a
    /// client is told about the first thing wrong with its request and that is the answer an
    /// operator reads. The template is resolved first, since it chooses the CA and the profiles;
    /// the caller is then authorized against that CA by the pipeline; and the renewal evidence is
    /// proven after that, from the pipeline post-authorization check, so that a caller who may not
    /// enroll here learns only that.
    /// </remarks>
    public async Task<MsaeEnrollmentResult> EnrollAsync(byte[] pkcs10Der, MsaeCaller caller, string? sourceIp, string? caLabel, MsaeRenewal? renewal)
    {
        ArgumentNullException.ThrowIfNull(pkcs10Der);
        if (pkcs10Der.Length == 0)
            throw new ArgumentException("PKCS#10 is empty.", nameof(pkcs10Der));
        ArgumentNullException.ThrowIfNull(caller);

        var csrPem = CertificateUtil.ConvertDerToPem(pkcs10Der, "CERTIFICATE REQUEST");

        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "MSAE request from {Caller} carried an unreadable PKCS#10.", caller.AuditPrincipal);
            var reason = "The request does not contain a readable PKCS#10.";
            await protocolAudit.LogMsaeAsync(RejectOperation, null, null, null, null, null, caLabel, sourceIp,
                success: false, errorMessage: reason, callerPrincipal: caller.AuditPrincipal, realm: caller.Realm, authMethod: caller.AuthMethod);
            throw new MsaeEnrollmentException(reason);
        }

        // Which CA and profiles: the named template if there is one, else the CA MSAE defaults.
        // This is the one step of the middle a Windows request decides for itself, so it is made
        // here and handed to the pipeline; see EnrollmentSubmission.ResolvedContext.
        var template = MsaeCsrTemplate.TryRead(pkcs10Der);
        var audit = new AuditContext(caller, sourceIp, parsedCsr, template?.Name ?? template?.Oid);
        var (context, resolvedTemplateName) = await ResolveContextAsync(template, caLabel, audit);
        if (resolvedTemplateName != null)
            audit = audit with { TemplateName = resolvedTemplateName };

        // Windows matches a certificate to its template through this extension: without it the
        // autoenrollment pulse cannot see that it already holds one and enrolls again every time,
        // and renewal cannot tell which template to renew under. Stamped from the template as
        // stored, not from the CSR, so a client cannot claim a template it did not resolve to.
        var templateRow = await TemplateRowAsync(audit.TemplateName);
        var requested = templateRow == null
            ? null
            : new[] { MsaeCsrTemplate.TemplateInfoExtension(templateRow.Oid, templateRow.Major, templateRow.Minor) };

        var subject = parsedCsr.SubjectName;
        IReadOnlyList<string> sans = parsedCsr.SubjectAlternativeNames;

        // A Kerberos caller identity names the certificate; whatever the CSR carried is replaced.
        // The request profile naming rules still run in the middle, so a profile can narrow, never
        // widen. This is settled before the renewal below rather than after it, as it was, because
        // a subject taken from the ticket wins over one taken from the certificate being renewed
        // either way.
        if (caller.Kerberos is { } identity)
            (subject, sans) = IdentitySubject(identity);

        // The submitting identity owns the request: only it may collect the certificate later.
        var requestor = await db.Users.AsNoTracking()
            .Where(u => u.Username == caller.ActingAsUsername)
            .Select(u => (Guid?)u.Id)
            .FirstOrDefaultAsync();

        CertificateEntity? renewed = null;

        var submission = new EnrollmentSubmission
        {
            Protocol = Protocol,
            CaLabel = caLabel,
            SourceIp = sourceIp,
            ResolvedContext = context,
            ProfileHint = audit.TemplateName,
            RequestorUserId = requestor,
            RequestedExtensions = requested,
            IssuanceRefusalIsRefusal = true,
            Caller = new EnrollmentCaller(
                Principal: caller.AuditPrincipal,
                AuthMethod: caller.Kerberos != null ? EnrollmentAuthMethod.Kerberos : EnrollmentAuthMethod.HttpCredential,
                IsVerified: true,
                Username: caller.ActingAsUsername),
            Request = new EnrollmentRequestMaterial
            {
                CsrPem = csrPem,
                Subject = subject,
                SubjectAlternativeNames = sans,
                KeyAlgorithm = parsedCsr.KeyAlgorithm,
                KeySize = parsedCsr.KeySize,
                SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            },
            AfterAuthorization = async authorized =>
            {
                if (renewal == null) return authorized;
                renewed = await ValidateRenewalAsync(renewal, context, templateRow?.Oid, audit);

                // A renewal PKCS#10 has no subject of its own: the certificate being renewed names
                // the new one, names and all, so a renewal can never drift to a subject the old one
                // lacked.
                var material = authorized.Request;
                if (string.IsNullOrWhiteSpace(material.Subject))
                {
                    material = material with
                    {
                        Subject = renewed.SubjectDN,
                        SubjectAlternativeNames = RenewedNames(renewal.Certificate),
                    };
                }
                return authorized with
                {
                    Request = material,
                    Renewal = new EnrollmentRenewal(renewed.CertificateId, renewed.SerialNumber),
                };
            },
            Audit = record => WriteMsaeAuditAsync(record, audit, renewed != null),
        };

        var outcome = await pipeline.SubmitAsync(submission);
        switch (outcome)
        {
            case EnrollmentOutcome.Issued issued:
                if (renewed != null)
                    logger.LogInformation("MSAE renewal: {Caller} renewed serial {OldSerial} as {NewSerial} under {Template} at {Ca}.",
                        caller.AuditPrincipal, renewed.SerialNumber, issued.SerialNumber, audit.TemplateName, context.Ca!.Label);
                return MsaeEnrollmentResult.Issued(Pkcs7(issued.CertificatePem, issued.ChainPem));

            case EnrollmentOutcome.Pending pending:
                // Taken under submission: an approver owns the row now, and the client polls with
                // the id. Audited as such by the pipeline, so the approval queue and the MSAE tab
                // agree.
                logger.LogInformation("MSAE request {RequestId} from {Caller} for {Template} at {Ca} awaits approval.",
                    pending.RequestId, caller.AuditPrincipal, audit.TemplateName, context.Ca!.Label);
                return MsaeEnrollmentResult.Pending(pending.RequestId);

            case EnrollmentOutcome.Refused refused:
                // Already audited: every refusal the middle makes goes through the audit writer
                // above, in the shape an MSAE rejection has always had.
                throw new MsaeEnrollmentException(refused.Message);

            // A CA with no certificate profile to issue from is something the client is told and
            // the MSAE tab records, because an operator testing the endpoint needs to read it. The
            // pipeline calls it a fault rather than a refusal - nothing about the request is wrong
            // - and does not audit it, so the audit row is written here.
            case EnrollmentOutcome.Failed failed when failed.Reason == EnrollmentFailureReason.NoCertificateProfileAvailable:
                throw await RefuseAsync(audit, context.Ca, failed.Message);

            // A profile row the configuration names and the database does not have is a broken
            // installation: reported generically to the client, in the log, and nowhere else.
            case EnrollmentOutcome.Failed failed:
                throw new InvalidOperationException(failed.Message);

            default:
                throw new InvalidOperationException("Unrecognised enrollment outcome.");
        }
    }

    /// <summary>
    /// Writes the shared audit fields the pipeline supplies as an MSAE row, in MSAE own operation
    /// names and with the columns only it has: the template and the realm.
    /// </summary>
    /// <remarks>
    /// A refusal is recorded against the request as it arrived - the CSR subject and key, not the
    /// subject the middle would have issued - because that is the row this service has always
    /// written and it is what an operator matches against the client log.
    /// </remarks>
    /// <param name="record">The shared fields; see <see cref="EnrollmentAuditRecord"/>.</param>
    /// <param name="audit">What every row for this request has in common.</param>
    /// <param name="renewed">Whether the request renewed a certificate, which names the operation.</param>
    private Task WriteMsaeAuditAsync(EnrollmentAuditRecord record, AuditContext audit, bool renewed)
        => record.Event switch
        {
            EnrollmentAuditEvent.Issued => protocolAudit.LogMsaeAsync(
                renewed ? RenewOperation : EnrollOperation, record.Subject, record.SerialNumber,
                record.KeyAlgorithm, record.KeySize, audit.TemplateName, record.CaLabel, audit.SourceIp,
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: audit.Caller.AuditPrincipal, realm: audit.Caller.Realm, authMethod: audit.Caller.AuthMethod),

            EnrollmentAuditEvent.Pending => protocolAudit.LogMsaeAsync(
                PendingOperation, record.Subject, null,
                record.KeyAlgorithm, record.KeySize, audit.TemplateName, record.CaLabel, audit.SourceIp,
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: audit.Caller.AuditPrincipal, realm: audit.Caller.Realm, authMethod: audit.Caller.AuthMethod),

            _ => protocolAudit.LogMsaeAsync(
                RejectOperation, audit.Csr.SubjectName, null,
                audit.Csr.KeyAlgorithm, audit.Csr.KeySize, audit.TemplateName, record.CaLabel, audit.SourceIp,
                success: false, errorMessage: record.Message ?? "Enrollment refused.",
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: audit.Caller.AuditPrincipal, realm: audit.Caller.Realm, authMethod: audit.Caller.AuthMethod),
        };

    /// <inheritdoc />
    public async Task<MsaeStatusResult> QueryStatusAsync(string requestId, MsaeCaller caller, string? sourceIp, string? caLabel)
    {
        ArgumentNullException.ThrowIfNull(caller);

        // Everything a stranger could learn is folded into one answer: a request that does not
        // exist, belongs to someone else, or sits at another CA all read as denied.
        async Task<MsaeStatusResult> DeniedAsync(string reason, Guid? caId = null, Guid? tenantId = null)
        {
            await protocolAudit.LogMsaeAsync(RejectOperation, null, null, null, null, null, caLabel, sourceIp,
                success: false, errorMessage: reason, certificateAuthorityId: caId, tenantId: tenantId,
                callerPrincipal: caller.AuditPrincipal, realm: caller.Realm, authMethod: caller.AuthMethod);
            return new MsaeStatusResult(MsaeRequestState.Denied, Reason: reason);
        }

        if (!Guid.TryParse(requestId, out var id))
            return await DeniedAsync("The request id is not one this service issued.");

        var request = await db.CertificateRequests.AsNoTracking()
            .Include(r => r.SigningProfile)
            .Include(r => r.IssuedCertificate)
            .FirstOrDefaultAsync(r => r.Id == id);
        if (request == null)
            return await DeniedAsync($"Request {id} is not known.");

        var context = await caResolver.ResolveAsync(caLabel, Protocol);
        var ca = context.Ca;
        if (ca == null || request.SigningProfile == null || request.SigningProfile.IssuerId != ca.CertificateId)
            return await DeniedAsync($"Request {id} does not belong to CA '{caLabel}'.", ca?.Id, ca?.TenantId);

        var requestor = await db.Users.AsNoTracking()
            .Where(u => u.Username == caller.ActingAsUsername)
            .Select(u => (Guid?)u.Id)
            .FirstOrDefaultAsync();
        if (request.RequestorUserId == null || requestor == null || request.RequestorUserId != requestor)
            return await DeniedAsync($"Request {id} was not submitted by this caller.", ca.Id, ca.TenantId);

        if (request.IssuedCertificateId != null && request.IssuedCertificate != null)
        {
            await protocolAudit.LogMsaeAsync(CollectOperation, request.Subject, request.IssuedCertificate.SerialNumber,
                request.KeyAlgorithm, request.KeySize, null, ca.Label, sourceIp,
                certificateAuthorityId: ca.Id, tenantId: ca.TenantId,
                callerPrincipal: caller.AuditPrincipal, realm: caller.Realm, authMethod: caller.AuthMethod);
            return new MsaeStatusResult(MsaeRequestState.Issued, await BuildChainPkcs7Async(request.IssuedCertificate.Pem, request.SigningProfile));
        }

        return request.Status switch
        {
            "Rejected" or "Cancelled" => await DeniedAsync($"Request {id} was {request.Status.ToLowerInvariant()} by an operator.", ca.Id, ca.TenantId),
            _ => new MsaeStatusResult(MsaeRequestState.Pending),
        };
    }

    /// <summary>The identity of a template offered to Windows: its OID and version as stored.</summary>
    private sealed record TemplateRow(string Oid, int Major, int Minor);

    /// <summary>
    /// The resolved template's OID and version, the same values the policy service advertises and
    /// issuance stamps. Null when the request resolved to the CA's defaults rather than a template.
    /// </summary>
    private async Task<TemplateRow?> TemplateRowAsync(string? templateName)
    {
        if (templateName == null) return null;
        var t = await db.CertificateTemplates.AsNoTracking()
            .Where(x => x.Name == templateName && x.MsaeTemplateOid != null)
            .Select(x => new { x.MsaeTemplateOid, x.MsaeMajorVersion, x.MsaeMinorVersion })
            .FirstOrDefaultAsync();
        return t == null ? null : new TemplateRow(t.MsaeTemplateOid!, t.MsaeMajorVersion, t.MsaeMinorVersion);
    }

    /// <summary>
    /// Checks a renewal against what this CA knows: the wrapper must be signed by the certificate
    /// being renewed, and that certificate must be one this CA issued, unrevoked, unexpired, and
    /// of the template the request resolved to. Returns the stored certificate on success; throws
    /// the audited refusal otherwise.
    /// </summary>
    private async Task<CertificateEntity> ValidateRenewalAsync(MsaeRenewal renewal, ResolvedCaContext context, string? templateOid, AuditContext audit)
    {
        if (!renewal.SignedByOldCertificate)
            throw await RefuseAsync(audit, context.Ca, "The renewal request is not signed by the certificate it names as the one to renew.");

        var old = renewal.Certificate;
        var serial = CertificateUtil.FormatSerialNumber(old.SerialNumber);
        var stored = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.SerialNumber == serial);
        if (stored == null)
            throw await RefuseAsync(audit, context.Ca, $"The certificate to renew (serial {serial}) was not issued by this service.");
        if (context.Ca!.CertificateId != null && stored.IssuerCertificateId != context.Ca.CertificateId)
            throw await RefuseAsync(audit, context.Ca, $"The certificate to renew (serial {serial}) was not issued by CA '{context.Ca.Label}'.");
        if (stored.Revoked)
            throw await RefuseAsync(audit, context.Ca, $"The certificate to renew (serial {serial}) is revoked.");
        if (stored.NotAfter < DateTime.UtcNow)
            throw await RefuseAsync(audit, context.Ca, $"The certificate to renew (serial {serial}) has expired; enroll anew instead of renewing.");

        // A certificate issued before templates were stamped carries no template extension and is
        // allowed through; one that carries a different template is refused, since renewal must
        // not be a way to swap templates.
        var oldTemplate = MsaeCsrTemplate.ReadTemplateOid(old);
        if (oldTemplate != null && templateOid != null && !string.Equals(oldTemplate, templateOid, StringComparison.Ordinal))
            throw await RefuseAsync(audit, context.Ca, $"The certificate to renew belongs to template {oldTemplate}, not the requested template.");

        return stored;
    }

    /// <summary>
    /// The alternative names of the certificate being renewed, in the <c>TYPE:value</c> form the
    /// request row stores. The subject comes from the stored row rather than from here, so a
    /// renewal is named by what this CA recorded and not by what the client presented.
    /// </summary>
    private static IReadOnlyList<string> RenewedNames(Org.BouncyCastle.X509.X509Certificate old)
    {
        var sans = new List<string>();
        var sanExt = old.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectAlternativeName);
        if (sanExt != null)
        {
            var names = Org.BouncyCastle.Asn1.X509.GeneralNames.GetInstance(
                Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(sanExt));
            foreach (var name in names.GetNames())
                sans.Add(UpnSanEncoding.Describe(name));
        }
        return sans;
    }

    /// <summary>What every audit row for one request has in common.</summary>
    private sealed record AuditContext(
        MsaeCaller Caller, string? SourceIp, CertificateUtil.ParsedCsrInfo Csr, string? TemplateName);

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
    /// The subject and SAN a Kerberos identity yields: a machine is <c>CN=host.dns.domain</c>
    /// with a matching dNSName; a user is <c>CN=name</c> with a UPN. The policy service
    /// advertised exactly these through the template's subject name flags.
    /// </summary>
    internal static (string Subject, IReadOnlyList<string> Sans) IdentitySubject(KerberosCaller identity)
    {
        if (identity.IsMachine)
            return ($"CN={identity.DnsHostName}", new[] { $"DNS:{identity.DnsHostName}" });
        return ($"CN={identity.Principal}", new[] { $"{UpnSanEncoding.UpnPrefix}:{identity.Upn}" });
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
            callerPrincipal: audit.Caller.AuditPrincipal, realm: audit.Caller.Realm, authMethod: audit.Caller.AuthMethod);
        return new MsaeEnrollmentException(reason);
    }

    /// <summary>
    /// Wraps an issued leaf and the chain the pipeline walked for it as a certs-only PKCS#7, which
    /// is what a Windows client expects in a WS-Trust response.
    /// </summary>
    private static byte[] Pkcs7(string leafPem, IReadOnlyList<string> chainPem)
    {
        var certs = new List<X509Certificate> { CertificateUtil.ParseFromPem(leafPem) };
        foreach (var issuerPem in chainPem)
            certs.Add(CertificateUtil.ParseFromPem(issuerPem));
        return Pkcs7Util.BuildCertsOnly(certs);
    }

    /// <summary>
    /// Wraps a collected certificate and its issuer chain, walked through the signing profile's
    /// issuer links, as a certs-only PKCS#7. The enrollment path takes the chain from the pipeline,
    /// which walked the same links while it still had the profile in hand; a status query has only
    /// the stored request, so it walks them here.
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
