using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Enrollment;

/// <summary>
/// The one implementation of the shared enrollment middle; see <see cref="IEnrollmentPipeline"/>.
/// </summary>
/// <remarks>
/// <para>
/// The order of the steps is the contract, not an implementation detail: the CA is resolved before
/// anything is decided about it, the protocol's enablement is checked before the caller is
/// authorized, the caller is authorized before any profile is read, and the names are validated
/// before a row exists. Each step reuses the service that already owns it —
/// <see cref="ICaResolverService"/>, <see cref="IEnrollmentAuthorizationService"/>,
/// <see cref="RequestProfileValidationService"/>, <see cref="IProfileResolutionService"/>,
/// <see cref="ICertificateIssuanceService"/> — so this is a sequence, not a reimplementation.
/// </para>
/// <para>
/// The CA lookup and the protocol-enablement check are made here as well as inside
/// <see cref="IEnrollmentAuthorizationService"/>, which makes them too. That is deliberate: the
/// pipeline must be able to tell a missing CA from a disabled protocol from an unauthorized
/// caller, and a boolean-and-a-sentence cannot say which it was without reading the sentence. The
/// refusal text is the same text the authorization service would have produced, so nothing a
/// client sees changes.
/// </para>
/// </remarks>
public class EnrollmentPipeline : IEnrollmentPipeline
{
    private readonly ModularCADbContext _db;
    private readonly ICaResolverService _caResolver;
    private readonly IEnrollmentAuthorizationService _enrollmentAuth;
    private readonly RequestProfileValidationService _requestProfileValidation;
    private readonly IProfileResolutionService _profileResolution;
    private readonly ICertificateIssuanceService _issuance;
    private readonly INotificationService _notifications;
    private readonly ILogger<EnrollmentPipeline> _logger;

    /// <summary>Constructs the pipeline over the services that own each step.</summary>
    public EnrollmentPipeline(
        ModularCADbContext db,
        ICaResolverService caResolver,
        IEnrollmentAuthorizationService enrollmentAuth,
        RequestProfileValidationService requestProfileValidation,
        IProfileResolutionService profileResolution,
        ICertificateIssuanceService issuance,
        INotificationService notifications,
        ILogger<EnrollmentPipeline> logger)
    {
        _db = db;
        _caResolver = caResolver;
        _enrollmentAuth = enrollmentAuth;
        _requestProfileValidation = requestProfileValidation;
        _profileResolution = profileResolution;
        _issuance = issuance;
        _notifications = notifications;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<EnrollmentOutcome> SubmitAsync(
        EnrollmentSubmission submission, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(submission);
        var protocol = submission.Protocol.ToUpperInvariant();
        var resolved = submission.ResolvedContext;

        // 1. The CA the request addresses. Everything below is decided about this CA and no other.
        //    A protocol whose wire format chooses the CA - MSAE, through the template a client
        //    named - has resolved it already and supplies it; see
        //    EnrollmentSubmission.ResolvedContext.
        var ca = resolved?.Ca ?? await _caResolver.ResolveCaEntityAsync(submission.CaLabel);
        if (ca == null)
        {
            return await RefuseAsync(submission, submission.Request, null, EnrollmentRefusalReason.CaNotFound,
                submission.CaLabel != null
                    ? $"CA '{submission.CaLabel}' not found or disabled."
                    : "No enabled Certificate Authority found.");
        }

        // 2. Is this protocol offered here at all.
        var protocolConfig = await _db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == protocol, cancellationToken);
        if (protocolConfig == null || !protocolConfig.IsEnabled)
        {
            return await RefuseAsync(submission, submission.Request, ca, EnrollmentRefusalReason.ProtocolDisabledOnCa,
                $"{protocol} is not enabled for CA '{ca.Label}'.");
        }

        // 3. May this caller enroll here. The protocol has already proven who they are. The CA
        //    asked about is the one that will issue, which for a protocol that resolved its own is
        //    not necessarily the label in the route.
        var (allowed, authError) = await _enrollmentAuth.ValidateAsync(
            protocol, resolved != null ? ca.Label : submission.CaLabel, submission.Request.CsrPem,
            submission.Caller.ClientCertificate, submission.Caller.IsVerified, submission.Caller.Username);
        if (!allowed)
        {
            return await RefuseAsync(submission, submission.Request, ca, EnrollmentRefusalReason.CallerNotAuthorized,
                authError ?? "Enrollment not authorized");
        }

        // 4. The protocol's own check, in the place it already ran it, and what it settled: the
        //    names the request will carry, and the renewal it proved.
        var request = submission.Request;
        var renewal = submission.Renewal;
        if (submission.AfterAuthorization != null)
        {
            var settled = await submission.AfterAuthorization(new EnrollmentAuthorizedRequest(request, renewal));
            request = settled.Request;
            renewal = settled.Renewal;
        }

        // 5. The effective profiles: the CA's protocol configuration chooses them, or the protocol
        //    supplied them along with the CA; the request profile's allowed list bounds what a
        //    requester may ask for instead.
        var context = resolved ?? await _caResolver.ResolveAsync(submission.CaLabel, protocol);
        var (resolvedCertProfileId, certProfileError) = await _requestProfileValidation
            .ResolveCertProfileIdAsync(submission.RequestedCertProfileId, context.CertProfileId, context.RequestProfileId);
        if (resolvedCertProfileId == null)
        {
            // Not a refusal: nothing about the request is wrong, the CA has no profile to issue
            // from. The protocol reports it as the configuration fault it is.
            return new EnrollmentOutcome.Failed(
                certProfileError ?? $"No certificate profile available for {protocol}",
                Reason: EnrollmentFailureReason.NoCertificateProfileAvailable);
        }

        var signingProfile = await _db.SigningProfiles.FindAsync([context.SigningProfileId], cancellationToken);
        if (signingProfile == null)
            return new EnrollmentOutcome.Failed($"Configured {protocol} signing profile not found.",
                Reason: EnrollmentFailureReason.ConfiguredProfileMissing);
        var certProfile = await _db.CertProfiles.FindAsync([resolvedCertProfileId.Value], cancellationToken);
        if (certProfile == null)
            return new EnrollmentOutcome.Failed($"Configured {protocol} certificate profile not found.",
                Reason: EnrollmentFailureReason.ConfiguredProfileMissing);

        // 6. The names, against the request profile. A fixed value in the profile can rewrite the
        //    subject, which is why the row below is written from the result and not from the CSR.
        var subject = request.Subject ?? string.Empty;

        // Every component within the limits the certificate will be held to, before the name
        // reaches the ASN.1 library. Since BouncyCastle 2.7.0 an over-long common name is refused
        // when the name is constructed, deep inside issuance, where the exception is a server
        // error rather than something a client can act on. Checked here, it is a refusal like any
        // other, and every protocol inherits it.
        if (!string.IsNullOrWhiteSpace(subject))
        {
            try { DnComponentSanitizer.SanitizeDistinguishedName(subject); }
            catch (InvalidOperationException ex)
            {
                return await RefuseAsync(submission, request, ca, EnrollmentRefusalReason.NameRejectedByProfile, ex.Message);
            }
        }

        var sanJson = JsonSerializer.Serialize(request.SubjectAlternativeNames);
        var requireApproval = false;
        if (context.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await _requestProfileValidation
                .ValidateAsync(context.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
            {
                return await RefuseAsync(submission, request, ca, EnrollmentRefusalReason.NameRejectedByProfile,
                    error ?? "Request profile validation failed");
            }
            if (modifiedSubject != null)
                subject = modifiedSubject;

            // Read from the RESOLVED profile, not the raw row: a CA-scoped child can otherwise set
            // RequireApproval=false against a parent that requires it, and the inheritance clamp
            // never runs.
            var effective = await _profileResolution.ResolveRequestProfileAsync(context.RequestProfileId.Value);
            requireApproval = effective.RequireApproval;
        }

        // 7. The protocol's own check, now that the profile is known.
        if (submission.AfterProfileValidation != null)
        {
            await submission.AfterProfileValidation(new EnrollmentPolicyContext(
                ca.Id, ca.Label, context.RequestProfileId, certProfile.Id,
                subject, request.SubjectAlternativeNames));
        }

        // 8. The request row, with whatever extensions the protocol asked to be echoed.
        var csrEntity = new CertRequestEntity
        {
            Subject = subject,
            SubjectAlternativeNames = sanJson,
            AdditionalExtensions = RequestedExtension.ToJson(submission.RequestedExtensions),
            RenewalOfCertificateId = renewal?.RenewedCertificateId,
            RequestorUserId = submission.RequestorUserId,
            CSR = request.CsrPem ?? string.Empty,
            KeyAlgorithm = request.KeyAlgorithm ?? string.Empty,
            KeySize = request.KeySize ?? string.Empty,
            SignatureAlgorithm = request.SignatureAlgorithm ?? string.Empty,
            SubmittedAt = DateTime.UtcNow,
            Status = requireApproval ? PendingApprovalStatus : "Pending",
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
        };
        _db.CertificateRequests.Add(csrEntity);
        await _db.SaveChangesAsync(cancellationToken);

        // 9a. Taken under submission: an approver owns the row now and the client is told to come
        //     back for it.
        if (requireApproval)
        {
            _logger.LogInformation(
                "{Protocol} request {RequestId} at CA {CaLabel} awaits approval.", protocol, csrEntity.Id, ca.Label);
            await AuditAsync(submission, new EnrollmentAuditRecord(
                protocol, EnrollmentAuditEvent.Pending, null, null,
                subject, null, request.KeyAlgorithm, request.KeySize,
                ca.Label, ca.Id, ca.TenantId, submission.SourceIp, csrEntity.Id, submission.Correlation));
            _ = _notifications.NotifyCsrPendingApprovalAsync(subject, protocol);
            return new EnrollmentOutcome.Pending(csrEntity.Id);
        }

        // 9b. Issued. The window the client asked for, each end defaulted separately: a start of
        //     now less the skew allowance, and an expiry of the certificate profile's maximum
        //     measured from that start. The floor on the start is applied here rather than left to
        //     the protocol, because a backdated notBefore is a certificate whose signatures can be
        //     made to look older than a revocation. Everything below this only shortens.
        var notBefore = CertificateValidityUtil.ClampRequestedNotBefore(submission.RequestedNotBefore, out _);
        var profileMaximum = notBefore.Add(Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y"));
        var notAfter = submission.RequestedNotAfter ?? profileMaximum;

        // A protocol that has always shortened an over-long request rather than refusing it says
        // so; see EnrollmentSubmission.ClampRequestedNotAfterToProfileMax. Issuance refuses one,
        // and refusing where a client used to be issued is a wire change.
        if (submission.ClampRequestedNotAfterToProfileMax && notAfter > profileMaximum)
            notAfter = profileMaximum;

        IssuanceResult issuanceResult;
        try
        {
            issuanceResult = await _issuance.IssueCertificateAsync(csrEntity.Id, notBefore, notAfter,
                cancellationToken: cancellationToken);
        }
        catch (RequestValidationException ex) when (submission.IssuanceRefusalIsRefusal)
        {
            // Issuance refused the request on the profile's own rules. For a protocol that says so
            // - see EnrollmentSubmission.IssuanceRefusalIsRefusal - that is a refusal the client
            // should read, and the row it already wrote is closed rather than left for an approver.
            csrEntity.Status = RejectedStatus;
            await _db.SaveChangesAsync(cancellationToken);
            return await RefuseAsync(submission, request, ca,
                EnrollmentRefusalReason.IssuanceRefusedByProfile, ex.Message);
        }

        var serial = await _db.CertificateRequests
            .Where(c => c.Id == csrEntity.Id)
            .Select(c => c.IssuedCertificate!.SerialNumber)
            .FirstOrDefaultAsync(cancellationToken);

        // 10. The audit row, before the protocol renders anything.
        await AuditAsync(submission, new EnrollmentAuditRecord(
            protocol, EnrollmentAuditEvent.Issued, null, null,
            subject, serial, request.KeyAlgorithm, request.KeySize,
            ca.Label, ca.Id, ca.TenantId, submission.SourceIp, csrEntity.Id, submission.Correlation));

        return new EnrollmentOutcome.Issued(
            csrEntity.Id, issuanceResult.Pem, await ChainAsync(signingProfile, cancellationToken), serial);
    }

    /// <summary>Request status while an approver owns the row; the cleanup job never touches it.</summary>
    private const string PendingApprovalStatus = "PendingApproval";

    /// <summary>Request status for a row issuance refused, so the approval queue reads it as closed.</summary>
    private const string RejectedStatus = "Rejected";

    /// <summary>
    /// Audits a refusal and returns it. Every refusal goes through here, so none can be added
    /// without an audit row — which is the failure mode that made refused enrollments invisible on
    /// the protocol tabs in the first place.
    /// </summary>
    /// <param name="request">
    /// The request as it stands at the point of the refusal: what the protocol submitted before its
    /// own check has run, and what that check settled afterwards.
    /// </param>
    private async Task<EnrollmentOutcome> RefuseAsync(
        EnrollmentSubmission submission, EnrollmentRequestMaterial request, CertificateAuthorityEntity? ca,
        EnrollmentRefusalReason reason, string message)
    {
        await AuditAsync(submission, new EnrollmentAuditRecord(
            submission.Protocol.ToUpperInvariant(), EnrollmentAuditEvent.Refused, reason, message,
            request.Subject, null, request.KeyAlgorithm, request.KeySize,
            ca?.Label ?? submission.CaLabel, ca?.Id, ca?.TenantId, submission.SourceIp, null, submission.Correlation));
        return new EnrollmentOutcome.Refused(reason, message);
    }

    /// <summary>
    /// Hands the shared audit fields to the protocol's own writer. A protocol that supplies none
    /// is not audited by the pipeline; that is a hole worth seeing in the log rather than a silent
    /// one.
    /// </summary>
    private async Task AuditAsync(EnrollmentSubmission submission, EnrollmentAuditRecord record)
    {
        if (submission.Audit == null)
        {
            _logger.LogWarning(
                "{Protocol} submitted an enrollment with no audit writer; {Event} was not recorded on a protocol tab.",
                record.Protocol, record.Event);
            return;
        }
        await submission.Audit(record);
    }

    /// <summary>
    /// The issuer chain above the leaf, walked through the signing profile's issuer links, nearest
    /// issuer first. The visited set is what stops a cycle in the links from walking forever.
    /// </summary>
    private async Task<IReadOnlyList<string>> ChainAsync(
        SigningProfileEntity signingProfile, CancellationToken cancellationToken)
    {
        var chain = new List<string>();
        var visited = new HashSet<Guid>();
        var issuerId = signingProfile.IssuerId;
        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuer = await _db.Certificates
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value, cancellationToken);
            if (issuer == null) break;
            chain.Add(issuer.Pem);
            issuerId = issuer.SigningProfile?.IssuerId;
        }
        return chain;
    }
}
