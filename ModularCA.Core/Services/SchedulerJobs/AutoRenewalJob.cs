using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that finds non-revoked, non-CA certificates approaching expiration
/// and automatically creates renewal CSR requests. When auto-approve is enabled and
/// the certificate's profile does not require manual approval, the renewed certificate
/// is issued immediately. Duplicate renewal requests are suppressed and failures are
/// reported via the security alert service.
///
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math against
/// <c>AutoRenewal.Schedule</c>, missed-run policy, timeout enforcement, metrics, and
/// <c>SchedulerJobStates</c> persistence — the body below is purely the per-tick renewal
/// work. The <c>RunAsync(ct)</c> entry point is retained as the operator-facing manual-run
/// path: <c>SchedulerJobRegistry.RunNowAsync</c> calls it directly when an operator clicks
/// "Run Now" in the admin Schedules page — bypassing the cron past-due gate that
/// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
/// regardless of schedule.
/// </summary>
public class AutoRenewalJob : SingletonCronJob
{
    private readonly ModularCADbContext _db;
    private readonly ICertificateIssuanceService _issuance;
    private readonly ICsrService _csrService;
    private readonly IAuditService _audit;
    private readonly ISecurityAlertService _alerts;
    private readonly INotificationService _notifications;
    private readonly SystemConfig _config;
    private readonly ILogger<AutoRenewalJob> _logger;
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="AutoRenewalJob"/> class.
    /// </summary>
    /// <param name="db">Database context for querying certificates and creating renewal requests.</param>
    /// <param name="issuance">Certificate issuance service for auto-issuing renewed certificates.</param>
    /// <param name="csrService">CSR service for generating fresh key pairs during key-rotation renewals.</param>
    /// <param name="audit">Audit service for logging each renewal attempt.</param>
    /// <param name="alerts">Security alert service for reporting failures.</param>
    /// <param name="notifications">Notification service for alerting admins of pending renewals.</param>
    /// <param name="config">System configuration containing auto-renewal settings.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="serviceProvider">DI service provider for scoped operations and the <see cref="SingletonCronJob"/> base.</param>
    /// <param name="runner">Shared job runner that owns timeout enforcement, metrics, and state persistence for the base class.</param>
    public AutoRenewalJob(
        ModularCADbContext db,
        ICertificateIssuanceService issuance,
        ICsrService csrService,
        IAuditService audit,
        ISecurityAlertService alerts,
        INotificationService notifications,
        SystemConfig config,
        ILogger<AutoRenewalJob> logger,
        IServiceProvider serviceProvider,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _db = db;
        _issuance = issuance;
        _csrService = csrService;
        _audit = audit;
        _alerts = alerts;
        _notifications = notifications;
        _config = config;
        _logger = logger;
        _serviceProvider = serviceProvider;
    }

    /// <inheritdoc />
    public override string Name => "AutoRenewal";

    /// <summary>
    /// Cron expression for the auto-renewal sweep. Returns <see cref="string.Empty"/> when
    /// auto-renewal is disabled, which the base <see cref="SingletonCronJob.TickAsync"/>
    /// treats as "skip without state write".
    /// </summary>
    protected override string CronExpression =>
        _config.AutoRenewal.Enabled
            ? _config.AutoRenewal.Schedule
            : string.Empty;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
    /// operator clicks "Run Now" for this job — bypassing the cron past-due gate that
    /// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
    /// regardless of schedule. The protected <see cref="ExecuteAsync"/> body is invoked
    /// directly.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Executes the automatic certificate renewal check. Finds all active, non-revoked,
    /// non-CA certificates expiring within the configured window, creates renewal CSR
    /// requests for those without existing renewals, and optionally auto-issues them.
    /// </summary>
    /// <param name="cancellationToken">Token to signal cancellation of the operation.</param>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        // CronExpression already short-circuits when auto-renewal is disabled. The check
        // here is defense-in-depth for the manual-run RunAsync path which bypasses
        // the cron evaluation in the base class.
        if (!_config.AutoRenewal.Enabled)
            return;

        var now = TimeProvider.GetUtcNow().UtcDateTime;
        var renewalCutoff = now.AddDays(_config.AutoRenewal.RenewDaysBeforeExpiry);

        // Find all non-revoked, non-CA certificates expiring within the renewal window
        var expiringCerts = await _db.Certificates
            .AsNoTracking()
            .Where(c => !c.Revoked
                         && !c.IsCA
                         && c.NotAfter <= renewalCutoff
                         && c.NotAfter > now)
            .ToListAsync(cancellationToken);

        if (expiringCerts.Count == 0)
            return;

        // Collect certificate IDs that already have a pending or completed (non-rejected) renewal request
        var expiringCertIds = expiringCerts.Select(c => c.CertificateId).ToList();
        var existingRenewalCertIds = await _db.CertificateRequests
            .Where(r => r.RenewalOfCertificateId != null
                         && expiringCertIds.Contains(r.RenewalOfCertificateId.Value)
                         && r.Status != "Rejected")
            .Select(r => r.RenewalOfCertificateId!.Value)
            .Distinct()
            .ToListAsync(cancellationToken);

        var existingRenewalSet = new HashSet<Guid>(existingRenewalCertIds);

        var certsToRenew = expiringCerts
            .Where(c => !existingRenewalSet.Contains(c.CertificateId))
            .ToList();

        if (certsToRenew.Count == 0)
            return;

        _logger.LogInformation(
            "AutoRenewalJob: processing {Count} certificate(s) for renewal (RequireKeyRotation={Rotate})",
            certsToRenew.Count, _config.AutoRenewal.RequireKeyRotation);

        foreach (var cert in certsToRenew)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ProcessRenewalAsync(cert, cancellationToken);
        }
    }

    /// <summary>
    /// Processes the renewal of a single certificate. Looks up the original CSR request
    /// to copy subject DN, SANs, cert profile, and signing profile. Creates a new CSR
    /// entity with <see cref="CertRequestEntity.RenewalOfCertificateId"/> set. If auto-approve
    /// is enabled and the profile does not require approval, issues the certificate immediately.
    /// </summary>
    /// <param name="cert">The certificate entity approaching expiration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task ProcessRenewalAsync(CertificateEntity cert, CancellationToken cancellationToken)
    {
        try
        {
            // Find the original CSR that produced this certificate
            var originalRequest = await _db.CertificateRequests
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.IssuedCertificateId == cert.CertificateId, cancellationToken);

            // Determine profile IDs from the certificate entity; fall back to the original request
            var certProfileId = cert.CertProfileId ?? originalRequest?.CertProfileId;
            var signingProfileId = cert.SigningProfileId ?? originalRequest?.SigningProfileId;

            if (certProfileId == null || signingProfileId == null)
            {
                _logger.LogWarning(
                    "AutoRenewalJob: skipping cert {Serial} — cannot determine cert or signing profile",
                    cert.SerialNumber);
                return;
            }

            // Use subject and SANs from the certificate itself (includes any overrides applied at original issuance)
            var subjectDn = cert.SubjectDN;
            var sanJson = cert.SubjectAlternativeNamesJson;

            // Carry forward key parameters from the original request when available
            var keyAlgorithm = originalRequest?.KeyAlgorithm ?? string.Empty;
            var keySize = originalRequest?.KeySize ?? string.Empty;
            var signatureAlgorithm = originalRequest?.SignatureAlgorithm ?? string.Empty;

            // CLM-001: key-rotation policy. When RequireKeyRotation is true (default),
            // generate a fresh CSR with a new key pair via the CSR service instead of
            // setting CSR to empty string (which the issuance pipeline rejects). When
            // false, the prior behaviour of carrying forward encrypted key blobs is
            // preserved for devices that cannot rotate keys.
            var rekey = _config.AutoRenewal.RequireKeyRotation;

            CertRequestEntity renewalRequest;
            if (rekey)
            {
                // CLM-001: generate a fresh CSR with new key pair using the same subject
                // DN, SANs, and profiles from the original certificate.
                var keySizeInt = ParseKeySizeToInt(keyAlgorithm, keySize);
                var sans = ParseSansFromJson(sanJson);

                // Renewing a subscriber certificate is NOT an infrastructure issuance: it must
                // stay subject to quota and validity policy, and stay owned by whoever requested
                // the original so they keep self-service on the replacement.
                var (csrId, _) = await _csrService.GenerateInfrastructureCsrAsync(
                    subjectDn, keyAlgorithm, keySizeInt,
                    certProfileId.Value, signingProfileId.Value,
                    sans,
                    isInfrastructure: originalRequest?.IsInfrastructureCert ?? false,
                    requestorUserId: originalRequest?.RequestorUserId);

                // Retrieve the generated CSR entity and stamp it as a renewal
                renewalRequest = await _db.CertificateRequests.FirstAsync(r => r.Id == csrId, cancellationToken);
                renewalRequest.RenewalOfCertificateId = cert.CertificateId;
                await _db.SaveChangesAsync(cancellationToken);
            }
            else
            {
                renewalRequest = new CertRequestEntity
                {
                    Subject = subjectDn,
                    SubjectAlternativeNames = sanJson,
                    CSR = originalRequest?.CSR ?? string.Empty,
                    KeyAlgorithm = keyAlgorithm,
                    KeySize = keySize,
                    SignatureAlgorithm = signatureAlgorithm,
                    SubmittedAt = TimeProvider.GetUtcNow().UtcDateTime,
                    Status = "Pending",
                    CertProfileId = certProfileId.Value,
                    SigningProfileId = signingProfileId.Value,
                    RenewalOfCertificateId = cert.CertificateId,
                    EncryptedPrivateKey = originalRequest?.EncryptedPrivateKey,
                    EncryptedAesForPrivateKey = originalRequest?.EncryptedAesForPrivateKey,
                    AesKeyEncryptionIv = originalRequest?.AesKeyEncryptionIv,
                    EncryptionCertSerialNumber = originalRequest?.EncryptionCertSerialNumber
                };

                _db.CertificateRequests.Add(renewalRequest);
                await _db.SaveChangesAsync(cancellationToken);
            }

            var daysRemaining = (int)Math.Ceiling((cert.NotAfter - TimeProvider.GetUtcNow().UtcDateTime).TotalDays);

            await _audit.LogAsync(
                rekey ? "AutoRenewal.RenewedRekeyed" : "AutoRenewal.RenewedSameKey",
                actorUserId: null,
                actorUsername: "system/auto-renewal",
                targetEntityType: "Certificate",
                targetEntityId: cert.SerialNumber,
                details: new
                {
                    RenewalRequestId = renewalRequest.Id,
                    OriginalSerial = cert.SerialNumber,
                    cert.SubjectDN,
                    DaysRemaining = daysRemaining,
                    CertProfileId = certProfileId,
                    SigningProfileId = signingProfileId,
                    KeyRotated = rekey
                });

            // Determine whether to auto-issue or leave as pending for admin approval
            bool requiresApproval = await CheckProfileRequiresApprovalAsync(certProfileId.Value, cancellationToken);

            if (_config.AutoRenewal.AutoApprove && !requiresApproval)
            {
                await AutoIssueRenewalAsync(renewalRequest, cert, cancellationToken);
            }
            else
            {
                _logger.LogInformation(
                    "AutoRenewalJob: renewal request {RequestId} created for cert {Serial} — pending admin approval",
                    renewalRequest.Id, cert.SerialNumber);

                await _notifications.NotifyCertExpiringAsync(cert, daysRemaining);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "AutoRenewalJob: failed to process renewal for cert {Serial}",
                cert.SerialNumber);

            await _alerts.RaiseAlertAsync(
                "AutoRenewalFailure",
                AlertSeverity.Warning,
                $"Automatic renewal failed for certificate: Subject={cert.SubjectDN}, Serial={cert.SerialNumber}",
                new
                {
                    cert.SubjectDN,
                    cert.SerialNumber,
                    ExpiryDate = cert.NotAfter,
                    Error = ex.Message
                });

            await _audit.LogAsync(
                "AutoRenewal.Failed",
                actorUserId: null,
                actorUsername: "system/auto-renewal",
                targetEntityType: "Certificate",
                targetEntityId: cert.SerialNumber,
                success: false,
                errorMessage: ex.Message);
        }
    }

    /// <summary>
    /// Checks whether the request profile associated with the given cert profile requires
    /// manual admin approval. Returns true if any linked request profile has RequireApproval set.
    /// If no request profile references the cert profile, returns false (no approval needed).
    /// </summary>
    /// <param name="certProfileId">The certificate profile ID to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the profile requires admin approval; false otherwise.</returns>
    private async Task<bool> CheckProfileRequiresApprovalAsync(Guid certProfileId, CancellationToken cancellationToken)
    {
        // Check if any request profile that references this cert profile requires approval
        var requiresApproval = await _db.RequestProfiles
            .AsNoTracking()
            .AnyAsync(rp => rp.DefaultCertProfileId == certProfileId && rp.RequireApproval, cancellationToken);

        return requiresApproval;
    }

    /// <summary>
    /// Attempts to auto-issue a renewal certificate by invoking the issuance pipeline.
    /// If issuance succeeds, logs an audit event and sends a notification. If it fails,
    /// raises a security alert and logs the failure.
    /// </summary>
    /// <param name="renewalRequest">The newly created renewal CSR request entity.</param>
    /// <param name="originalCert">The original certificate being renewed.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task AutoIssueRenewalAsync(CertRequestEntity renewalRequest, CertificateEntity originalCert, CancellationToken cancellationToken)
    {
        try
        {
            // Named argument: the tenant validity-ceiling enforcement mode now sits ahead of the
            // token. The default — always shorten — is mandatory on this path. A renewal derives
            // its window from the certificate profile with no knowledge of the tenant, so honouring
            // a Refuse setting here would fail every renewal whose profile out-reaches its tenant,
            // silently, at 3am, for certificates that were issued perfectly happily before someone
            // changed a tenant setting.
            var issuanceResult = await _issuance.IssueCertificateAsync(renewalRequest.Id, null, null, cancellationToken: cancellationToken);
            var pem = issuanceResult.Pem;

            _logger.LogInformation(
                "AutoRenewalJob: auto-issued renewal for cert {Serial} — new request {RequestId}",
                originalCert.SerialNumber, renewalRequest.Id);

            await _audit.LogAsync(
                "AutoRenewal.Issued",
                actorUserId: null,
                actorUsername: "system/auto-renewal",
                targetEntityType: "Certificate",
                targetEntityId: originalCert.SerialNumber,
                details: new
                {
                    RenewalRequestId = renewalRequest.Id,
                    OriginalSerial = originalCert.SerialNumber,
                    originalCert.SubjectDN
                });

            await _notifications.NotifyCertIssuedAsync(
                originalCert.SubjectDN,
                originalCert.SerialNumber,
                "auto-renewal");
        }
        catch (Exception ex)
        {
            // Use a fresh DI scope + new DbContext for the failure status write. The job
            // cancellation token may already be firing — calling _db.SaveChangesAsync()
            // with no token would block on the connection until it timed out and could
            // leave the row stuck as "Pending".
            try
            {
                await using var failScope = _serviceProvider.CreateAsyncScope();
                var failDb = failScope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                var row = await failDb.CertificateRequests.FirstOrDefaultAsync(r => r.Id == renewalRequest.Id, CancellationToken.None);
                if (row != null)
                {
                    row.Status = "Failed";
                    row.RejectionReason = $"Auto-issuance failed: {ex.Message}";
                    await failDb.SaveChangesAsync(CancellationToken.None);
                }
            }
            catch (Exception failEx)
            {
                _logger.LogWarning(failEx,
                    "AutoRenewalJob: failed to mark renewal request {RequestId} as Failed after issuance error",
                    renewalRequest.Id);
            }

            _logger.LogError(ex,
                "AutoRenewalJob: auto-issue failed for renewal request {RequestId} (cert {Serial})",
                renewalRequest.Id, originalCert.SerialNumber);

            await _alerts.RaiseAlertAsync(
                "AutoRenewalIssuanceFailure",
                AlertSeverity.Warning,
                $"Auto-renewal issuance failed for certificate: Subject={originalCert.SubjectDN}, Serial={originalCert.SerialNumber}",
                new
                {
                    originalCert.SubjectDN,
                    originalCert.SerialNumber,
                    RenewalRequestId = renewalRequest.Id,
                    Error = ex.Message
                });

            await _audit.LogAsync(
                "AutoRenewal.IssuanceFailed",
                actorUserId: null,
                actorUsername: "system/auto-renewal",
                targetEntityType: "CertificateRequest",
                targetEntityId: renewalRequest.Id.ToString(),
                success: false,
                errorMessage: ex.Message);
        }
    }

    /// <summary>
    /// CLM-001: parses a key size string (e.g. "P-256", "2048") back to an integer
    /// suitable for <see cref="ICsrService.GenerateInfrastructureCsrAsync"/>.
    /// ECDSA curves are mapped: P-256→256, P-384→384, P-521→521. RSA and others
    /// are parsed as integers directly. Falls back to sensible defaults when parsing fails.
    /// </summary>
    internal static int ParseKeySizeToInt(string keyAlgorithm, string keySize)
    {
        if (string.IsNullOrWhiteSpace(keySize))
            return keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase) ? 256 : 2048;

        if (keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return keySize.ToUpperInvariant() switch
            {
                "P-256" => 256,
                "P-384" => 384,
                "P-521" => 521,
                _ => int.TryParse(keySize, out var n) ? n : 256
            };
        }

        return int.TryParse(keySize, out var size) ? size : 2048;
    }

    /// <summary>
    /// CLM-001: parses the JSON-encoded SAN list from a certificate entity into
    /// the "TYPE:value" format expected by <see cref="ICsrService.GenerateInfrastructureCsrAsync"/>.
    /// Returns null when the JSON is empty or unparseable.
    /// </summary>
    private static List<string>? ParseSansFromJson(string? sanJson)
    {
        if (string.IsNullOrWhiteSpace(sanJson))
            return null;

        try
        {
            var sans = JsonSerializer.Deserialize<List<string>>(sanJson);
            return sans is { Count: > 0 } ? sans : null;
        }
        catch
        {
            return null;
        }
    }
}
