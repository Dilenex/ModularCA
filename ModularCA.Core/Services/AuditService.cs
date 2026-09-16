using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using System.Net;

namespace ModularCA.Core.Services;

/// <summary>
/// Persists audit log entries to the audit database. Applies the central
/// <see cref="AuditJsonScrubber"/> to the serialized details and
/// honours <c>SystemConfig.Audit.FailMode</c> on write failure — <see cref="AuditFailMode.LogAndContinue"/>
/// logs and moves on, <see cref="AuditFailMode.LogAndAlert"/> additionally raises a
/// deduplicated <see cref="ISecurityAlertService"/> critical alert, and
/// <see cref="AuditFailMode.FailClosed"/> throws <see cref="AuditWriteFailedException"/>
/// so the caller can propagate a 503 back to the client.
/// </summary>
public class AuditService : IAuditService
{
    private readonly AuditDbContext? _auditDb;
    private readonly ILogger<AuditService> _logger;
    private readonly SystemConfig? _config;
    private readonly ISecurityAlertService? _alertService;

    // Dedup window for audit-failure alerts. Shared across the process so
    // a sustained outage doesn't flood the alert pipeline. Accessed under the lock below.
    private static long _lastAlertTicks;
    private static readonly object _alertLock = new();

    /// <summary>
    /// Constructs a new <see cref="AuditService"/>. <paramref name="auditDb"/>,
    /// <paramref name="config"/>, and <paramref name="alertService"/> are optional so
    /// bootstrap / test scenarios where the audit DB hasn't been provisioned yet can
    /// still resolve the service without crashing.
    /// </summary>
    private readonly AuditHashChainService? _hashChain;
    private readonly IWornBadgeProvider? _wornBadge;

    public AuditService(
        ILogger<AuditService> logger,
        AuditDbContext? auditDb = null,
        SystemConfig? config = null,
        ISecurityAlertService? alertService = null,
        AuditHashChainService? hashChain = null,
        IWornBadgeProvider? wornBadge = null)
    {
        _logger = logger;
        _auditDb = auditDb;
        _wornBadge = wornBadge;
        _config = config;
        _alertService = alertService;
        _hashChain = hashChain;
    }

    /// <summary>
    /// Persists an audit log entry. When <paramref name="certificateAuthorityId"/> is provided,
    /// the event is scoped to that CA for filtered audit queries. The <paramref name="details"/>
    /// object is serialized and scrubbed via <see cref="AuditJsonScrubber"/> before persistence.
    /// </summary>
    public async Task LogAsync(
        string actionType,
        Guid? actorUserId,
        string? actorUsername,
        string? targetEntityType = null,
        string? targetEntityId = null,
        object? details = null,
        string? sourceIp = null,
        bool success = true,
        string? errorMessage = null,
        Guid? certificateAuthorityId = null,
        Guid? tenantId = null)
    {
        if (_auditDb == null)
        {
            // ALC-08: security-critical operations must not silently degrade to no audit trail.
            // Ceremony and authentication actions throw so the caller gets a hard failure;
            // everything else logs a Warning so operators notice the missing audit DB.
            if (IsSecurityCriticalAction(actionType))
                throw new InvalidOperationException(
                    "Audit database is not configured. Security-critical operations require audit logging.");

            _logger.LogWarning("Audit database is not configured — audit entry for {ActionType} was discarded", actionType);
            return;
        }

        try
        {
            var entry = new AuditLogEntity
            {
                ActionType = actionType,
                ActorUserId = actorUserId,
                ActorUsername = actorUsername ?? (actorUserId == null ? "system" : null),
                TargetEntityType = targetEntityType,
                TargetEntityId = targetEntityId,
                // Route every details blob through the scrubber so any
                // property whose name matches password/secret/token/key/hmac/etc. is
                // replaced with "***" before it lands in AuditLogs.DetailsJson. This is
                // defence-in-depth on top of the controller-level allowlist projections
                // in AdminConfigController.
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(details),
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = errorMessage,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                // The badge the actor wore. Forgetting which hat you wear is the classic
                // failure of restricted-rights features; the trail must not share it.
                AccessBadgeId = _wornBadge?.BadgeId,
                AccessBadgeName = _wornBadge?.BadgeName,
            };

            // Compute hash chain for tamper-evident audit trail
            IDisposable? chainLock = null;
            try
            {
                if (_hashChain != null)
                {
                    chainLock = await _hashChain.AcquireAndComputeAsync(_auditDb, entry);
                }
                _auditDb.AuditLogs.Add(entry);
                await _auditDb.SaveChangesAsync();
            }
            finally
            {
                chainLock?.Dispose();
            }
        }
        catch (Exception ex)
        {
            HandleFailure(actionType, ex);
        }
    }

    /// <summary>
    /// Centralised audit-failure policy. Increments the
    /// <c>modularca_audit_writes_failed_total</c> counter, logs the exception, and then
    /// either raises a dedup'd alert or throws <see cref="AuditWriteFailedException"/>
    /// depending on <c>SystemConfig.Audit.FailMode</c>.
    /// </summary>
    private void HandleFailure(string actionType, Exception ex)
    {
        try
        {
            MetricsService.AuditWritesFailed.WithLabels(ex.GetType().Name).Inc();
        }
        catch
        {
            // Counter registration issues must never prevent the error from reaching the logger.
        }

        _logger.LogError(ex, "Failed to write audit log entry for {ActionType}", actionType);

        var mode = _config?.Audit?.FailMode ?? AuditFailMode.LogAndContinue;

        if (mode == AuditFailMode.LogAndAlert && _alertService != null)
        {
            MaybeRaiseAlert(actionType, ex);
        }
        else if (mode == AuditFailMode.FailClosed)
        {
            if (_alertService != null)
                MaybeRaiseAlert(actionType, ex);
            throw new AuditWriteFailedException(actionType, ex);
        }
    }

    /// <summary>
    /// Dedup'd alert raise. At most one alert per cooldown window
    /// (default 10 minutes) regardless of how many failures occur in the interval —
    /// sustained outages must not flood the alert pipeline.
    /// </summary>
    private void MaybeRaiseAlert(string actionType, Exception ex)
    {
        int cooldownSeconds = _config?.Audit?.FailureAlertCooldownSeconds ?? 600;
        if (cooldownSeconds < 0) cooldownSeconds = 0;
        var now = DateTime.UtcNow.Ticks;

        lock (_alertLock)
        {
            if (_lastAlertTicks != 0)
            {
                var elapsed = TimeSpan.FromTicks(now - _lastAlertTicks);
                if (elapsed.TotalSeconds < cooldownSeconds)
                    return;
            }
            _lastAlertTicks = now;
        }

        try
        {
            _ = _alertService!.RaiseAlertAsync(
                eventType: "AuditWriteFailed",
                severity: AlertSeverity.Critical,
                message: $"Audit write failed for action '{actionType}': {ex.GetType().Name}",
                details: new { ActionType = actionType, ExceptionType = ex.GetType().FullName, ex.Message });
        }
        catch (Exception alertEx)
        {
            _logger.LogError(alertEx, "Audit-failure alert dispatch itself failed");
        }
    }

    /// <summary>
    /// ALC-08: Returns true for audit action types that represent security-critical operations
    /// (key ceremonies, authentication, keystore mutations). When the audit DB is not configured,
    /// these actions must fail hard rather than silently losing the audit trail.
    /// </summary>
    private static bool IsSecurityCriticalAction(string actionType) =>
        actionType is
            // Key ceremony workflow
            AuditActionType.KeyCeremonyInitiated or
            AuditActionType.KeyCeremonyApproved or
            AuditActionType.KeyCeremonyRejected or
            AuditActionType.KeyCeremonyExecuted or
            AuditActionType.KeyCeremonyCancelled or
            AuditActionType.KeyCeremonyExpired or
            // Authentication
            AuditActionType.UserLogin or
            AuditActionType.UserLoginFailed or
            AuditActionType.UserCertLogin or
            AuditActionType.UserLogout or
            // MFA
            AuditActionType.MfaTotpVerified or
            AuditActionType.MfaTotpFailed or
            AuditActionType.MfaWebAuthnVerified or
            AuditActionType.MfaWebAuthnFailed or
            AuditActionType.MfaMtlsVerified or
            AuditActionType.MfaTokenInvalid or
            AuditActionType.MfaStepUpVerified or
            AuditActionType.MfaStepUpFailed or
            AuditActionType.MfaTotpSetup or
            AuditActionType.MfaTotpRemoved or
            AuditActionType.MfaWebAuthnRemoved or
            AuditActionType.MfaMtlsRemoved or
            // Keystore mutations
            AuditActionType.KeystoreInitialized or
            AuditActionType.KeystoreUnlocked or
            AuditActionType.KeystoreKeyAdded or
            AuditActionType.KeystoreKeyRemoved or
            AuditActionType.KeystoreKeyReplaced or
            AuditActionType.KeystoreBackupCreated or
            AuditActionType.KeystoreBackfillRun or
            // Backup / restore
            AuditActionType.BackupCreated or
            AuditActionType.BackupRestored or
            // Privileged access
            AuditActionType.SystemAdminElevatedAccess;

    private static string? NormalizeIp(string? ip)
    {
        if (ip == null) return null;
        // Strip IPv4-mapped IPv6 prefix (::ffff:10.1.2.3 → 10.1.2.3)
        if (IPAddress.TryParse(ip, out var addr) && addr.IsIPv4MappedToIPv6)
            return addr.MapToIPv4().ToString();
        return ip;
    }
}
