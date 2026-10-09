using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that checks for non-revoked, non-CA certificates approaching expiration
/// and sends grouped notifications to administrators via email and security alerts.
/// <para>
/// De-dup is backed by the <c>NotificationLog</c> table with a unique composite index on
/// <c>(EventType, TargetEntityId, NotificationDate)</c>. Duplicate inserts fail atomically
/// at the DB level so two racing instances cannot both send the same email.
/// </para>
/// <para>
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math
/// against <c>CertExpiryNotification.Schedule</c>, missed-run policy, timeout enforcement,
/// metrics, and <c>SchedulerJobStates</c> persistence — the body below is purely
/// the per-tick expiry-scan work. The <c>RunAsync(ct)</c> entry point is retained as
/// the operator-facing manual-run path: <c>SchedulerJobRegistry.RunNowAsync</c> calls
/// it directly when an operator clicks "Run Now" in the admin Schedules page — bypassing
/// the cron past-due gate that <see cref="SingletonCronJob.TickAsync"/> evaluates so the
/// work fires immediately regardless of schedule.
/// </para>
/// <para>
/// The same run reminds administrators of SSH CA keys due for review. An SSH CA key has no
/// expiry; its review date is advisory, and the reminder is all this job does about it.
/// </para>
/// </summary>
public class CertExpiryNotificationJob : SingletonCronJob
{
    private readonly ModularCADbContext _db;
    private readonly INotificationService _notifications;
    private readonly ISecurityAlertService _alerts;
    private readonly SystemConfig _config;
    private readonly ILogger<CertExpiryNotificationJob> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertExpiryNotificationJob"/> class.
    /// </summary>
    public CertExpiryNotificationJob(
        IServiceProvider serviceProvider,
        ModularCADbContext db,
        INotificationService notifications,
        ISecurityAlertService alerts,
        SystemConfig config,
        ILogger<CertExpiryNotificationJob> logger,
        SchedulerJobRunner runner,
        TimeProvider? timeProvider = null)
        : base(serviceProvider, logger, config, runner, timeProvider)
    {
        _db = db;
        _notifications = notifications;
        _alerts = alerts;
        _config = config;
        _logger = logger;
    }

    /// <inheritdoc />
    public override string Name => "CertExpiryNotification";

    /// <summary>
    /// Cron expression for the expiry-notification scan. Returns <see cref="string.Empty"/>
    /// when the feature is disabled, which the base <see cref="SingletonCronJob.TickAsync"/>
    /// treats as "skip without state write".
    /// </summary>
    protected override string CronExpression =>
        _config.CertExpiryNotification.Enabled
            ? _config.CertExpiryNotification.Schedule
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
    /// Executes the certificate expiry notification check. For each configured warning
    /// threshold, queries non-revoked, non-CA certificates expiring within that window
    /// and sends grouped notifications. Already-expired certificates are excluded.
    /// Duplicate alerts for the same cert on the same calendar day are suppressed via
    /// <c>NotificationLogEntity</c>'s unique index. The same run then sends the SSH CA key
    /// review reminders (<see cref="ProcessSshCaKeyReviewsAsync"/>), whether or not any
    /// certificate threshold is configured.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        // CronExpression already short-circuits when expiry-notifications are disabled.
        // The check here is defense-in-depth for the manual-run RunAsync path which
        // bypasses the cron evaluation in the base class.
        if (!_config.CertExpiryNotification.Enabled)
            return;

        if (!_config.Email.Enabled)
            return;

        // Expiry scans may pull large cert sets — bump the command
        // timeout to 5 minutes for this run so the scheduler job never throws on 30s.
        _db.Database.SetCommandTimeout(TimeSpan.FromMinutes(5));

        var thresholds = _config.CertExpiryNotification.WarningDaysBeforeExpiry ?? [];

        // Sort descending so we process the largest window first
        var sortedThresholds = thresholds.OrderByDescending(d => d).ToList();

        foreach (var days in sortedThresholds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ProcessThresholdAsync(days, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await ProcessSshCaKeyReviewsAsync(cancellationToken);
    }

    /// <summary>The event type of the SSH CA key review reminder, in the notification log and to webhooks.</summary>
    public const string SshCaKeyReviewDueEvent = "SshCaKeyReviewDue";

    /// <summary>
    /// Tells administrators once about each enabled SSH CA key whose advisory review date is
    /// within <see cref="SshCaKeyDefaults.ReviewWarningDays"/> days or has passed. One message
    /// per key and review date: the <c>NotificationLog</c> row is keyed by the review date, so
    /// moving the date allows the next reminder. It reads the key rows and writes only that log.
    /// No key is disabled and nothing is refused or revoked.
    /// </summary>
    /// <returns>How many reminders were sent.</returns>
    internal async Task<int> ProcessSshCaKeyReviewsAsync(CancellationToken cancellationToken)
    {
        var now = TimeProvider.GetUtcNow().UtcDateTime;
        var horizon = now.AddDays(SshCaKeyDefaults.ReviewWarningDays);
        var due = await _db.SshCaKeys.AsNoTracking()
            .Where(k => k.IsEnabled && k.ReviewBy != null && k.ReviewBy <= horizon)
            .OrderBy(k => k.Name)
            .Select(k => new { k.Id, k.Name, k.IsUserCa, k.IsHostCa, ReviewBy = k.ReviewBy!.Value })
            .ToListAsync(cancellationToken);

        var sent = 0;
        foreach (var key in due)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var target = key.Id.ToString();
            var reviewDay = DateTime.SpecifyKind(key.ReviewBy.Date, DateTimeKind.Utc);
            if (await _db.NotificationLogs.AsNoTracking().AnyAsync(
                    n => n.EventType == SshCaKeyReviewDueEvent && n.TargetEntityId == target && n.NotificationDate == reviewDay, cancellationToken))
                continue;

            var logRow = new NotificationLogEntity
            {
                EventType = SshCaKeyReviewDueEvent,
                TargetEntityId = target,
                NotificationDate = reviewDay,
                CreatedAtUtc = now
            };
            _db.NotificationLogs.Add(logRow);
            try
            {
                await _db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
            {
                _db.Entry(logRow).State = EntityState.Detached;
                continue;
            }

            var signs = key.IsUserCa && key.IsHostCa ? "user and host" : key.IsHostCa ? "host" : "user";
            var when = key.ReviewBy <= now ? "was due for review on" : "is due for review on";
            try
            {
                await _notifications.NotifyAsync(SshCaKeyReviewDueEvent,
                    $"The SSH CA key '{key.Name}' ({signs} certificates) {when} {key.ReviewBy:yyyy-MM-dd} UTC.\n\n"
                    + "This is a reminder only. The key keeps signing, its certificates stay valid and its revocation list is still served.\n\n"
                    + "Decide whether the key should still be in use, then move the review date on the key's page in the console (Authorities, the SSH tab, the key, Review by).");
                sent++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send the review reminder for SSH CA key {KeyId}", key.Id);
            }
        }

        if (sent > 0)
            _logger.LogInformation("Sent {Count} SSH CA key review reminder(s)", sent);
        return sent;
    }

    /// <summary>
    /// Processes a single day-threshold bracket. Per-certificate de-dup is atomic via
    /// the <c>NotificationLog</c> unique index.
    /// </summary>
    internal async Task ProcessThresholdAsync(int days, CancellationToken cancellationToken)
    {
        var queryNow = TimeProvider.GetUtcNow().UtcDateTime;
        var targetDate = queryNow.AddDays(days);

        // Find non-revoked, non-CA certs that expire within this window but haven't expired yet
        var expiringCerts = await _db.Certificates
            .AsNoTracking()
            .Where(c => !c.Revoked
                         && !c.IsCA
                         && c.NotAfter <= targetDate
                         && c.NotAfter > queryNow)
            .ToListAsync(cancellationToken);

        if (expiringCerts.Count == 0)
            return;

        var eventType = $"CertExpiring_{days}d";

        _logger.LogInformation(
            "Checking expiry notifications for {Count} certificate(s) within {Days} days",
            expiringCerts.Count, days);

        int sent = 0;
        int skipped = 0;
        foreach (var cert in expiringCerts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Recompute now/today PER CERT so a long scan that crosses midnight UTC writes
            // the correct calendar key into NotificationLog.NotificationDate. Without this,
            // certs processed after midnight would dedup against yesterday's date and skip
            // sending today's notification (or vice versa).
            var now = TimeProvider.GetUtcNow().UtcDateTime;
            var today = now.Date;

            // Try to insert a NotificationLog row first. If the unique composite index
            // rejects it, we've already notified today for this (cert, event) pair —
            // skip sending.
            var logRow = new NotificationLogEntity
            {
                EventType = eventType,
                TargetEntityId = cert.SerialNumber,
                NotificationDate = today,
                CreatedAtUtc = now
            };
            _db.NotificationLogs.Add(logRow);
            try
            {
                await _db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
            {
                // MySQL ER_DUP_ENTRY (1062) on the (EventType, TargetEntityId, NotificationDate)
                // unique index — another instance or prior run already sent this notification
                // today. Detach and skip. Other DbUpdateException variants (transient connection
                // drops, schema mismatches, foreign-key violations) propagate so the runner
                // can mark the tick as failed and escalate consecutive failures.
                _db.Entry(logRow).State = EntityState.Detached;
                skipped++;
                continue;
            }

            var daysRemaining = (int)Math.Ceiling((cert.NotAfter - now).TotalDays);
            var issuingCaName = cert.Issuer;

            try
            {
                await _notifications.NotifyCertExpiringAsync(cert, daysRemaining);

                var alertMessage = $"Certificate expiring in {daysRemaining} day(s): " +
                                   $"Subject={cert.SubjectDN}, Serial={cert.SerialNumber}, " +
                                   $"Issuer={issuingCaName}, Expires={cert.NotAfter:yyyy-MM-dd HH:mm} UTC";

                await _alerts.RaiseAlertAsync(
                    "CertificateExpiring",
                    AlertSeverity.Warning,
                    alertMessage,
                    new
                    {
                        cert.SubjectDN,
                        cert.SerialNumber,
                        IssuingCA = issuingCaName,
                        ExpiryDate = cert.NotAfter,
                        DaysRemaining = daysRemaining
                    });
                sent++;
            }
            catch (Exception ex)
            {
                // Don't let a single-cert notify failure mask the rest of the batch.
                // The log row is already committed so we won't retry today — this is
                // intentional to avoid flooding on a persistently failing dependency.
                _logger.LogWarning(ex,
                    "Failed to send expiry notification for cert {Serial} at {Days}d threshold",
                    cert.SerialNumber, days);
            }
        }

        _logger.LogInformation(
            "{Days}-day expiry notification bracket: sent {Sent}, skipped {Skipped}",
            days, sent, skipped);
    }

}
