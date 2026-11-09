using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that tells administrators, by e-mail and security alert, about non-revoked,
/// non-CA certificates in their expiry warning: once when the soft warning starts, once at each
/// reminder (<c>CertExpiryNotification.WarningDaysBeforeExpiry</c>) that falls inside the
/// warning, and once when the alert starts. Retired certificates, those whose expiry warning
/// was dismissed and those already replaced (renewed or reissued) are left out, as are those
/// whose profile never warns.
/// <para>
/// Each step is sent at most once per certificate. It is logged in the <c>NotificationLog</c>
/// table, keyed by the certificate id and its <c>NotAfter</c> date, whose unique composite index
/// on <c>(EventType, TargetEntityId, NotificationDate)</c> makes two racing instances fail on
/// the insert rather than both send. Before 0.4.3 each threshold was keyed by the day it ran, so
/// a certificate inside a threshold was mailed again every day.
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
    /// Executes the certificate expiry notification check (<see cref="ProcessCertificatesAsync"/>),
    /// then sends the SSH CA key review reminders (<see cref="ProcessSshCaKeyReviewsAsync"/>).
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

        await ProcessCertificatesAsync(cancellationToken);

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

    /// <summary>Notification log event of the soft warning starting.</summary>
    public const string WarningEvent = "CertExpiryWarning";

    /// <summary>Notification log event of the alert starting.</summary>
    public const string AlertEvent = "CertExpiryAlert";

    /// <summary>Notification log event of the reminder <paramref name="days"/> days before expiry.</summary>
    public static string ReminderEvent(int days) => $"CertExpiryReminder_{days}d";

    /// <summary>One step of a certificate's expiry warning: its log event, its notification stage and when it falls.</summary>
    private sealed record Step(string EventType, string Stage, DateTime At, int Order);

    /// <summary>
    /// The steps of <paramref name="cert"/>'s expiry warning in the order they fall: the soft
    /// warning, each reminder of <paramref name="reminderDays"/> that falls after it, then the alert.
    /// </summary>
    private static List<Step> StepsOf(CertificateEntity cert, IReadOnlyCollection<int> reminderDays)
    {
        var steps = new List<Step> { new(WarningEvent, CertExpiryStage.Warning, cert.ExpiryWarningAt, 0) };
        foreach (var days in reminderDays)
        {
            var at = cert.NotAfter.AddDays(-days);
            if (at > cert.ExpiryWarningAt)
                steps.Add(new Step(ReminderEvent(days), CertExpiryStage.Reminder, at, 1));
        }
        steps.Add(new Step(AlertEvent, CertExpiryStage.Alert, cert.ExpiryAlertAt, 2));
        return steps.OrderBy(s => s.At).ThenBy(s => s.Order).ToList();
    }

    /// <summary>
    /// Sends one notification for each certificate in its expiry warning
    /// (<see cref="CertificateExpiry.InWarning"/>; not a CA certificate, not retired, warning not
    /// dismissed, not replaced by <see cref="CertificateExpiry.ReplacedAsync"/>, the lifecycle
    /// summary's rule) whose latest step due is not yet logged: the soft warning, a reminder or the
    /// alert. Every step due is logged with it, so a certificate first seen past several steps
    /// gets one message, for the latest, and none is sent twice. A step's log row is keyed by the
    /// certificate id and its <c>NotAfter</c> date, so a run on another day finds it. A replaced
    /// certificate gets no mail and no security alert, and nothing is logged for it.
    /// </summary>
    /// <returns>How many notifications were sent.</returns>
    internal async Task<int> ProcessCertificatesAsync(CancellationToken cancellationToken)
    {
        var queryNow = TimeProvider.GetUtcNow().UtcDateTime;
        var reminderDays = (_config.CertExpiryNotification.WarningDaysBeforeExpiry ?? [])
            .Where(d => d > 0).Distinct().ToList();

        var inWarning = _db.Certificates
            .AsNoTracking()
            .Where(CertificateExpiry.InWarning(queryNow))
            .Where(c => !c.IsCA && c.RetiredAt == null && c.ExpiryWarningDismissedAt == null);
        var due = await inWarning.OrderBy(c => c.NotAfter).ToListAsync(cancellationToken);
        if (due.Count == 0)
            return 0;

        var replaced = await CertificateExpiry.ReplacedAsync(_db, inWarning, queryNow, ct: cancellationToken);
        var replacedCount = due.RemoveAll(c => replaced.Contains(c.CertificateId));
        if (due.Count == 0)
        {
            _logger.LogInformation("Certificate expiry notifications: {Replaced} in their warning, all replaced", replacedCount);
            return 0;
        }

        var targets = due.Select(c => c.CertificateId.ToString()).ToList();
        var logged = (await _db.NotificationLogs.AsNoTracking()
                .Where(n => targets.Contains(n.TargetEntityId) && n.EventType.StartsWith("CertExpiry"))
                .Select(n => new { n.EventType, n.TargetEntityId })
                .ToListAsync(cancellationToken))
            .Select(n => (n.EventType, n.TargetEntityId))
            .ToHashSet();

        int sent = 0, skipped = 0;
        foreach (var cert in due)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var now = TimeProvider.GetUtcNow().UtcDateTime;
            var target = cert.CertificateId.ToString();
            var reached = StepsOf(cert, reminderDays).Where(s => s.At <= now).ToList();
            if (reached.Count == 0 || logged.Contains((reached[^1].EventType, target)))
            {
                skipped++;
                continue;
            }

            var key = DateTime.SpecifyKind(cert.NotAfter.Date, DateTimeKind.Utc);
            var rows = reached
                .Where(s => !logged.Contains((s.EventType, target)))
                .Select(s => new NotificationLogEntity { EventType = s.EventType, TargetEntityId = target, NotificationDate = key, CreatedAtUtc = now })
                .ToList();
            _db.NotificationLogs.AddRange(rows);
            try
            {
                await _db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
            {
                // Another instance logged a step of this certificate first and sends it. Other
                // DbUpdateException variants propagate so the runner marks the tick failed.
                foreach (var row in rows)
                    _db.Entry(row).State = EntityState.Detached;
                skipped++;
                continue;
            }

            var step = reached[^1];
            var daysRemaining = (int)Math.Ceiling((cert.NotAfter - now).TotalDays);
            try
            {
                await _notifications.NotifyCertExpiryStageAsync(cert, step.Stage, now);

                var alert = step.Stage == CertExpiryStage.Alert;
                await _alerts.RaiseAlertAsync(
                    "CertificateExpiring",
                    alert ? AlertSeverity.Critical : AlertSeverity.Warning,
                    $"Certificate expiry {(alert ? "alert" : step.Stage == CertExpiryStage.Reminder ? "reminder" : "warning")}: expires in "
                        + $"{CertExpiryStage.TimeLeft(cert.NotAfter - now)}: Subject={cert.SubjectDN}, Serial={cert.SerialNumber}, "
                        + $"Issuer={cert.Issuer}, Expires={cert.NotAfter:yyyy-MM-dd HH:mm} UTC",
                    new
                    {
                        cert.SubjectDN,
                        cert.SerialNumber,
                        IssuingCA = cert.Issuer,
                        ExpiryDate = cert.NotAfter,
                        DaysRemaining = daysRemaining,
                        step.Stage,
                    });
                sent++;
            }
            catch (Exception ex)
            {
                // The step is logged, so it is not retried: a dependency that keeps failing must
                // not turn into a flood once it recovers.
                _logger.LogWarning(ex, "Failed to send the expiry {Stage} notification for cert {Serial}", step.Stage, cert.SerialNumber);
            }
        }

        _logger.LogInformation("Certificate expiry notifications: {Due} in their warning and not replaced, sent {Sent}, nothing new for {Skipped}, {Replaced} replaced",
            due.Count, sent, skipped, replacedCount);
        return sent;
    }

}
