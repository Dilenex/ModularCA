using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using System.Security.Cryptography;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that creates a new backup archive on the configured cron schedule.
/// Mirrors the manual <c>POST /api/v1/admin/backup</c> endpoint: writes a timestamped
/// archive to <see cref="BackupConfig.OutputPath"/>, enforces
/// <see cref="BackupConfig.RetentionCount"/> (respecting
/// <see cref="BackupConfig.MinimumRetentionDays"/> as a hard floor), and logs an audit
/// entry on success or failure. Gated on <see cref="BackupConfig.CreateOnSchedule"/> so
/// operators can disable automated creation without clearing the cron expression (the
/// same cron still drives <see cref="BackupVerificationJob"/>). Also gated on the
/// <see cref="BackupConfig.Enabled"/> master flag (Audit Item #11): when that flag is
/// <c>false</c> the job exits before doing any work — the setup wizard's
/// "Enable scheduled backups" checkbox flows through to that flag, so unchecking it
/// genuinely stops backups instead of silently leaving them on.
/// </summary>
/// <remarks>
/// <para>
/// Before this job existed, <see cref="BackupConfig.Schedule"/> only drove verification —
/// the setup wizard's cron field collected an expectation of "automatic backup" that the
/// runtime did not honour. Operators who set <c>0 2 * * *</c> during setup discovered
/// the next morning that no archive had been written. This job closes that gap.
/// </para>
/// <para>
/// The job runs before <see cref="BackupVerificationJob"/> in the scheduler poll cycle,
/// so a brand-new archive created at 02:00 UTC is available to the verifier when it
/// fires in the same cycle. Each job gates independently on its own <c>*OnSchedule</c>
/// flag, so the two can be enabled or disabled separately.
/// </para>
/// <para>
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math against
/// <see cref="BackupConfig.Schedule"/>, missed-run policy, timeout enforcement, metrics,
/// and <c>SchedulerJobStates</c> persistence — the body below is purely the per-tick
/// archive-creation work. The <c>RunAsync(ct)</c> entry point is retained as the
/// operator-facing manual-run path: <c>SchedulerJobRegistry.RunNowAsync</c> calls it
/// directly when an operator clicks "Run Now" in the admin Schedules page — bypassing
/// the cron past-due gate that <see cref="SingletonCronJob.TickAsync"/> evaluates so the
/// work fires immediately regardless of schedule.
/// </para>
/// </remarks>
public class BackupCreationJob : SingletonCronJob
{
    private readonly SystemConfig _config;
    private readonly IAuditService _audit;
    private readonly ISecurityAlertService _alerts;
    private readonly IBackupArchiver _archiver;
    private readonly ILogger<BackupCreationJob> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="BackupCreationJob"/> class.
    /// </summary>
    public BackupCreationJob(
        IServiceProvider serviceProvider,
        SystemConfig config,
        IAuditService audit,
        ISecurityAlertService alerts,
        IBackupArchiver archiver,
        ILogger<BackupCreationJob> logger,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _config = config;
        _audit = audit;
        _alerts = alerts;
        _archiver = archiver;
        _logger = logger;
    }

    /// <inheritdoc />
    public override string Name => "BackupCreation";

    /// <summary>
    /// Cron expression for the scheduled backup creation. Returns <see cref="string.Empty"/>
    /// when either the master <see cref="BackupConfig.Enabled"/> flag or the per-cadence
    /// <see cref="BackupConfig.CreateOnSchedule"/> flag is <c>false</c>, which the base
    /// <see cref="SingletonCronJob.TickAsync"/> treats as "skip without state write" so a
    /// disabled job doesn't churn <c>SchedulerJobStates</c> rows.
    /// </summary>
    protected override string CronExpression =>
        (_config.Backup.Enabled && _config.Backup.CreateOnSchedule)
            ? _config.Backup.Schedule
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
    /// Creates a new backup archive using <see cref="BackupRestore.Backup(string?)"/> and
    /// enforces retention. Failures raise a <c>BackupFailed</c> critical alert so operators
    /// notice even if they don't watch logs. Returns without writing when
    /// <see cref="BackupConfig.Enabled"/> (master gate, Audit Item #11) or
    /// <see cref="BackupConfig.CreateOnSchedule"/> (per-cadence flag) is <c>false</c>.
    /// The master flag is checked first so the verbose "creating archive" log line never
    /// fires on a deployment where the operator has explicitly disabled scheduled backups.
    /// </summary>
    /// <param name="cancellationToken">Token to signal cancellation.</param>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        // CronExpression already short-circuits when either gate is false. The checks
        // here are defense-in-depth for the manual-run RunAsync path which bypasses
        // the cron evaluation in the base class.
        //
        // Audit Item #11: master gate. Operators who unchecked "Enable scheduled
        // backups" in the setup wizard (or flipped Backup.Enabled later) get a true
        // no-op here — no directory creation, no audit row, no alert traffic.
        if (!_config.Backup.Enabled)
        {
            _logger.LogDebug("Scheduled backup: skipped — Backup.Enabled master flag is false");
            return;
        }

        if (!_config.Backup.CreateOnSchedule)
            return;

        var backupDir = ResolveBackupDirectory();
        try
        {
            Directory.CreateDirectory(backupDir);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scheduled backup: failed to create backup directory {BackupDir}", backupDir);
            await _alerts.RaiseAlertAsync(
                "BackupFailed",
                AlertSeverity.Critical,
                $"Scheduled backup directory could not be created: {backupDir}",
                new { BackupDirectory = backupDir, Error = ex.Message });
            return;
        }

        // Random suffix so directory enumeration can't guess filenames.
        var timestamp = TimeProvider.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmmss");
        var suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var fileName = $"modularca-backup-{timestamp}-{suffix}.zip";
        var outputPath = Path.Combine(backupDir, fileName);

        _logger.LogInformation("Scheduled backup: creating archive {FileName} in {BackupDir}", fileName, backupDir);

        int exitCode;
        try
        {
            exitCode = await _archiver.CreateArchiveAsync(outputPath, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scheduled backup: archive creation threw");
            await _alerts.RaiseAlertAsync(
                "BackupFailed",
                AlertSeverity.Critical,
                $"Scheduled backup threw an exception: {ex.Message}",
                new { FileName = fileName, OutputPath = outputPath, Error = ex.Message });
            await _audit.LogAsync(
                AuditActionType.BackupCreated,
                actorUserId: null,
                actorUsername: SchedulerService.AuditActor,
                targetEntityType: "Backup",
                targetEntityId: fileName,
                success: false,
                errorMessage: ex.Message);
            return;
        }

        if (exitCode != 0)
        {
            _logger.LogError("Scheduled backup: archive creation returned non-zero exit code {ExitCode}", exitCode);
            await _alerts.RaiseAlertAsync(
                "BackupFailed",
                AlertSeverity.Critical,
                $"Scheduled backup failed with exit code {exitCode}.",
                new { FileName = fileName, OutputPath = outputPath, ExitCode = exitCode });
            await _audit.LogAsync(
                AuditActionType.BackupCreated,
                actorUserId: null,
                actorUsername: SchedulerService.AuditActor,
                targetEntityType: "Backup",
                targetEntityId: fileName,
                success: false,
                errorMessage: $"Backup failed with exit code {exitCode}");
            return;
        }

        EnforceRetention(backupDir);

        _logger.LogInformation("Scheduled backup: archive {FileName} created successfully", fileName);

        await _audit.LogAsync(
            AuditActionType.BackupCreated,
            actorUserId: null,
            actorUsername: SchedulerService.AuditActor,
            targetEntityType: "Backup",
            targetEntityId: fileName,
            details: new { outputPath, trigger = "scheduler" });
    }

    private string ResolveBackupDirectory()
    {
        var outputPath = _config.Backup.OutputPath;
        if (Path.IsPathRooted(outputPath))
            return outputPath;
        return Path.Combine(AppContext.BaseDirectory, outputPath);
    }

    /// <summary>
    /// Deletes oldest archives beyond <see cref="BackupConfig.RetentionCount"/>, honouring
    /// <see cref="BackupConfig.MinimumRetentionDays"/> as a hard floor. Mirrors
    /// <c>AdminBackupController.EnforceRetention</c> so scheduled and manual backups apply
    /// the same retention rules.
    /// </summary>
    private void EnforceRetention(string backupDir)
    {
        var retentionCount = _config.Backup.RetentionCount;
        if (retentionCount <= 0) return;

        var retentionDirInfo = new DirectoryInfo(backupDir);
        var files = retentionDirInfo.GetFiles("modularca-backup-*.zip")
            .Concat(retentionDirInfo.GetFiles("modularca-backup-*.enc"))
            .OrderByDescending(f => f.CreationTimeUtc)
            .ToList();

        var minDays = Math.Max(0, _config.Backup.MinimumRetentionDays);
        var floor = TimeProvider.GetUtcNow().UtcDateTime.AddDays(-minDays);

        foreach (var file in files.Skip(retentionCount))
        {
            if (minDays > 0 && file.CreationTimeUtc > floor)
            {
                _logger.LogInformation(
                    "Scheduled backup retention: skipping delete of {FileName} — younger than MinimumRetentionDays={MinDays} floor",
                    file.Name, minDays);
                continue;
            }
            try
            {
                file.Delete();
                _logger.LogWarning(
                    "Scheduled backup retention: deleted {FileName} (retentionCount={Count})",
                    file.Name, retentionCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Scheduled backup retention: failed to delete {FileName}", file.Name);
            }
        }
    }
}
