using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services;

/// <summary>
/// Default <see cref="ISchedulerJobRegistry"/> implementation. Holds a hardcoded
/// dispatch table mapping each system job name to:
/// <list type="bullet">
///   <item><description>The <c>SystemConfig</c> path that owns its cron expression (or null when the job is continuous / not cron-driven).</description></item>
///   <item><description>The optional <c>SystemConfig</c>-backed enabled-flag accessor.</description></item>
///   <item><description>The fire-and-forget invocation closure that resolves the job from a fresh DI scope and calls its run method.</description></item>
/// </list>
/// <para>
/// Registered as a singleton because the dispatch table is immutable and the
/// closures only capture the <see cref="IServiceProvider"/> root — every actual
/// invocation creates its own scope.
/// </para>
/// <para>
/// Every singleton job in the dispatch table is an <see cref="ISchedulerJob"/>
/// inheritor (via <c>SingletonCronJob</c> or <c>PerRowScheduledJob&lt;TRow&gt;</c>)
/// and is also dispatched by <c>SchedulerService.PollCycleAsync</c> through
/// <c>IServiceProvider.GetServices&lt;ISchedulerJob&gt;()</c>. The registry is
/// retained because it owns the per-job <c>SystemConfig</c> metadata (cron path
/// + enabled flag) that the unified Schedules admin page edits, and because its
/// closure-based <c>RunNowAsync</c> preserves the operator-facing "Run Now"
/// semantic of "fire the work immediately, regardless of cron past-due gating"
/// that a <c>TickAsync</c>-based dispatch would not satisfy.
/// </para>
/// </summary>
public sealed class SchedulerJobRegistry : ISchedulerJobRegistry
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SchedulerJobRegistry> _logger;
    private readonly SystemConfig _config;
    private readonly IReadOnlyDictionary<string, JobEntry> _entries;
    private readonly IReadOnlyList<string> _jobNames;

    /// <summary>
    /// Initializes the registry. The dispatch table is built once at construction.
    /// </summary>
    public SchedulerJobRegistry(
        IServiceProvider serviceProvider,
        ILogger<SchedulerJobRegistry> logger,
        SystemConfig config)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _config = config;

        var entries = new Dictionary<string, JobEntry>(StringComparer.OrdinalIgnoreCase)
        {
            // ---- BackupCreation: Backup.Schedule + Backup.CreateOnSchedule -----------------
            // Audit Item #11: the isEnabled predicate ANDs with the master Backup.Enabled
            // gate so an operator who unchecked "Enable scheduled backups" in the setup
            // wizard sees this job reported as disabled here too. setEnabled writes to BOTH
            // the master and the per-cadence flag so the Schedules admin page stays in
            // sync with the wizard checkbox — flipping one row turns the master back on
            // (or leaves it off when toggling off matches the master's existing state).
            ["BackupCreation"] = new JobEntry(
                getCron: cfg => cfg.Backup.Schedule,
                setCron: (cfg, value) => cfg.Backup.Schedule = value,
                isEnabled: cfg => cfg.Backup.Enabled && cfg.Backup.CreateOnSchedule,
                setEnabled: (cfg, v) =>
                {
                    cfg.Backup.Enabled = v;
                    cfg.Backup.CreateOnSchedule = v;
                },
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<BackupCreationJob>();
                    return job.RunAsync(ct);
                }),

            // ---- BackupVerification: Backup.Schedule + Backup.VerifyOnSchedule -------------
            // Shares the cron with BackupCreation by design — operators set one schedule and
            // both create+verify fire in the same poll cycle. Editing this job's cron also
            // moves BackupCreation; the controller surfaces both rows pointing at the same
            // value so the UI shows that intent clearly. Audit Item #11: also AND-gated on
            // Backup.Enabled so the master switch silences both jobs together.
            ["BackupVerification"] = new JobEntry(
                getCron: cfg => cfg.Backup.Schedule,
                setCron: (cfg, value) => cfg.Backup.Schedule = value,
                isEnabled: cfg => cfg.Backup.Enabled && cfg.Backup.VerifyOnSchedule,
                setEnabled: (cfg, v) =>
                {
                    cfg.Backup.Enabled = v;
                    cfg.Backup.VerifyOnSchedule = v;
                },
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<BackupVerificationJob>();
                    return job.RunAsync(ct);
                }),

            // ---- AuditRetention: Audit.Retention.Schedule + Audit.Retention.Enabled --------
            ["AuditRetention"] = new JobEntry(
                getCron: cfg => cfg.Audit.Retention.Schedule,
                setCron: (cfg, value) => cfg.Audit.Retention.Schedule = value,
                isEnabled: cfg => cfg.Audit.Retention.Enabled,
                setEnabled: (cfg, v) => cfg.Audit.Retention.Enabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<AuditRetentionJob>();
                    return job.RunAsync(ct);
                }),

            // ---- AutoRenewal: AutoRenewal.Schedule + AutoRenewal.Enabled -------------------
            ["AutoRenewal"] = new JobEntry(
                getCron: cfg => cfg.AutoRenewal.Schedule,
                setCron: (cfg, value) => cfg.AutoRenewal.Schedule = value,
                isEnabled: cfg => cfg.AutoRenewal.Enabled,
                setEnabled: (cfg, v) => cfg.AutoRenewal.Enabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<AutoRenewalJob>();
                    return job.RunAsync(ct);
                }),

            // ---- Compliance (certificate compliance scan): ComplianceScan.Schedule + .Enabled ----------
            ["Compliance"] = new JobEntry(
                getCron: cfg => cfg.ComplianceScan.Schedule,
                setCron: (cfg, value) => cfg.ComplianceScan.Schedule = value,
                isEnabled: cfg => cfg.ComplianceScan.Enabled,
                setEnabled: (cfg, v) => cfg.ComplianceScan.Enabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<ComplianceScanJob>();
                    return job.RunAsync(ct);
                }),

            // ---- CertExpiryNotification: CertExpiryNotification.Schedule + .Enabled --------
            ["CertExpiryNotification"] = new JobEntry(
                getCron: cfg => cfg.CertExpiryNotification.Schedule,
                setCron: (cfg, value) => cfg.CertExpiryNotification.Schedule = value,
                isEnabled: cfg => cfg.CertExpiryNotification.Enabled,
                setEnabled: (cfg, v) => cfg.CertExpiryNotification.Enabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<CertExpiryNotificationJob>();
                    return job.RunAsync(ct);
                }),

            // ---- CertExpire: CertPolicy.ExpireCheckSchedule + CertPolicy.Enabled -----------
            ["CertExpire"] = new JobEntry(
                getCron: cfg => cfg.CertPolicy.ExpireCheckSchedule,
                setCron: (cfg, value) => cfg.CertPolicy.ExpireCheckSchedule = value,
                isEnabled: cfg => cfg.CertPolicy.Enabled,
                setEnabled: (cfg, v) => cfg.CertPolicy.Enabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<CertExpireJob>();
                    return job.RunAsync(ct);
                }),

            // ---- AcmeCleanup: Acme.CleanupSchedule (no master Enabled gate) ----------------
            // Runs on cron, idempotent so always safe to fire. Surfaced in the admin UI so
            // operators can edit the cadence and trigger manual runs.
            ["AcmeCleanup"] = new JobEntry(
                getCron: cfg => cfg.Acme.CleanupSchedule,
                setCron: (cfg, value) => cfg.Acme.CleanupSchedule = value,
                isEnabled: _ => true,
                setEnabled: null,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<AcmeCleanupJob>();
                    return job.RunAsync(ct);
                }),

            // ---- ProtocolCleanup: ProtocolCleanup.Schedule (no master Enabled gate) ---------
            // Orphaned enrollment request rows from every protocol, plus the SCEP/CMP
            // transaction sweeps. Idempotent, so always safe to fire.
            ["ProtocolCleanup"] = new JobEntry(
                getCron: cfg => cfg.ProtocolCleanup.Schedule,
                setCron: (cfg, value) => cfg.ProtocolCleanup.Schedule = value,
                isEnabled: _ => true,
                setEnabled: null,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<ProtocolCleanupJob>();
                    return job.RunAsync(ct);
                }),

            // ---- LdapGroupSync: LdapAuth.GroupSyncSchedule + LdapAuth.GroupSyncEnabled ------
            ["LdapGroupSync"] = new JobEntry(
                getCron: cfg => cfg.LdapAuth.GroupSyncSchedule,
                setCron: (cfg, value) => cfg.LdapAuth.GroupSyncSchedule = value,
                isEnabled: cfg => cfg.LdapAuth.GroupSyncEnabled,
                setEnabled: (cfg, v) => cfg.LdapAuth.GroupSyncEnabled = v,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<LdapGroupSyncJob>();
                    return job.RunAsync(ct);
                }),

            // ---- TlsRenewal: Https.RenewalCheckSchedule (no master Enabled gate) -----------
            // Always-on; an internal renewal-window check inside the job decides whether
            // an actual renewal fires. Surfaced in the admin UI so operators can edit the
            // check cadence and trigger manual runs.
            ["TlsRenewal"] = new JobEntry(
                getCron: cfg => cfg.Https.RenewalCheckSchedule,
                setCron: (cfg, value) => cfg.Https.RenewalCheckSchedule = value,
                isEnabled: _ => true,
                setEnabled: null,
                invokeAsync: (sp, ct) =>
                {
                    var job = sp.GetRequiredService<TlsRenewalJob>();
                    return job.RunAsync(ct);
                }),
        };

        _entries = entries;
        _jobNames = entries.Keys.ToList();
    }

    /// <inheritdoc />
    public IReadOnlyList<string> JobNames => _jobNames;

    /// <inheritdoc />
    public bool IsRegistered(string jobName) => _entries.ContainsKey(jobName);

    /// <inheritdoc />
    public string? GetCron(string jobName)
    {
        if (!_entries.TryGetValue(jobName, out var entry)) return null;
        return entry.GetCron(_config);
    }

    /// <inheritdoc />
    public Task<bool> GetEnabledAsync(string jobName, CancellationToken cancellationToken = default)
    {
        if (!_entries.TryGetValue(jobName, out var entry)) return Task.FromResult(false);
        return Task.FromResult(entry.IsEnabled(_config));
    }

    /// <inheritdoc />
    public int GetTimeoutSeconds(string jobName)
    {
        if (_config.Scheduler.JobTimeouts.TryGetValue(jobName, out var seconds) && seconds > 0)
            return seconds;
        var fallback = _config.Scheduler.DefaultJobTimeoutSeconds;
        return fallback > 0 ? fallback : 120;
    }

    /// <inheritdoc />
    public bool SetCron(string jobName, string cronExpression)
    {
        if (!_entries.TryGetValue(jobName, out var entry)) return false;
        if (entry.SetCron == null) return false;
        entry.SetCron(_config, cronExpression);
        return true;
    }

    /// <inheritdoc />
    public void SetTimeoutSeconds(string jobName, int seconds)
    {
        if (seconds <= 0) return;
        _config.Scheduler.JobTimeouts[jobName] = seconds;
    }

    /// <inheritdoc />
    public bool SetEnabled(string jobName, bool enabled)
    {
        if (!_entries.TryGetValue(jobName, out var entry)) return false;
        if (entry.SetEnabled == null) return false;
        entry.SetEnabled(_config, enabled);
        return true;
    }

    /// <inheritdoc />
    public Task RunNowAsync(string jobName, CancellationToken cancellationToken = default)
    {
        if (!_entries.TryGetValue(jobName, out var entry))
            throw new ArgumentException($"Unknown scheduler job '{jobName}'.", nameof(jobName));

        // Fire-and-forget: returns immediately so the controller can answer 202. The work
        // is routed through SchedulerJobRunner so manual runs get the same metrics, state
        // persistence, audit emission, and consecutive-failure escalation as scheduled
        // runs. The runner owns timeout via Scheduler.JobTimeouts. We pass
        // CancellationToken.None as the stopping token because operators expect a manual
        // run to keep going even if their browser disconnects.
        _ = Task.Run(async () =>
        {
            try
            {
                await using var scope = _serviceProvider.CreateAsyncScope();
                var runner = scope.ServiceProvider.GetRequiredService<SchedulerJobRunner>();
                await runner.RunAsync(
                    jobName,
                    ct => entry.InvokeAsync(scope.ServiceProvider, ct),
                    CancellationToken.None);
                _logger.LogInformation(
                    "SchedulerJobRegistry: manual run of '{JobName}' completed",
                    jobName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "SchedulerJobRegistry: manual run of '{JobName}' failed outside the runner",
                    jobName);
            }
        }, CancellationToken.None);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Internal entry struct holding the per-job dispatch closures. Kept private so
    /// the wire-up table is the only place these strategies are constructed.
    /// </summary>
    private sealed class JobEntry
    {
        public Func<SystemConfig, string?> GetCron { get; }
        public Action<SystemConfig, string>? SetCron { get; }
        public Func<SystemConfig, bool> IsEnabled { get; }
        public Action<SystemConfig, bool>? SetEnabled { get; }
        public Func<IServiceProvider, CancellationToken, Task> InvokeAsync { get; }

        public JobEntry(
            Func<SystemConfig, string?> getCron,
            Action<SystemConfig, string>? setCron,
            Func<SystemConfig, bool> isEnabled,
            Action<SystemConfig, bool>? setEnabled,
            Func<IServiceProvider, CancellationToken, Task> invokeAsync)
        {
            GetCron = getCron;
            SetCron = setCron;
            IsEnabled = isEnabled;
            SetEnabled = setEnabled;
            InvokeAsync = invokeAsync;
        }
    }
}
