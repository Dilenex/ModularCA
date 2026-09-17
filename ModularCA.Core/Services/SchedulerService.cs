using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Background service that drives the scheduler poll loop. The scheduler is always-on:
    /// every replica runs this loop with a fixed 30-second poll, and the database-backed
    /// leader-election lease decides which replica actually dispatches jobs. Each poll cycle:
    /// <list type="number">
    /// <item><description>Takes or refreshes the MySQL-backed <c>SchedulerLease</c> leader-election lease.</description></item>
    /// <item><description>Skips the cycle when another instance holds the lease, or when the database has no CAs (post-reset / setup mode).</description></item>
    /// <item><description>Resolves every <see cref="ISchedulerJob"/> from a fresh DI scope and invokes its <see cref="ISchedulerJob.TickAsync"/>.</description></item>
    /// </list>
    /// <para>
    /// Past-due math, cron evaluation, per-row fan-out, and state persistence live on each
    /// job's base class (<c>SingletonCronJob</c> / <c>PerRowScheduledJob</c>) routed through
    /// <c>SchedulerJobRunner</c>. The dispatch loop in this class is now a thin
    /// enumerate-and-tick — adding a new job is a DI registration only, no edit to
    /// <c>PollCycleAsync</c> required.
    /// </para>
    /// <para>
    /// <c>ExecuteAsync</c> is already serial — there is no intra-process overlap. The real
    /// concurrency concern (multiple replicas pointed at the same MySQL database) is handled
    /// by the lease.
    /// </para>
    /// </summary>
    public class SchedulerService : BackgroundService
    {
        /// <summary>Unique ID for this scheduler instance (one GUID per process).</summary>
        public static readonly string InstanceId = Guid.NewGuid().ToString("N");

        /// <summary>The lease name every install has used; a process passes another when its job set is not the control plane's.</summary>
        public const string DefaultLeaseName = "scheduler";

        private readonly string _leaseName;

        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<SchedulerService> _logger;
        private readonly ModularCA.Shared.Models.Config.SystemConfig _config;
        private readonly TimeProvider _timeProvider;
        private readonly TimeSpan _pollInterval;

        private bool _firstRun = true;

        // Cached list of concrete ISchedulerJob types, captured once on first poll cycle.
        // Each tick resolves each type in its own DI scope so jobs don't share a
        // ModularCADbContext (or any other scoped service) across the same poll cycle —
        // eliminates change-tracker leaks and SetCommandTimeout cross-contamination.
        private List<Type>? _jobTypes;

        /// <summary>
        /// Constructs the scheduler. The poll interval is hardcoded to 30 seconds —
        /// runs are gated by the leader-election lease, so a fixed cadence keeps
        /// scheduling deterministic across the fleet. <paramref name="timeProvider"/>
        /// is optional and defaults to <see cref="TimeProvider.System"/> so production
        /// code does not need to wire an explicit registration; tests may inject a fake.
        /// <paramref name="leaseName"/> names the lease this instance contends for; the default
        /// is the one every install has used, and a process whose job set is not the control
        /// plane's passes its own so the two sets do not starve each other.
        /// </summary>
        public SchedulerService(
            IServiceProvider serviceProvider,
            ILogger<SchedulerService> logger,
            ModularCA.Shared.Models.Config.SystemConfig config,
            TimeProvider? timeProvider = null,
            string? leaseName = null)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _config = config;
            _timeProvider = timeProvider ?? TimeProvider.System;
            _pollInterval = TimeSpan.FromSeconds(30);
            _leaseName = string.IsNullOrWhiteSpace(leaseName) ? DefaultLeaseName : leaseName;
        }

        /// <summary>
        /// Main polling loop. Each iteration: lease acquire → CA-exists check →
        /// enumerate <see cref="ISchedulerJob"/> implementations and call
        /// <see cref="ISchedulerJob.TickAsync"/>. The scheduler is always running on every
        /// replica; the leader-election lease decides which replica actually executes jobs.
        /// <c>ExecuteAsync</c> is serial — multi-instance concurrency is owned by the lease.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "SchedulerService started. InstanceId={InstanceId} PollInterval={PollInterval}",
                InstanceId, _pollInterval);

            // Log the missed-run policy on startup. Each job's base class owns the actual
            // missed-run gate via SchedulerJobStates.LastRunUtc.
            _logger.LogInformation(
                "SchedulerService: missed-run policy = {Policy}. InstanceId={InstanceId}",
                _config.Scheduler.MissedRunPolicy, InstanceId);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PollCycleAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "SchedulerService main loop error");
                }

                try
                {
                    await Task.Delay(_pollInterval, stoppingToken);
                }
                catch (OperationCanceledException) { break; }
            }

            _logger.LogInformation("SchedulerService stopped. InstanceId={InstanceId}", InstanceId);
        }

        /// <summary>
        /// One poll cycle: acquire/refresh the lease, check CA presence, then enumerate every
        /// registered <see cref="ISchedulerJob"/> and call its <see cref="ISchedulerJob.TickAsync"/>.
        /// <para>
        /// Each job owns its own past-due gate, cron evaluation, per-row fan-out, audit, and
        /// state persistence via its base class (<c>SingletonCronJob</c> /
        /// <c>PerRowScheduledJob</c>) routed through <c>SchedulerJobRunner</c>. A throwing tick
        /// is logged and skipped — siblings still run in the same cycle.
        /// </para>
        /// </summary>
        private async Task PollCycleAsync(CancellationToken stoppingToken)
        {
            // Short-lived scope used only for lease acquisition and table-existence checks.
            // Each job below owns its own scope inside its TickAsync via SchedulerJobRunner.
            await using var leaseScope = _serviceProvider.CreateAsyncScope();
            var db = leaseScope.ServiceProvider.GetRequiredService<ModularCADbContext>();

            // Skip all jobs if the system has no CAs (post-reset / pre-setup state).
            // Use raw SQL to check table existence first — avoids EF Core logging
            // noisy errors when the table doesn't exist yet during setup mode.
            bool hasCas = false;
            var conn = db.Database.GetDbConnection();
            try
            {
                if (conn.State != System.Data.ConnectionState.Open)
                    await conn.OpenAsync(stoppingToken);
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'CertificateAuthorities'";
                    var result = await cmd.ExecuteScalarAsync(stoppingToken);
                    if (Convert.ToInt64(result) > 0)
                        hasCas = await db.CertificateAuthorities.AnyAsync(stoppingToken);
                }
            }
            finally
            {
                if (conn.State == System.Data.ConnectionState.Open)
                    await conn.CloseAsync();
            }

            if (!hasCas)
            {
                if (_firstRun)
                {
                    _logger.LogInformation("SchedulerService: no CAs found — waiting for setup to complete.");
                    _firstRun = false;
                }
                return;
            }

            // Leader-election lease. Non-leaders skip this cycle.
            var leaseHeld = await TryAcquireLeaseAsync(db, stoppingToken);
            if (!leaseHeld)
            {
                _logger.LogDebug(
                    "SchedulerService: lease held by another instance. Skipping poll cycle. " +
                    "InstanceId={InstanceId}", InstanceId);
                return;
            }

            if (_firstRun)
            {
                _logger.LogInformation(
                    "SchedulerService: first poll cycle as lease holder. InstanceId={InstanceId}",
                    InstanceId);
                _firstRun = false;
            }

            // Resolve every registered ISchedulerJob in ITS OWN scope so jobs don't share
            // a ModularCADbContext across the same tick. The first cycle uses a probe scope
            // to capture concrete job types; subsequent cycles iterate the cached type list
            // and create one scope per job. Adding a new job is still a DI registration only.
            if (_jobTypes == null)
            {
                await using var probeScope = _serviceProvider.CreateAsyncScope();
                _jobTypes = probeScope.ServiceProvider.GetServices<ISchedulerJob>()
                    .Select(j => j.GetType())
                    .ToList();
            }

            foreach (var jobType in _jobTypes)
            {
                if (stoppingToken.IsCancellationRequested) break;

                await using var perJobScope = _serviceProvider.CreateAsyncScope();
                ISchedulerJob job;
                try
                {
                    job = (ISchedulerJob)perJobScope.ServiceProvider.GetRequiredService(jobType);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "SchedulerService: failed to resolve job type {JobType}; skipping this tick",
                        jobType.Name);
                    continue;
                }

                try
                {
                    await job.TickAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "SchedulerService: ISchedulerJob '{JobName}' tick threw outside its runner; continuing with remaining jobs",
                        job.Name);
                }
            }
        }

        /// <summary>
        /// Atomic lease acquire/refresh. Preferred over MySQL <c>GET_LOCK</c> because it
        /// survives connection drops and is observable via a simple SELECT.
        /// </summary>
        private async Task<bool> TryAcquireLeaseAsync(ModularCADbContext db, CancellationToken cancellationToken)
        {
            var now = _timeProvider.GetUtcNow().UtcDateTime;
            var expires = now.AddSeconds(Math.Max(15, _config.Scheduler.LeaseTtlSeconds));

            try
            {
                // Ensure the lease row exists. INSERT IGNORE on the PK — if two instances
                // race, one succeeds, the other is ignored.
                var seed = await db.SchedulerLeases.FirstOrDefaultAsync(l => l.Name == _leaseName, cancellationToken);
                if (seed == null)
                {
                    try
                    {
                        db.SchedulerLeases.Add(new SchedulerLeaseEntity
                        {
                            Name = _leaseName,
                            OwnerInstanceId = InstanceId,
                            AcquiredAtUtc = now,
                            ExpiresAtUtc = expires
                        });
                        await db.SaveChangesAsync(cancellationToken);
                        _logger.LogInformation(
                            "SchedulerService: created and acquired lease {Lease} for instance {InstanceId}",
                            _leaseName, InstanceId);
                        return true;
                    }
                    catch (DbUpdateException)
                    {
                        // Another instance won the race. Fall through to the normal update path.
                        db.ChangeTracker.Clear();
                    }
                }

                // Atomic "take or refresh": rows-affected = 1 only when we already hold
                // the lease or it's expired. Uses ExecuteUpdateAsync so no row loading.
                var rows = await db.SchedulerLeases
                    .Where(l => l.Name == _leaseName
                                && (l.ExpiresAtUtc < now || l.OwnerInstanceId == InstanceId))
                    .ExecuteUpdateAsync(
                        setters => setters
                            .SetProperty(l => l.OwnerInstanceId, InstanceId)
                            .SetProperty(l => l.AcquiredAtUtc, now)
                            .SetProperty(l => l.ExpiresAtUtc, expires),
                        cancellationToken);

                if (rows < 1)
                    return false;

                // Owner verification read-back: under significant clock skew between replicas,
                // two instances could each compute their local 'now' such that both pass the
                // ExpiresAtUtc < now predicate against snapshots they each just wrote. The
                // last writer wins at the row level; this read confirms WE are that winner
                // before we proceed to dispatch jobs as the leader.
                var owner = await db.SchedulerLeases.AsNoTracking()
                    .Where(l => l.Name == _leaseName)
                    .Select(l => l.OwnerInstanceId)
                    .FirstOrDefaultAsync(cancellationToken);
                return owner == InstanceId;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "SchedulerService: lease acquire failed. Treating as non-leader to be safe. InstanceId={InstanceId}",
                    InstanceId);
                return false;
            }
        }
    }
}
