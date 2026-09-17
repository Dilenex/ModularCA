using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Scheduler;
using ModularCA.Shared.Utils;
using NCrontab;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Aggregator admin endpoints powering the central Schedules page. Surfaces a unified
/// view of system jobs (singleton crons), per-row schedules (CRL configurations and
/// LDAP publishers), and scheduler-wide globals — plus per-job edit, manual-run, and
/// global config writeback. Per-row CRUD lives on
/// <c>AdminCrlScheduleController</c> / <c>AdminLdapPublishersController</c> and is
/// intentionally not duplicated here.
/// </summary>
[ApiController]
[Route("api/v1/admin/scheduler")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminSchedulerController(
    SystemConfig config,
    ISchedulerJobRegistry registry,
    ModularCADbContext db,
    IServiceProvider serviceProvider,
    IAuditService audit,
    ICurrentUserService currentUser,
    EnvVarConfigOverlay envOverlay,
    ILogger<AdminSchedulerController> logger,
    TimeProvider? timeProvider = null) : ControllerBase
{
    private readonly SystemConfig _config = config;
    private readonly ISchedulerJobRegistry _registry = registry;
    private readonly ModularCADbContext _db = db;
    private readonly IServiceProvider _serviceProvider = serviceProvider;
    private readonly IAuditService _audit = audit;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly EnvVarConfigOverlay _envOverlay = envOverlay;
    private readonly ILogger<AdminSchedulerController> _logger = logger;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    private const int PollIntervalSeconds = 30;
    private static readonly HashSet<string> AllowedMissedRunPolicies =
        new(StringComparer.OrdinalIgnoreCase) { "SkipMissed", "RunOnce", "RunAll" };

    /// <summary>
    /// Serializes the read-modify-write-persist sequence across the three PUT handlers
    /// that mutate <c>SystemConfig</c> and call <see cref="PersistSystemConfig"/>. Without
    /// this lock, two concurrent operator edits can interleave the in-memory mutation and
    /// the YAML serialization, producing torn output where one writer's mutation is
    /// overwritten by the other's serialized snapshot. Static so the lock survives across
    /// requests (controllers are scoped per-request in ASP.NET Core).
    /// </summary>
    private static readonly SemaphoreSlim _persistLock = new(1, 1);

    /// <summary>
    /// Returns scheduler-wide health: current lease holder, hardcoded poll interval,
    /// and the operator-tunable globals (lease TTL, missed-run policy, default job
    /// timeout, consecutive-failure alert threshold).
    /// </summary>
    [HttpGet("health")]
    public async Task<IActionResult> GetHealth()
    {
        var lease = await _db.SchedulerLeases
            .AsNoTracking()
            .FirstOrDefaultAsync(l => l.Name == "scheduler");

        return Ok(new
        {
            leaseHolder = lease == null ? null : new
            {
                instanceId = lease.OwnerInstanceId,
                acquiredAtUtc = lease.AcquiredAtUtc,
                expiresAtUtc = lease.ExpiresAtUtc
            },
            pollIntervalSeconds = PollIntervalSeconds,
            leaseTtlSeconds = _config.Scheduler.LeaseTtlSeconds,
            missedRunPolicy = _config.Scheduler.MissedRunPolicy,
            defaultJobTimeoutSeconds = _config.Scheduler.DefaultJobTimeoutSeconds,
            consecutiveFailureAlertThreshold = _config.Scheduler.ConsecutiveFailureAlertThreshold,
        });
    }

    /// <summary>
    /// Returns the unified list of system jobs from the registry, joined with the
    /// persistent <c>SchedulerJobStates</c> rows so each entry includes cron + enabled
    /// + timeout + last-run telemetry + next-run projection.
    /// </summary>
    [HttpGet("jobs")]
    public async Task<IActionResult> ListJobs()
    {
        var states = await _db.SchedulerJobStates
            .AsNoTracking()
            .ToDictionaryAsync(s => s.JobName, StringComparer.OrdinalIgnoreCase);

        var rows = new List<object>(_registry.JobNames.Count);
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var name in _registry.JobNames)
        {
            var cron = _registry.GetCron(name);
            var enabled = await _registry.GetEnabledAsync(name);
            var timeout = _registry.GetTimeoutSeconds(name);
            states.TryGetValue(name, out var state);

            DateTime? nextRun = null;
            if (!string.IsNullOrWhiteSpace(cron))
            {
                try
                {
                    var sched = CrontabSchedule.TryParse(cron);
                    if (sched != null)
                    {
                        var anchor = state?.LastRunUtc ?? now;
                        nextRun = sched.GetNextOccurrence(anchor);
                    }
                }
                catch
                {
                    // Bad cron — surfaced via lastError when state has one; nextRun stays null.
                }
            }

            rows.Add(new
            {
                name,
                cronExpression = cron,
                enabled,
                timeoutSeconds = timeout,
                lastRunUtc = state?.LastRunUtc,
                lastResult = state?.LastResult,
                lastDurationMs = state?.LastDurationMs,
                lastError = state?.LastError,
                consecutiveFailureCount = state?.ConsecutiveFailureCount ?? 0,
                nextRunUtc = nextRun,
            });
        }

        return Ok(rows);
    }

    /// <summary>
    /// Updates the cron expression and/or per-job timeout for a registered system job.
    /// Cron is validated via NCrontab before persistence; an invalid expression returns
    /// 400 without mutating anything.
    /// </summary>
    [HttpPut("jobs/{name}")]
    [RequireStepUp(StepUpOps.UpdateSchedulerJob, "name")]
    public async Task<IActionResult> UpdateJob(string name, [FromBody] UpdateSchedulerJobRequest request)
    {
        if (!_registry.IsRegistered(name))
            return NotFound(new { error = $"Unknown scheduler job '{name}'." });
        if (request == null)
            return BadRequest(new { error = "Request body is required." });

        // Validate cron BEFORE entering the persist lock — failing fast on bad input
        // doesn't burn the lock for unrelated requests.
        if (request.CronExpression != null)
        {
            if (string.IsNullOrWhiteSpace(request.CronExpression))
                return BadRequest(new { error = "cronExpression must be non-empty when provided." });

            CrontabSchedule? parsed;
            try
            {
                parsed = CrontabSchedule.TryParse(request.CronExpression);
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = $"Invalid cron expression: {ex.Message}" });
            }
            if (parsed == null)
                return BadRequest(new { error = "Invalid cron expression." });
        }

        if (request.TimeoutSeconds.HasValue
            && (request.TimeoutSeconds.Value < 1 || request.TimeoutSeconds.Value > 86_400))
            return BadRequest(new { error = "timeoutSeconds must be between 1 and 86400." });

        string? beforeCron;
        int beforeTimeout;
        string? afterCron;
        int afterTimeout;

        await _persistLock.WaitAsync(HttpContext.RequestAborted);
        try
        {
            beforeCron = _registry.GetCron(name);
            beforeTimeout = _registry.GetTimeoutSeconds(name);

            if (request.CronExpression != null
                && !_registry.SetCron(name, request.CronExpression))
                return BadRequest(new { error = $"Job '{name}' has no operator-tunable cron expression." });

            if (request.TimeoutSeconds.HasValue)
                _registry.SetTimeoutSeconds(name, request.TimeoutSeconds.Value);

            try { PersistSystemConfig(); }
            catch (Exception) { return StatusCode(500, new { error = "Failed to persist scheduler configuration to config.yaml." }); }

            afterCron = _registry.GetCron(name);
            afterTimeout = _registry.GetTimeoutSeconds(name);
        }
        finally
        {
            _persistLock.Release();
        }

        await _currentUser.EnsureLoadedAsync();

        await _audit.LogAsync(
            AuditActionType.SchedulerJobUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "SchedulerJob", name,
            new
            {
                jobName = name,
                before = new { cronExpression = beforeCron, timeoutSeconds = beforeTimeout },
                after = new { cronExpression = afterCron, timeoutSeconds = afterTimeout }
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            name,
            cronExpression = afterCron,
            timeoutSeconds = afterTimeout
        });
    }

    /// <summary>
    /// Toggles the enabled state for a registered system job by writing the corresponding
    /// <c>SystemConfig</c> boolean (e.g. <c>Backup.CreateOnSchedule</c>,
    /// <c>AutoRenewal.Enabled</c>). Continuous-throttle jobs (AcmeCleanup, TlsRenewal)
    /// have no operator-tunable toggle and return 400. Reuses
    /// <c>StepUpOps.UpdateSchedulerJob</c> because operator intent is the same as a cron
    /// edit — flipping how the job behaves on the next tick.
    /// </summary>
    [HttpPut("jobs/{name}/enabled")]
    [RequireStepUp(StepUpOps.UpdateSchedulerJob, "name")]
    public async Task<IActionResult> UpdateJobEnabled(string name, [FromBody] UpdateSchedulerJobEnabledRequest request)
    {
        if (!_registry.IsRegistered(name))
            return NotFound(new { error = $"Unknown scheduler job '{name}'." });
        if (request == null)
            return BadRequest(new { error = "Request body is required." });

        bool beforeEnabled;
        bool afterEnabled;

        await _persistLock.WaitAsync(HttpContext.RequestAborted);
        try
        {
            beforeEnabled = await _registry.GetEnabledAsync(name);

            if (!_registry.SetEnabled(name, request.Enabled))
                return BadRequest(new { error = $"Job '{name}' has no operator-tunable enabled toggle (continuous job)." });

            try { PersistSystemConfig(); }
            catch (Exception) { return StatusCode(500, new { error = "Failed to persist scheduler configuration to config.yaml." }); }

            afterEnabled = await _registry.GetEnabledAsync(name);
        }
        finally
        {
            _persistLock.Release();
        }

        await _currentUser.EnsureLoadedAsync();

        await _audit.LogAsync(
            AuditActionType.SchedulerJobUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "SchedulerJob", name,
            new
            {
                jobName = name,
                before = new { enabled = beforeEnabled },
                after = new { enabled = afterEnabled }
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { name, enabled = afterEnabled });
    }

    /// <summary>
    /// Manually triggers a single run of the named system job. Returns 202 Accepted —
    /// the job runs on a background task with its own DI scope and timeout. Failures
    /// surface in the regular scheduler audit/alert path.
    /// </summary>
    [HttpPost("jobs/{name}/run")]
    [RequireStepUp(StepUpOps.RunSchedulerJob, "name")]
    public async Task<IActionResult> RunJob(string name)
    {
        if (!_registry.IsRegistered(name))
            return NotFound(new { error = $"Unknown scheduler job '{name}'." });

        await _currentUser.EnsureLoadedAsync();

        await _audit.LogAsync(
            AuditActionType.SchedulerJobManualRun,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "SchedulerJob", name,
            new { jobName = name, trigger = "manual" },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        try
        {
            await _registry.RunNowAsync(name, HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AdminSchedulerController: manual run dispatch failed for '{JobName}'", name);
            return StatusCode(500, new { error = "Failed to dispatch manual run." });
        }

        return Accepted(new { name, status = "dispatched" });
    }

    /// <summary>
    /// Returns the unified list of per-row schedules: every CRL configuration and
    /// every LDAP publisher row. Items are projected with stable shapes so the UI
    /// can render both groups side-by-side without parsing different schemas.
    /// </summary>
    [HttpGet("schedules")]
    public async Task<IActionResult> ListSchedules()
    {
        // CRL configurations join CertificateAuthority.Label so the UI can group by CA.
        // CertificateAuthority.CertificateId is nullable (SSH-only CAs); cast to Guid?
        // on the CRL side so EF translates the join under MySQL's nullable equality.
        var crl = await (
            from cfg in _db.CrlConfigurations.AsNoTracking()
            join ca in _db.CertificateAuthorities.AsNoTracking()
                on (Guid?)cfg.CaCertificateId equals ca.CertificateId into caJoin
            from ca in caJoin.DefaultIfEmpty()
            orderby ca != null ? ca.Label : null, cfg.Name
            select new
            {
                taskId = cfg.TaskId,
                caCertificateId = cfg.CaCertificateId,
                caLabel = ca != null ? ca.Label : null,
                name = cfg.Name,
                enabled = cfg.Enabled,
                updateInterval = cfg.UpdateInterval,
                deltaInterval = cfg.DeltaInterval,
                isDelta = cfg.IsDelta,
                nextUpdateUtc = cfg.NextUpdateUtc,
                nextDeltaRunUtc = (DateTime?)null,
                lastUpdatedUtc = cfg.LastUpdatedUtc,
                lastGenerated = cfg.LastGenerated,
                lastCrlNumber = cfg.LastCrlNumber,
            }
        ).ToListAsync();

        var ldap = await (
            from cfg in _db.LdapConfigurations.AsNoTracking()
            join ca in _db.CertificateAuthorities.AsNoTracking()
                on cfg.CertificateAuthorityId equals ca.Id into caJoin
            from ca in caJoin.DefaultIfEmpty()
            orderby ca != null ? ca.Label : null, cfg.Name
            select new
            {
                id = cfg.Id,
                certificateAuthorityId = cfg.CertificateAuthorityId,
                caLabel = ca != null ? ca.Label : null,
                name = cfg.Name,
                host = cfg.Host,
                port = cfg.Port,
                baseDn = cfg.BaseDn,
                enabled = cfg.Enabled,
                updateInterval = cfg.UpdateInterval,
                nextUpdateUtc = cfg.NextUpdateUtc,
                lastUpdatedUtc = cfg.LastUpdatedUtc,
                publishCACert = cfg.PublishCACert,
                publishCRL = cfg.PublishCRL,
                publishDelta = cfg.PublishDelta,
                publishUserCerts = cfg.PublishUserCerts,
            }
        ).ToListAsync();

        return Ok(new { crl, ldap });
    }

    /// <summary>
    /// Manually triggers CRL export for the specified CRL configuration row. Returns
    /// 202 Accepted — the export runs on a background task and writes its own audit
    /// row on completion via <c>CrlExportJob</c>.
    /// </summary>
    [HttpPost("schedules/crl/{taskId:guid}/run")]
    [RequireStepUp(StepUpOps.RunSchedulerSchedule, "taskId")]
    public async Task<IActionResult> RunCrlSchedule(Guid taskId)
    {
        var cfg = await _db.CrlConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.TaskId == taskId);

        if (cfg == null)
            return NotFound(new { error = "CRL configuration not found." });

        await _currentUser.EnsureLoadedAsync();
        await _audit.LogAsync(
            AuditActionType.SchedulerScheduleManualRun,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "CrlSchedule", taskId.ToString(),
            new { kind = "crl", taskId, caCertificateId = cfg.CaCertificateId, trigger = "manual" },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        var taskIdLocal = cfg.TaskId;
        var caCertId = cfg.CaCertificateId;
        var cronHint = string.IsNullOrWhiteSpace(cfg.UpdateInterval) ? "0 * * * *" : cfg.UpdateInterval;

        // Route through SchedulerJobRunner with the same per-row jobName the cron-driven
        // path uses ("CrlExport:{taskId}"), so manual runs land in the same SchedulerJobStates
        // row as scheduled runs and get metrics, audit emission, and consecutive-failure
        // escalation. CancellationToken.None — operators expect a manual run to continue
        // even if their browser disconnects.
        var jobName = $"CrlExport:{taskIdLocal}";
        _ = Task.Run(async () =>
        {
            try
            {
                await using var scope = _serviceProvider.CreateAsyncScope();
                var runner = scope.ServiceProvider.GetRequiredService<SchedulerJobRunner>();
                await runner.RunAsync(
                    jobName,
                    ct =>
                    {
                        var job = scope.ServiceProvider.GetRequiredService<CrlExportJob>();
                        var options = new CrlExportScheduleOptions
                        {
                            TaskId = taskIdLocal,
                            CaCertificateId = caCertId
                        };
                        return job.RunAsync(options, cronHint, ct);
                    },
                    CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "AdminSchedulerController: manual CRL export run failed for task {TaskId} outside the runner", taskIdLocal);
            }
        }, CancellationToken.None);

        return Accepted(new { taskId, status = "dispatched" });
    }

    /// <summary>
    /// Manually triggers an LDAP publish run for the specified LDAP publisher row.
    /// Returns 202 Accepted — the publish runs on a background task. <c>LdapPublisherJob</c>
    /// hydrates the connection/credential fields from the row when only <c>TaskId</c>
    /// is supplied.
    /// </summary>
    [HttpPost("schedules/ldap/{id:guid}/run")]
    [RequireStepUp(StepUpOps.RunSchedulerSchedule, "id")]
    public async Task<IActionResult> RunLdapSchedule(Guid id)
    {
        var cfg = await _db.LdapConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id);

        if (cfg == null)
            return NotFound(new { error = "LDAP publisher not found." });

        await _currentUser.EnsureLoadedAsync();
        await _audit.LogAsync(
            AuditActionType.SchedulerScheduleManualRun,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "LdapSchedule", id.ToString(),
            new { kind = "ldap", id, certificateAuthorityId = cfg.CertificateAuthorityId, trigger = "manual" },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: cfg.CertificateAuthorityId);

        var taskIdLocal = cfg.Id;
        var cronHint = string.IsNullOrWhiteSpace(cfg.UpdateInterval) ? "0 * * * *" : cfg.UpdateInterval;

        // Route through SchedulerJobRunner with the same per-row jobName the cron-driven
        // path uses ("LdapPublisher:{id}"), so manual runs land in the same SchedulerJobStates
        // row as scheduled runs and get metrics, audit emission, and consecutive-failure
        // escalation.
        var jobName = $"LdapPublisher:{taskIdLocal}";
        _ = Task.Run(async () =>
        {
            try
            {
                await using var scope = _serviceProvider.CreateAsyncScope();
                var runner = scope.ServiceProvider.GetRequiredService<SchedulerJobRunner>();
                await runner.RunAsync(
                    jobName,
                    ct =>
                    {
                        var job = scope.ServiceProvider.GetRequiredService<LdapPublisherJob>();
                        var options = new LdapScheduleOptions { TaskId = taskIdLocal };
                        return job.RunAsync(options, cronHint, ct);
                    },
                    CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "AdminSchedulerController: manual LDAP publish run failed for publisher {Id} outside the runner", taskIdLocal);
            }
        }, CancellationToken.None);

        return Accepted(new { id, status = "dispatched" });
    }

    /// <summary>
    /// Updates scheduler-wide configuration: lease TTL, missed-run policy, default
    /// job timeout, consecutive-failure alert threshold. Validates each field
    /// independently so a malformed request never partially mutates state.
    /// </summary>
    [HttpPut("config")]
    [RequireStepUp(StepUpOps.UpdateSchedulerConfig)]
    public async Task<IActionResult> UpdateConfig([FromBody] UpdateSchedulerConfigRequest request)
    {
        if (request == null)
            return BadRequest(new { error = "Request body is required." });

        if (request.LeaseTtlSeconds.HasValue && request.LeaseTtlSeconds.Value < 15)
            return BadRequest(new { error = "leaseTtlSeconds must be >= 15." });

        if (request.MissedRunPolicy != null && !AllowedMissedRunPolicies.Contains(request.MissedRunPolicy))
            return BadRequest(new { error = "missedRunPolicy must be one of SkipMissed, RunOnce, RunAll." });

        if (request.DefaultJobTimeoutSeconds.HasValue
            && (request.DefaultJobTimeoutSeconds.Value < 1 || request.DefaultJobTimeoutSeconds.Value > 86_400))
            return BadRequest(new { error = "defaultJobTimeoutSeconds must be between 1 and 86400." });

        if (request.ConsecutiveFailureAlertThreshold.HasValue && request.ConsecutiveFailureAlertThreshold.Value < 1)
            return BadRequest(new { error = "consecutiveFailureAlertThreshold must be >= 1." });

        object before;
        object after;

        await _persistLock.WaitAsync(HttpContext.RequestAborted);
        try
        {
            before = new
            {
                leaseTtlSeconds = _config.Scheduler.LeaseTtlSeconds,
                missedRunPolicy = _config.Scheduler.MissedRunPolicy,
                defaultJobTimeoutSeconds = _config.Scheduler.DefaultJobTimeoutSeconds,
                consecutiveFailureAlertThreshold = _config.Scheduler.ConsecutiveFailureAlertThreshold,
            };

            if (request.LeaseTtlSeconds.HasValue)
                _config.Scheduler.LeaseTtlSeconds = request.LeaseTtlSeconds.Value;
            if (request.MissedRunPolicy != null)
                _config.Scheduler.MissedRunPolicy = request.MissedRunPolicy;
            if (request.DefaultJobTimeoutSeconds.HasValue)
                _config.Scheduler.DefaultJobTimeoutSeconds = request.DefaultJobTimeoutSeconds.Value;
            if (request.ConsecutiveFailureAlertThreshold.HasValue)
                _config.Scheduler.ConsecutiveFailureAlertThreshold = request.ConsecutiveFailureAlertThreshold.Value;

            try { PersistSystemConfig(); }
            catch (Exception) { return StatusCode(500, new { error = "Failed to persist scheduler configuration to config.yaml." }); }

            after = new
            {
                leaseTtlSeconds = _config.Scheduler.LeaseTtlSeconds,
                missedRunPolicy = _config.Scheduler.MissedRunPolicy,
                defaultJobTimeoutSeconds = _config.Scheduler.DefaultJobTimeoutSeconds,
                consecutiveFailureAlertThreshold = _config.Scheduler.ConsecutiveFailureAlertThreshold,
            };
        }
        finally
        {
            _persistLock.Release();
        }

        await _currentUser.EnsureLoadedAsync();

        await _audit.LogAsync(
            AuditActionType.SchedulerConfigUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "SchedulerConfig", "scheduler",
            new { before, after },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(after);
    }

    /// <summary>
    /// Persists the in-memory <see cref="SystemConfig"/> to <c>config.yaml</c>, mirroring
    /// the env-secret protection pattern used by <c>AdminConfigController.PersistConfig</c>.
    /// Throws on write failure so callers can surface the failure as 500 to the operator
    /// instead of silently returning 200 — a swallowed warning produced misleading "saved"
    /// UX in earlier revisions. The in-memory mutation is left in place either way; the
    /// operator can retry once the underlying file-permission / disk issue is resolved.
    /// </summary>
    private void PersistSystemConfig()
    {
        Exception? writeFailure = null;
        _envOverlay.WithSecretsProtected(_config, () =>
        {
            try
            {
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(PascalCaseNamingConvention.Instance)
                    .Build();
                var yaml = serializer.Serialize(_config);
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                System.IO.File.WriteAllText(configPath, yaml);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "AdminSchedulerController: persisting config.yaml failed; in-memory change still applies but operator must retry to persist.");
                writeFailure = ex;
            }
        });
        if (writeFailure != null)
            throw writeFailure;
    }
}

/// <summary>Request body for <c>PUT /api/v1/admin/scheduler/jobs/{name}</c>.</summary>
public class UpdateSchedulerJobRequest
{
    /// <summary>Optional new cron expression. Validated via NCrontab before persistence.</summary>
    public string? CronExpression { get; set; }

    /// <summary>Optional new per-job timeout in seconds. Bounded to [1, 86400].</summary>
    public int? TimeoutSeconds { get; set; }
}

/// <summary>Request body for <c>PUT /api/v1/admin/scheduler/jobs/{name}/enabled</c>.</summary>
public class UpdateSchedulerJobEnabledRequest
{
    /// <summary>Target enabled state. Writes the corresponding <c>SystemConfig</c> boolean.</summary>
    public bool Enabled { get; set; }
}

/// <summary>Request body for <c>PUT /api/v1/admin/scheduler/config</c>.</summary>
public class UpdateSchedulerConfigRequest
{
    /// <summary>New lease TTL in seconds. Minimum 15s to survive one missed poll.</summary>
    public int? LeaseTtlSeconds { get; set; }

    /// <summary>New missed-run policy. Must be one of <c>SkipMissed</c>, <c>RunOnce</c>, <c>RunAll</c>.</summary>
    public string? MissedRunPolicy { get; set; }

    /// <summary>New fallback per-job timeout in seconds.</summary>
    public int? DefaultJobTimeoutSeconds { get; set; }

    /// <summary>New consecutive-failure threshold above which the scheduler escalates alerts to Critical.</summary>
    public int? ConsecutiveFailureAlertThreshold { get; set; }
}
