using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Crl;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin
{
    /// <summary>
    /// Admin endpoints for managing CRL generation schedules and configurations.
    /// Mutations require step-up MFA via <c>X-MFA-Token</c> and enforce the standard
    /// tenant fence: the schedule's owning CA must belong to a tenant in the caller's
    /// <c>AccessibleTenantIds</c>. Audit events are emitted on both success and failure
    /// paths so cross-tenant probes are recorded.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/crl-schedules")]
    [Authorize]
    [NodeRole(ProcessRole.Control)]
    public class AdminCrlScheduleController(
        ICrlConfigurationService crlConfigService,
        IAuditService audit,
        ICurrentUserService currentUser,
        IDistributedCache cache,
        ModularCADbContext db) : ControllerBase
    {
        private readonly ICrlConfigurationService _crlConfigService = crlConfigService;
        private readonly IAuditService _audit = audit;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly IDistributedCache _cache = cache;
        private readonly ModularCADbContext _db = db;

        /// <summary>
        /// Resolves a CRL schedule's owning CA + tenant from its <paramref name="taskId"/>
        /// and verifies the caller's <c>AccessibleTenantIds</c> includes that tenant.
        /// Returns the (CaId, TenantId) tuple on success, or null when the schedule is
        /// missing, the CA is unresolvable, or the request is cross-tenant. System admins
        /// always pass.
        /// </summary>
        private async Task<(Guid CaId, Guid TenantId)?> ResolveAndFenceScheduleAsync(Guid taskId)
        {
            var config = await _db.CrlConfigurations.AsNoTracking()
                .FirstOrDefaultAsync(c => c.TaskId == taskId);
            if (config == null)
                return null;

            var ca = await _db.CertificateAuthorities
                .AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(c => c.CertificateId == config.CaCertificateId);
            if (ca == null || ca.IsDeleted)
                return null;

            if (HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
                if (tenantIds == null || !tenantIds.Contains(ca.TenantId))
                    return null;
            }
            return (ca.Id, ca.TenantId);
        }

        /// <summary>
        /// Resolves the CA + tenant for a Create request, where the CA is supplied by
        /// <paramref name="caCertificateId"/> rather than an existing schedule row.
        /// </summary>
        private async Task<(Guid CaId, Guid TenantId)?> ResolveAndFenceByCaCertificateAsync(Guid caCertificateId)
        {
            var ca = await _db.CertificateAuthorities
                .AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId);
            if (ca == null || ca.IsDeleted)
                return null;

            if (HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
                if (tenantIds == null || !tenantIds.Contains(ca.TenantId))
                    return null;
            }
            return (ca.Id, ca.TenantId);
        }

        /// <summary>
        /// Lists every CRL scheduled job. Non-system admins receive only schedules whose
        /// owning CA belongs to a tenant in their <c>AccessibleTenantIds</c>.
        /// </summary>
        [HttpGet]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetAll()
        {
            var jobs = (await _crlConfigService.GetAllAsync()).ToList();

            if (HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
                if (tenantIds == null || tenantIds.Count == 0)
                    return Ok(Array.Empty<CrlConfigurationDto>());

                var caCertIds = jobs.Select(j => j.CaCertificateId).Distinct().ToList();
                var allowedCaCertIds = await _db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .Where(ca => ca.CertificateId != null
                                 && caCertIds.Contains(ca.CertificateId.Value)
                                 && tenantIds.Contains(ca.TenantId)
                                 && !ca.IsDeleted)
                    .Select(ca => ca.CertificateId!.Value)
                    .ToListAsync();
                var allowedSet = new HashSet<Guid>(allowedCaCertIds);
                jobs = jobs.Where(j => allowedSet.Contains(j.CaCertificateId)).ToList();
            }

            return Ok(jobs);
        }

        /// <summary>
        /// Creates a new CRL scheduled job. Requires <c>CaOperator</c> + step-up MFA
        /// (<see cref="StepUpOps.CreateCrlSchedule"/>) and verifies the caller can
        /// access the target CA's tenant. Audit fires on success and on access-failure paths.
        /// </summary>
        [HttpPost]
        [Authorize]
        [RequireCaCapability(Capabilities.CertRevoke, CaTarget.CaCertificate, "request.CaCertificateId")]
        [RequireStepUp(StepUpOps.CreateCrlSchedule)]
        public async Task<IActionResult> Create([FromBody] CreateCrlConfigurationRequest request)
        {
            await _currentUser.EnsureLoadedAsync();

            // UpdateInterval is a cron expression, and CrlConfigurationService parses it with
            // NCrontab before any validation runs. A typo therefore surfaced as an unhandled
            // CrontabException — a 500 with no indication of which field was wrong.
            if (!IsValidCronExpression(request.UpdateInterval))
                return BadRequest(new { error = "UpdateInterval must be a valid cron expression, e.g. '0 */6 * * *'." });

            var fence = await ResolveAndFenceByCaCertificateAsync(request.CaCertificateId);
            if (fence == null)
            {
                await _audit.LogAsync(AuditActionType.CrlScheduleCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CrlSchedule", null,
                    new { request.Name, request.CaCertificateId, request.IsDelta, Reason = "ca-not-found-or-cross-tenant" },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: "Certificate authority not found or outside accessible tenants.");
                return NotFound(new { error = "Certificate authority not found." });
            }

            var job = await _crlConfigService.CreateAsync(request);

            await _audit.LogAsync(AuditActionType.CrlScheduleCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                "CrlSchedule", job.Id.ToString(),
                new { job.Id, request.Name, request.CaCertificateId, request.IsDelta },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: fence.Value.CaId,
                tenantId: fence.Value.TenantId);

            return CreatedAtAction(nameof(GetById), new { id = job.Id }, job);
        }

        /// <summary>
        /// Returns a CRL scheduled job by ID. Enforces the tenant fence so cross-tenant
        /// callers receive a 404 even if the row exists.
        /// </summary>
        [HttpGet("{id:guid}")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetById(Guid id)
        {
            if (await ResolveAndFenceScheduleAsync(id) == null)
                return NotFound();

            var job = await _crlConfigService.GetByIdAsync(id);
            if (job == null)
                return NotFound();
            return Ok(job);
        }

        /// <summary>
        /// Updates a CRL scheduled job. Requires <c>CaOperator</c> + step-up MFA
        /// (<see cref="StepUpOps.UpdateCrlSchedule"/>) and enforces the tenant fence.
        /// Captures before/after snapshots in the audit payload so changes to schedule
        /// cadence/overlap/delta config are reviewable. Failure paths (cross-tenant or
        /// missing schedule) emit a failure audit row.
        /// </summary>
        [HttpPut("{id:guid}")]
        [Authorize(Policy = "CaOperator")]
        [RequireStepUp(StepUpOps.UpdateCrlSchedule, "id")]
        public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCrlConfigurationRequest request)
        {
            await _currentUser.EnsureLoadedAsync();

            if (!IsValidCronExpression(request.UpdateInterval))
                return BadRequest(new { error = "UpdateInterval must be a valid cron expression, e.g. '0 */6 * * *'." });

            var fence = await ResolveAndFenceScheduleAsync(id);
            if (fence == null)
            {
                await _audit.LogAsync(AuditActionType.CrlScheduleUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CrlSchedule", id.ToString(),
                    new { ScheduleId = id, Reason = "schedule-not-found-or-cross-tenant" },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: "CRL schedule not found or outside accessible tenants.");
                return NotFound(new { error = "CRL schedule not found." });
            }

            // Capture before-snapshot for the audit trail; the service layer mutates and saves
            // the entity in-place so we read it via a no-tracking query first.
            var before = await _db.CrlConfigurations.AsNoTracking()
                .Where(c => c.TaskId == id)
                .Select(c => new { c.Description, c.UpdateInterval, c.OverlapPeriod, c.IsDelta, c.DeltaInterval })
                .FirstOrDefaultAsync();

            request.TaskId = id;
            await _crlConfigService.UpdateAsync(request);

            var after = new { request.Description, request.UpdateInterval, request.OverlapPeriod, request.IsDelta, request.DeltaInterval };

            await _audit.LogAsync(AuditActionType.CrlScheduleUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "CrlSchedule", id.ToString(),
                new { ScheduleId = id, Before = before, After = after },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: fence.Value.CaId,
                tenantId: fence.Value.TenantId);

            return NoContent();
        }

        /// <summary>
        /// Toggles the enabled flag on a CRL scheduled job. Requires <c>CaOperator</c> +
        /// step-up MFA (<see cref="StepUpOps.ToggleCrlSchedule"/>) and enforces the
        /// tenant fence. Toggling is treated as a sensitive operation because disabling
        /// CRL generation silently degrades revocation freshness for an entire CA.
        /// </summary>
        [HttpPut("{id:guid}/status")]
        [Authorize(Policy = "CaOperator")]
        [RequireStepUp(StepUpOps.ToggleCrlSchedule, "id")]
        public async Task<IActionResult> SetStatus(Guid id, [FromBody] CrlScheduleStatusRequest request)
        {
            await _currentUser.EnsureLoadedAsync();

            var fence = await ResolveAndFenceScheduleAsync(id);
            if (fence == null)
            {
                await _audit.LogAsync(AuditActionType.CrlScheduleStatusChanged, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CrlSchedule", id.ToString(),
                    new { ScheduleId = id, request.Enabled, Reason = "schedule-not-found-or-cross-tenant" },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: "CRL schedule not found or outside accessible tenants.");
                return NotFound(new { error = "CRL schedule not found." });
            }

            await _crlConfigService.SetEnabledAsync(id, request.Enabled);

            await _audit.LogAsync(AuditActionType.CrlScheduleStatusChanged, _currentUser.User?.Id, _currentUser.User?.Username,
                "CrlSchedule", id.ToString(),
                new { ScheduleId = id, Enabled = request.Enabled },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: fence.Value.CaId,
                tenantId: fence.Value.TenantId);

            return NoContent();
        }

        /// <summary>
        /// Deletes a CRL scheduled job. Requires <c>CaOperator</c> + step-up MFA
        /// (<see cref="StepUpOps.DeleteCrlSchedule"/>) and enforces the tenant fence.
        /// Captures the deleted resource's identifying fields in the audit payload so
        /// deletes are reviewable after the row is gone. Failure paths emit a failure audit row.
        /// </summary>
        [HttpDelete("{id:guid}")]
        [Authorize(Policy = "CaOperator")]
        [RequireStepUp(StepUpOps.DeleteCrlSchedule, "id")]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _currentUser.EnsureLoadedAsync();

            var fence = await ResolveAndFenceScheduleAsync(id);
            if (fence == null)
            {
                await _audit.LogAsync(AuditActionType.CrlScheduleDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CrlSchedule", id.ToString(),
                    new { ScheduleId = id, Reason = "schedule-not-found-or-cross-tenant" },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: "CRL schedule not found or outside accessible tenants.");
                return NotFound(new { error = "CRL schedule not found." });
            }

            var deletedSnapshot = await _db.CrlConfigurations.AsNoTracking()
                .Where(c => c.TaskId == id)
                .Select(c => new { c.TaskId, c.Name, c.CaCertificateId, c.UpdateInterval, c.IsDelta, c.Enabled })
                .FirstOrDefaultAsync();

            await _crlConfigService.DeleteAsync(id);

            await _audit.LogAsync(AuditActionType.CrlScheduleDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
                "CrlSchedule", id.ToString(),
                new { ScheduleId = id, Deleted = deletedSnapshot },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: fence.Value.CaId,
                tenantId: fence.Value.TenantId);

            return NoContent();
        }

        /// <summary>
        /// Applies a batch of enable/disable/delete actions across several CRL schedules behind a
        /// SINGLE step-up token (<see cref="StepUpOps.BulkCrlSchedule"/>, batch-scoped / no target),
        /// so a multi-row selection on the Distribution page prompts for MFA exactly once instead of
        /// once per row. Each action is fenced independently (missing / cross-tenant rows are skipped,
        /// not failed) and the batch never aborts on a single error; a per-id summary is returned.
        /// Requires <c>CaOperator</c>.
        /// </summary>
        /// <summary>
        /// True when <paramref name="expression"/> is a cron expression NCrontab can parse.
        /// Used to reject a bad schedule at the API boundary rather than letting it throw out
        /// of the service layer as an unhandled 500.
        /// </summary>
        private static bool IsValidCronExpression(string? expression) =>
            !string.IsNullOrWhiteSpace(expression)
            && NCrontab.CrontabSchedule.TryParse(expression) != null;

        [HttpPost("bulk")]
        [Authorize]
        [RequireCaCapability(Capabilities.CertRevoke, CaTarget.CrlConfigurations, "request.Actions")]
        public async Task<IActionResult> BulkUpdate([FromBody] BulkCrlScheduleRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();

            if (request?.Actions == null || request.Actions.Count == 0)
                return BadRequest(new { error = "At least one action is required." });

            // ONE BulkCrlSchedule token (no target) authorizes the whole batch — a selection can
            // span CAs, so the token cannot be bound to a single schedule/CA id.
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.BulkCrlSchedule))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var results = new List<object>();
            int ok = 0, skipped = 0, failed = 0;

            foreach (var action in request.Actions)
            {
                var id = action.Id;
                var verb = (action.Action ?? string.Empty).Trim().ToLowerInvariant();

                if (verb != "enable" && verb != "disable" && verb != "delete")
                {
                    results.Add(new { id, status = "invalid_action" });
                    skipped++;
                    continue;
                }

                var fence = await ResolveAndFenceScheduleAsync(id);
                if (fence == null)
                {
                    results.Add(new { id, status = "denied" });
                    skipped++;
                    continue;
                }

                try
                {
                    if (verb == "delete")
                    {
                        var deletedSnapshot = await _db.CrlConfigurations.AsNoTracking()
                            .Where(c => c.TaskId == id)
                            .Select(c => new { c.TaskId, c.Name, c.CaCertificateId, c.UpdateInterval, c.IsDelta, c.Enabled })
                            .FirstOrDefaultAsync();

                        await _crlConfigService.DeleteAsync(id);

                        await _audit.LogAsync(AuditActionType.CrlScheduleDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
                            "CrlSchedule", id.ToString(),
                            new { ScheduleId = id, Bulk = true, Deleted = deletedSnapshot },
                            HttpContext.Connection.RemoteIpAddress?.ToString(),
                            certificateAuthorityId: fence.Value.CaId,
                            tenantId: fence.Value.TenantId);
                    }
                    else
                    {
                        var enabled = verb == "enable";
                        await _crlConfigService.SetEnabledAsync(id, enabled);

                        await _audit.LogAsync(AuditActionType.CrlScheduleStatusChanged, _currentUser.User?.Id, _currentUser.User?.Username,
                            "CrlSchedule", id.ToString(),
                            new { ScheduleId = id, Enabled = enabled, Bulk = true },
                            HttpContext.Connection.RemoteIpAddress?.ToString(),
                            certificateAuthorityId: fence.Value.CaId,
                            tenantId: fence.Value.TenantId);
                    }

                    results.Add(new { id, status = "ok" });
                    ok++;
                }
                catch (Exception ex)
                {
                    results.Add(new { id, status = "failed", error = ex.Message });
                    failed++;
                }
            }

            return Ok(new { ok, skipped, failed, results });
        }
    }

    /// <summary>Request body for the CRL schedule enable/disable toggle endpoint.</summary>
    public class CrlScheduleStatusRequest
    {
        /// <summary>Target enabled flag for the schedule.</summary>
        public bool Enabled { get; set; }
    }

    /// <summary>Request body for the bulk CRL schedule action endpoint.</summary>
    public class BulkCrlScheduleRequest
    {
        /// <summary>The set of per-schedule actions to apply in this batch.</summary>
        public List<BulkCrlScheduleAction> Actions { get; set; } = new();
    }

    /// <summary>A single schedule action within a bulk CRL request.</summary>
    public class BulkCrlScheduleAction
    {
        /// <summary>The schedule's task id.</summary>
        public Guid Id { get; set; }

        /// <summary>One of <c>enable</c>, <c>disable</c>, or <c>delete</c> (case-insensitive).</summary>
        public string Action { get; set; } = string.Empty;
    }
}
