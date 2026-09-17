using System.ComponentModel.DataAnnotations;
using System.Net;
using System.DirectoryServices.Protocols;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Scheduler;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing per-CA LDAP publishing configurations.
/// Mutations require step-up MFA via <c>X-MFA-Token</c> and enforce the
/// standard tenant fence: the target CA must belong to a tenant in the
/// caller's <c>AccessibleTenantIds</c>.
/// </summary>
[ApiController]
[Route("api/v1/admin/authorities/{caId:guid}/ldap-publishers")]
[Authorize(Policy = "CaAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminLdapPublishersController(
    ModularCADbContext dbContext,
    ICurrentUserService currentUser,
    IAuditService audit,
    ILdapSecretProtector secretProtector,
    ILogger<AdminLdapPublishersController> logger) : ControllerBase
{
    /// <summary>
    /// Resolves <paramref name="caId"/> to its owning tenant and verifies the caller
    /// has access. Returns the tenant id on success, or null if the CA is missing or
    /// outside the caller's <c>AccessibleTenantIds</c>. System admins always pass.
    /// </summary>
    private async Task<Guid?> ResolveAndFenceCaAsync(Guid caId)
    {
        var ca = await dbContext.CertificateAuthorities
            .AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(c => c.Id == caId);
        if (ca == null || ca.IsDeleted)
            return null;

        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null || !tenantIds.Contains(ca.TenantId))
                return null;
        }
        return ca.TenantId;
    }

    /// <summary>
    /// Lists all LDAP publisher configurations for the specified CA. Enforces the tenant fence
    /// so callers in other tenants cannot enumerate another tenant's LDAP catalog.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List(Guid caId)
    {
        if (await ResolveAndFenceCaAsync(caId) == null)
            return NotFound(new { error = "Certificate authority not found." });

        var publishers = await dbContext.LdapConfigurations
            .AsNoTracking()
            .Where(c => c.CertificateAuthorityId == caId)
            .OrderBy(c => c.Name)
            .Select(c => new
            {
                c.Id,
                c.Name,
                c.Enabled,
                c.Host,
                c.Port,
                c.UseSsl,
                c.BaseDn,
                c.PublishCACert,
                c.PublishCRL,
                c.PublishDelta,
                c.PublishUserCerts,
                c.UpdateInterval,
                c.LastUpdatedUtc,
                c.NextUpdateUtc,
                Password = "***"
            })
            .ToListAsync();

        return Ok(publishers);
    }

    /// <summary>
    /// Returns detail for a single LDAP publisher configuration. Enforces the tenant fence
    /// on the owning CA before returning any row.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid caId, Guid id)
    {
        if (await ResolveAndFenceCaAsync(caId) == null)
            return NotFound(new { error = "LDAP publisher not found." });

        var cfg = await dbContext.LdapConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.CertificateAuthorityId == caId);

        if (cfg == null)
            return NotFound(new { error = "LDAP publisher not found." });

        return Ok(new
        {
            cfg.Id,
            cfg.Name,
            cfg.Enabled,
            cfg.Host,
            cfg.Port,
            cfg.UseSsl,
            cfg.Username,
            cfg.BaseDn,
            cfg.PublishCACert,
            cfg.PublishCRL,
            cfg.PublishDelta,
            cfg.PublishUserCerts,
            cfg.UserDnTemplate,
            cfg.UpdateInterval,
            cfg.LastUpdatedUtc,
            cfg.NextUpdateUtc,
            Password = "***"
        });
    }

    /// <summary>
    /// Creates a new LDAP publisher configuration for the specified CA. Requires step-up MFA
    /// (<see cref="StepUpOps.CreateLdapPublisher"/>) and enforces the tenant fence on the
    /// target CA. Emits an audit event on both success and access-failure paths.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateLdapPublisher, "caId")]
    public async Task<IActionResult> Create(Guid caId, [FromBody] CreateLdapPublisherRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        var resolvedTenantId = await ResolveAndFenceCaAsync(caId);
        if (resolvedTenantId == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherCreated,
                currentUser.User?.Id,
                currentUser.User?.Username,
                "LdapConfiguration", null,
                new { CaId = caId, request.Name, request.Host, Reason = "ca-not-found-or-cross-tenant" },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "Certificate authority not found or outside accessible tenants.",
                certificateAuthorityId: caId);
            return NotFound(new { error = "Certificate authority not found." });
        }

        var entity = new LdapConfigurationEntity
        {
            Id = Guid.NewGuid(),
            CertificateAuthorityId = caId,
            Name = request.Name,
            Host = request.Host,
            Port = request.Port,
            UseSsl = request.UseSsl,
            Username = request.Username ?? string.Empty,
            // Encrypted before it reaches the column. The API already masked it on read and kept
            // it out of the audit payload; the value itself was the one place it stayed in clear.
            Password = secretProtector.Protect(request.Password),
            BaseDn = request.BaseDn,
            PublishCACert = request.PublishCACert,
            PublishCRL = request.PublishCRL,
            PublishDelta = request.PublishDelta,
            PublishUserCerts = request.PublishUserCerts,
            UserDnTemplate = request.UserDnTemplate,
            UpdateInterval = request.UpdateInterval ?? string.Empty,
            Enabled = request.Enabled,
        };

        dbContext.LdapConfigurations.Add(entity);
        await dbContext.SaveChangesAsync();

        await audit.LogAsync(
            AuditActionType.LdapPublisherCreated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapConfiguration", entity.Id.ToString(),
            new { entity.Name, entity.Host, entity.Port, CaId = caId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caId,
            tenantId: resolvedTenantId);

        return CreatedAtAction(nameof(Get), new { caId, id = entity.Id }, new { entity.Id });
    }

    /// <summary>
    /// Updates an existing LDAP publisher configuration. Non-null fields are applied;
    /// password is skipped when sent as "***". Requires step-up MFA
    /// (<see cref="StepUpOps.UpdateLdapPublisher"/>) and enforces the tenant fence.
    /// Audit emits before/after field snapshots on success and access-failure on cross-tenant
    /// or missing-publisher paths. The password value is never written to the audit payload.
    /// </summary>
    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateLdapPublisher, "id")]
    public async Task<IActionResult> Update(Guid caId, Guid id, [FromBody] UpdateLdapPublisherRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        var resolvedTenantId = await ResolveAndFenceCaAsync(caId);
        if (resolvedTenantId == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherUpdated,
                currentUser.User?.Id,
                currentUser.User?.Username,
                "LdapConfiguration", id.ToString(),
                new { CaId = caId, Reason = "ca-not-found-or-cross-tenant" },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "Certificate authority not found or outside accessible tenants.",
                certificateAuthorityId: caId);
            return NotFound(new { error = "LDAP publisher not found." });
        }

        var entity = await dbContext.LdapConfigurations
            .FirstOrDefaultAsync(c => c.Id == id && c.CertificateAuthorityId == caId);

        if (entity == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherUpdated,
                currentUser.User?.Id,
                currentUser.User?.Username,
                "LdapConfiguration", id.ToString(),
                new { CaId = caId, Reason = "publisher-not-found" },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "LDAP publisher not found.",
                certificateAuthorityId: caId,
                tenantId: resolvedTenantId);
            return NotFound(new { error = "LDAP publisher not found." });
        }

        // Snapshot fields BEFORE mutation for the audit "before" payload. Password is
        // intentionally excluded — never write secrets to audit, even at trace level.
        var before = new
        {
            entity.Name,
            entity.Host,
            entity.Port,
            entity.UseSsl,
            entity.Username,
            entity.BaseDn,
            entity.PublishCACert,
            entity.PublishCRL,
            entity.PublishDelta,
            entity.PublishUserCerts,
            entity.UserDnTemplate,
            entity.UpdateInterval,
            entity.Enabled,
        };

        if (request.Name != null) entity.Name = request.Name;
        if (request.Host != null) entity.Host = request.Host;
        if (request.Port.HasValue) entity.Port = request.Port.Value;
        if (request.UseSsl.HasValue) entity.UseSsl = request.UseSsl.Value;
        if (request.Username != null) entity.Username = request.Username;
        if (request.Password != null && request.Password != "***")
            entity.Password = secretProtector.Protect(request.Password);
        if (request.BaseDn != null) entity.BaseDn = request.BaseDn;
        if (request.PublishCACert.HasValue) entity.PublishCACert = request.PublishCACert.Value;
        if (request.PublishCRL.HasValue) entity.PublishCRL = request.PublishCRL.Value;
        if (request.PublishDelta.HasValue) entity.PublishDelta = request.PublishDelta.Value;
        if (request.PublishUserCerts.HasValue) entity.PublishUserCerts = request.PublishUserCerts.Value;
        if (request.UserDnTemplate != null) entity.UserDnTemplate = request.UserDnTemplate;
        if (request.UpdateInterval != null) entity.UpdateInterval = request.UpdateInterval;
        if (request.Enabled.HasValue) entity.Enabled = request.Enabled.Value;

        var passwordRotated = request.Password != null && request.Password != "***";

        await dbContext.SaveChangesAsync();

        var after = new
        {
            entity.Name,
            entity.Host,
            entity.Port,
            entity.UseSsl,
            entity.Username,
            entity.BaseDn,
            entity.PublishCACert,
            entity.PublishCRL,
            entity.PublishDelta,
            entity.PublishUserCerts,
            entity.UserDnTemplate,
            entity.UpdateInterval,
            entity.Enabled,
        };

        await audit.LogAsync(
            AuditActionType.LdapPublisherUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapConfiguration", entity.Id.ToString(),
            new { CaId = caId, PasswordRotated = passwordRotated, Before = before, After = after },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caId,
            tenantId: resolvedTenantId);

        return Ok(new { message = "LDAP publisher updated." });
    }

    /// <summary>
    /// Deletes an LDAP publisher configuration. Requires step-up MFA
    /// (<see cref="StepUpOps.DeleteLdapPublisher"/>) and enforces the tenant fence.
    /// Audit emits identifying fields of the deleted resource on success, and access-failure
    /// payloads on cross-tenant or missing-publisher paths.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.DeleteLdapPublisher, "id")]
    public async Task<IActionResult> Delete(Guid caId, Guid id)
    {
        await currentUser.EnsureLoadedAsync();

        var resolvedTenantId = await ResolveAndFenceCaAsync(caId);
        if (resolvedTenantId == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherDeleted,
                currentUser.User?.Id,
                currentUser.User?.Username,
                "LdapConfiguration", id.ToString(),
                new { CaId = caId, Reason = "ca-not-found-or-cross-tenant" },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "Certificate authority not found or outside accessible tenants.",
                certificateAuthorityId: caId);
            return NotFound(new { error = "LDAP publisher not found." });
        }

        var entity = await dbContext.LdapConfigurations
            .FirstOrDefaultAsync(c => c.Id == id && c.CertificateAuthorityId == caId);

        if (entity == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherDeleted,
                currentUser.User?.Id,
                currentUser.User?.Username,
                "LdapConfiguration", id.ToString(),
                new { CaId = caId, Reason = "publisher-not-found" },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "LDAP publisher not found.",
                certificateAuthorityId: caId,
                tenantId: resolvedTenantId);
            return NotFound(new { error = "LDAP publisher not found." });
        }

        var deletedSnapshot = new
        {
            entity.Id,
            entity.Name,
            entity.Host,
            entity.Port,
            entity.BaseDn,
            entity.Enabled,
            CaId = caId,
        };

        dbContext.LdapConfigurations.Remove(entity);
        await dbContext.SaveChangesAsync();

        await audit.LogAsync(
            AuditActionType.LdapPublisherDeleted,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapConfiguration", entity.Id.ToString(),
            deletedSnapshot,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caId,
            tenantId: resolvedTenantId);

        return Ok(new { message = "LDAP publisher deleted." });
    }

    /// <summary>
    /// Applies a batch of enable/disable/delete actions across several LDAP publishers belonging to
    /// one CA behind a SINGLE step-up token (<see cref="StepUpOps.BulkLdapPublisher"/>, bound to
    /// <c>caId</c>), so a multi-row selection on the Distribution page prompts for MFA exactly once
    /// instead of once per row. The tenant fence is enforced on the CA up front; each publisher row
    /// is resolved within that CA, and rows that are missing are skipped (not failed). The batch
    /// never aborts on a single error; a per-id summary is returned.
    /// </summary>
    [HttpPost("bulk")]
    [RequireStepUp(StepUpOps.BulkLdapPublisher, "caId")]
    public async Task<IActionResult> BulkUpdate(Guid caId, [FromBody] BulkLdapPublisherRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        if (request?.Actions == null || request.Actions.Count == 0)
            return BadRequest(new { error = "At least one action is required." });

        var resolvedTenantId = await ResolveAndFenceCaAsync(caId);
        if (resolvedTenantId == null)
        {
            await audit.LogAsync(
                AuditActionType.LdapPublisherUpdated,
                currentUser.User?.Id, currentUser.User?.Username,
                "LdapConfiguration", null,
                new { CaId = caId, Reason = "ca-not-found-or-cross-tenant", Bulk = true },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: "Certificate authority not found or outside accessible tenants.",
                certificateAuthorityId: caId);
            return NotFound(new { error = "Certificate authority not found." });
        }

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

            var entity = await dbContext.LdapConfigurations
                .FirstOrDefaultAsync(c => c.Id == id && c.CertificateAuthorityId == caId);
            if (entity == null)
            {
                results.Add(new { id, status = "not_found" });
                skipped++;
                continue;
            }

            try
            {
                if (verb == "delete")
                {
                    var deletedSnapshot = new { entity.Id, entity.Name, entity.Host, entity.Port, entity.BaseDn, entity.Enabled, CaId = caId };
                    dbContext.LdapConfigurations.Remove(entity);
                    await dbContext.SaveChangesAsync();

                    await audit.LogAsync(
                        AuditActionType.LdapPublisherDeleted,
                        currentUser.User?.Id, currentUser.User?.Username,
                        "LdapConfiguration", id.ToString(),
                        new { Bulk = true, Deleted = deletedSnapshot },
                        HttpContext.Connection.RemoteIpAddress?.ToString(),
                        certificateAuthorityId: caId,
                        tenantId: resolvedTenantId);
                }
                else
                {
                    var enabled = verb == "enable";
                    entity.Enabled = enabled;
                    await dbContext.SaveChangesAsync();

                    await audit.LogAsync(
                        AuditActionType.LdapPublisherUpdated,
                        currentUser.User?.Id, currentUser.User?.Username,
                        "LdapConfiguration", id.ToString(),
                        new { CaId = caId, Bulk = true, Enabled = enabled },
                        HttpContext.Connection.RemoteIpAddress?.ToString(),
                        certificateAuthorityId: caId,
                        tenantId: resolvedTenantId);
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

    /// <summary>
    /// Tests the LDAP connection for the specified publisher configuration. Enforces the
    /// tenant fence on the owning CA so callers cannot probe directories belonging to
    /// other tenants.
    /// </summary>
    [HttpPost("{id:guid}/test")]
    public async Task<IActionResult> TestConnection(Guid caId, Guid id)
    {
        if (await ResolveAndFenceCaAsync(caId) == null)
            return NotFound(new { error = "LDAP publisher not found." });

        var cfg = await dbContext.LdapConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id && c.CertificateAuthorityId == caId);

        if (cfg == null)
            return NotFound(new { error = "LDAP publisher not found." });

        try
        {
            var options = new LdapScheduleOptions
            {
                LdapHost = cfg.Host,
                LdapPort = cfg.Port,
                // Carried so the test exercises the connection the publisher will actually make.
                // Without it this reported success for a cleartext bind while the row said TLS,
                // which is worse than not testing at all: it confirmed a configuration that was
                // never in effect.
                UseSsl = cfg.UseSsl,
                BaseDn = cfg.BaseDn,
                Username = cfg.Username,
                Password = secretProtector.Unprotect(cfg.Password),
                TaskId = cfg.Id,
            };

            using var connection = LdapPublishHelper.Connect(options, TimeSpan.FromSeconds(10), logger);
            var transport = cfg.UseSsl ? "LDAPS" : "cleartext LDAP";
            return Ok(new { success = true, message = $"LDAP bind successful to {cfg.Host}:{cfg.Port} over {transport}." });
        }
        catch (Exception ex)
        {
            // Do NOT include ex.Message in the response — even admin-only messages
            // can end up in browser history and leak internal DNs/server paths.
            Serilog.Log.Warning(ex, "LDAP publisher test connection failed for CA {CaId}, publisher {PublisherId} ({Host}:{Port})", caId, id, cfg.Host, cfg.Port);
            return Ok(new { success = false, message = "LDAP connection failed." });
        }
    }
}

/// <summary>Request DTO for creating an LDAP publisher configuration.</summary>
public class CreateLdapPublisherRequest
{
    [Required, MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [Required, MaxLength(255)]
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 389;
    public bool UseSsl { get; set; }

    [MaxLength(255)]
    public string? Username { get; set; }

    [MaxLength(512)]
    public string? Password { get; set; }

    [Required, MaxLength(1024)]
    public string BaseDn { get; set; } = string.Empty;

    public bool PublishCACert { get; set; }
    public bool PublishCRL { get; set; }
    public bool PublishDelta { get; set; }
    public bool PublishUserCerts { get; set; }

    [MaxLength(1024)]
    public string? UserDnTemplate { get; set; }

    [MaxLength(100)]
    public string? UpdateInterval { get; set; }

    public bool Enabled { get; set; } = true;
}

/// <summary>Request DTO for updating an LDAP publisher configuration. Non-null fields are applied.</summary>
public class UpdateLdapPublisherRequest
{
    [MaxLength(255)]
    public string? Name { get; set; }

    [MaxLength(255)]
    public string? Host { get; set; }

    public int? Port { get; set; }
    public bool? UseSsl { get; set; }

    [MaxLength(255)]
    public string? Username { get; set; }

    [MaxLength(512)]
    public string? Password { get; set; }

    [MaxLength(1024)]
    public string? BaseDn { get; set; }

    public bool? PublishCACert { get; set; }
    public bool? PublishCRL { get; set; }
    public bool? PublishDelta { get; set; }
    public bool? PublishUserCerts { get; set; }

    [MaxLength(1024)]
    public string? UserDnTemplate { get; set; }

    [MaxLength(100)]
    public string? UpdateInterval { get; set; }

    public bool? Enabled { get; set; }
}

/// <summary>Request body for the bulk LDAP publisher action endpoint.</summary>
public class BulkLdapPublisherRequest
{
    /// <summary>The set of per-publisher actions to apply in this batch (all within the route's CA).</summary>
    public List<BulkLdapPublisherAction> Actions { get; set; } = new();
}

/// <summary>A single publisher action within a bulk LDAP request.</summary>
public class BulkLdapPublisherAction
{
    /// <summary>The LDAP publisher configuration id.</summary>
    public Guid Id { get; set; }

    /// <summary>One of <c>enable</c>, <c>disable</c>, or <c>delete</c> (case-insensitive).</summary>
    public string Action { get; set; } = string.Empty;
}
