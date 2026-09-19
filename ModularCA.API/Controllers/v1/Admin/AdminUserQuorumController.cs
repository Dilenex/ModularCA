using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for the controlled-user ("user") ceremony quorum, configurable per scope:
/// System (read here; written via the security-policy endpoint), Tenant, and CA. Scopes are
/// independent and parents are <b>ceilings</b>, not floors — a CA may require fewer approvals than
/// its tenant, never more. Distinct from the per-tenant <i>key</i>-ceremony quorum. The resolver
/// lives in <c>ControlledUserCeremonyService.ResolveUserQuorumAsync</c>.
/// </summary>
[ApiController]
[Route("api/v1/admin/user-quorum")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminUserQuorumController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit) : ControllerBase
{
    /// <summary>
    /// Returns the system quorum plus every tenant and CA with its override and effective value.
    /// Effective: tenant = override ?? 1; CA = override (capped at tenant) ?? tenant.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var systemQuorum = Math.Max(1, (await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync())?.UserQuorum ?? 1);

        var tenants = await db.Tenants.AsNoTracking()
            .OrderBy(t => t.Name)
            .Select(t => new { t.Id, t.Name, Override = t.UserCeremonyRequiredApprovals })
            .ToListAsync();

        var cas = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => !c.IsDeleted)
            .Select(c => new { c.Id, c.Name, c.Label, c.TenantId, Override = c.UserCeremonyRequiredApprovals })
            .ToListAsync();
        var casByTenant = cas.GroupBy(c => c.TenantId).ToDictionary(g => g.Key, g => g.ToList());

        var tenantDtos = tenants.Select(t =>
        {
            var tenantEffective = Math.Max(1, t.Override ?? 1);
            var caDtos = casByTenant.GetValueOrDefault(t.Id, new()).Select(c => new
            {
                c.Id,
                c.Name,
                c.Label,
                @override = c.Override,
                // CA effective is capped by the tenant (ceiling), else inherits the tenant.
                effective = c.Override.HasValue ? Math.Max(1, Math.Min(c.Override.Value, tenantEffective)) : tenantEffective,
            }).ToList();

            return new { t.Id, t.Name, @override = t.Override, effective = tenantEffective, cas = caDtos };
        }).ToList();

        return Ok(new { system = new { quorum = systemQuorum }, tenants = tenantDtos });
    }

    /// <summary>Sets (or clears, when null) a tenant's user-quorum override.</summary>
    [HttpPut("tenant/{id:guid}")]
    public async Task<IActionResult> SetTenant(Guid id, [FromBody] QuorumValueRequest request)
    {
        if (request.Quorum is int q && q < 1)
            return BadRequest(new { error = "Quorum must be at least 1, or null to clear the override." });

        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == id);
        if (tenant == null) return NotFound(new { error = "Tenant not found." });

        tenant.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.TenantUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "Tenant", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = tenant.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Sets (or clears, when null) a CA's user-quorum override. Rejects a value above the tenant's
    /// effective quorum — the tenant is the ceiling.
    /// </summary>
    [HttpPut("ca/{id:guid}")]
    public async Task<IActionResult> SetCa(Guid id, [FromBody] QuorumValueRequest request)
    {
        var ca = await db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == id);
        if (ca == null) return NotFound(new { error = "CA not found." });

        if (request.Quorum is int q)
        {
            if (q < 1)
                return BadRequest(new { error = "Quorum must be at least 1, or null to inherit the tenant value." });

            var tq = await db.Tenants.Where(t => t.Id == ca.TenantId)
                .Select(t => t.UserCeremonyRequiredApprovals).FirstOrDefaultAsync();
            var tenantEffective = Math.Max(1, tq ?? 1);
            if (q > tenantEffective)
                return BadRequest(new { error = $"A CA's quorum can't exceed its tenant's ({tenantEffective}). Use {tenantEffective} or lower, or clear it to inherit." });
        }

        ca.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CaUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CertificateAuthority", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = ca.UserCeremonyRequiredApprovals });
    }
}

/// <summary>Request body carrying a single quorum value; null clears the override.</summary>
public class QuorumValueRequest
{
    /// <summary>The new override, or null to clear it (inherit the parent scope).</summary>
    public int? Quorum { get; set; }
}
