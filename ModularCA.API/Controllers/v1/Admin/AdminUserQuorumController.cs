using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for the controlled-user ("user") ceremony quorum, configurable per scope:
/// System (read here; written via the security-policy endpoint), Instance (the CA-level ceiling
/// for instance CAs), Tenant, and CA. Scopes are
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
    IAuditService audit,
    ITenantPolicyChangeService tenantPolicyChangeService,
    IControlledUserCeremonyService controlledUserSvc) : ControllerBase
{
    /// <summary>
    /// Returns the system quorum, the instance's CA-level quorum with the instance CAs, and every
    /// tenant and CA with its override and effective value. Effective: scope = override ?? 1;
    /// CA = override (capped at its scope) ?? scope. The instance's CA-level quorum is the value
    /// the System tenant held before 0.4.0; it is distinct from the system quorum.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        var systemQuorum = Math.Max(1, policy?.UserQuorum ?? 1);

        var tenants = await db.Tenants.AsNoTracking()
            .OrderBy(t => t.Name)
            .Select(t => new { t.Id, t.Name, Override = t.UserCeremonyRequiredApprovals })
            .ToListAsync();

        var cas = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => !c.IsDeleted)
            .Select(c => new { c.Id, c.Name, c.Label, c.TenantId, Override = c.UserCeremonyRequiredApprovals })
            .ToListAsync();

        object ScopeDto(Guid? id, string name, int? scopeOverride)
        {
            var scopeEffective = Math.Max(1, scopeOverride ?? 1);
            var caDtos = cas.Where(c => c.TenantId == id).Select(c => new
            {
                c.Id,
                c.Name,
                c.Label,
                @override = c.Override,
                // CA effective is capped by its scope (ceiling), else inherits the scope.
                effective = c.Override.HasValue ? Math.Max(1, Math.Min(c.Override.Value, scopeEffective)) : scopeEffective,
            }).ToList();
            return new { Id = id, Name = name, @override = scopeOverride, effective = scopeEffective, cas = caDtos };
        }

        return Ok(new
        {
            system = new { quorum = systemQuorum },
            instance = ScopeDto(null, "Instance", policy?.UserCeremonyRequiredApprovals),
            tenants = tenants.Select(t => ScopeDto(t.Id, t.Name, t.Override)).ToList(),
        });
    }

    /// <summary>
    /// Sets (or clears, when null) the instance's CA-level user quorum, the ceiling for instance
    /// CAs. Step-up gated. System-super applies directly; any other caller opens an
    /// InstancePolicyChange ceremony (202 + ceremonyId).
    /// </summary>
    [HttpPut("instance")]
    [RequireStepUp(StepUpOps.UpdateTenantSettings)]
    public async Task<IActionResult> SetInstance([FromBody] QuorumValueRequest request)
    {
        if (request.Quorum is int q && q < 1)
            return BadRequest(new { error = "Quorum must be at least 1, or null to clear the override." });

        var policy = await db.SecurityPolicies.FirstOrDefaultAsync();
        if (policy == null) return NotFound(new { error = "No security policy is configured." });

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (request.Quorum != policy.UserCeremonyRequiredApprovals && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id))
            return await GateThroughCeremonyAsync(null, userQuorumIncluded: true, proposedUserQuorum: request.Quorum, caChanges: null);

        policy.UserCeremonyRequiredApprovals = request.Quorum;
        policy.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.SecurityPolicyUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "SecurityPolicy", policy.Id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { quorum = policy.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Sets (or clears, when null) a tenant's user-quorum override. Step-up gated like the tenant
    /// settings save. System-super applies directly; any other caller opens a TenantPolicyChange
    /// ceremony (202 + ceremonyId), mirroring <c>AdminTenantController.UpdateSettings</c>.
    /// </summary>
    [HttpPut("tenant/{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateTenantSettings, "id")]
    public async Task<IActionResult> SetTenant(Guid id, [FromBody] QuorumValueRequest request)
    {
        if (request.Quorum is int q && q < 1)
            return BadRequest(new { error = "Quorum must be at least 1, or null to clear the override." });

        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == id);
        if (tenant == null) return NotFound(new { error = "Tenant not found." });

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (request.Quorum != tenant.UserCeremonyRequiredApprovals && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id))
            return await GateThroughCeremonyAsync(id, userQuorumIncluded: true, proposedUserQuorum: request.Quorum, caChanges: null);

        tenant.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.TenantUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "Tenant", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = tenant.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Sets (or clears, when null) a CA's user-quorum override. Rejects a value above its scope's
    /// effective quorum — the tenant (or, for an instance CA, the instance) is the ceiling.
    /// Step-up gated; system-super applies directly, any other caller opens a policy-change
    /// ceremony on the CA's scope (202 + ceremonyId).
    /// </summary>
    [HttpPut("ca/{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateTenantSettings, "id")]
    public async Task<IActionResult> SetCa(Guid id, [FromBody] QuorumValueRequest request)
    {
        var ca = await db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == id);
        if (ca == null) return NotFound(new { error = "CA not found." });

        if (request.Quorum is int q)
        {
            if (q < 1)
                return BadRequest(new { error = "Quorum must be at least 1, or null to inherit the tenant value." });

            var scope = await new ModularCA.Database.EffectivePolicyResolver(db).ResolveAsync(ca.TenantId);
            var tenantEffective = Math.Max(1, (scope.Found ? scope.UserCeremonyRequiredApprovals : null) ?? 1);
            if (q > tenantEffective)
                return BadRequest(new { error = $"A CA's quorum can't exceed its {(ca.TenantId == null ? "instance" : "tenant")}'s ({tenantEffective}). Use {tenantEffective} or lower, or clear it to inherit." });
        }

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (request.Quorum != ca.UserCeremonyRequiredApprovals && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id))
            return await GateThroughCeremonyAsync(ca.TenantId, userQuorumIncluded: false, proposedUserQuorum: null,
                caChanges: [new ModularCA.Shared.Models.CaUserQuorumChange { CaId = ca.Id, ProposedQuorum = request.Quorum }]);

        ca.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.CaUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CertificateAuthority", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = ca.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Opens a TenantPolicyChange ceremony (an InstancePolicyChange one for a null
    /// <paramref name="tenantId"/>) carrying a deferred user-quorum change (the same path the
    /// tenant settings save uses for non-super callers) and returns 202, or 409 when one is already
    /// pending for the scope.
    /// </summary>
    private async Task<IActionResult> GateThroughCeremonyAsync(
        Guid? tenantId, bool userQuorumIncluded, int? proposedUserQuorum,
        IReadOnlyList<ModularCA.Shared.Models.CaUserQuorumChange>? caChanges)
    {
        Guid ceremonyId;
        try
        {
            ceremonyId = await tenantPolicyChangeService.InitiateChangeAsync(
                tenantId, null, null,
                currentUser.User!.Id, currentUser.User.Username,
                userQuorumIncluded: userQuorumIncluded,
                proposedUserQuorum: proposedUserQuorum,
                caUserQuorums: caChanges);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
        {
            return Conflict(new
            {
                error = tenantId == null
                    ? "An instance policy-change ceremony is already pending. Resolve or cancel it before opening a new one."
                    : "A tenant policy-change ceremony is already pending for this tenant. Resolve or cancel it before opening a new one."
            });
        }

        await audit.LogAsync(tenantId == null ? AuditActionType.SecurityPolicyUpdated : AuditActionType.TenantUpdated,
            currentUser.User.Id, currentUser.User.Username,
            tenantId == null ? "SecurityPolicy" : "Tenant", tenantId?.ToString() ?? "instance",
            new { GatedThroughCeremony = true, CeremonyId = ceremonyId, ProposedUserQuorum = proposedUserQuorum, CaUserQuorums = caChanges },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Accepted(new
        {
            ceremonyId,
            requiresCeremony = true,
            message = "Changing a user-approval quorum requires ceremony approval. Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
        });
    }
}

/// <summary>Request body carrying a single quorum value; null clears the override.</summary>
public class QuorumValueRequest
{
    /// <summary>The new override, or null to clear it (inherit the parent scope).</summary>
    public int? Quorum { get; set; }
}
