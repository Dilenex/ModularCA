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
/// for instance CAs), Space, and CA. Scopes are
/// independent and parents are <b>ceilings</b>, not floors — a CA may require fewer approvals than
/// its space, never more. Distinct from the per-space <i>key</i>-ceremony quorum. The resolver
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
    ISpacePolicyChangeService spacePolicyChangeService,
    IControlledUserCeremonyService controlledUserSvc) : ControllerBase
{
    /// <summary>
    /// Returns the system quorum, the instance's CA-level quorum with the instance CAs, and every
    /// space and CA with its override and effective value. Effective: scope = override ?? 1;
    /// CA = override (capped at its scope) ?? scope. The instance's CA-level quorum is the value
    /// the system tenant held before 0.4.0; it is distinct from the system quorum.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        var systemQuorum = Math.Max(1, policy?.UserQuorum ?? 1);

        var spaces = await db.Spaces.AsNoTracking()
            .OrderBy(t => t.Name)
            .Select(t => new { t.Id, t.Name, Override = t.UserCeremonyRequiredApprovals })
            .ToListAsync();

        var cas = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => !c.IsDeleted)
            .Select(c => new { c.Id, c.Name, c.Label, c.SpaceId, Override = c.UserCeremonyRequiredApprovals })
            .ToListAsync();

        object ScopeDto(Guid? id, string name, int? scopeOverride)
        {
            var scopeEffective = Math.Max(1, scopeOverride ?? 1);
            var caDtos = cas.Where(c => c.SpaceId == id).Select(c => new
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
            spaces = spaces.Select(t => ScopeDto(t.Id, t.Name, t.Override)).ToList(),
        });
    }

    /// <summary>
    /// Sets (or clears, when null) the instance's CA-level user quorum, the ceiling for instance
    /// CAs. Step-up gated. System-super applies directly; any other caller opens an
    /// InstancePolicyChange ceremony (202 + ceremonyId).
    /// </summary>
    [HttpPut("instance")]
    [RequireStepUp(StepUpOps.UpdateSpaceSettings)]
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
    /// Sets (or clears, when null) a space's user-quorum override. Step-up gated like the space
    /// settings save. System-super applies directly; any other caller opens a SpacePolicyChange
    /// ceremony (202 + ceremonyId), mirroring <c>AdminSpaceController.UpdateSettings</c>.
    /// </summary>
    [HttpPut("space/{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateSpaceSettings, "id")]
    public async Task<IActionResult> SetSpace(Guid id, [FromBody] QuorumValueRequest request)
    {
        if (request.Quorum is int q && q < 1)
            return BadRequest(new { error = "Quorum must be at least 1, or null to clear the override." });

        var space = await db.Spaces.FirstOrDefaultAsync(t => t.Id == id);
        if (space == null) return NotFound(new { error = "Space not found." });

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (request.Quorum != space.UserCeremonyRequiredApprovals && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id))
            return await GateThroughCeremonyAsync(id, userQuorumIncluded: true, proposedUserQuorum: request.Quorum, caChanges: null);

        space.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.SpaceUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "Space", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = space.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Sets (or clears, when null) a CA's user-quorum override. Rejects a value above its scope's
    /// effective quorum — the space (or, for an instance CA, the instance) is the ceiling.
    /// Step-up gated; system-super applies directly, any other caller opens a policy-change
    /// ceremony on the CA's scope (202 + ceremonyId).
    /// </summary>
    [HttpPut("ca/{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateSpaceSettings, "id")]
    public async Task<IActionResult> SetCa(Guid id, [FromBody] QuorumValueRequest request)
    {
        var ca = await db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == id);
        if (ca == null) return NotFound(new { error = "CA not found." });

        if (request.Quorum is int q)
        {
            if (q < 1)
                return BadRequest(new { error = "Quorum must be at least 1, or null to inherit the space value." });

            var scope = await new ModularCA.Database.EffectivePolicyResolver(db).ResolveAsync(ca.SpaceId);
            var spaceEffective = Math.Max(1, (scope.Found ? scope.UserCeremonyRequiredApprovals : null) ?? 1);
            if (q > spaceEffective)
                return BadRequest(new { error = $"A CA's quorum can't exceed its {(ca.SpaceId == null ? "instance" : "space")}'s ({spaceEffective}). Use {spaceEffective} or lower, or clear it to inherit." });
        }

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (request.Quorum != ca.UserCeremonyRequiredApprovals && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id))
            return await GateThroughCeremonyAsync(ca.SpaceId, userQuorumIncluded: false, proposedUserQuorum: null,
                caChanges: [new ModularCA.Shared.Models.CaUserQuorumChange { CaId = ca.Id, ProposedQuorum = request.Quorum }]);

        ca.UserCeremonyRequiredApprovals = request.Quorum;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.CaUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CertificateAuthority", id.ToString(), new { UserCeremonyRequiredApprovals = request.Quorum },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { id, quorum = ca.UserCeremonyRequiredApprovals });
    }

    /// <summary>
    /// Opens a SpacePolicyChange ceremony (an InstancePolicyChange one for a null
    /// <paramref name="spaceId"/>) carrying a deferred user-quorum change (the same path the
    /// space settings save uses for non-super callers) and returns 202, or 409 when one is already
    /// pending for the scope.
    /// </summary>
    private async Task<IActionResult> GateThroughCeremonyAsync(
        Guid? spaceId, bool userQuorumIncluded, int? proposedUserQuorum,
        IReadOnlyList<ModularCA.Shared.Models.CaUserQuorumChange>? caChanges)
    {
        Guid ceremonyId;
        try
        {
            ceremonyId = await spacePolicyChangeService.InitiateChangeAsync(
                spaceId, null, null,
                currentUser.User!.Id, currentUser.User.Username,
                userQuorumIncluded: userQuorumIncluded,
                proposedUserQuorum: proposedUserQuorum,
                caUserQuorums: caChanges);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
        {
            return Conflict(new
            {
                error = spaceId == null
                    ? "An instance policy-change ceremony is already pending. Resolve or cancel it before opening a new one."
                    : "A space policy-change ceremony is already pending for this space. Resolve or cancel it before opening a new one."
            });
        }

        await audit.LogAsync(spaceId == null ? AuditActionType.SecurityPolicyUpdated : AuditActionType.SpaceUpdated,
            currentUser.User.Id, currentUser.User.Username,
            spaceId == null ? "SecurityPolicy" : "Space", spaceId?.ToString() ?? "instance",
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
