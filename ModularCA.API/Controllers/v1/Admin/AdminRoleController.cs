using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing roles (named bundles of capabilities) and their capability bindings.
/// Taking a capability from a role, or deleting one, revokes through
/// <see cref="ISshLoginNameService"/> the SSH certificates of every user who could request from
/// an SSH CA only through that role.
/// </summary>
[ApiController]
[Route("api/v1/admin/roles")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminRoleController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    IControlledUserCeremonyService controlledUserSvc,
    ISshLoginNameService? sshLoginNames = null) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;

    /// <summary>
    /// Reconciles every SSH user certificate after a role lost a capability or was deleted:
    /// anyone who held the role, directly or through a group, may have lost the right to request.
    /// </summary>
    private async Task ReconcileSshAsync(string reason)
    {
        if (sshLoginNames != null)
            await sshLoginNames.ReconcileAllAsync(reason,
                new SshCaActor(_currentUser.User?.Id, _currentUser.User?.Username, HttpContext.Connection.RemoteIpAddress?.ToString()));
    }

    /// <summary>
    /// Lists all roles with their capability counts.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> GetAll()
    {
        var roles = await _db.Roles
            .Include(r => r.Capabilities)
            .AsNoTracking()
            .OrderBy(r => r.Name)
            .ToListAsync();

        return Ok(roles.Select(r => new
        {
            r.Id,
            r.Name,
            r.Description,
            r.IsBuiltIn,
            r.SpaceId,
            CapabilityCount = r.Capabilities.Count,
            r.CreatedAt
        }));
    }

    /// <summary>
    /// Returns a role by ID with its full list of capability bindings.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var role = await _db.Roles
            .Include(r => r.Capabilities)
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == id);

        if (role == null)
            return NotFound(new { error = $"Role with ID {id} not found" });

        return Ok(new
        {
            role.Id,
            role.Name,
            role.Description,
            role.IsBuiltIn,
            role.SpaceId,
            role.CreatedAt,
            Capabilities = role.Capabilities.Select(c => new
            {
                c.Id,
                c.Capability,
                c.ResourceType,
                c.ResourceId
            })
        });
    }

    /// <summary>
    /// Creates a custom (non-built-in) role. Requires step-up MFA because a freshly minted role
    /// becomes available for assignment immediately and can carry arbitrary capability bundles.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateRole)]
    public async Task<IActionResult> Create([FromBody] CreateRoleRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Role name is required" });

        var exists = await _db.Roles.AnyAsync(r => r.Name == request.Name.Trim());
        if (exists)
            return Conflict(new { error = $"A role with name '{request.Name.Trim()}' already exists" });

        var role = new RoleEntity
        {
            Name = request.Name.Trim(),
            Description = request.Description,
            IsBuiltIn = false,
            SpaceId = request.SpaceId,
            CreatedByUserId = _currentUser.User?.Id
        };

        _db.Roles.Add(role);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Role", role.Id.ToString(),
            new { Action = "Created", role.Name, role.Description, role.SpaceId },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetById), new { id = role.Id }, new
        {
            role.Id,
            role.Name,
            role.Description,
            role.IsBuiltIn,
            role.SpaceId,
            role.CreatedAt
        });
    }

    /// <summary>
    /// Updates a role's name and description. Built-in roles cannot be renamed. Requires
    /// step-up MFA because every assignment that references this role inherits the change.
    /// Adding or removing a controlled capability on an assigned role is system-super only (403 otherwise).
    /// When a capability is removed, the SSH certificates of users who may no longer request from
    /// their SSH CA are revoked.
    /// </summary>
    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateRole, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateRoleRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        var role = await _db.Roles.FindAsync(id);
        if (role == null)
            return NotFound(new { error = $"Role with ID {id} not found" });

        if (role.IsBuiltIn)
            return BadRequest(new { error = "Built-in roles cannot be renamed or modified" });

        static string Key(string cap, string? rt, Guid? rid) => $"{cap}|{rt}|{rid}";
        var toRemove = new List<RoleCapabilityEntity>();
        var toAdd = new List<RoleCapabilityInput>();
        var controlledChanged = false;
        await using var tx = await _db.Database.BeginTransactionAsync();
        if (request.Capabilities != null)
        {
            foreach (var c in request.Capabilities)
            {
                if (string.IsNullOrWhiteSpace(c.Capability) || !Capabilities.All.Contains(c.Capability))
                    return BadRequest(new { error = $"Unknown capability '{c.Capability}'. Must be one of: {string.Join(", ", Capabilities.All)}" });
            }

            // Same role lock as role assignment, so a concurrent assignment cannot miss an added capability.
            await ControlledTierResolver.LockRoleAsync(_db, id);
            var existing = await _db.RoleCapabilities.Where(rc => rc.RoleId == id).ToListAsync();
            var desiredKeys = request.Capabilities.Select(c => Key(c.Capability, c.ResourceType, c.ResourceId)).ToHashSet();
            var existingKeys = existing.Select(e => Key(e.Capability, e.ResourceType, e.ResourceId)).ToHashSet();
            toRemove = existing.Where(e => !desiredKeys.Contains(Key(e.Capability, e.ResourceType, e.ResourceId))).ToList();
            toAdd = request.Capabilities
                .Where(c => !existingKeys.Contains(Key(c.Capability, c.ResourceType, c.ResourceId)))
                .DistinctBy(c => Key(c.Capability, c.ResourceType, c.ResourceId))
                .ToList();

            // Tiers come only from effective (ResourceType == null) bindings, so diff those: swapping a
            // role-wide system.manage for a resource-scoped one is a removal.
            var effectiveBefore = EffectiveControlled(existing.Select(e => (e.Capability, e.ResourceType)));
            var effectiveAfter = EffectiveControlled(request.Capabilities.Select(c => (c.Capability, c.ResourceType)));
            var addedControlled = effectiveAfter.Except(effectiveBefore, StringComparer.OrdinalIgnoreCase).ToList();
            var removedControlled = effectiveBefore.Except(effectiveAfter, StringComparer.OrdinalIgnoreCase).ToList();
            controlledChanged = addedControlled.Count > 0 || removedControlled.Count > 0;
            if (addedControlled.Count > 0
                && await GuardControlledRoleChangeAsync(id, addedControlled, removing: false) is { } addDenied)
                return addDenied;
            if (removedControlled.Count > 0
                && await GuardControlledRoleChangeAsync(id, removedControlled, removing: true) is { } removeDenied)
                return removeDenied;
        }

        if (request.Name != null)
        {
            var trimmed = request.Name.Trim();
            var duplicate = await _db.Roles.AnyAsync(r => r.Name == trimmed && r.Id != id);
            if (duplicate)
                return Conflict(new { error = $"A role with name '{trimmed}' already exists" });
            role.Name = trimmed;
        }

        if (request.Description != null)
            role.Description = request.Description;

        // When the request carries a full desired capability set, reconcile it in the SAME step-up-gated
        // update — so the detail page saves the role's fields and capabilities with one MFA prompt
        // instead of a separate add/remove call (and step-up) per capability.
        _db.RoleCapabilities.RemoveRange(toRemove);
        foreach (var c in toAdd)
        {
            _db.RoleCapabilities.Add(new RoleCapabilityEntity
            {
                RoleId = id,
                Capability = c.Capability,
                ResourceType = c.ResourceType,
                ResourceId = c.ResourceId,
            });
        }
        int capsAdded = toAdd.Count, capsRemoved = toRemove.Count;

        await _db.SaveChangesAsync();
        await tx.CommitAsync();
        if (capsRemoved > 0)
            await ReconcileSshAsync($"role '{role.Name}' lost a capability");

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Role", role.Id.ToString(),
            new { Action = "Updated", request.Name, request.Description, CapabilitiesAdded = capsAdded, CapabilitiesRemoved = capsRemoved, ControlledCapabilityChanged = controlledChanged },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Role {role.Name} updated" });
    }

    /// <summary>
    /// Adds a capability binding to a role. The capability must be a recognized value from <see cref="Capabilities.All"/>.
    /// Requires step-up MFA because adding a capability to a role IS a role update — every existing
    /// assignment of this role inherits the new capability.
    /// Built-in roles are refused; adding a controlled capability to an assigned role is system-super only.
    /// The assigned-role check runs under the same row lock on the role that role assignment takes.
    /// </summary>
    [HttpPost("{id:guid}/capabilities")]
    [RequireStepUp(StepUpOps.UpdateRole, "id")]
    public async Task<IActionResult> AddCapability(Guid id, [FromBody] AddRoleCapabilityRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        var role = await _db.Roles.FindAsync(id);
        if (role == null)
            return NotFound(new { error = $"Role with ID {id} not found" });

        if (role.IsBuiltIn)
            return BadRequest(new { error = "Cannot add capabilities to built-in roles" });

        if (string.IsNullOrWhiteSpace(request.Capability))
            return BadRequest(new { error = "Capability is required" });

        if (!Capabilities.All.Contains(request.Capability))
            return BadRequest(new { error = $"Unknown capability '{request.Capability}'. Must be one of: {string.Join(", ", Capabilities.All)}" });

        var duplicate = await _db.RoleCapabilities.AnyAsync(c =>
            c.RoleId == id &&
            c.Capability == request.Capability &&
            c.ResourceType == request.ResourceType &&
            c.ResourceId == request.ResourceId);
        if (duplicate)
            return Conflict(new { error = "This capability binding already exists on the role" });

        // Same role lock as role assignment: an assignment racing this add either sees the new
        // capability when it classifies, or is visible to the assigned-role check below.
        await using var tx = await _db.Database.BeginTransactionAsync();
        await ControlledTierResolver.LockRoleAsync(_db, id);
        if (request.ResourceType == null && IsControlled(request.Capability)
            && await GuardControlledRoleChangeAsync(id, new[] { request.Capability }, removing: false) is { } denied)
            return denied;

        var capability = new RoleCapabilityEntity
        {
            RoleId = id,
            Capability = request.Capability,
            ResourceType = request.ResourceType,
            ResourceId = request.ResourceId
        };

        _db.RoleCapabilities.Add(capability);
        await _db.SaveChangesAsync();
        await tx.CommitAsync();

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "RoleCapability", capability.Id.ToString(),
            new { Action = "CapabilityAdded", RoleName = role.Name, request.Capability, request.ResourceType, request.ResourceId },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            capability.Id,
            capability.Capability,
            capability.ResourceType,
            capability.ResourceId
        });
    }

    /// <summary>
    /// Removes a capability binding from a role. Built-in roles cannot have capabilities removed.
    /// Requires step-up MFA because revoking a capability from a role can lock assigned principals
    /// out of resources mid-session.
    /// Removing a controlled capability from an assigned role is system-super only, and never orphans a scope.
    /// The SSH certificates of users who may no longer request from their SSH CA are revoked.
    /// </summary>
    [HttpDelete("{id:guid}/capabilities/{capabilityId:guid}")]
    [RequireStepUp(StepUpOps.UpdateRole, "id")]
    public async Task<IActionResult> RemoveCapability(Guid id, Guid capabilityId)
    {
        await _currentUser.EnsureLoadedAsync();

        var role = await _db.Roles.FindAsync(id);
        if (role == null)
            return NotFound(new { error = $"Role with ID {id} not found" });

        if (role.IsBuiltIn)
            return BadRequest(new { error = "Cannot remove capabilities from built-in roles" });

        await using var tx = await _db.Database.BeginTransactionAsync();
        await ControlledTierResolver.LockRoleAsync(_db, id);
        var capability = await _db.RoleCapabilities
            .FirstOrDefaultAsync(c => c.Id == capabilityId && c.RoleId == id);
        if (capability == null)
            return NotFound(new { error = "Capability binding not found on this role" });

        // Only a role-wide binding confers a tier, and removing one of two role-wide bindings of the
        // same capability leaves it in effect.
        var removesEffective = capability.ResourceType == null && IsControlled(capability.Capability)
            && !await _db.RoleCapabilities.AnyAsync(c => c.RoleId == id && c.Id != capabilityId
                && c.ResourceType == null && c.Capability == capability.Capability);
        if (removesEffective
            && await GuardControlledRoleChangeAsync(id, new[] { capability.Capability }, removing: true) is { } denied)
            return denied;

        _db.RoleCapabilities.Remove(capability);
        await _db.SaveChangesAsync();
        await tx.CommitAsync();
        await ReconcileSshAsync($"role '{role.Name}' lost a capability");

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "RoleCapability", capabilityId.ToString(),
            new { Action = "CapabilityRemoved", RoleName = role.Name, capability.Capability },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Capability removed from role" });
    }

    /// <summary>
    /// Deletes a custom role and cascade-deletes its assignments. Built-in roles cannot be deleted.
    /// Requires step-up MFA because deletion cascades through every assignment, potentially
    /// dropping authorization for many users and groups at once.
    /// Deleting an assigned role that carries a controlled capability is system-super only, and never orphans a scope.
    /// The SSH certificates of users who may no longer request from their SSH CA are revoked.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.DeleteRole, "id")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();

        await using var tx = await _db.Database.BeginTransactionAsync();
        await ControlledTierResolver.LockRoleAsync(_db, id);
        var role = await _db.Roles
            .Include(r => r.Capabilities)
            .Include(r => r.Assignments)
            .FirstOrDefaultAsync(r => r.Id == id);

        if (role == null)
            return NotFound(new { error = $"Role with ID {id} not found" });

        if (role.IsBuiltIn)
            return BadRequest(new { error = "Built-in roles cannot be deleted" });

        var controlledCaps = EffectiveControlled(role.Capabilities.Select(c => (c.Capability, c.ResourceType))).ToList();
        if (controlledCaps.Count > 0
            && await GuardControlledRoleChangeAsync(id, controlledCaps, removing: true, wholeRole: true) is { } denied)
            return denied;

        _db.RoleCapabilities.RemoveRange(role.Capabilities);
        _db.RoleAssignments.RemoveRange(role.Assignments);
        _db.Roles.Remove(role);
        await _db.SaveChangesAsync();
        await tx.CommitAsync();
        await ReconcileSshAsync($"role '{role.Name}' was deleted");

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Role", id.ToString(),
            new { Action = "Deleted", role.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Role {role.Name} deleted" });
    }

    /// <summary>True when <paramref name="capability"/> can confer a controlled tier at some scope.</summary>
    private static bool IsControlled(string capability) => ControlledTierResolver.IsControlledCapability(capability);

    /// <summary>
    /// The controlled capabilities among <paramref name="bindings"/> that are effective for tiering,
    /// i.e. bound role-wide (<c>ResourceType == null</c>), as the tier resolver reads them.
    /// </summary>
    private static HashSet<string> EffectiveControlled(IEnumerable<(string Capability, string? ResourceType)> bindings)
        => bindings.Where(b => b.ResourceType == null && IsControlled(b.Capability))
            .Select(b => b.Capability)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gate for adding or removing controlled capabilities on a role. It applies only when the
    /// capabilities confer a controlled tier through one of the role's current assignments or a
    /// pending/approved <c>AssignRole</c> ceremony (each read at its own scope, a group assignment at
    /// the group's); an unassigned role passes because assigning it later is ceremony-gated and
    /// re-validated at execute. Otherwise the change would promote or demote every
    /// holder at once, so only system-super may make it; and even super is refused on
    /// <paramref name="removing"/> when some affected tier would be left with no dominating user
    /// other than the actor. <paramref name="wholeRole"/> evaluates removal of every controlled
    /// capability of the role (deletion).
    /// </summary>
    private async Task<IActionResult?> GuardControlledRoleChangeAsync(Guid roleId, IReadOnlyCollection<string> capabilities, bool removing, bool wholeRole = false)
    {
        var tiers = await _controlledUserSvc.TiersConferredByRoleAsync(roleId, capabilities);
        if (tiers.Count == 0) return null;

        if (_currentUser.User == null || !await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id))
            return StatusCode(403, new
            {
                error = "This role is assigned and the change adds or removes a privileged capability, which would promote or demote "
                        + "every holder at once. Change who holds it through role assignments (ceremony-gated) instead, or ask a system-super."
            });

        if (!removing) return null;
        foreach (var tier in tiers)
        {
            if (await _controlledUserSvc.IsLastControlledSourceForRoleAsync(roleId, tier, _currentUser.User.Id, wholeRole ? null : capabilities))
                return BadRequest(new { error = "Refusing this change: it would remove the last controlled user of this scope." });
        }
        return null;
    }
}

/// <summary>
/// Request body for creating a new role. An unknown member (a pre-0.4.0 <c>tenantId</c>) is
/// refused with 400, never read as no space.
/// </summary>
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public class CreateRoleRequest
{
    /// <summary>Unique name for the role.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description of what the role grants.</summary>
    public string? Description { get; set; }

    /// <summary>Optional space scope. Null for system-wide roles.</summary>
    public Guid? SpaceId { get; set; }
}

/// <summary>
/// Request body for updating an existing role.
/// </summary>
public class UpdateRoleRequest
{
    /// <summary>New name for the role.</summary>
    public string? Name { get; set; }

    /// <summary>New description for the role.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// When non-null, the role's capability bindings are reconciled to exactly this set in the same
    /// step-up-gated update (add missing, remove extra). Null leaves capabilities untouched.
    /// </summary>
    public List<RoleCapabilityInput>? Capabilities { get; set; }
}

/// <summary>A desired capability binding for the reconcile-on-update path.</summary>
public class RoleCapabilityInput
{
    /// <summary>The capability string (must be one of <see cref="Capabilities.All"/>).</summary>
    public string Capability { get; set; } = string.Empty;

    /// <summary>Optional resource type for scoped capabilities.</summary>
    public string? ResourceType { get; set; }

    /// <summary>Optional resource ID for scoped capabilities.</summary>
    public Guid? ResourceId { get; set; }
}

/// <summary>
/// Request body for adding a capability binding to a role.
/// </summary>
public class AddRoleCapabilityRequest
{
    /// <summary>The capability string (e.g. "cert.request", "profile.manage").</summary>
    public string Capability { get; set; } = string.Empty;

    /// <summary>Optional resource type for scoped capabilities (e.g. "CertProfile").</summary>
    public string? ResourceType { get; set; }

    /// <summary>Optional resource ID for scoped capabilities.</summary>
    public Guid? ResourceId { get; set; }
}
