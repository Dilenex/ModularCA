using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing direct user capability grants and querying effective permissions.
/// </summary>
[ApiController]
[Route("api/v1/admin/user-grants")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminUserGrantController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    IControlledUserCeremonyService controlledUserSvc) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;

    /// <summary>
    /// Lists user capability grants, optionally filtered by user ID.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> GetAll([FromQuery] Guid? userId)
    {
        var query = _db.UserCapabilityGrants.AsNoTracking().AsQueryable();

        if (userId.HasValue)
            query = query.Where(g => g.UserId == userId.Value);

        var grants = await query.OrderByDescending(g => g.GrantedAt).ToListAsync();

        return Ok(grants.Select(g => new
        {
            g.Id,
            g.UserId,
            g.Capability,
            g.TenantId,
            g.CertificateAuthorityId,
            g.ResourceType,
            g.ResourceId,
            g.GrantedAt
        }));
    }

    /// <summary>
    /// Creates a direct capability grant for a user. The capability must be a known value
    /// from <see cref="Capabilities.All"/>. Requires step-up MFA because direct grants bypass
    /// the role/group catalog and immediately expand the target user's effective authorization.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.GrantUserCapability)]
    [ProducesResponseType(201)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> Create([FromBody] CreateUserGrantRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (!Capabilities.All.Contains(request.Capability))
            return BadRequest(new { error = $"Unknown capability '{request.Capability}'. Must be one of: {string.Join(", ", Capabilities.All)}" });

        var userExists = await _db.Users.AnyAsync(u => u.Id == request.UserId);
        if (!userExists)
            return NotFound(new { error = $"User with ID {request.UserId} not found" });

        // Validate tenant exists if provided
        if (request.TenantId.HasValue)
        {
            var tenantExists = await _db.Tenants.AnyAsync(t => t.Id == request.TenantId.Value);
            if (!tenantExists)
                return BadRequest(new { error = $"Tenant with ID {request.TenantId.Value} not found." });
        }

        // Validate CA exists if provided, and belongs to the specified tenant
        if (request.CertificateAuthorityId.HasValue)
        {
            var ca = await _db.CertificateAuthorities.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == request.CertificateAuthorityId.Value);
            if (ca == null)
                return BadRequest(new { error = $"Certificate Authority with ID {request.CertificateAuthorityId.Value} not found." });
            if (request.TenantId.HasValue && ca.TenantId != request.TenantId.Value)
                return BadRequest(new { error = $"CA {request.CertificateAuthorityId.Value} does not belong to tenant {request.TenantId.Value}." });
        }

        // Rate limit: prevent more than 1000 direct capability grants per user
        var existingCount = await _db.UserCapabilityGrants.CountAsync(ug => ug.UserId == request.UserId);
        if (existingCount >= 1000)
            return BadRequest(new { error = "Maximum of 1000 direct capability grants per user reached." });

        // Controlled-user gate: granting a privilege-controlled capability (e.g. system.manage)
        // promotes a controlled user. A system-super applies it directly (falls through); any
        // other actor must route it through a ControlledUserChange ceremony approved by a quorum
        // that dominates the affected tier.
        var minted = _controlledUserSvc.ClassifyCapabilityGrant(request.Capability, request.CertificateAuthorityId);
        if (minted != null && _currentUser.User != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id))
        {
            if (!await _controlledUserSvc.CanInitiateAsync(_currentUser.User.Id, minted.Value))
                return StatusCode(403, new { error = "You cannot grant a privilege above your own tier. A higher-tier admin must initiate this." });

            var targetUsername = await _db.Users
                .Where(u => u.Id == request.UserId)
                .Select(u => u.Username)
                .FirstOrDefaultAsync();

            var ceremonyId = await _controlledUserSvc.InitiateCapabilityGrantAsync(
                request.UserId, targetUsername, request.Capability,
                request.TenantId, request.CertificateAuthorityId, request.ResourceType, request.ResourceId,
                minted.Value, _currentUser.User.Id, _currentUser.User.Username ?? string.Empty);

            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = "This grant promotes a controlled user and requires a controlled-user ceremony. "
                          + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
            });
        }

        var grant = new UserCapabilityGrantEntity
        {
            UserId = request.UserId,
            Capability = request.Capability,
            TenantId = request.TenantId,
            CertificateAuthorityId = request.CertificateAuthorityId,
            ResourceType = request.ResourceType,
            ResourceId = request.ResourceId,
            GrantedByUserId = _currentUser.User?.Id
        };

        _db.UserCapabilityGrants.Add(grant);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "UserCapabilityGrant", grant.Id.ToString(),
            new { grant.UserId, grant.Capability, grant.TenantId, grant.CertificateAuthorityId, grant.ResourceType, grant.ResourceId },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetAll), new { userId = grant.UserId }, new
        {
            grant.Id,
            grant.UserId,
            grant.Capability,
            grant.TenantId,
            grant.CertificateAuthorityId,
            grant.ResourceType,
            grant.ResourceId,
            grant.GrantedAt
        });
    }

    /// <summary>
    /// Revokes (deletes) a direct user capability grant by its ID. Requires step-up MFA because
    /// the revocation can lock another admin out of resources mid-session.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.RevokeUserCapability, "id")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();

        var grant = await _db.UserCapabilityGrants.FindAsync(id);
        if (grant == null)
            return NotFound(new { error = $"User grant with ID {id} not found" });

        // Controlled-user gate (demote): revoking a controlled capability demotes a controlled
        // user — non-super must route it through a ceremony, and we hard-refuse removing the last
        // dominating controlled user of the scope.
        var demoteTier = _controlledUserSvc.ClassifyCapabilityGrant(grant.Capability, grant.CertificateAuthorityId);
        if (demoteTier != null && _currentUser.User != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id))
        {
            if (await _controlledUserSvc.CountDominatingControlledUsersAsync(demoteTier.Value, grant.UserId) == 0)
                return BadRequest(new { error = "Refusing to remove the last controlled user of this scope." });
            if (!await _controlledUserSvc.CanInitiateAsync(_currentUser.User.Id, demoteTier.Value))
                return StatusCode(403, new { error = "You cannot demote a privilege above your own tier." });

            var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                new Shared.Models.ControlledUserChangeParameters
                {
                    ChangeType = "RevokeCapability",
                    TargetUserId = grant.UserId,
                    RecordId = grant.Id,
                    Capability = grant.Capability,
                    TenantId = grant.TenantId,
                    CertificateAuthorityId = grant.CertificateAuthorityId,
                },
                demoteTier.Value,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty);

            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = "Revoking this grant demotes a controlled user and requires a controlled-user ceremony. "
                          + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
            });
        }

        _db.UserCapabilityGrants.Remove(grant);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "UserCapabilityGrant", id.ToString(),
            new { Action = "Revoked", grant.UserId, grant.Capability },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"User grant {id} revoked" });
    }

    /// <summary>
    /// Returns a user's effective permissions aggregated from all sources: direct user grants,
    /// direct role assignments, group memberships with their grants, and group role assignments.
    /// </summary>
    [HttpGet("effective/{userId:guid}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetEffective(Guid userId)
    {
        var userExists = await _db.Users.AnyAsync(u => u.Id == userId);
        if (!userExists)
            return NotFound(new { error = $"User with ID {userId} not found" });

        // 1. Direct user grants
        var directGrants = await _db.UserCapabilityGrants
            .AsNoTracking()
            .Where(g => g.UserId == userId)
            .Select(g => new
            {
                g.Id,
                g.Capability,
                g.TenantId,
                g.CertificateAuthorityId,
                g.ResourceType,
                g.ResourceId,
                g.GrantedAt
            })
            .ToListAsync();

        // 2. Direct role assignments on the user (GroupId is null)
        var userRoleAssignments = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role)
                .ThenInclude(r => r.Capabilities)
            .Where(ra => ra.UserId == userId && ra.GroupId == null)
            .ToListAsync();

        var roleAssignments = userRoleAssignments.Select(ra => new
        {
            RoleName = ra.Role.Name,
            Capabilities = ra.Role.Capabilities.Select(c => new
            {
                c.Capability,
                c.ResourceType,
                c.ResourceId
            }),
            Scope = new
            {
                ra.TenantId,
                ra.CertificateAuthorityId
            }
        }).ToList();

        // 3. Group memberships -> group direct grants + group role assignments
        var groupMembershipIds = await _db.CaGroupMembers
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .Select(m => m.GroupId)
            .ToListAsync();

        var groups = await _db.CaGroups
            .AsNoTracking()
            .Where(g => groupMembershipIds.Contains(g.Id))
            .ToListAsync();

        var groupDirectGrants = await _db.CapabilityGrants
            .AsNoTracking()
            .Where(cg => groupMembershipIds.Contains(cg.GroupId))
            .ToListAsync();

        var groupRoleAssignments = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role)
                .ThenInclude(r => r.Capabilities)
            .Where(ra => ra.GroupId != null && groupMembershipIds.Contains(ra.GroupId.Value))
            .ToListAsync();

        var groupMemberships = groups.Select(g => new
        {
            GroupName = g.DisplayName ?? g.Name,
            DirectCapabilities = groupDirectGrants
                .Where(cg => cg.GroupId == g.Id)
                .Select(cg => new
                {
                    cg.Capability,
                    cg.ResourceType,
                    cg.ResourceId
                }),
            RoleAssignments = groupRoleAssignments
                .Where(ra => ra.GroupId == g.Id)
                .Select(ra => new
                {
                    RoleName = ra.Role.Name,
                    Capabilities = ra.Role.Capabilities.Select(c => new
                    {
                        c.Capability,
                        c.ResourceType,
                        c.ResourceId
                    }),
                    Scope = new
                    {
                        ra.TenantId,
                        ra.CertificateAuthorityId
                    }
                })
        }).ToList();

        return Ok(new
        {
            UserId = userId,
            DirectGrants = directGrants,
            RoleAssignments = roleAssignments,
            GroupMemberships = groupMemberships
        });
    }
}

/// <summary>
/// Request body for creating a direct user capability grant.
/// </summary>
public class CreateUserGrantRequest
{
    /// <summary>The user to grant the capability to.</summary>
    public Guid UserId { get; set; }

    /// <summary>The capability to grant (must be a value from <see cref="Capabilities.All"/>).</summary>
    public string Capability { get; set; } = string.Empty;

    /// <summary>Optional tenant scope. Null for global.</summary>
    public Guid? TenantId { get; set; }

    /// <summary>Optional CA scope. Null for all CAs in scope.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>Optional resource type for resource-scoped grants (e.g. "CertProfile").</summary>
    public string? ResourceType { get; set; }

    /// <summary>Optional resource ID for resource-scoped grants.</summary>
    public Guid? ResourceId { get; set; }
}
