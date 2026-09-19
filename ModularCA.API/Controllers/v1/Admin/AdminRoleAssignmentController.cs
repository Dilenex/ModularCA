using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing role assignments (assigning roles to users or groups with optional scope).
/// </summary>
[ApiController]
[Route("api/v1/admin/role-assignments")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminRoleAssignmentController(
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
    /// Lists role assignments with optional filtering by user, group, or role.
    /// Joins with Role, User, and Group entities to include display names.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> GetAll(
        [FromQuery] Guid? userId,
        [FromQuery] Guid? groupId,
        [FromQuery] Guid? roleId)
    {
        var query = _db.RoleAssignments
            .Include(ra => ra.Role)
            .Include(ra => ra.User)
            .Include(ra => ra.Group)
            .AsNoTracking()
            .AsQueryable();

        if (userId.HasValue)
            query = query.Where(ra => ra.UserId == userId.Value);

        if (groupId.HasValue)
            query = query.Where(ra => ra.GroupId == groupId.Value);

        if (roleId.HasValue)
            query = query.Where(ra => ra.RoleId == roleId.Value);

        var assignments = await query
            .OrderByDescending(ra => ra.AssignedAt)
            .ToListAsync();

        return Ok(assignments.Select(ra => new
        {
            ra.Id,
            ra.RoleId,
            RoleName = ra.Role?.Name,
            ra.UserId,
            UserName = ra.User?.Username,
            ra.GroupId,
            GroupName = ra.Group?.DisplayName,
            ra.TenantId,
            ra.CertificateAuthorityId,
            ra.AssignedAt
        }));
    }

    /// <summary>
    /// Creates a new role assignment. Exactly one of UserId or GroupId must be provided.
    /// Validates that the referenced role exists before creating the assignment. Requires step-up
    /// MFA because a fresh assignment immediately grants every capability bound to the role.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.AssignRole)]
    [ProducesResponseType(201)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> Create([FromBody] CreateRoleAssignmentRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        // Validate exactly one of userId/groupId is set
        var hasUser = request.UserId.HasValue;
        var hasGroup = request.GroupId.HasValue;

        if (hasUser == hasGroup)
            return BadRequest(new { error = "Exactly one of UserId or GroupId must be provided." });

        // Validate the role exists
        var role = await _db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == request.RoleId);
        if (role == null)
            return NotFound(new { error = $"Role with ID {request.RoleId} not found." });

        // Validate the user exists if provided
        if (hasUser)
        {
            var userExists = await _db.Users.AnyAsync(u => u.Id == request.UserId!.Value);
            if (!userExists)
                return NotFound(new { error = $"User with ID {request.UserId} not found." });
        }

        // Validate the group exists if provided
        if (hasGroup)
        {
            var groupExists = await _db.CaGroups.AnyAsync(g => g.Id == request.GroupId!.Value);
            if (!groupExists)
                return NotFound(new { error = $"Group with ID {request.GroupId} not found." });
        }

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

        // Rate limit: prevent more than 1000 role assignments per user or group
        var existingCount = await _db.RoleAssignments.CountAsync(ra =>
            (request.UserId != null && ra.UserId == request.UserId) ||
            (request.GroupId != null && ra.GroupId == request.GroupId));
        if (existingCount >= 1000)
            return BadRequest(new { error = "Maximum of 1000 role assignments per user or group reached." });

        // Check for duplicate assignment
        var duplicate = await _db.RoleAssignments.AnyAsync(ra =>
            ra.RoleId == request.RoleId
            && ra.UserId == request.UserId
            && ra.GroupId == request.GroupId
            && ra.TenantId == request.TenantId
            && ra.CertificateAuthorityId == request.CertificateAuthorityId);

        if (duplicate)
            return Conflict(new { error = "An identical role assignment already exists." });

        // Controlled-user gate: assigning a role that carries a controlled capability (e.g.
        // system.manage) promotes a controlled user/group. A non-super must route it through a
        // ControlledUserChange ceremony; system-super assigns directly.
        var minted = await _controlledUserSvc.ClassifyRoleAssignmentAsync(request.RoleId, request.CertificateAuthorityId);
        if (minted != null && _currentUser.User != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id))
        {
            if (!await _controlledUserSvc.CanInitiateAsync(_currentUser.User.Id, minted.Value))
                return StatusCode(403, new { error = "You cannot assign a role above your own tier. A higher-tier admin must initiate this." });

            string? targetUsername = request.UserId.HasValue
                ? await _db.Users.Where(u => u.Id == request.UserId.Value).Select(u => u.Username).FirstOrDefaultAsync()
                : null;

            var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                new Shared.Models.ControlledUserChangeParameters
                {
                    ChangeType = "AssignRole",
                    TargetUserId = request.UserId ?? Guid.Empty,
                    TargetUsername = targetUsername,
                    RoleId = request.RoleId,
                    GroupId = request.GroupId,
                    TenantId = request.TenantId,
                    CertificateAuthorityId = request.CertificateAuthorityId,
                },
                minted.Value,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty);

            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = "This role assignment promotes a controlled user and requires a controlled-user ceremony. "
                          + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
            });
        }

        var assignment = new RoleAssignmentEntity
        {
            RoleId = request.RoleId,
            UserId = request.UserId,
            GroupId = request.GroupId,
            TenantId = request.TenantId,
            CertificateAuthorityId = request.CertificateAuthorityId,
            AssignedByUserId = _currentUser.User?.Id
        };

        _db.RoleAssignments.Add(assignment);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.ConfigUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "RoleAssignment",
            assignment.Id.ToString(),
            new
            {
                Action = "Created",
                assignment.RoleId,
                RoleName = role.Name,
                assignment.UserId,
                assignment.GroupId,
                assignment.TenantId,
                assignment.CertificateAuthorityId
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetAll), null, new
        {
            assignment.Id,
            assignment.RoleId,
            RoleName = role.Name,
            assignment.UserId,
            assignment.GroupId,
            assignment.TenantId,
            assignment.CertificateAuthorityId,
            assignment.AssignedAt
        });
    }

    /// <summary>
    /// Revokes (deletes) a role assignment by its ID. Requires step-up MFA because the
    /// revocation can immediately strip the target principal of role-derived capabilities.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.UnassignRole, "id")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();

        var assignment = await _db.RoleAssignments
            .Include(ra => ra.Role)
            .FirstOrDefaultAsync(ra => ra.Id == id);

        if (assignment == null)
            return NotFound(new { error = $"Role assignment with ID {id} not found." });

        // Controlled-user gate (demote): unassigning a role that carries a controlled capability
        // demotes a controlled user — non-super routes it through a ceremony, with the last-user guard.
        var demoteTier = await _controlledUserSvc.ClassifyRoleAssignmentAsync(assignment.RoleId, assignment.CertificateAuthorityId);
        if (demoteTier != null && _currentUser.User != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id))
        {
            if (assignment.UserId.HasValue
                && await _controlledUserSvc.CountDominatingControlledUsersAsync(demoteTier.Value, assignment.UserId.Value) == 0)
                return BadRequest(new { error = "Refusing to remove the last controlled user of this scope." });
            if (!await _controlledUserSvc.CanInitiateAsync(_currentUser.User.Id, demoteTier.Value))
                return StatusCode(403, new { error = "You cannot demote a privilege above your own tier." });

            var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                new Shared.Models.ControlledUserChangeParameters
                {
                    ChangeType = "UnassignRole",
                    TargetUserId = assignment.UserId ?? Guid.Empty,
                    RecordId = assignment.Id,
                    RoleId = assignment.RoleId,
                    GroupId = assignment.GroupId,
                    TenantId = assignment.TenantId,
                    CertificateAuthorityId = assignment.CertificateAuthorityId,
                },
                demoteTier.Value,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty);

            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = "Unassigning this role demotes a controlled user and requires a controlled-user ceremony. "
                          + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
            });
        }

        _db.RoleAssignments.Remove(assignment);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.ConfigUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "RoleAssignment",
            id.ToString(),
            new
            {
                Action = "Revoked",
                assignment.RoleId,
                RoleName = assignment.Role?.Name,
                assignment.UserId,
                assignment.GroupId
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Role assignment {id} revoked." });
    }
}

/// <summary>
/// Request body for creating a new role assignment.
/// </summary>
public class CreateRoleAssignmentRequest
{
    /// <summary>The role to assign.</summary>
    public Guid RoleId { get; set; }

    /// <summary>The user to assign the role to. Mutually exclusive with GroupId.</summary>
    public Guid? UserId { get; set; }

    /// <summary>The group to assign the role to. Mutually exclusive with UserId.</summary>
    public Guid? GroupId { get; set; }

    /// <summary>Optional tenant scope. Null for global assignments.</summary>
    public Guid? TenantId { get; set; }

    /// <summary>Optional CA scope. Null for tenant-wide or global assignments.</summary>
    public Guid? CertificateAuthorityId { get; set; }
}
