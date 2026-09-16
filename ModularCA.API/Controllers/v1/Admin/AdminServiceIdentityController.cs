using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Service identities: accounts that hold permissions for a non-person caller, such as the
/// enrollment identity a Kerberos realm acts as, and that can never sign in. Each lives at
/// system, tenant or CA scope; managing one needs <c>ca.manage</c> at that scope, and its
/// groups must lie within it.
/// </summary>
[ApiController]
[Route("api/v1/admin/service-identities")]
[Authorize]
public class AdminServiceIdentityController(
    ServiceIdentityService identities,
    ICurrentUserService currentUser,
    IAuditService audit,
    ModularCADbContext db) : ControllerBase
{
    /// <summary>The identities the caller may manage, with scope names and groups.</summary>
    [HttpGet]
    public async Task<IActionResult> List()
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var list = await identities.ListAsync(currentUser.User.Id);
        return Ok(await ProjectAsync(list));
    }

    /// <summary>One identity.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var user = await identities.GetAsync(id);
        if (user == null || !await identities.MayManageAsync(currentUser.User.Id, ServiceIdentityService.ScopeOf(user))) return NotFound();
        return Ok((await ProjectAsync([user]))[0]);
    }

    /// <summary>Creates an identity. No password exists for it, ever.</summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateUser)]
    public async Task<IActionResult> Create([FromBody] ServiceIdentityRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        try
        {
            var user = await identities.CreateAsync(currentUser.User.Id,
                new ServiceIdentitySpec(request.Username, request.DisplayName, request.Description,
                    new ServiceIdentityScope(request.TenantId, request.CaId), request.GroupIds ?? []));
            await LogAsync(AuditActionType.ServiceIdentityCreated, user, new { user.Username, user.ServiceScopeTenantId, user.ServiceScopeCaId, request.GroupIds });
            return Ok((await ProjectAsync([(await identities.GetAsync(user.Id))!]))[0]);
        }
        catch (UnauthorizedAccessException ex) { return StatusCode(403, new { error = ex.Message }); }
        catch (InvalidOperationException ex) { return BadRequest(new { error = ex.Message }); }
    }

    /// <summary>Changes display name, description and the active flag.</summary>
    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateUser, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] ServiceIdentityUpdateRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        try
        {
            var user = await identities.UpdateAsync(currentUser.User.Id, id, request.DisplayName, request.Description, request.IsActive);
            await LogAsync(AuditActionType.ServiceIdentityUpdated, user, new { user.Username, user.IsActive });
            return Ok((await ProjectAsync([(await identities.GetAsync(id))!]))[0]);
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException ex) { return StatusCode(403, new { error = ex.Message }); }
    }

    /// <summary>Replaces the identity's group memberships.</summary>
    [HttpPut("{id:guid}/groups")]
    [RequireStepUp(StepUpOps.UpdateUserGroups, "id")]
    public async Task<IActionResult> SetGroups(Guid id, [FromBody] ServiceIdentityGroupsRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        try
        {
            var user = await identities.SetGroupsAsync(currentUser.User.Id, id, request.GroupIds ?? []);
            await LogAsync(AuditActionType.ServiceIdentityGroupsChanged, user, new { user.Username, request.GroupIds });
            return Ok((await ProjectAsync([user]))[0]);
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException ex) { return StatusCode(403, new { error = ex.Message }); }
        catch (InvalidOperationException ex) { return BadRequest(new { error = ex.Message }); }
    }

    /// <summary>Deletes the identity. Refused while a Kerberos realm acts as it.</summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.DeleteUser, "id")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        try
        {
            var user = await identities.GetAsync(id);
            if (user == null) return NotFound();
            await identities.DeleteAsync(currentUser.User.Id, id);
            await LogAsync(AuditActionType.ServiceIdentityDeleted, user, new { user.Username });
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException ex) { return StatusCode(403, new { error = ex.Message }); }
        catch (InvalidOperationException ex) { return BadRequest(new { error = ex.Message }); }
    }

    private Task LogAsync(string action, UserEntity user, object details)
        => audit.LogAsync(action, currentUser.User?.Id, currentUser.User?.Username, "User", user.Id.ToString(), details,
            HttpContext.Connection.RemoteIpAddress?.ToString(), certificateAuthorityId: user.ServiceScopeCaId, tenantId: user.ServiceScopeTenantId);

    private async Task<List<object>> ProjectAsync(IReadOnlyList<UserEntity> users)
    {
        var tenantIds = users.Select(u => u.ServiceScopeTenantId).Where(t => t != null).Select(t => t!.Value).Distinct().ToList();
        var caIds = users.Select(u => u.ServiceScopeCaId).Where(c => c != null).Select(c => c!.Value).Distinct().ToList();
        var tenants = await db.Tenants.AsNoTracking().IgnoreQueryFilters().Where(t => tenantIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id, t => t.Name);
        var cas = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters().Where(c => caIds.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.Label);
        return users.Select(u => (object)new
        {
            u.Id,
            u.Username,
            u.DisplayName,
            u.Description,
            u.IsActive,
            u.CreatedAt,
            Scope = u.ServiceScopeCaId != null ? "ca" : u.ServiceScopeTenantId != null ? "tenant" : "system",
            TenantId = u.ServiceScopeTenantId,
            TenantName = u.ServiceScopeTenantId is Guid t && tenants.TryGetValue(t, out var tn) ? tn : null,
            CaId = u.ServiceScopeCaId,
            CaLabel = u.ServiceScopeCaId is Guid c && cas.TryGetValue(c, out var cl) ? cl : null,
            Groups = (u.GroupMemberships ?? []).Where(m => m.Group != null).Select(m => new
            {
                GroupId = m.GroupId,
                m.Group!.Name,
                m.Group.DisplayName,
                m.Group.CertificateAuthorityId,
                m.Group.TenantId,
                m.Group.TemplateName,
            }),
        }).ToList();
    }
}

/// <summary>Body for creating a service identity. Exactly one of the scope fields, or neither for a system identity.</summary>
public class ServiceIdentityRequest
{
    public string Username { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    /// <summary>Tenant scope. Ignored when <see cref="CaId"/> is set, since a CA carries its tenant.</summary>
    public Guid? TenantId { get; set; }
    /// <summary>CA scope.</summary>
    public Guid? CaId { get; set; }
    public List<Guid>? GroupIds { get; set; }
}

/// <summary>Body for updating a service identity's non-structural fields.</summary>
public class ServiceIdentityUpdateRequest
{
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
}

/// <summary>Body for replacing a service identity's group memberships.</summary>
public class ServiceIdentityGroupsRequest
{
    public List<Guid>? GroupIds { get; set; }
}
