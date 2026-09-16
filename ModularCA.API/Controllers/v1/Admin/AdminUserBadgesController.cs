using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.AccessBadges;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// An administrator managing another user's access badges: issuing a badge is how an
/// administrator hands someone a narrowed way of working without touching their grants.
/// The same rule applies as for self-management: a badge keeps only sources that user holds.
/// </summary>
[ApiController]
[Route("api/v1/admin/users/{userId:guid}/badges")]
[Authorize(Policy = "SystemAdmin")]
public class AdminUserBadgesController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    AccessBadgeService badges,
    IAuditService audit) : ControllerBase
{
    private Task<bool> UserExistsAsync(Guid userId) => db.Users.AnyAsync(u => u.Id == userId);

    private async Task AuditAsync(string action, Guid userId, Guid badgeId, object? details = null)
    {
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(action, currentUser.User?.Id, currentUser.User?.Username, "AccessBadge", badgeId.ToString(),
            details: details == null ? new { ForUserId = userId } : new { ForUserId = userId, Badge = details },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
    }

    /// <summary>The user's badges.</summary>
    [HttpGet]
    public async Task<IActionResult> List(Guid userId)
    {
        if (!await UserExistsAsync(userId)) return NotFound();
        return Ok(await badges.ListAsync(userId));
    }

    /// <summary>The grant sources the user holds and may have on a badge.</summary>
    [HttpGet("sources")]
    public async Task<IActionResult> Sources(Guid userId)
    {
        if (!await UserExistsAsync(userId)) return NotFound();
        return Ok(await badges.ListSourceOptionsAsync(userId));
    }

    /// <summary>Creates a badge for the user.</summary>
    [HttpPost]
    public async Task<IActionResult> Create(Guid userId, [FromBody] AccessBadgeWriteRequest request)
    {
        if (!await UserExistsAsync(userId)) return NotFound();
        await currentUser.EnsureLoadedAsync();
        try
        {
            var created = await badges.CreateAsync(userId, request, currentUser.User?.Id);
            await AuditAsync(AuditActionType.BadgeCreated, userId, created.Id, new { created.Name, Sources = created.Sources.Count, created.IsDefault });
            return Ok(created);
        }
        catch (AccessBadgeService.BadgeValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Replaces one of the user's badges.</summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid userId, Guid id, [FromBody] AccessBadgeWriteRequest request)
    {
        try
        {
            var updated = await badges.UpdateAsync(userId, id, request);
            if (updated == null) return NotFound();
            await AuditAsync(AuditActionType.BadgeUpdated, userId, id, new { updated.Name, Sources = updated.Sources.Count, updated.IsDefault });
            return Ok(updated);
        }
        catch (AccessBadgeService.BadgeValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Deletes one of the user's badges.</summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid userId, Guid id)
    {
        if (!await badges.DeleteAsync(userId, id)) return NotFound();
        await AuditAsync(AuditActionType.BadgeDeleted, userId, id);
        return NoContent();
    }
}
