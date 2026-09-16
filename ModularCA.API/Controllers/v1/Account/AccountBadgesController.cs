using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.AccessBadges;

namespace ModularCA.API.Controllers.v1.Account;

/// <summary>
/// A user's own access badges: list, the grant sources available to build one from, create,
/// edit, delete. A badge can only keep sources the user already holds, so self-management
/// cannot escalate; it can only narrow.
/// </summary>
[ApiController]
[Route("api/v1/account/badges")]
[Authorize]
public class AccountBadgesController(
    ICurrentUserService currentUser,
    AccessBadgeService badges,
    IAuditService audit) : ControllerBase
{
    private async Task<Guid?> CallerAsync()
    {
        await currentUser.EnsureLoadedAsync();
        return currentUser.IsAuthenticated ? currentUser.User?.Id : null;
    }

    /// <summary>The caller's badges.</summary>
    [HttpGet]
    public async Task<IActionResult> List()
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        return Ok(await badges.ListAsync(userId));
    }

    /// <summary>The grant sources the caller holds and may put on a badge.</summary>
    [HttpGet("sources")]
    public async Task<IActionResult> Sources()
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        return Ok(await badges.ListSourceOptionsAsync(userId));
    }

    /// <summary>Creates a badge.</summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] AccessBadgeWriteRequest request)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        try
        {
            var created = await badges.CreateAsync(userId, request, userId);
            await audit.LogAsync(AuditActionType.BadgeCreated, userId, currentUser.User!.Username, "AccessBadge", created.Id.ToString(),
                details: new { created.Name, Sources = created.Sources.Count, created.IsDefault }, sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
            return CreatedAtAction(nameof(Get), new { id = created.Id }, created);
        }
        catch (AccessBadgeService.BadgeValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>One badge.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        var badge = await badges.GetAsync(userId, id);
        return badge == null ? NotFound() : Ok(badge);
    }

    /// <summary>Replaces a badge's name, description, default flag and sources.</summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] AccessBadgeWriteRequest request)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        try
        {
            var updated = await badges.UpdateAsync(userId, id, request);
            if (updated == null) return NotFound();
            await audit.LogAsync(AuditActionType.BadgeUpdated, userId, currentUser.User!.Username, "AccessBadge", id.ToString(),
                details: new { updated.Name, Sources = updated.Sources.Count, updated.IsDefault }, sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
            return Ok(updated);
        }
        catch (AccessBadgeService.BadgeValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Deletes a badge and takes it off every session that carried it.</summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        if (!await badges.DeleteAsync(userId, id)) return NotFound();
        await audit.LogAsync(AuditActionType.BadgeDeleted, userId, currentUser.User!.Username, "AccessBadge", id.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }
}
