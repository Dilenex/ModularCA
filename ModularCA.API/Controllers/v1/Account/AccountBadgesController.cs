using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.AccessBadges;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Account;

/// <summary>
/// A user's own access badges: list, the grant sources available to build one from, create,
/// edit, delete. A badge can only keep sources the user already holds, so self-management
/// cannot escalate past the user's own rights. Editing or deleting the badge the session is
/// wearing so that the session gains rights asks for the same step-up as switching to a wider
/// badge (<see cref="AccessBadgePolicy.EditWidensSession"/>).
/// </summary>
[ApiController]
[Route("api/v1/account/badges")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AccountBadgesController(
    ICurrentUserService currentUser,
    AccessBadgeService badges,
    IAuditService audit,
    IAccessBadgeContext badgeContext,
    IDistributedCache cache) : ControllerBase
{
    private async Task<Guid?> CallerAsync()
    {
        await currentUser.EnsureLoadedAsync();
        return currentUser.IsAuthenticated ? currentUser.User?.Id : null;
    }

    /// <summary>
    /// The refusal of an edit that widens the session making it without step-up MFA, or null
    /// when the edit does not widen it or the step-up token (<c>X-MFA-Token</c>, operation
    /// <see cref="StepUpOps.SwitchBadge"/>) is valid. The worn badge is read live on every
    /// request, so without this a stolen access token wearing a narrow badge could edit or
    /// delete that badge and undo its own narrowing.
    /// </summary>
    /// <param name="userId">The caller.</param>
    /// <param name="badgeId">The badge being edited or deleted.</param>
    /// <param name="edited">Its sources afterwards; null when it is being deleted.</param>
    private async Task<IActionResult?> RefuseWideningWithoutStepUpAsync(Guid userId, Guid badgeId, IReadOnlySet<AccessBadgePolicy.SourceKey>? edited)
    {
        var wornBadgeId = (await badgeContext.GetWornAsync(userId))?.BadgeId;
        if (wornBadgeId != badgeId) return null;
        var stored = await badges.GetAsync(userId, badgeId);
        if (stored == null) return null;
        var storedKeys = stored.Sources.Select(s => new AccessBadgePolicy.SourceKey(s.Kind, s.SourceId)).ToHashSet();
        if (!AccessBadgePolicy.EditWidensSession(wornBadgeId, badgeId, storedKeys, edited))
            return null;

        var mfaToken = Request.Headers.TryGetValue("X-MFA-Token", out var h) ? h.ToString() : null;
        if (await MfaStepUpController.ValidateStepUpTokenAsync(cache, HttpContext, mfaToken, StepUpOps.SwitchBadge))
            return null;
        return StatusCode(403, new
        {
            error = "This change widens what this session may do and needs MFA re-verification. Call /api/v1/auth/mfa/verify-stepup first.",
            requiresStepUp = true,
            operation = StepUpOps.SwitchBadge,
        });
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

    /// <summary>
    /// Replaces a badge's name, description, default flag and sources. Giving the worn badge a
    /// source it lacked needs step-up MFA.
    /// </summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] AccessBadgeWriteRequest request)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        var edited = request.Sources.Select(s => new AccessBadgePolicy.SourceKey(s.Kind, s.SourceId)).ToHashSet();
        if (await RefuseWideningWithoutStepUpAsync(userId, id, edited) is { } refusal) return refusal;
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

    /// <summary>
    /// Deletes a badge and takes it off every session that carried it. Deleting the worn badge
    /// takes it off this session too, which widens it, so that needs step-up MFA.
    /// </summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        if (await CallerAsync() is not Guid userId) return Unauthorized();
        if (await RefuseWideningWithoutStepUpAsync(userId, id, edited: null) is { } refusal) return refusal;
        if (!await badges.DeleteAsync(userId, id)) return NotFound();
        await audit.LogAsync(AuditActionType.BadgeDeleted, userId, currentUser.User!.Username, "AccessBadge", id.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }
}
