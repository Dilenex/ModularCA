using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.AccessBadges;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Auth;

/// <summary>
/// Puts an access badge on, takes it off, or switches to another. Mints a fresh access token
/// carrying the badge and records it on the session's refresh token so later refreshes keep it.
/// </summary>
/// <remarks>
/// Narrowing is free; broadening (taking a badge off, or switching to one that keeps a source
/// the current one does not) requires step-up MFA, presented as <c>X-MFA-Token</c> for
/// <see cref="StepUpOps.SwitchBadge"/>. Every switch is audited as
/// <see cref="AuditActionType.BadgeSwitched"/> with both sides named.
/// </remarks>
[ApiController]
[Route("api/v1/auth/badge")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AccessBadgeSwitchController(
    ICurrentUserService currentUser,
    ModularCADbContext db,
    IJwtTokenService jwt,
    IAccessBadgeContext badgeContext,
    IDistributedCache cache,
    IAuditService audit) : ControllerBase
{
    /// <summary>Switches the session's badge. <c>BadgeId</c> null takes the worn badge off.</summary>
    [HttpPost]
    public async Task<IActionResult> Switch([FromBody] AccessBadgeSwitchRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (!currentUser.IsAuthenticated || currentUser.User == null)
            return Unauthorized();
        var user = currentUser.User;
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        // The session: the caller's own live refresh token.
        var hashed = JwtTokenService.HashRefreshToken(request.RefreshToken);
        var session = await db.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == hashed && t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);
        if (session == null)
            return Unauthorized(new { error = "The refresh token does not belong to a live session of this account." });

        // What is worn now, from the token; what is asked for, from the body.
        var worn = await badgeContext.GetWornAsync(user.Id);
        IReadOnlySet<AccessBadgePolicy.SourceKey>? currentKeys = null;
        if (worn != null)
        {
            var current = await db.AccessBadges.AsNoTracking().Include(b => b.Sources).FirstOrDefaultAsync(b => b.Id == worn.BadgeId);
            currentKeys = current == null ? new HashSet<AccessBadgePolicy.SourceKey>() : AccessBadgePolicy.KeysOf(current.Sources);
        }

        Shared.Entities.AccessBadgeEntity? target = null;
        IReadOnlySet<AccessBadgePolicy.SourceKey>? targetKeys = null;
        if (request.BadgeId is Guid badgeId)
        {
            target = await db.AccessBadges.AsNoTracking().Include(b => b.Sources).FirstOrDefaultAsync(b => b.Id == badgeId && b.UserId == user.Id);
            if (target == null)
                return NotFound(new { error = "No such badge on this account." });
            targetKeys = AccessBadgePolicy.KeysOf(target.Sources);
        }

        if (AccessBadgePolicy.IsBroadening(currentKeys, targetKeys))
        {
            var mfaToken = Request.Headers.TryGetValue("X-MFA-Token", out var h) ? h.ToString() : null;
            var ok = await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.SwitchBadge);
            if (!ok)
            {
                return StatusCode(403, new
                {
                    error = "Widening what this session may do needs MFA re-verification. Call /api/v1/auth/mfa/verify-stepup first.",
                    requiresStepUp = true,
                    operation = StepUpOps.SwitchBadge,
                });
            }
        }

        var groups = await db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group).ThenInclude(g => g.Grants)
            .Select(gm => gm.Group)
            .ToListAsync();
        var mfaSetupRequired = User.FindFirst("mfa_setup_required")?.Value == "true";
        var claim = target == null ? null : new AccessBadgeClaim(target.Id, target.Name);
        var (token, expiresAt) = jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired, claim);

        session.AccessBadgeId = target?.Id;
        session.LastActivityAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        await audit.LogAsync(AuditActionType.BadgeSwitched, user.Id, user.Username,
            targetEntityType: "AccessBadge", targetEntityId: target?.Id.ToString(),
            details: new
            {
                From = worn == null ? null : new { worn.BadgeId, worn.Name },
                To = target == null ? null : new { target.Id, target.Name },
                Broadening = AccessBadgePolicy.IsBroadening(currentKeys, targetKeys),
            },
            sourceIp: sourceIp);

        return Ok(new AccessBadgeSwitchResponse
        {
            Token = token,
            ExpiresAt = expiresAt,
            Badge = target == null ? null : new AccessBadgeSummary { Id = target.Id, Name = target.Name },
        });
    }
}
