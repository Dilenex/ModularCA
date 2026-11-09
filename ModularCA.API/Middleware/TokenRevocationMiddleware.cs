using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Auth.Services;
using ModularCA.Database;

namespace ModularCA.API.Middleware;

/// <summary>
/// Checks whether the current request's JWT has been revoked or superseded.
/// <para>
/// Two layers of validation:
/// </para>
/// <list type="number">
///   <item>
///     <b>Per-jti blacklist</b>: logout adds the jti to the distributed cache. A
///     lookup hit results in an immediate 401.
///   </item>
///   <item>
///     <b>stamp/ghash check</b>: the JWT carries the user's
///     <see cref="Shared.Entities.UserEntity.SecurityStamp"/> as a <c>stamp</c>
///     claim and a SHA-256 of the user's sorted group IDs as a <c>ghash</c> claim.
///     The middleware compares both against the current DB values and 401s on
///     mismatch — so admin-initiated disable/lock/password-reset/group-change
///     invalidates outstanding tokens immediately instead of waiting for TTL.
///     A 30-second per-user cache slot keeps the round-trip cost low on hot paths.
///   </item>
/// </list>
/// </summary>
public class TokenRevocationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IDistributedCache _cache;

    // Short cache TTL so admin actions propagate quickly. Keep in sync with the
    // documented "admin disable/lock propagation window".
    private static readonly TimeSpan StampCacheTtl = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRevocationMiddleware"/> class.
    /// </summary>
    public TokenRevocationMiddleware(RequestDelegate next, IDistributedCache cache)
    {
        _next = next;
        _cache = cache;
    }

    /// <summary>
    /// For authenticated requests bearing a JWT, first checks the per-jti revocation
    /// cache and then validates the <c>stamp</c>/<c>ghash</c> claims against the
    /// current DB state. Returns 401 when either check fails.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var jti = context.User.FindFirst("jti")?.Value;
            if (!string.IsNullOrEmpty(jti))
            {
                var revoked = await _cache.GetStringAsync($"revoked-jwt:{jti}");
                if (revoked != null)
                {
                    await Write401(context, "Token has been revoked", "TOKEN_REVOKED");
                    return;
                }
            }

            // Stamp + ghash claim validation.
            var subClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var stampClaim = context.User.FindFirst("stamp")?.Value;
            var ghashClaim = context.User.FindFirst("ghash")?.Value;

            // If the JWT carries a sub claim, enforce stamp/ghash. Legacy tokens without
            // the claims (issued before this upgrade) are allowed through and will
            // naturally expire within the configured ExpirationMinutes.
            if (Guid.TryParse(subClaim, out var userId) && !string.IsNullOrEmpty(stampClaim))
            {
                // Cache slot: "user-stamp:{id}" => "{stamp}|{ghash}"
                var cacheKey = ModularCA.Core.Helpers.UserSessionTermination.StampCacheKey(userId);
                var cached = await _cache.GetStringAsync(cacheKey);
                string? dbStamp;
                string? dbGhash;

                if (cached != null)
                {
                    var parts = cached.Split('|', 2);
                    dbStamp = parts.Length > 0 ? parts[0] : null;
                    dbGhash = parts.Length > 1 ? parts[1] : null;
                }
                else
                {
                    // Resolve from DB via a scoped service.
                    using var scope = context.RequestServices.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                    var row = await db.Users
                        .AsNoTracking()
                        .Where(u => u.Id == userId)
                        .Select(u => new
                        {
                            u.SecurityStamp,
                            u.IsActive,
                            u.IsLocked,
                            Groups = u.GroupMemberships.Select(gm => gm.Group).ToList()
                        })
                        .FirstOrDefaultAsync();

                    if (row == null || !row.IsActive || row.IsLocked)
                    {
                        await Write401(context, "Account is not active", "ACCOUNT_INACTIVE");
                        return;
                    }

                    dbStamp = row.SecurityStamp;
                    dbGhash = JwtTokenService.ComputeGroupHash(row.Groups);
                    await _cache.SetStringAsync(cacheKey, $"{dbStamp}|{dbGhash}",
                        new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = StampCacheTtl });
                }

                if (!string.Equals(stampClaim, dbStamp, StringComparison.Ordinal))
                {
                    await Write401(context, "Session invalidated — please log in again", "STAMP_MISMATCH");
                    return;
                }
                if (!string.IsNullOrEmpty(ghashClaim) && !string.Equals(ghashClaim, dbGhash, StringComparison.Ordinal))
                {
                    await Write401(context, "Group membership changed — please refresh your session", "GHASH_MISMATCH");
                    return;
                }
            }
        }

        await _next(context);
    }

    /// <summary>
    /// Drops the cached stamp/ghash entry for the given user so the next authenticated
    /// request re-reads from the DB. Call this from admin flows that rotate SecurityStamp
    /// (disable, lock, reset-password, group change) so propagation is instant rather than
    /// TTL-bound.
    /// </summary>
    public static Task InvalidateUserStampCacheAsync(IDistributedCache cache, Guid userId)
    {
        return cache.RemoveAsync(ModularCA.Core.Helpers.UserSessionTermination.StampCacheKey(userId));
    }

    private static async Task Write401(HttpContext context, string error, string code)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($"{{\"error\":\"{error}\",\"code\":\"{code}\"}}");
    }
}
