using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Database;

namespace ModularCA.Core.Helpers;

/// <summary>The sessions ended for one account by <see cref="UserSessionTermination.EndAllSessionsAsync"/>.</summary>
/// <param name="UserId">The account.</param>
/// <param name="Username">The account's username, for audit records.</param>
/// <param name="RefreshTokensRevoked">How many live refresh tokens were revoked.</param>
public readonly record struct EndedSessions(Guid UserId, string Username, int RefreshTokensRevoked);

/// <summary>
/// Ends every session of an account the way a password reset does: the security stamp rotates, so
/// access tokens carrying the old stamp are refused on their next request, and every live refresh
/// token is revoked, so none can mint a new access token.
/// <para>
/// Used where a credential stops being trusted and the sessions it opened cannot be told apart from
/// the account's others: refresh tokens do not record which credential signed them in.
/// </para>
/// </summary>
public static class UserSessionTermination
{
    /// <summary>
    /// The distributed-cache key under which an account's current stamp and group hash are cached
    /// for access-token checks. Removing it makes a rotated stamp take effect on the next request.
    /// </summary>
    public static string StampCacheKey(Guid userId) => $"user-stamp:{userId:N}";

    /// <summary>
    /// Rotates the security stamp of each account in <paramref name="userIds"/> and revokes its live
    /// refresh tokens at <paramref name="nowUtc"/>, on the tracked context; the caller saves, so the
    /// change commits with whatever else the caller is writing. After the save, call
    /// <see cref="InvalidateStampCacheAsync"/>. Accounts that do not exist are skipped.
    /// </summary>
    public static async Task<IReadOnlyList<EndedSessions>> EndAllSessionsAsync(
        ModularCADbContext db, IReadOnlyCollection<Guid> userIds, DateTime nowUtc, CancellationToken ct = default)
    {
        if (userIds.Count == 0)
            return [];

        var users = await db.Users.Where(u => userIds.Contains(u.Id)).ToListAsync(ct);
        var tokens = await db.RefreshTokens.Where(t => userIds.Contains(t.UserId) && !t.IsRevoked).ToListAsync(ct);
        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = nowUtc;
        }

        var ended = new List<EndedSessions>(users.Count);
        foreach (var user in users)
        {
            user.SecurityStamp = Guid.NewGuid().ToString();
            ended.Add(new EndedSessions(user.Id, user.Username, tokens.Count(t => t.UserId == user.Id)));
        }
        return ended;
    }

    /// <summary>
    /// Drops the cached stamp of each account so a stamp rotated by
    /// <see cref="EndAllSessionsAsync"/> refuses old access tokens on their next request rather than
    /// when the cache entry lapses. A null cache does nothing.
    /// </summary>
    public static async Task InvalidateStampCacheAsync(IDistributedCache? cache, IEnumerable<Guid> userIds, CancellationToken ct = default)
    {
        if (cache == null)
            return;
        foreach (var userId in userIds.Distinct())
            await cache.RemoveAsync(StampCacheKey(userId), ct);
    }
}
