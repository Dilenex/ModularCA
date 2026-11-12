using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Helpers;

/// <summary>The sessions ended for one account by <see cref="UserSessionTermination.EndAllSessionsAsync"/>.</summary>
/// <param name="UserId">The account.</param>
/// <param name="Username">The account's username, for audit records.</param>
/// <param name="RefreshTokensRevoked">How many live refresh tokens were revoked.</param>
public readonly record struct EndedSessions(Guid UserId, string Username, int RefreshTokensRevoked);

/// <summary>
/// Ends every session of an account: the security stamp rotates, so access tokens carrying the old
/// stamp are refused on their next request, and every live refresh token is revoked, so none can
/// mint a new access token. <c>/auth/refresh</c> does not read the stamp, so one without the other
/// leaves sessions alive; this class is the one place that assigns the stamp to end sessions, and
/// <c>SecurityStampGuardTests</c> fails on an assignment made anywhere else without a stated reason.
/// <para>
/// Used wherever a credential or the account's standing changes (password change or reset, MFA
/// reset, recovery code, claim, disable, lock, unlock, password source change, a revoked sign-in
/// certificate): refresh tokens do not record which credential signed them in, so the sessions the
/// credential opened cannot be told apart from the account's others.
/// </para>
/// <para>
/// Three forms. The two <c>EndAllSessionsAsync</c> overloads change tracked entities and leave the
/// save to the caller, so they work on any provider and commit with whatever else the caller is
/// writing. <see cref="EndAllSessionsSetBasedAsync"/> saves and revokes with one UPDATE inside a
/// transaction, which needs a relational provider.
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
    /// Rotates the security stamp of <paramref name="user"/>, an entity the caller already loaded
    /// through <paramref name="db"/>, and revokes its live refresh tokens at
    /// <paramref name="nowUtc"/>, on the tracked context; the caller saves, so the change commits
    /// with whatever else the caller is writing to the account. After the save, call
    /// <see cref="InvalidateStampCacheAsync"/> where a cache is in reach.
    /// </summary>
    /// <param name="db">The context <paramref name="user"/> is tracked by.</param>
    /// <param name="user">The account whose sessions end.</param>
    /// <param name="nowUtc">The revocation instant.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The account and how many refresh tokens were revoked, for audit records.</returns>
    public static async Task<EndedSessions> EndAllSessionsAsync(
        ModularCADbContext db, UserEntity user, DateTime nowUtc, CancellationToken ct = default)
    {
        var tokens = await db.RefreshTokens.Where(t => t.UserId == user.Id && !t.IsRevoked).ToListAsync(ct);
        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = nowUtc;
        }
        user.SecurityStamp = Guid.NewGuid().ToString();
        return new EndedSessions(user.Id, user.Username, tokens.Count);
    }

    /// <summary>
    /// Rotates the security stamp of <paramref name="user"/>, saves the context (so everything else
    /// the caller changed on it is written too) and then revokes the account's live refresh tokens
    /// at <paramref name="nowUtc"/> with one UPDATE. Both happen in one transaction: the one the
    /// caller already holds on <paramref name="db"/>, which the caller commits, or else one opened
    /// and committed here, so the stamp never rotates without the tokens going. Needs a relational
    /// provider. After it returns (and after the caller's commit), call
    /// <see cref="InvalidateStampCacheAsync"/> where a cache is in reach.
    /// </summary>
    /// <param name="db">The context <paramref name="user"/> is tracked by.</param>
    /// <param name="user">The account whose sessions end.</param>
    /// <param name="nowUtc">The revocation instant.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The account and how many refresh tokens were revoked, for audit records.</returns>
    public static async Task<EndedSessions> EndAllSessionsSetBasedAsync(
        ModularCADbContext db, UserEntity user, DateTime nowUtc, CancellationToken ct = default)
    {
        await using var own = db.Database.CurrentTransaction == null
            ? await db.Database.BeginTransactionAsync(ct)
            : null;

        user.SecurityStamp = Guid.NewGuid().ToString();
        await db.SaveChangesAsync(ct);
        var userId = user.Id;
        var revoked = await db.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.IsRevoked, true)
                .SetProperty(t => t.RevokedAt, nowUtc), ct);

        if (own != null)
            await own.CommitAsync(ct);
        return new EndedSessions(user.Id, user.Username, revoked);
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
