using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Auth.Services;

namespace ModularCA.Auth.Utils;

/// <summary>
/// The pending-MFA token that bridges a first factor to its second: cache key <c>mfa:{token}</c>,
/// value <c>{firstFactor}:{userId}</c>. The first factor is recorded so a client certificate cannot
/// be both factors: certificate completion refuses a token whose first factor was a certificate.
/// A bare user id (written before the factor was recorded) is read as <see cref="Password"/>.
/// </summary>
public static class PendingMfaToken
{
    /// <summary>First factor was a password (<c>/auth/login</c>).</summary>
    public const string Password = "password";

    /// <summary>First factor was a client certificate (<c>/auth/cert-login</c>, <c>/auth/mtls/login-redirect</c>).</summary>
    public const string Certificate = "certificate";

    /// <summary>
    /// The longest a pending-MFA token lives. The sign-in paths clamp the policy's
    /// <c>MfaSessionTtlSeconds</c> to 900 seconds; <see cref="StoreAsync"/> holds every token to
    /// this ceiling as well, so a consume claim of this lifetime outlives any token it guards.
    /// </summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(15);

    /// <summary>A pending-MFA token's owner and the factor that minted it.</summary>
    public readonly record struct Entry(Guid UserId, string FirstFactor)
    {
        /// <summary>True when the first factor was a client certificate.</summary>
        public bool IsCertificateFirst => FirstFactor == Certificate;
    }

    /// <summary>The cache key for a pending-MFA token.</summary>
    public static string Key(string token) => $"mfa:{token}";

    /// <summary>The <see cref="IReplayGuard"/> key that marks a pending-MFA token as consumed.</summary>
    public static string ConsumedKey(string token) => $"mfa:consumed:{token}";

    /// <summary>Encodes a cache value recording the user and the first factor.</summary>
    public static string Encode(Guid userId, string firstFactor) => $"{firstFactor}:{userId}";

    /// <summary>
    /// Stores a pending-MFA token for <paramref name="userId"/> minted by
    /// <paramref name="firstFactor"/>, for <paramref name="ttl"/> but never longer than
    /// <see cref="MaxLifetime"/>.
    /// </summary>
    public static Task StoreAsync(IDistributedCache cache, string token, Guid userId, string firstFactor, TimeSpan ttl) =>
        cache.SetStringAsync(Key(token), Encode(userId, firstFactor),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl < MaxLifetime ? ttl : MaxLifetime });

    /// <summary>
    /// Parses a cached value. A bare user id is a legacy entry and means <see cref="Password"/>; an
    /// unknown factor or malformed value is rejected.
    /// </summary>
    public static bool TryParse(string? value, out Entry entry)
    {
        entry = default;
        if (string.IsNullOrEmpty(value)) return false;
        if (Guid.TryParse(value, out var legacy))
        {
            entry = new Entry(legacy, Password);
            return true;
        }
        var sep = value.IndexOf(':');
        if (sep <= 0) return false;
        var factor = value[..sep];
        if (factor != Password && factor != Certificate) return false;
        if (!Guid.TryParse(value[(sep + 1)..], out var userId)) return false;
        entry = new Entry(userId, factor);
        return true;
    }

    /// <summary>Reads a pending-MFA token without consuming it.</summary>
    public static async Task<Entry?> PeekAsync(IDistributedCache cache, string token) =>
        TryParse(await cache.GetStringAsync(Key(token)), out var entry) ? entry : null;

    /// <summary>
    /// Reads and removes a pending-MFA token. Of any number of concurrent consumes of one token, on
    /// one node or across nodes sharing the cache, exactly one returns the entry: the consume is
    /// decided by an atomic claim through <paramref name="replayGuard"/> (Redis <c>SET NX</c> when
    /// Redis is configured), not by the cache read, which every concurrent caller can pass.
    /// </summary>
    /// <remarks>
    /// The cache is read first so a token that does not exist makes no claim; an unauthenticated
    /// caller cannot fill the guard with made-up tokens. The claim lives for
    /// <see cref="MaxLifetime"/>, as long as any token can, so a consumed token can never be
    /// consumed again even if its removal from the cache were lost.
    /// </remarks>
    /// <param name="cache">The cache holding the token.</param>
    /// <param name="replayGuard">The atomic single-use claim.</param>
    /// <param name="token">The pending-MFA token the client presented.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>The token's entry for the one caller that consumed it; null otherwise, or when it is unknown or malformed.</returns>
    public static async Task<Entry?> ConsumeAsync(IDistributedCache cache, IReplayGuard replayGuard, string token, CancellationToken ct = default)
    {
        var value = await cache.GetStringAsync(Key(token), ct);
        if (value == null) return null;
        if (!await replayGuard.TryClaimAsync(ConsumedKey(token), MaxLifetime, ct)) return null;
        await cache.RemoveAsync(Key(token), ct);
        return TryParse(value, out var entry) ? entry : null;
    }
}
