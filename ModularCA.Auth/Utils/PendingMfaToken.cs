using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Distributed;

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

    private static readonly ConcurrentDictionary<string, byte> Consuming = new(StringComparer.Ordinal);

    /// <summary>A pending-MFA token's owner and the factor that minted it.</summary>
    public readonly record struct Entry(Guid UserId, string FirstFactor)
    {
        /// <summary>True when the first factor was a client certificate.</summary>
        public bool IsCertificateFirst => FirstFactor == Certificate;
    }

    /// <summary>The cache key for a pending-MFA token.</summary>
    public static string Key(string token) => $"mfa:{token}";

    /// <summary>Encodes a cache value recording the user and the first factor.</summary>
    public static string Encode(Guid userId, string firstFactor) => $"{firstFactor}:{userId}";

    /// <summary>Stores a pending-MFA token for <paramref name="userId"/> minted by <paramref name="firstFactor"/>.</summary>
    public static Task StoreAsync(IDistributedCache cache, string token, Guid userId, string firstFactor, TimeSpan ttl) =>
        cache.SetStringAsync(Key(token), Encode(userId, firstFactor),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl });

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
    /// Reads and removes a pending-MFA token. A concurrent consume of the same token in this process
    /// returns null; across nodes sharing a distributed cache the read and remove are not atomic.
    /// </summary>
    public static async Task<Entry?> ConsumeAsync(IDistributedCache cache, string token)
    {
        if (!Consuming.TryAdd(token, 0)) return null;
        try
        {
            var value = await cache.GetStringAsync(Key(token));
            if (value == null) return null;
            await cache.RemoveAsync(Key(token));
            return TryParse(value, out var entry) ? entry : null;
        }
        finally
        {
            Consuming.TryRemove(token, out _);
        }
    }
}
