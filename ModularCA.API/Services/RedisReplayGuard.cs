using ModularCA.Auth.Services;
using StackExchange.Redis;

namespace ModularCA.API.Services;

/// <summary>
/// <see cref="IReplayGuard"/> over Redis, registered when Redis is configured. A claim is one
/// <c>SET key 1 PX lifetime NX</c>, which Redis executes atomically, so the single-use guarantee
/// holds across every node sharing the server. A Redis failure throws, and callers treat that as a
/// refusal.
/// </summary>
/// <param name="redis">The shared Redis connection.</param>
/// <param name="keyPrefix">Prefix for every claim key, keeping them apart from the cache's own entries.</param>
public sealed class RedisReplayGuard(IConnectionMultiplexer redis, string keyPrefix) : IReplayGuard
{
    /// <inheritdoc />
    public Task<bool> TryClaimAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
        => redis.GetDatabase().StringSetAsync(keyPrefix + key, 1, lifetime, When.NotExists);
}
