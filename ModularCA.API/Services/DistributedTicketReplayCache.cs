using Kerberos.NET;
using Microsoft.Extensions.Caching.Distributed;

namespace ModularCA.API.Services;

/// <summary>
/// Kerberos authenticator replay detection over the distributed cache, so a captured
/// <c>Authorization: Negotiate</c> header cannot be presented twice, across restarts and
/// instances. The library computes the entry key from the authenticator; we only remember it
/// for as long as the ticket could still be valid.
/// </summary>
public sealed class DistributedTicketReplayCache(IDistributedCache cache) : ITicketReplayValidator
{
    private const string Prefix = "krb-replay:";

    /// <inheritdoc />
    public async Task<bool> Add(TicketCacheEntry entry)
    {
        var key = Prefix + entry.Computed;
        if (await cache.GetAsync(key) != null)
            return false;
        var lifetime = entry.Expires - DateTimeOffset.UtcNow;
        if (lifetime < TimeSpan.FromMinutes(10)) lifetime = TimeSpan.FromMinutes(10);
        await cache.SetAsync(key, new byte[] { 1 }, new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime });
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> Contains(TicketCacheEntry entry)
        => await cache.GetAsync(Prefix + entry.Computed) != null;
}
