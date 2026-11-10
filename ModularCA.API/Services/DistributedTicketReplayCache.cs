using Kerberos.NET;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Auth.Services;

namespace ModularCA.API.Services;

/// <summary>
/// Kerberos authenticator replay detection, so a captured <c>Authorization: Negotiate</c> header
/// cannot be presented twice, across restarts and instances. The library computes the entry key
/// from the authenticator; we only remember it for as long as the ticket could still be valid.
/// </summary>
/// <remarks>
/// The record is one atomic claim through <see cref="IReplayGuard"/> (Redis <c>SET NX</c> when
/// Redis is configured, an in-process claim otherwise). It was a read of the distributed cache
/// followed by a write, so two concurrent requests carrying the same authenticator could both see
/// it absent and both be accepted. A marker is also written to the distributed cache after a
/// successful claim, so <see cref="Contains"/> can answer without making a claim of its own.
/// </remarks>
/// <param name="cache">The distributed cache, holding the marker <see cref="Contains"/> reads.</param>
/// <param name="replayGuard">The atomic single-use claim that decides acceptance.</param>
public sealed class DistributedTicketReplayCache(IDistributedCache cache, IReplayGuard replayGuard) : ITicketReplayValidator
{
    private const string Prefix = "krb-replay:";

    /// <summary>
    /// The shortest time an authenticator is remembered, whatever the ticket's own expiry: it
    /// covers the acceptor's clock-skew allowance for a ticket that is about to expire.
    /// </summary>
    private static readonly TimeSpan MinimumLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Records <paramref name="entry"/>; false when it has been recorded before, which the
    /// library treats as a replay.
    /// </summary>
    /// <param name="entry">The authenticator, as the library keys it, and the ticket's expiry.</param>
    /// <returns>True when this call made the record; false for a replay.</returns>
    public async Task<bool> Add(TicketCacheEntry entry)
    {
        var key = Prefix + entry.Computed;
        var lifetime = entry.Expires - DateTimeOffset.UtcNow;
        if (lifetime < MinimumLifetime) lifetime = MinimumLifetime;

        if (!await replayGuard.TryClaimAsync(key, lifetime))
            return false;

        await cache.SetAsync(key, [1], new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime });
        return true;
    }

    /// <summary>Whether <paramref name="entry"/> has been recorded by <see cref="Add"/>.</summary>
    /// <param name="entry">The authenticator, as the library keys it.</param>
    public async Task<bool> Contains(TicketCacheEntry entry)
        => await cache.GetAsync(Prefix + entry.Computed) != null;
}
