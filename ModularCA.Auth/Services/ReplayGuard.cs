using System.Collections.Concurrent;

namespace ModularCA.Auth.Services;

/// <summary>
/// Records single-use values (a DPoP proof's <c>jti</c>, for one) so a second presentation can be
/// refused. The check and the record are one atomic step: of two concurrent claims of the same key,
/// exactly one succeeds.
/// </summary>
/// <remarks>
/// <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> cannot do this; it has
/// no add-if-absent, so a read followed by a write lets two concurrent requests both see the key
/// absent. The in-process implementation serves single-node installs (the memory cache's case);
/// with Redis configured, the Redis implementation in the API uses <c>SET NX</c> so the guarantee
/// holds across nodes.
/// </remarks>
public interface IReplayGuard
{
    /// <summary>
    /// Claims <paramref name="key"/> for <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="key">The single-use value, already namespaced by the caller.</param>
    /// <param name="lifetime">How long the claim must be remembered: at least as long as the value could still be accepted.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>True when this call made the claim; false when an unexpired claim already exists.</returns>
    Task<bool> TryClaimAsync(string key, TimeSpan lifetime, CancellationToken ct = default);
}

/// <summary>
/// <see cref="IReplayGuard"/> held in process memory. Atomic within one process; registered when
/// Redis is not configured, which is also when every other cache-backed flow is process-local.
/// </summary>
public sealed class InProcessReplayGuard : IReplayGuard
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _claims = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private long _nextSweepUtcTicks;

    /// <summary>Creates the guard.</summary>
    /// <param name="time">Clock for claim expiry; the system clock when null.</param>
    public InProcessReplayGuard(TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<bool> TryClaimAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        SweepIfDue(now);
        var expires = now + lifetime;

        while (true)
        {
            if (_claims.TryAdd(key, expires))
                return Task.FromResult(true);
            if (!_claims.TryGetValue(key, out var existing))
                continue; // Swept between the two calls; try the add again.
            if (existing > now)
                return Task.FromResult(false);
            // An expired claim is replaced only if nobody else replaced it first.
            if (_claims.TryUpdate(key, expires, existing))
                return Task.FromResult(true);
        }
    }

    /// <summary>Drops expired claims at most once per <see cref="SweepInterval"/> so memory stays bounded.</summary>
    /// <param name="now">The current time.</param>
    private void SweepIfDue(DateTimeOffset now)
    {
        var due = Interlocked.Read(ref _nextSweepUtcTicks);
        if (now.UtcTicks < due) return;
        if (Interlocked.CompareExchange(ref _nextSweepUtcTicks, (now + SweepInterval).UtcTicks, due) != due) return;

        foreach (var claim in _claims)
        {
            if (claim.Value <= now)
                _claims.TryRemove(claim);
        }
    }
}
