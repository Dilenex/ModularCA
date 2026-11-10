using Kerberos.NET;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Msae.Kerberos;

/// <summary>
/// The MSAE Kerberos replay cache (<c>DistributedTicketReplayCache</c>) records an authenticator
/// with one atomic claim. It read the distributed cache and then wrote it, so two requests carrying
/// the same captured <c>Authorization: Negotiate</c> header could both see it absent and both be
/// accepted.
/// </summary>
public class TicketReplayCacheTests
{
    private static IDistributedCache NewCache() =>
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    /// <summary>A cache whose reads block until released, so concurrent callers overlap between read and write.</summary>
    private sealed class GatedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner = NewCache();
        public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public byte[]? Get(string key) => _inner.Get(key);
        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            await Gate.Task;
            return await _inner.GetAsync(key, token);
        }
        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => _inner.SetAsync(key, value, options, token);
    }

    /// <summary>A guard that records the lifetime each claim asked for.</summary>
    private sealed class RecordingGuard : IReplayGuard
    {
        private readonly InProcessReplayGuard _inner = new();
        public List<(string Key, TimeSpan Lifetime)> Claims { get; } = [];
        public Task<bool> TryClaimAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
        {
            lock (Claims) Claims.Add((key, lifetime));
            return _inner.TryClaimAsync(key, lifetime, ct);
        }
    }

    /// <summary>Builds the API's replay cache over whichever of the given services its constructor takes.</summary>
    private static ITicketReplayValidator Create(IDistributedCache cache, IReplayGuard guard)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Services.DistributedTicketReplayCache");
        var ctor = type.GetConstructors().Single();
        var available = new object[] { cache, guard };
        return (ITicketReplayValidator)ctor.Invoke(ctor.GetParameters()
            .Select(p => available.First(a => p.ParameterType.IsInstanceOfType(a)))
            .ToArray());
    }

    private static TicketCacheEntry Entry(string key, TimeSpan validFor) =>
        new() { Key = key, Expires = DateTimeOffset.UtcNow + validFor };

    [Fact]
    public async Task Concurrent_presentations_of_one_authenticator_are_accepted_exactly_once()
    {
        var cache = new GatedCache();
        var replay = Create(cache, new InProcessReplayGuard());
        var entry = Entry("authenticator-1", TimeSpan.FromHours(8));

        var attempts = Enumerable.Range(0, 32).Select(_ => Task.Run(() => replay.Add(entry))).ToArray();
        cache.Gate.SetResult();
        var results = await Task.WhenAll(attempts);

        Assert.Equal(1, results.Count(r => r));
        Assert.True(await replay.Contains(entry));
    }

    [Fact]
    public async Task A_second_presentation_is_refused_and_a_different_authenticator_is_not()
    {
        var replay = Create(NewCache(), new InProcessReplayGuard());

        Assert.True(await replay.Add(Entry("authenticator-1", TimeSpan.FromHours(8))));
        Assert.False(await replay.Add(Entry("authenticator-1", TimeSpan.FromHours(8))));
        Assert.True(await replay.Add(Entry("authenticator-2", TimeSpan.FromHours(8))));
        Assert.False(await replay.Contains(Entry("authenticator-3", TimeSpan.FromHours(8))));
    }

    /// <summary>
    /// The entry is remembered for as long as the ticket could still be presented, and never less
    /// than ten minutes, which covers the acceptor's clock-skew allowance for a ticket about to
    /// expire.
    /// </summary>
    [Theory]
    [InlineData(480, 479)]
    [InlineData(2, 10)]
    [InlineData(-5, 10)]
    public async Task The_claim_lives_as_long_as_the_ticket_and_at_least_ten_minutes(int validForMinutes, int atLeastMinutes)
    {
        var guard = new RecordingGuard();
        var replay = Create(NewCache(), guard);

        Assert.True(await replay.Add(Entry("authenticator-1", TimeSpan.FromMinutes(validForMinutes))));

        var (key, lifetime) = Assert.Single(guard.Claims);
        Assert.StartsWith("krb-replay:", key);
        Assert.True(lifetime >= TimeSpan.FromMinutes(atLeastMinutes), $"lifetime {lifetime}");
        Assert.True(lifetime <= TimeSpan.FromMinutes(Math.Max(validForMinutes, 10)), $"lifetime {lifetime}");
    }
}
