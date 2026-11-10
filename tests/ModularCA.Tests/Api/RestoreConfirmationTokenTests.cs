using System.Reflection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The restore-confirmation token from <c>/preview-restore</c> starts one restore. It was read
/// from the cache and then removed, so two simultaneous restores carrying it could both pass and
/// run over each other; it is now claimed through the atomic replay guard.
/// </summary>
public class RestoreConfirmationTokenTests
{
    private static readonly Type Controller = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminBackupController");
    private static readonly Guid User = Guid.NewGuid();
    private const string Payload = "{\"fileName\":\"backup-1.tar.gz.enc\"}";

    private readonly IReplayGuard _guard = new InProcessReplayGuard();

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static async Task<string> IssueAsync(IDistributedCache cache)
    {
        var token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        await cache.SetStringAsync($"restore-token:{User}:{token}", Payload,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
        return token;
    }

    private Task<string?> ConsumeAsync(IDistributedCache cache, string token, Guid? user = null)
        => (Task<string?>)Controller.GetMethod("ConsumeRestoreTokenAsync", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [cache, _guard, user ?? User, token])!;

    [Fact]
    public async Task A_token_returns_its_payload_once()
    {
        var cache = NewCache();
        var token = await IssueAsync(cache);

        Assert.Equal(Payload, await ConsumeAsync(cache, token));
        Assert.Null(await ConsumeAsync(cache, token));
    }

    [Fact]
    public async Task An_unknown_token_or_another_users_token_is_refused()
    {
        var cache = NewCache();
        var token = await IssueAsync(cache);

        Assert.Null(await ConsumeAsync(cache, "00" + token[2..]));
        Assert.Null(await ConsumeAsync(cache, token, Guid.NewGuid()));
        Assert.Equal(Payload, await ConsumeAsync(cache, token));
    }

    [Fact]
    public async Task Concurrent_restores_with_one_token_let_exactly_one_through()
    {
        var cache = new SlowReadDistributedCache(NewCache());
        var token = await IssueAsync(cache);

        var results = await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => ConsumeAsync(cache, token))));

        Assert.Equal(1, results.Count(p => p != null));
    }
}
