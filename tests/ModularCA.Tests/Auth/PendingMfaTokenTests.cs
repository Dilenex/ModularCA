using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A client certificate is one factor: a pending-MFA token minted by a certificate login must not
/// be completable by the certificate endpoints, while TOTP and WebAuthn accept either first factor.
/// </summary>
public sealed class PendingMfaTokenTests
{
    private static IDistributedCache NewCache() =>
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public void Legacy_bare_user_id_reads_as_password_first()
    {
        var id = Guid.NewGuid();
        Assert.True(PendingMfaToken.TryParse(id.ToString(), out var entry));
        Assert.Equal(id, entry.UserId);
        Assert.Equal(PendingMfaToken.Password, entry.FirstFactor);
        Assert.False(entry.IsCertificateFirst);
    }

    [Theory]
    [InlineData(PendingMfaToken.Password, false)]
    [InlineData(PendingMfaToken.Certificate, true)]
    public void Encoded_value_round_trips(string factor, bool certificateFirst)
    {
        var id = Guid.NewGuid();
        Assert.True(PendingMfaToken.TryParse(PendingMfaToken.Encode(id, factor), out var entry));
        Assert.Equal(id, entry.UserId);
        Assert.Equal(certificateFirst, entry.IsCertificateFirst);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    [InlineData("kerberos:5f0c9a3e-0000-0000-0000-000000000000")]
    [InlineData("certificate:not-a-guid")]
    [InlineData(":5f0c9a3e-0000-0000-0000-000000000000")]
    public void Unknown_or_malformed_values_are_rejected(string? value)
    {
        Assert.False(PendingMfaToken.TryParse(value, out _));
    }

    [Fact]
    public async Task Consume_succeeds_once()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await PendingMfaToken.StoreAsync(cache, "t1", id, PendingMfaToken.Password, TimeSpan.FromMinutes(5));

        var guard = new InProcessReplayGuard();
        var first = await PendingMfaToken.ConsumeAsync(cache, guard, "t1");
        var second = await PendingMfaToken.ConsumeAsync(cache, guard, "t1");

        Assert.Equal(id, first?.UserId);
        Assert.Null(second);
    }

    /// <summary>A guard that records each claim and the lifetime it asked for.</summary>
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

    /// <summary>
    /// The cross-node case: another node sharing the cache has claimed the token and not yet
    /// removed it. The cache still holds the token, and the old read-then-remove (whose only
    /// guard was a lock inside one process) handed it out a second time. The shared claim
    /// refuses it.
    /// </summary>
    [Fact]
    public async Task A_token_another_node_has_claimed_is_refused_while_the_cache_still_holds_it()
    {
        var cache = NewCache();
        var guard = new InProcessReplayGuard();
        await PendingMfaToken.StoreAsync(cache, "t3", Guid.NewGuid(), PendingMfaToken.Password, TimeSpan.FromMinutes(5));
        Assert.True(await guard.TryClaimAsync(PendingMfaToken.ConsumedKey("t3"), PendingMfaToken.MaxLifetime));

        Assert.Null(await PendingMfaToken.ConsumeAsync(cache, guard, "t3"));
        Assert.NotNull(await cache.GetStringAsync(PendingMfaToken.Key("t3")));
    }

    /// <summary>
    /// The consume claim outlives any token it guards: tokens are stored for at most
    /// <see cref="PendingMfaToken.MaxLifetime"/>, which covers the 900-second policy ceiling, and
    /// the claim is made for that long.
    /// </summary>
    [Fact]
    public async Task The_consume_claim_lives_at_least_as_long_as_any_token()
    {
        var cache = NewCache();
        var guard = new RecordingGuard();
        await PendingMfaToken.StoreAsync(cache, "t4", Guid.NewGuid(), PendingMfaToken.Password, TimeSpan.FromSeconds(900));

        Assert.NotNull(await PendingMfaToken.ConsumeAsync(cache, guard, "t4"));

        var (key, lifetime) = Assert.Single(guard.Claims);
        Assert.Equal(PendingMfaToken.ConsumedKey("t4"), key);
        Assert.True(lifetime >= TimeSpan.FromSeconds(900));
        Assert.Equal(PendingMfaToken.MaxLifetime, lifetime);
    }

    /// <summary>A token that does not exist makes no claim, so made-up tokens cannot fill the guard.</summary>
    [Fact]
    public async Task An_unknown_token_makes_no_claim()
    {
        var guard = new RecordingGuard();

        Assert.Null(await PendingMfaToken.ConsumeAsync(NewCache(), guard, "no-such-token"));
        Assert.Empty(guard.Claims);
    }

    /// <summary>A cache whose read blocks until released, so two consumers overlap.</summary>
    private sealed class GatedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner = NewCache();
        public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Reads;
        public byte[]? Get(string key) => _inner.Get(key);
        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Interlocked.Increment(ref Reads);
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

    /// <summary>
    /// Every consumer passes the cache read (the gate holds them all inside it); the shared claim
    /// decides, and exactly one gets the entry.
    /// </summary>
    [Fact]
    public async Task Concurrent_consume_of_one_token_succeeds_exactly_once()
    {
        var cache = new GatedCache();
        var guard = new InProcessReplayGuard();
        await PendingMfaToken.StoreAsync(cache, "t2", Guid.NewGuid(), PendingMfaToken.Password, TimeSpan.FromMinutes(5));

        var consumers = Enumerable.Range(0, 32).Select(_ => Task.Run(() => PendingMfaToken.ConsumeAsync(cache, guard, "t2"))).ToArray();
        while (Volatile.Read(ref cache.Reads) < consumers.Length)
            await Task.Yield();
        cache.Gate.SetResult();
        var results = await Task.WhenAll(consumers);

        Assert.Single(results, r => r != null);
    }

    // ---- Controller behaviour ----

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new() { SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    private sealed class World
    {
        private readonly string _dbName = $"pending-mfa-{Guid.NewGuid():N}";
        public Guid UserId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new() { JWT = new JwtConfig { Secret = new string('k', 64) } };
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = NewCache();

        public World()
        {
            using var db = Db();
            db.Users.Add(new UserEntity { Id = UserId, Username = "cora", Email = "cora@example.test", IsActive = true, SecurityStamp = "s" });
            db.SaveChanges();
        }

        public ModularCADbContext Db() => InMemoryDbContextFactory.Create(_dbName);

        /// <summary>Stores a pending-MFA token for the test user with the given first factor.</summary>
        public async Task<string> PendingAsync(string firstFactor)
        {
            var token = Guid.NewGuid().ToString("N");
            await PendingMfaToken.StoreAsync(Cache, token, UserId, firstFactor, TimeSpan.FromMinutes(5));
            return token;
        }

        /// <summary>Invokes a controller action whose single parameter is a request DTO with an MfaToken property.</summary>
        public async Task<IActionResult> InvokeAsync(string controller, string action, string mfaToken, params (string Name, object Value)[] extra)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(controller);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[] { db, Cache, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider(), new InProcessReplayGuard() };
            var instance = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(instance, new ControllerContext { HttpContext = new DefaultHttpContext() });

            var method = type.GetMethods().Single(m => m.Name == action && m.GetParameters().Length == 1);
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("MfaToken")!.SetValue(request, mfaToken);
            foreach (var (name, value) in extra)
                request.GetType().GetProperty(name)!.SetValue(request, value);
            return await (Task<IActionResult>)method.Invoke(instance, new[] { request })!;
        }
    }

    private const string Mtls = "ModularCA.API.Controllers.v1.Auth.MtlsController";
    private const string Totp = "ModularCA.API.Controllers.v1.Auth.TotpController";

    private static string ErrorOf(IActionResult result) =>
        JsonSerializer.Serialize(result is ObjectResult o ? o.Value : null);

    [Fact]
    public async Task Mtls_verify_refuses_and_consumes_a_certificate_first_token()
    {
        var w = new World();
        var token = await w.PendingAsync(PendingMfaToken.Certificate);

        var result = await w.InvokeAsync(Mtls, "Verify", token);

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains("cannot complete a sign-in that began with a client certificate", ErrorOf(result));
        Assert.Null(await w.Cache.GetStringAsync(PendingMfaToken.Key(token)));
        Assert.Contains(w.Audit.Entries, e => e.Action == ModularCA.Shared.Enums.AuditActionType.UserLoginFailed);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Mtls_verify_accepts_a_password_first_token_including_legacy_values(bool legacy)
    {
        var w = new World();
        var token = Guid.NewGuid().ToString("N");
        var value = legacy ? w.UserId.ToString() : PendingMfaToken.Encode(w.UserId, PendingMfaToken.Password);
        await w.Cache.SetStringAsync(PendingMfaToken.Key(token), value);

        var result = await w.InvokeAsync(Mtls, "Verify", token);

        // Past the token check: the test connection carries no client certificate.
        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains("No client certificate presented", ErrorOf(result));
    }

    [Fact]
    public async Task Mtls_prepare_redirect_refuses_a_certificate_first_token()
    {
        var w = new World();
        var token = await w.PendingAsync(PendingMfaToken.Certificate);

        var result = await w.InvokeAsync(Mtls, "PrepareRedirect", token);

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains("cannot complete a sign-in that began with a client certificate", ErrorOf(result));
    }

    [Theory]
    [InlineData(PendingMfaToken.Password)]
    [InlineData(PendingMfaToken.Certificate)]
    public async Task Totp_verify_accepts_either_first_factor(string factor)
    {
        var w = new World();
        var token = await w.PendingAsync(factor);

        var result = await w.InvokeAsync(Totp, "Verify", token, ("Code", "123456"));

        // Past the token check: the user has no TOTP secret.
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("No TOTP secret configured", ErrorOf(bad));
    }
}
