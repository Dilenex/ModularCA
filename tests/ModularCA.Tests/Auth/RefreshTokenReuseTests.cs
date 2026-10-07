using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Drives the real <c>AuthController.Refresh</c>: any replay of a rotated refresh token, however soon,
/// revokes the whole family including the unused successor, and returns 401.
/// </summary>
public sealed class RefreshTokenReuseTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string KeyA = "jkt-key-a";

    private sealed class FixedDpop : IDpopProofService
    {
        public string? Jkt { get; set; }
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult(Jkt);
    }

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new() { SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    /// <summary>
    /// SQLite rather than the in-memory provider: rotation revokes the presented token with a
    /// conditional ExecuteUpdate, which the in-memory provider cannot execute.
    /// </summary>
    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        public FixedDpop Dpop { get; } = new();
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        public World()
        {
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity { Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s" });
            db.SaveChanges();
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        /// <summary>Issues a first-login refresh token and returns its plaintext.</summary>
        public string Login(string? cnfJkt = null)
        {
            using var db = Db();
            var rt = new JwtTokenService(Config).GenerateRefreshToken(UserId, "127.0.0.1", null, cnfJkt);
            db.RefreshTokens.Add(rt);
            db.SaveChanges();
            return rt.PlaintextTokenForClient!;
        }

        /// <summary>Calls <c>AuthController.Refresh</c> with the given plaintext refresh token.</summary>
        public async Task<IActionResult> RefreshAsync(string plaintext)
        {
            using var db = Db();
            var controller = NewController(db);
            var type = ApiAssembly.TypeNamed(ControllerName);
            var method = type.GetMethod("Refresh")!;
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("RefreshToken")!.SetValue(request, plaintext);
            return await (Task<IActionResult>)method.Invoke(controller, new[] { request })!;
        }

        /// <summary>Calls <c>AuthController.Logout</c> as the test user.</summary>
        public async Task LogoutAsync()
        {
            using var db = Db();
            var controller = NewController(db);
            await (Task<IActionResult>)controller.GetType().GetMethod("Logout")!.Invoke(controller, null)!;
        }

        private object NewController(ModularCADbContext db)
        {
            var type = ApiAssembly.TypeNamed(ControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[] { db, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), Cache };
            var args = ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray();
            var controller = ctor.Invoke(args);

            var services = new ServiceCollection().AddSingleton<IDpopProofService>(Dpop).BuildServiceProvider();
            var http = new DefaultHttpContext
            {
                RequestServices = services,
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", UserId.ToString()) }, "test")),
            };
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return controller;
        }

        /// <summary>Returns the stored row for a plaintext refresh token.</summary>
        public RefreshTokenEntity Row(string plaintext)
        {
            using var db = Db();
            var hash = JwtTokenService.HashRefreshToken(plaintext);
            return db.RefreshTokens.AsNoTracking().Single(t => t.Token == hash);
        }

        /// <summary>Returns every refresh token row of the test user.</summary>
        public List<RefreshTokenEntity> Family()
        {
            using var db = Db();
            return db.RefreshTokens.AsNoTracking().Where(t => t.UserId == UserId).ToList();
        }
    }

    private static string NewRefreshToken(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.SerializeToElement(ok.Value);
        return json.GetProperty("RefreshToken").GetString()!;
    }

    private static void AssertFamilyRevoked(World w, IActionResult result)
    {
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains("compromised", JsonSerializer.Serialize(unauthorized.Value));
        Assert.All(w.Family(), t => Assert.True(t.IsRevoked));
        Assert.Contains(w.Audit.Entries, e => e.Action == AuditActionType.UserLoginFailed);
    }

    [Fact]
    public async Task Rotation_chain_succeeds_and_revokes_each_predecessor()
    {
        using var w = new World();
        var rt1 = w.Login();
        var rt2 = NewRefreshToken(await w.RefreshAsync(rt1));
        var rt3 = NewRefreshToken(await w.RefreshAsync(rt2));

        Assert.True(w.Row(rt1).IsRevoked);
        Assert.True(w.Row(rt2).IsRevoked);
        Assert.False(w.Row(rt3).IsRevoked);
        Assert.Equal(w.Row(rt3).Token, w.Row(rt2).ReplacedByToken);
    }

    [Fact]
    public async Task Immediate_replay_of_rotated_token_revokes_the_family_including_the_unused_successor()
    {
        using var w = new World();
        var rt1 = w.Login();
        var rt2 = NewRefreshToken(await w.RefreshAsync(rt1));

        AssertFamilyRevoked(w, await w.RefreshAsync(rt1));
        Assert.True(w.Row(rt2).IsRevoked);
        Assert.IsType<UnauthorizedObjectResult>(await w.RefreshAsync(rt2));
    }

    [Fact]
    public async Task Replay_after_successor_was_used_revokes_the_family()
    {
        using var w = new World();
        var rt1 = w.Login();
        var rt2 = NewRefreshToken(await w.RefreshAsync(rt1));
        var rt3 = NewRefreshToken(await w.RefreshAsync(rt2));

        AssertFamilyRevoked(w, await w.RefreshAsync(rt1));
        Assert.True(w.Row(rt3).IsRevoked);
    }

    [Fact]
    public async Task Replay_with_the_bound_DPoP_key_still_revokes_the_family()
    {
        using var w = new World();
        w.Config.Security.EnforceRefreshTokenPoP = true;
        w.Dpop.Jkt = KeyA;
        var rt1 = w.Login(KeyA);
        var rt2 = NewRefreshToken(await w.RefreshAsync(rt1));

        AssertFamilyRevoked(w, await w.RefreshAsync(rt1));
        Assert.True(w.Row(rt2).IsRevoked);
    }

    [Fact]
    public async Task Token_revoked_by_logout_is_refused()
    {
        using var w = new World();
        var rt1 = w.Login();
        await w.LogoutAsync();

        AssertFamilyRevoked(w, await w.RefreshAsync(rt1));
    }
}
