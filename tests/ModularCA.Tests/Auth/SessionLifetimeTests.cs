using System.IdentityModel.Tokens.Jwt;
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
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// The maximum session lifetime, in hours from the sign-in: a new install's default is 12; the
/// session maximum wins over the refresh-token lifetime at issuance and at every refresh, so a
/// chain of refreshed tokens cannot outlive it; and the 14 days an older install stored, kept as
/// 336 hours, still means 14 days. Drives the real <c>AuthController.Refresh</c>.
/// </summary>
public sealed class SessionLifetimeTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";

    private sealed class NoDpop : IDpopProofService
    {
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private sealed class FixedPolicy(SecurityPolicyEntity policy) : ISecurityPolicyService
    {
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(policy);
        public void InvalidateCache() { }
    }

    /// <summary>SQLite, because rotation revokes the presented token with a conditional ExecuteUpdate.</summary>
    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public SecurityPolicyEntity Policy { get; }
        public SystemConfig Config { get; }

        public World(int maxSessionLifetimeHours, int refreshTokenDays = 7)
        {
            Policy = new SecurityPolicyEntity { SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeHours = maxSessionLifetimeHours, LoginResponseDelayMs = 0 };
            Config = new SystemConfig
            {
                JWT = new JwtConfig { Secret = new string('k', 64), ExpirationMinutes = 30 },
                Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
                Tokens = new TokenConfig { RefreshTokenDays = refreshTokenDays },
            };
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity { Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s" });
            db.SaveChanges();
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        /// <summary>
        /// A sign-in <paramref name="ago"/> in the past: its refresh token as the sign-in issued it
        /// under the policy of the time, <paramref name="issuedUnderMaxHours"/>, moved back in time.
        /// </summary>
        public string SignedIn(TimeSpan ago, int? issuedUnderMaxHours = null)
        {
            using var db = Db();
            var rt = new JwtTokenService(Config).GenerateRefreshToken(UserId, "127.0.0.1", issuedUnderMaxHours ?? Policy.MaxSessionLifetimeHours);
            rt.CreatedAt -= ago;
            rt.FamilyCreatedAt -= ago;
            rt.ExpiresAt -= ago;
            db.RefreshTokens.Add(rt);
            db.SaveChanges();
            return rt.PlaintextTokenForClient!;
        }

        /// <summary>Calls <c>AuthController.Refresh</c> with the given plaintext refresh token.</summary>
        public async Task<IActionResult> RefreshAsync(string plaintext)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(ControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, new JwtTokenService(Config), new RecordingAuditService(), Config, new FixedPolicy(Policy),
                new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a))).ToArray());
            var http = new DefaultHttpContext
            {
                RequestServices = new ServiceCollection().AddSingleton<IDpopProofService>(new NoDpop()).BuildServiceProvider(),
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", UserId.ToString()) }, "test")),
            };
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            var method = type.GetMethod("Refresh")!;
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("RefreshToken")!.SetValue(request, plaintext);
            return await (Task<IActionResult>)method.Invoke(controller, new[] { request })!;
        }

        /// <summary>The stored row for a plaintext refresh token.</summary>
        public RefreshTokenEntity Row(string plaintext)
        {
            using var db = Db();
            var hash = JwtTokenService.HashRefreshToken(plaintext);
            return db.RefreshTokens.AsNoTracking().Single(t => t.Token == hash);
        }
    }

    private static (string RefreshToken, DateTime AccessTokenExpiry) Refreshed(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.SerializeToElement(ok.Value);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(json.GetProperty("Token").GetString());
        return (json.GetProperty("RefreshToken").GetString()!, jwt.ValidTo);
    }

    private static void AssertSessionOver(IActionResult result)
    {
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains("Session lifetime exceeded", JsonSerializer.Serialize(unauthorized.Value));
    }

    private static void AssertClose(DateTime expected, DateTime actual) =>
        Assert.True((expected - actual).Duration() < TimeSpan.FromSeconds(30), $"expected about {expected:O}, got {actual:O}");

    [Fact]
    public void A_new_install_gets_twelve_hours_and_thirty_idle_minutes()
    {
        var seeded = new SecurityPolicyEntity();

        Assert.Equal(12, seeded.MaxSessionLifetimeHours);
        Assert.Equal(30, seeded.SessionIdleTimeoutMinutes);
        Assert.Equal(12, SessionLifetime.RecommendedMaxHours);
    }

    [Fact]
    public void Bootstrap_seeds_the_security_policy_with_twelve_hours()
    {
        using var db = InMemoryDbContextFactory.Create();

        ModularCA.Bootstrap.BootstrapProfileSeeder.SeedSecurityPolicy(db);

        Assert.Equal(12, db.SecurityPolicies.AsNoTracking().Single().MaxSessionLifetimeHours);
    }

    [Fact]
    public void The_horizon_is_the_sign_in_plus_the_maximum_and_none_when_the_maximum_is_off()
    {
        var start = new DateTime(2026, 11, 12, 8, 0, 0, DateTimeKind.Utc);

        Assert.Equal(start.AddHours(12), SessionLifetime.Horizon(start, 12));
        Assert.Null(SessionLifetime.Horizon(start, 0));
        Assert.Null(SessionLifetime.Horizon(start, -5));
        Assert.Equal(DateTime.MaxValue, SessionLifetime.Horizon(start, int.MaxValue));
        Assert.False(SessionLifetime.IsOver(start.AddHours(11), start, 12));
        Assert.True(SessionLifetime.IsOver(start.AddHours(12), start, 12));
        Assert.False(SessionLifetime.IsOver(start.AddYears(5), start, 0));
    }

    /// <summary>The rule the console states: the session maximum wins over the refresh-token lifetime.</summary>
    [Theory]
    [InlineData(7, 12, 12)]     // a new install: 7 days of refresh token, cut to 12 hours
    [InlineData(7, 336, 168)]   // an upgraded install: 14 days of session, the 7-day token is the shorter
    [InlineData(30, 336, 336)]
    [InlineData(7, 0, 168)]     // no maximum: the token lifetime alone
    [InlineData(1, 12, 12)]
    public void The_session_maximum_wins_over_the_refresh_token_lifetime(int refreshTokenDays, int maxHours, int effectiveHours)
    {
        var now = new DateTime(2026, 11, 12, 8, 0, 0, DateTimeKind.Utc);

        Assert.Equal(effectiveHours, SessionLifetime.EffectiveRefreshTokenHours(refreshTokenDays, maxHours));
        Assert.Equal(now.AddHours(effectiveHours), SessionLifetime.RefreshTokenExpiry(now, now, refreshTokenDays, maxHours));
    }

    [Fact]
    public void A_refresh_late_in_the_session_gets_what_is_left_of_it()
    {
        var start = new DateTime(2026, 11, 12, 8, 0, 0, DateTimeKind.Utc);

        Assert.Equal(start.AddHours(12), SessionLifetime.RefreshTokenExpiry(start.AddHours(11), start, 7, 12));
    }

    [Fact]
    public void A_sign_in_s_refresh_token_expires_with_the_session_not_after_seven_days()
    {
        using var w = new World(maxSessionLifetimeHours: 12);

        var row = w.Row(w.SignedIn(TimeSpan.Zero));

        AssertClose(DateTime.UtcNow.AddHours(12), row.ExpiresAt);
        AssertClose(DateTime.UtcNow, row.FamilyCreatedAt!.Value);
    }

    [Fact]
    public async Task A_refresh_inside_the_session_keeps_the_sign_in_time_and_neither_token_outlives_the_horizon()
    {
        using var w = new World(maxSessionLifetimeHours: 12);
        var first = w.SignedIn(TimeSpan.FromHours(11.75));
        var horizon = w.Row(first).FamilyCreatedAt!.Value.AddHours(12);

        var (second, accessExpiry) = Refreshed(await w.RefreshAsync(first));

        var successor = w.Row(second);
        AssertClose(w.Row(first).FamilyCreatedAt!.Value, successor.FamilyCreatedAt!.Value);
        AssertClose(horizon, successor.ExpiresAt);
        // 15 minutes of session are left, so the 30-minute access token is cut to them.
        Assert.True(accessExpiry <= horizon.AddSeconds(1), $"access token {accessExpiry:O} outlives the session horizon {horizon:O}");
        Assert.True(accessExpiry < DateTime.UtcNow.AddMinutes(20));
    }

    [Fact]
    public async Task A_chain_of_refreshes_cannot_outlive_the_maximum()
    {
        using var w = new World(maxSessionLifetimeHours: 12);
        var token = w.SignedIn(TimeSpan.FromHours(6));
        var horizon = w.Row(token).FamilyCreatedAt!.Value.AddHours(12);

        for (var i = 0; i < 5; i++)
        {
            (token, _) = Refreshed(await w.RefreshAsync(token));
            Assert.True(w.Row(token).ExpiresAt <= horizon.AddSeconds(1));
        }
    }

    /// <summary>
    /// A token issued while the maximum was longer (or off) still carries a later expiry of its
    /// own; the maximum as it stands now decides.
    /// </summary>
    [Fact]
    public async Task A_session_past_the_maximum_is_refused_even_when_its_token_has_not_expired()
    {
        using var w = new World(maxSessionLifetimeHours: 12);
        var token = w.SignedIn(TimeSpan.FromHours(13), issuedUnderMaxHours: 0);
        Assert.True(w.Row(token).ExpiresAt > DateTime.UtcNow.AddDays(6));

        AssertSessionOver(await w.RefreshAsync(token));

        Assert.True(w.Row(token).IsRevoked);
    }

    [Fact]
    public async Task The_fourteen_days_an_upgraded_install_stored_still_mean_fourteen_days()
    {
        // 14 days became 336 hours in the TighterDefaults migration. The refresh-token lifetime
        // is set past it so that the session maximum is what decides.
        using var w = new World(maxSessionLifetimeHours: 14 * 24, refreshTokenDays: 30);
        var thirteenDays = w.SignedIn(TimeSpan.FromDays(13));
        var fifteenDays = w.SignedIn(TimeSpan.FromDays(15), issuedUnderMaxHours: 0);

        var (successor, _) = Refreshed(await w.RefreshAsync(thirteenDays));
        AssertClose(w.Row(thirteenDays).FamilyCreatedAt!.Value.AddDays(14), w.Row(successor).ExpiresAt);

        AssertSessionOver(await w.RefreshAsync(fifteenDays));
    }

    [Fact]
    public async Task With_no_maximum_the_refresh_token_lifetime_alone_applies()
    {
        using var w = new World(maxSessionLifetimeHours: 0);
        var token = w.SignedIn(TimeSpan.FromDays(6));

        var (successor, accessExpiry) = Refreshed(await w.RefreshAsync(token));

        AssertClose(DateTime.UtcNow.AddDays(7), w.Row(successor).ExpiresAt);
        AssertClose(DateTime.UtcNow.AddMinutes(30), accessExpiry);
    }
}
