using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
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
/// Drives the real <c>AuthController.Login</c> with LDAP sign-in turned on: a bind the directory
/// refused never falls back to the local password hash.
/// </summary>
public sealed class LdapLocalFallbackTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string LocalPassword = "Local-Password-Stale-1!";

    private sealed class StubLdap(LdapBindOutcome outcome) : ILdapAuthService
    {
        public int Calls { get; private set; }

        public Task<LdapBindOutcome> AuthenticateAsync(string username, string password)
        {
            Calls++;
            return Task.FromResult(outcome);
        }

        public Task<List<string>?> GetUserGroupsAsync(string username) => Task.FromResult<List<string>?>(null);
    }

    private sealed class NoDpop : IDpopProofService
    {
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new()
        {
            SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0,
            MaxFailedLoginAttempts = 5, LockoutMinutes = 15,
        };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    /// <summary>
    /// SQLite rather than the in-memory provider: a failed login increments the counter with
    /// ExecuteUpdate, which the in-memory provider cannot execute.
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
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        public World()
        {
            Config.LdapAuth.Enabled = true;
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity
            {
                Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s",
                PasswordHash = PasswordUtil.HashPassword(LocalPassword), PasswordNeverExpires = true,
            });
            db.SaveChanges();
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        /// <summary>Calls <c>AuthController.Login</c> with the given credentials.</summary>
        public async Task<IActionResult> LoginAsync(ILdapAuthService ldap, string username, string password)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(ControllerName);
            var validatorType = ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.LoginRequestValidator");
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), Cache, ldap,
                Activator.CreateInstance(validatorType)!,
            };
            var args = ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray();
            var controller = ctor.Invoke(args);
            var services = new ServiceCollection()
                .AddSingleton(new ModularCA.Auth.Authorization.AccessBadgeService(db))
                .AddSingleton<IDpopProofService>(new NoDpop())
                .BuildServiceProvider();
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = services } });

            var method = type.GetMethod("Login")!;
            var request = new ModularCA.Auth.Models.LoginRequest { Username = username, Password = password };
            return await (Task<IActionResult>)method.Invoke(controller, new object[] { request })!;
        }

        /// <summary>Returns the stored user row.</summary>
        public UserEntity User()
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == UserId);
        }
    }

    [Fact]
    public async Task A_refused_ldap_bind_does_not_fall_back_to_the_local_password()
    {
        using var world = new World();
        var ldap = new StubLdap(LdapBindOutcome.Refused);

        // The directory refused the bind, so the directory is authoritative for this user. The local
        // hash may hold a stale password (the one handed out at account creation, say), and accepting
        // it would let a directory-disabled or directory-rotated account keep signing in.
        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        Assert.Equal(1, ldap.Calls);
        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(1, world.User().FailedLoginAttempts);
    }

    [Fact]
    public async Task An_unreachable_directory_refuses_the_sign_in_without_counting_a_failure()
    {
        using var world = new World();
        var ldap = new StubLdap(LdapBindOutcome.Unavailable);

        // Fail closed: without an answer there is no telling whether this is a directory account
        // with a stale local password. The password was never checked, so no failure is counted.
        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(0, world.User().FailedLoginAttempts);
        Assert.Contains(world.Audit.Entries, e => e.Details?.ToString()?.Contains("directory_unavailable") == true);
    }

    [Fact]
    public async Task An_account_the_directory_does_not_know_signs_in_with_the_local_password()
    {
        using var world = new World();
        var ldap = new StubLdap(LdapBindOutcome.UserNotFound);

        // A local-only account (the bootstrap administrator, for one) keeps password sign-in with
        // LDAP turned on.
        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(world.User().LastLoginAt);
    }

    [Fact]
    public async Task An_account_the_directory_does_not_know_is_refused_a_wrong_local_password()
    {
        using var world = new World();
        var ldap = new StubLdap(LdapBindOutcome.UserNotFound);

        var result = await world.LoginAsync(ldap, "rita", "Not-The-Password-1!");

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(1, world.User().FailedLoginAttempts);
    }
}
