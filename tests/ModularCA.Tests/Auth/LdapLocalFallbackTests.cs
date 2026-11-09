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
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Drives the real <c>AuthController.Login</c> with LDAP sign-in turned on: a bind the directory
/// refused never falls back to the local password hash, and an account's password source decides
/// whether the directory, the local hash or the instance rule answers.
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

        /// <summary>A world with one account, rita, whose local password is <see cref="LocalPassword"/>.</summary>
        /// <param name="source">Rita's password source.</param>
        /// <param name="ldapEnabled">The instance-wide LDAP sign-in setting.</param>
        public World(PasswordSource source = PasswordSource.Inherit, bool ldapEnabled = true)
        {
            Config.LdapAuth.Enabled = ldapEnabled;
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity
            {
                Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s",
                PasswordHash = PasswordUtil.HashPassword(LocalPassword), PasswordNeverExpires = true,
                PasswordSource = source,
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
            var (type, controller) = Controller(db, ldap);
            var method = type.GetMethod("Login")!;
            var request = new ModularCA.Auth.Models.LoginRequest { Username = username, Password = password };
            return await (Task<IActionResult>)method.Invoke(controller, new object[] { request })!;
        }

        /// <summary>Calls the pre-session <c>AuthController.ChangePassword</c> for rita.</summary>
        public async Task<IActionResult> PreSessionChangePasswordAsync(string oldPassword, string newPassword)
        {
            using var db = Db();
            var (type, controller) = Controller(db, new StubLdap(LdapBindOutcome.Succeeded));
            var request = new ModularCA.Auth.Models.PreJwtChangePasswordRequest
            {
                Username = "rita", OldPassword = oldPassword, NewPassword = newPassword, ConfirmNewPassword = newPassword,
            };
            return await (Task<IActionResult>)type.GetMethod("ChangePassword")!.Invoke(controller, new object[] { request })!;
        }

        /// <summary>An <c>AuthController</c> over <paramref name="db"/>, with what the tests use.</summary>
        private (Type Type, object Controller) Controller(ModularCADbContext db, ILdapAuthService ldap)
        {
            var type = ApiAssembly.TypeNamed(ControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), Cache, ldap,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.LoginRequestValidator"))!,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.PreJwtChangePasswordRequestValidator"))!,
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
            return (type, controller);
        }

        /// <summary>Returns the stored user row.</summary>
        public UserEntity User()
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == UserId);
        }

        /// <summary>Changes the stored user row.</summary>
        public void Change(Action<UserEntity> change)
        {
            using var db = Db();
            change(db.Users.Single(u => u.Id == UserId));
            db.SaveChanges();
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

    /// <summary>
    /// Each password source against each answer the directory can give, LDAP sign-in on, signing in
    /// with the account's local password (which the stub directory ignores). Inherit is the
    /// instance rule; Local never asks the directory; Directory never consults the local hash, and
    /// only an unreachable directory goes uncounted.
    /// </summary>
    [Theory]
    [InlineData(PasswordSource.Inherit, LdapBindOutcome.Succeeded, true, 0, 1)]
    [InlineData(PasswordSource.Inherit, LdapBindOutcome.Refused, false, 1, 1)]
    [InlineData(PasswordSource.Inherit, LdapBindOutcome.UserNotFound, true, 0, 1)]
    [InlineData(PasswordSource.Inherit, LdapBindOutcome.Unavailable, false, 0, 1)]
    [InlineData(PasswordSource.Local, LdapBindOutcome.Succeeded, true, 0, 0)]
    [InlineData(PasswordSource.Local, LdapBindOutcome.Refused, true, 0, 0)]
    [InlineData(PasswordSource.Local, LdapBindOutcome.UserNotFound, true, 0, 0)]
    [InlineData(PasswordSource.Local, LdapBindOutcome.Unavailable, true, 0, 0)]
    [InlineData(PasswordSource.Directory, LdapBindOutcome.Succeeded, true, 0, 1)]
    [InlineData(PasswordSource.Directory, LdapBindOutcome.Refused, false, 1, 1)]
    [InlineData(PasswordSource.Directory, LdapBindOutcome.UserNotFound, false, 1, 1)]
    [InlineData(PasswordSource.Directory, LdapBindOutcome.Unavailable, false, 0, 1)]
    public async Task The_password_source_decides_who_answers(
        PasswordSource source, LdapBindOutcome outcome, bool signsIn, int failedAttempts, int directoryCalls)
    {
        using var world = new World(source);
        var ldap = new StubLdap(outcome);

        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        if (signsIn)
            Assert.IsType<OkObjectResult>(result);
        else
            Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(failedAttempts, world.User().FailedLoginAttempts);
        Assert.Equal(directoryCalls, ldap.Calls);
    }

    [Fact]
    public async Task A_local_account_is_refused_a_wrong_password_without_asking_the_directory()
    {
        using var world = new World(PasswordSource.Local);
        var ldap = new StubLdap(LdapBindOutcome.Succeeded);

        // The directory would have accepted anything; it is not asked.
        var result = await world.LoginAsync(ldap, "rita", "Not-The-Password-1!");

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(1, world.User().FailedLoginAttempts);
        Assert.Equal(0, ldap.Calls);
    }

    [Fact]
    public async Task A_directory_account_whose_entry_is_gone_does_not_get_its_local_password_back()
    {
        using var world = new World(PasswordSource.Directory);
        var ldap = new StubLdap(LdapBindOutcome.UserNotFound);

        // The directory entry was deleted rather than disabled. The local row still holds the
        // password handed out at account creation, and it must not start working again.
        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Contains(world.Audit.Entries, e => e.Details?.ToString()?.Contains("not_in_directory") == true);
    }

    [Fact]
    public async Task An_inherit_account_the_directory_accepts_becomes_a_directory_account_and_its_entry_deletion_is_final()
    {
        using var world = new World(PasswordSource.Inherit);

        var result = await world.LoginAsync(new StubLdap(LdapBindOutcome.Succeeded), "rita", "the-directory-password");

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(PasswordSource.Directory, world.User().PasswordSource);
        var learned = Assert.Single(world.Audit.Entries, e => e.Action == AuditActionType.UserPasswordSourceLearned);
        Assert.Equal(world.UserId.ToString(), learned.TargetId);
        Assert.Contains("Inherit", learned.Details?.ToString());
        Assert.Contains("Directory", learned.Details?.ToString());

        // The directory entry is then deleted. As an Inherit account the local password would have
        // answered; as the Directory account it now is, it does not.
        var afterDeletion = await world.LoginAsync(new StubLdap(LdapBindOutcome.UserNotFound), "rita", LocalPassword);
        Assert.IsType<UnauthorizedObjectResult>(afterDeletion);
    }

    [Theory]
    [InlineData(PasswordSource.Inherit, LdapBindOutcome.UserNotFound)]
    [InlineData(PasswordSource.Local, LdapBindOutcome.Succeeded)]
    [InlineData(PasswordSource.Directory, LdapBindOutcome.Succeeded)]
    public async Task Only_an_inherit_account_accepted_by_the_directory_is_learned(PasswordSource source, LdapBindOutcome outcome)
    {
        using var world = new World(source);

        // A sign-in the local hash answered teaches nothing, and a set source is never overwritten.
        var result = await world.LoginAsync(new StubLdap(outcome), "rita", LocalPassword);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(source, world.User().PasswordSource);
        Assert.DoesNotContain(world.Audit.Entries, e => e.Action == AuditActionType.UserPasswordSourceLearned);
    }

    [Theory]
    [InlineData(PasswordSource.Directory)]
    [InlineData(PasswordSource.Inherit)]
    public async Task A_password_the_directory_accepted_is_not_held_to_the_local_password_flags(PasswordSource source)
    {
        using var world = new World(source);
        world.Change(u =>
        {
            u.PasswordChangeOnNextLogon = true;
            u.PasswordNeverExpires = false;
            u.PasswordExpirationDate = DateTime.UtcNow.AddDays(-1);
        });

        // The forced change and the expiry concern the local password, which this sign-in did not
        // use, and a directory account cannot set one: holding it to them would lock it out.
        var result = await world.LoginAsync(new StubLdap(LdapBindOutcome.Succeeded), "rita", "the-directory-password");

        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task A_local_password_is_still_held_to_the_forced_change()
    {
        using var world = new World(PasswordSource.Local);
        world.Change(u => u.PasswordChangeOnNextLogon = true);

        var result = await world.LoginAsync(new StubLdap(LdapBindOutcome.Succeeded), "rita", LocalPassword);

        Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task A_directory_account_cannot_set_a_local_password_before_signing_in()
    {
        using var world = new World(PasswordSource.Directory);
        world.Change(u => u.PasswordChangeOnNextLogon = true);
        var hash = world.User().PasswordHash;

        // The stale local password matches, but it is not this account's password; the generic
        // answer gives nothing away, and no failed attempt is counted.
        var result = await world.PreSessionChangePasswordAsync(LocalPassword, "A-Brand-New-Passw0rd!");

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(hash, world.User().PasswordHash);
        Assert.Equal(0, world.User().FailedLoginAttempts);
        Assert.Contains(world.Audit.Entries, e => e.Details?.ToString()?.Contains("directory_account") == true);
    }

    [Theory]
    [InlineData(PasswordSource.Inherit, true, 0)]
    [InlineData(PasswordSource.Local, true, 0)]
    [InlineData(PasswordSource.Directory, false, 0)]
    public async Task With_ldap_sign_in_off_only_a_directory_account_is_refused_and_nothing_is_counted(
        PasswordSource source, bool signsIn, int failedAttempts)
    {
        using var world = new World(source, ldapEnabled: false);
        var ldap = new StubLdap(LdapBindOutcome.Succeeded);

        // A directory account has no local password to fall back to: turning LDAP sign-in off
        // does not bring the stale local hash back into use.
        var result = await world.LoginAsync(ldap, "rita", LocalPassword);

        if (signsIn)
            Assert.IsType<OkObjectResult>(result);
        else
            Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(failedAttempts, world.User().FailedLoginAttempts);
        Assert.Equal(0, ldap.Calls);
    }
}
