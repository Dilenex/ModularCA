using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// TOTP recovery codes are stored salted and slow-hashed per user while rows in the pre-0.4.3
/// unsalted form still verify; wrong codes lock the account at the shared threshold and notify
/// administrators; refusals for unknown or ineligible accounts are held to the same response
/// budget; and both a recovery and a self-service password change drop the cached security stamp
/// so old JWTs stop at once instead of up to 30 seconds later.
/// </summary>
public sealed class TotpRecoveryCodeTests
{
    private const string TotpControllerName = "ModularCA.API.Controllers.v1.Auth.TotpController";
    private const string AccountControllerName = "ModularCA.API.Controllers.v1.Account.AccountManagerController";
    private const string Code = "ABCDE-FGHIJ";

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        public SecurityPolicyEntity Policy { get; } = new() { MaxFailedLoginAttempts = 3, LockoutMinutes = 15, LoginResponseDelayMs = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(Policy);
        public void InvalidateCache() { }
    }

    private sealed class RecordingNotifications : NoopNotificationService
    {
        public List<(string Username, string Reason)> Locked { get; } = new();
        public override Task NotifyAccountLockedAsync(string username, string reason)
        {
            Locked.Add((username, reason));
            return Task.CompletedTask;
        }
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "tess" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>A user-management service whose password change always succeeds.</summary>
    public class PasswordChangingProxy : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => targetMethod!.Name == nameof(IUserManagementService.UpdateUserPassword)
                ? Task.FromResult(true)
                : throw new NotSupportedException(targetMethod.Name);
    }

    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new() { JWT = new JwtConfig { Secret = new string('k', 64) } };
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public FixedPolicy Policy { get; } = new();
        public RecordingNotifications Notifications { get; } = new();
        private string StampKey => $"user-stamp:{UserId:N}";

        public World(string storedHash)
        {
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity { Id = UserId, Username = "tess", Email = "tess@example.test", IsActive = true, SecurityStamp = "s" });
            db.TotpRecoveryCodes.Add(new TotpRecoveryCodeEntity { UserId = UserId, CodeHash = storedHash });
            db.SaveChanges();
            Cache.SetString(StampKey, "s|g");
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        public bool StampCached => Cache.GetString(StampKey) != null;

        public UserEntity User()
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == UserId);
        }

        private object Controller(ModularCADbContext db, string name, params object[] extra)
        {
            var type = ApiAssembly.TypeNamed(name);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[] { db, Cache, new JwtTokenService(Config), Audit, Config, Policy, new EphemeralDataProtectionProvider(), new CurrentUserStub(UserId), Notifications }
                .Concat(extra).ToArray();
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", UserId.ToString()) }, "test")),
            };
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return controller;
        }

        public async Task<IActionResult> RecoverAsync(string code, string username = "tess")
        {
            using var db = Db();
            var controller = Controller(db, TotpControllerName);
            var method = controller.GetType().GetMethod("TotpRecovery")!;
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("Username")!.SetValue(request, username);
            request.GetType().GetProperty("RecoveryCode")!.SetValue(request, code);
            return await (Task<IActionResult>)method.Invoke(controller, new[] { request })!;
        }

        public async Task<IActionResult> ChangePasswordAsync()
        {
            using var db = Db();
            var users = DispatchProxy.Create<IUserManagementService, PasswordChangingProxy>();
            var controller = Controller(db, AccountControllerName, users);
            var stepUp = Guid.NewGuid().ToString("N");
            Cache.SetString($"mfa-stepup:{UserId}:{StepUpOps.ChangePassword}", stepUp);
            var method = controller.GetType().GetMethod("ChangePassword")!;
            return await (Task<IActionResult>)method.Invoke(controller, new object?[] { new UpdatePasswordRequest(), stepUp })!;
        }
    }

    [Fact]
    public void Stored_hashes_are_salted_per_user_and_fit_the_column()
    {
        var a = RecoveryCodeHash.Compute(Guid.NewGuid(), Code);
        var b = RecoveryCodeHash.Compute(Guid.NewGuid(), Code);

        Assert.NotEqual(a, b);
        Assert.StartsWith(RecoveryCodeHash.Prefix, a);
        Assert.True(a.Length <= 64, $"{a.Length} characters");
        Assert.NotEqual(RecoveryCodeHash.ComputeLegacy(Code), a.Substring(RecoveryCodeHash.Prefix.Length));
    }

    [Fact]
    public void Case_and_dashes_typed_from_paper_do_not_matter()
    {
        var user = Guid.NewGuid();
        Assert.Equal(RecoveryCodeHash.Compute(user, Code), RecoveryCodeHash.Compute(user, "abcdefghij"));
    }

    [Fact]
    public async Task A_code_in_the_current_form_is_accepted_and_drops_the_cached_stamp()
    {
        using var w = new World("placeholder");
        using (var db = w.Db())
        {
            db.TotpRecoveryCodes.Single().CodeHash = RecoveryCodeHash.Compute(w.UserId, Code);
            db.SaveChanges();
        }

        Assert.IsType<OkObjectResult>(await w.RecoverAsync("abcde-fghij"));
        Assert.False(w.StampCached);
        Assert.NotEqual("s", w.User().SecurityStamp);
    }

    [Fact]
    public async Task A_code_stored_in_the_legacy_unsalted_form_still_verifies()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));

        Assert.IsType<OkObjectResult>(await w.RecoverAsync(Code));
    }

    [Fact]
    public async Task Wrong_codes_lock_the_account_at_the_shared_threshold()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));

        for (var i = 0; i < 3; i++)
            Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync("ZZZZZ-ZZZZZ"));

        var user = w.User();
        Assert.Equal(3, user.FailedLoginAttempts);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.True(user.LockoutEndUtc > DateTime.UtcNow);

        // Locked: even the right code is refused now.
        Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync(Code));
        Assert.Equal("s", w.User().SecurityStamp);
    }

    /// <summary>
    /// A lockout that has run out starts the count again: the first wrong code after it counts one
    /// and does not lock the account again, and the right code is then accepted.
    /// </summary>
    [Fact]
    public async Task An_elapsed_lockout_starts_the_count_again()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));
        using (var db = w.Db())
        {
            var user = db.Users.Single();
            user.FailedLoginAttempts = 3;
            user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(-1);
            db.SaveChanges();
        }

        Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync("ZZZZZ-ZZZZZ"));
        var afterWrong = w.User();
        Assert.Equal(1, afterWrong.FailedLoginAttempts);
        Assert.Null(afterWrong.LockoutEndUtc);
        Assert.Empty(w.Notifications.Locked);

        Assert.IsType<OkObjectResult>(await w.RecoverAsync(Code));
    }

    [Fact]
    public async Task Locking_the_account_notifies_administrators_once()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));

        for (var i = 0; i < 2; i++)
            await w.RecoverAsync("ZZZZZ-ZZZZZ");
        Assert.Empty(w.Notifications.Locked);

        await w.RecoverAsync("ZZZZZ-ZZZZZ");
        var (username, reason) = Assert.Single(w.Notifications.Locked);
        Assert.Equal("tess", username);
        Assert.Contains("15 minutes", reason);

        // Refused while locked: no further failure counted, no second notice.
        await w.RecoverAsync("ZZZZZ-ZZZZZ");
        Assert.Single(w.Notifications.Locked);
        Assert.Equal(3, w.User().FailedLoginAttempts);
    }

    [Fact]
    public async Task A_hard_lock_is_reported_as_permanent()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));
        w.Policy.Policy.LockoutMinutes = 0;

        for (var i = 0; i < 3; i++)
            await w.RecoverAsync("ZZZZZ-ZZZZZ");

        Assert.True(w.User().IsLocked);
        Assert.Contains("Permanently locked", Assert.Single(w.Notifications.Locked).Reason);
    }

    [Fact]
    public async Task Refusals_for_unknown_and_ineligible_accounts_take_the_response_budget()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));
        w.Policy.Policy.LoginResponseDelayMs = 300;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync(Code, username: "nobody"));
        Assert.True(sw.ElapsedMilliseconds >= 280, $"unknown user answered in {sw.ElapsedMilliseconds} ms");
        Assert.Contains(w.Audit.Entries, e => e.Action == AuditActionType.MfaTotpFailed
            && System.Text.Json.JsonSerializer.Serialize(e.Details).Contains("totp_recovery_user_not_found"));

        sw.Restart();
        Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync("ZZZZZ-ZZZZZ"));
        Assert.True(sw.ElapsedMilliseconds >= 280, $"wrong code answered in {sw.ElapsedMilliseconds} ms");

        using (var db = w.Db())
        {
            db.Users.Single(u => u.Id == w.UserId).IsActive = false;
            db.SaveChanges();
        }
        sw.Restart();
        Assert.IsType<UnauthorizedObjectResult>(await w.RecoverAsync(Code));
        Assert.True(sw.ElapsedMilliseconds >= 280, $"disabled account answered in {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task A_self_service_password_change_drops_the_cached_stamp()
    {
        using var w = new World(RecoveryCodeHash.ComputeLegacy(Code));
        Assert.True(w.StampCached);

        Assert.IsType<OkObjectResult>(await w.ChangePasswordAsync());

        Assert.False(w.StampCached);
    }
}
