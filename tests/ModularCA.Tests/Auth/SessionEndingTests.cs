using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Models;
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
/// Every change that ends an account's sessions, driven through the real code and then the real
/// <c>AuthController.Refresh</c>: a refresh token issued before the change is refused after it, the
/// security stamp has rotated, and another account's session is left alone. Refresh does not read
/// the stamp, so each of these has to revoke the refresh tokens itself; they all do it through
/// <c>UserSessionTermination</c>. The changes that deliberately rotate the stamp without ending
/// sessions (a username or email change, a group change) are pinned the other way: the refresh
/// token still works. Revoking an mTLS credential or its certificate is covered by
/// <see cref="MtlsRevokedCertificateTests"/>.
/// </summary>
public sealed class SessionEndingTests
{
    private const string AuthControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string TotpControllerName = "ModularCA.API.Controllers.v1.Auth.TotpController";
    private const string WebAuthnControllerName = "ModularCA.API.Controllers.v1.Auth.WebAuthnController";
    private const string OldPassword = "Original-Passw0rd!correct-staple";
    private const string NewPassword = "Replaced-Passw0rd!horse-battery";
    private const string RecoveryCode = "ABCDE-FGHIJ";

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

    private sealed class NoLdap : ILdapAuthService
    {
        public Task<LdapBindOutcome> AuthenticateAsync(string username, string password) => Task.FromResult(LdapBindOutcome.UserNotFound);
        public Task<List<string>?> GetUserGroupsAsync(string username) => Task.FromResult<List<string>?>(null);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "rita" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>
    /// SQLite rather than the in-memory provider: refresh rotation, the claim, the forced password
    /// change and the recovery code all use set-based updates inside a transaction.
    /// </summary>
    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public Guid OtherUserId { get; } = Guid.NewGuid();
        public Guid GroupId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        public FixedPolicy Policy { get; } = new();
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        /// <summary>The account's refresh token from before the change, in plaintext.</summary>
        public string Before { get; }

        /// <summary>Another account's refresh token, which no change to the first may touch.</summary>
        public string Others { get; }

        public World()
        {
            _connection.Open();
            using (var db = Db())
            {
                db.Database.EnsureCreated();
                db.Users.Add(new UserEntity
                {
                    Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s",
                    PasswordHash = PasswordUtil.HashPassword(OldPassword), PasswordSource = PasswordSource.Local,
                });
                db.Users.Add(new UserEntity { Id = OtherUserId, Username = "noor", Email = "noor@example.test", IsActive = true, SecurityStamp = "o" });
                db.CaGroups.Add(new CaGroupEntity { Id = GroupId, Name = "operators", DisplayName = "Operators" });
                db.SaveChanges();
            }
            Before = Login(UserId);
            Others = Login(OtherUserId);
            Cache.SetString($"user-stamp:{UserId:N}", "s|g");
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        /// <summary>Issues a first-login refresh token for an account and returns its plaintext.</summary>
        public string Login(Guid userId)
        {
            using var db = Db();
            var rt = new JwtTokenService(Config).GenerateRefreshToken(userId, "127.0.0.1", null, null);
            db.RefreshTokens.Add(rt);
            db.SaveChanges();
            return rt.PlaintextTokenForClient!;
        }

        public void Change(Action<ModularCADbContext, UserEntity> change)
        {
            using var db = Db();
            change(db, db.Users.Single(u => u.Id == UserId));
            db.SaveChanges();
        }

        public string Stamp(Guid userId)
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == userId).SecurityStamp;
        }

        public bool StampCached => Cache.GetString($"user-stamp:{UserId:N}") != null;

        public RefreshTokenEntity Row(string plaintext)
        {
            using var db = Db();
            var hash = JwtTokenService.HashRefreshToken(plaintext);
            return db.RefreshTokens.AsNoTracking().Single(t => t.Token == hash);
        }

        /// <summary>Runs <paramref name="act"/> on a user-management service over its own context.</summary>
        public async Task<T> Users<T>(Func<UserManagementService, Task<T>> act)
        {
            using var db = Db();
            return await act(new UserManagementService(db, NullLogger<UserManagementService>.Instance, Config, Policy, new PasswordPolicyService(db)));
        }

        /// <summary>Invokes a controller action as the first account.</summary>
        public async Task<IActionResult> InvokeAsync(string controllerName, string action, params object?[] args)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(controllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, Cache, new JwtTokenService(Config), Audit, Config, Policy, new NoLdap(), new PasswordPolicyService(db),
                new EphemeralDataProtectionProvider(), new CurrentUserStub(UserId), new NoopNotificationService(), new InProcessReplayGuard(),
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.LoginRequestValidator"))!,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.PreJwtChangePasswordRequestValidator"))!,
            };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            var configDirectory = type.GetProperty("ConfigDirectory", BindingFlags.Instance | BindingFlags.NonPublic);
            configDirectory?.SetValue(controller, Path.Combine(Path.GetTempPath(), "mca-no-such-config-" + Guid.NewGuid().ToString("N")));
            var http = new DefaultHttpContext
            {
                RequestServices = new ServiceCollection().AddSingleton<IDpopProofService>(new NoDpop()).BuildServiceProvider(),
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", UserId.ToString()) }, "test")),
            };
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            var method = type.GetMethods().Single(m => m.Name == action && m.GetParameters().Length == args.Length);
            return await (Task<IActionResult>)method.Invoke(controller, args)!;
        }

        /// <summary>Calls <c>AuthController.Refresh</c> with a plaintext refresh token.</summary>
        public async Task<IActionResult> RefreshAsync(string plaintext)
        {
            var method = ApiAssembly.TypeNamed(AuthControllerName).GetMethod("Refresh")!;
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("RefreshToken")!.SetValue(request, plaintext);
            return await InvokeAsync(AuthControllerName, "Refresh", request);
        }

        /// <summary>
        /// Presents an access token of the first account carrying <paramref name="stamp"/> to the
        /// real <c>TokenRevocationMiddleware</c>, as a device that signed in before the change
        /// would, and returns the status it answers (200 when the request is let through).
        /// </summary>
        public async Task<int> AccessTokenStatusAsync(string stamp = "s", string? jti = null)
        {
            var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.TokenRevocationMiddleware");
            RequestDelegate next = _ => Task.CompletedTask;
            var middleware = Activator.CreateInstance(type, next, Cache)!;
            await using var services = new ServiceCollection().AddScoped(_ => Db()).BuildServiceProvider();
            var claims = new List<Claim> { new("sub", UserId.ToString()), new("stamp", stamp) };
            if (jti != null) claims.Add(new Claim("jti", jti));
            var http = new DefaultHttpContext
            {
                RequestServices = services,
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")),
            };
            await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [http])!;
            return http.Response.StatusCode;
        }

        /// <summary>Runs a host command (<c>RunAsync(db, auditDb, ...)</c>) with no audit database.</summary>
        public async Task<int> HostCommandAsync(string typeName, params object?[] args)
        {
            using var db = Db();
            var run = ApiAssembly.TypeNamed(typeName).GetMethod("RunAsync")!;
            return await (Task<int>)run.Invoke(null, [db, null, .. args, new StringWriter()])!;
        }
    }

    /// <summary>
    /// The account's sessions are over: its stamp rotated, the token from before the change is
    /// revoked and refresh refuses it, and the other account's session still refreshes.
    /// </summary>
    private static async Task AssertSessionsEndedAsync(World w)
    {
        Assert.NotEqual("s", w.Stamp(w.UserId));
        var row = w.Row(w.Before);
        Assert.True(row.IsRevoked);
        Assert.NotNull(row.RevokedAt);
        Assert.IsNotType<OkObjectResult>(await w.RefreshAsync(w.Before));

        // An access token from before the change is refused once the middleware reads the account
        // again: at once where the change dropped the cached stamp, within its 30 seconds otherwise.
        w.Cache.Remove($"user-stamp:{w.UserId:N}");
        Assert.Equal(401, await w.AccessTokenStatusAsync());

        Assert.Equal("o", w.Stamp(w.OtherUserId));
        Assert.False(w.Row(w.Others).IsRevoked);
    }

    /// <summary>The account's sessions carry on: the token from before the change still refreshes.</summary>
    private static async Task AssertSessionsCarryOnAsync(World w)
    {
        Assert.False(w.Row(w.Before).IsRevoked);
        Assert.IsType<OkObjectResult>(await w.RefreshAsync(w.Before));
    }

    [Fact]
    public async Task Without_a_change_the_refresh_token_works()
    {
        using var w = new World();

        await AssertSessionsCarryOnAsync(w);
    }

    /// <summary>
    /// The console's edit: disabling, enabling, locking, unlocking and a password source change each
    /// end the sessions. Refresh would refuse a disabled or locked account on its state alone, so
    /// the enable and the unlock are the cases only the revocation covers.
    /// </summary>
    [Theory]
    [InlineData("disable")]
    [InlineData("enable")]
    [InlineData("lock")]
    [InlineData("unlock")]
    [InlineData("password-source")]
    public async Task An_administrators_change_to_an_accounts_standing_ends_its_sessions(string change)
    {
        using var w = new World();
        if (change == "enable") w.Change((_, u) => u.IsActive = false);
        if (change == "unlock") w.Change((_, u) => u.IsLocked = true);
        var request = change switch
        {
            "disable" => new UpdateUserRequest { IsActive = false },
            "enable" => new UpdateUserRequest { IsActive = true },
            "lock" => new UpdateUserRequest { IsLocked = true },
            "unlock" => new UpdateUserRequest { IsLocked = false },
            _ => new UpdateUserRequest { PasswordSource = PasswordSource.Directory },
        };

        Assert.True(await w.Users(s => s.UpdateUser(w.UserId, request)));

        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task A_password_change_ends_the_sessions()
    {
        using var w = new World();

        Assert.True(await w.Users(s => s.UpdateUserPassword(w.UserId,
            new UpdatePasswordRequest { OldPassword = OldPassword, NewPassword = NewPassword, ConfirmNewPassword = NewPassword })));

        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task An_administrators_password_reset_ends_the_sessions()
    {
        using var w = new World();

        Assert.False(string.IsNullOrEmpty(await w.Users(s => s.ResetUserPassword(w.UserId))));

        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task An_administrators_mfa_reset_ends_the_sessions()
    {
        using var w = new World();
        w.Change((db, u) => db.TotpSecrets.Add(new TotpSecretEntity { UserId = u.Id, IsVerified = true }));

        Assert.Equal((1, 0), await w.Users(s => s.ResetUserMfa(w.UserId)));

        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task The_forced_password_change_at_sign_in_ends_the_sessions()
    {
        using var w = new World();
        w.Change((_, u) => u.PasswordChangeOnNextLogon = true);

        var result = await w.InvokeAsync(AuthControllerName, "ChangePassword", new PreJwtChangePasswordRequest
        {
            Username = "rita", OldPassword = OldPassword, NewPassword = NewPassword, ConfirmNewPassword = NewPassword,
        });

        Assert.IsType<OkObjectResult>(result);
        Assert.False(w.StampCached);
        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task Claiming_an_account_ends_the_sessions()
    {
        using var w = new World();
        var token = AccountClaims.NewToken();
        using (var db = w.Db())
        {
            await AccountClaims.IssueAsync(db, db.Users.Single(u => u.Id == w.UserId), AccountClaims.Hash(token),
                DateTime.UtcNow.AddDays(1), AccountClaims.IssuedByBootstrap, DateTime.UtcNow);
        }

        var result = await w.InvokeAsync(AuthControllerName, "Claim",
            new ClaimAccountRequest { Token = token, NewPassword = NewPassword, ConfirmNewPassword = NewPassword });

        Assert.IsType<OkObjectResult>(result);
        Assert.False(w.StampCached);
        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task A_totp_recovery_code_ends_the_sessions()
    {
        using var w = new World();
        w.Change((db, u) => db.TotpRecoveryCodes.Add(new TotpRecoveryCodeEntity { UserId = u.Id, CodeHash = RecoveryCodeHash.Compute(u.Id, RecoveryCode) }));
        var method = ApiAssembly.TypeNamed(TotpControllerName).GetMethod("TotpRecovery")!;
        var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
        request.GetType().GetProperty("Username")!.SetValue(request, "rita");
        request.GetType().GetProperty("RecoveryCode")!.SetValue(request, RecoveryCode);

        Assert.IsType<OkObjectResult>(await w.InvokeAsync(TotpControllerName, "TotpRecovery", request));

        Assert.False(w.StampCached);
        using (var db = w.Db())
            Assert.NotNull(db.TotpRecoveryCodes.Single().UsedAt);
        await AssertSessionsEndedAsync(w);
    }

    /// <summary>
    /// Removing a WebAuthn credential from the account page signs the account out everywhere, the
    /// session that asked included, as revoking an mTLS credential does, and is audited the same way.
    /// </summary>
    [Fact]
    public async Task Removing_a_webauthn_credential_ends_the_sessions()
    {
        using var w = new World();
        var credentialId = Guid.NewGuid();
        w.Change((db, u) =>
        {
            db.Fido2Credentials.Add(new Fido2CredentialEntity { Id = credentialId, UserId = u.Id, CredentialId = [1, 2, 3], PublicKey = [4, 5, 6], DeviceName = "key" });
            db.TotpSecrets.Add(new TotpSecretEntity { UserId = u.Id, IsVerified = true });
        });
        var stepUp = Guid.NewGuid().ToString("N");
        w.Cache.SetString($"mfa-stepup:{w.UserId}:{StepUpOps.WebAuthnDelete}:{credentialId}", stepUp);

        Assert.IsType<OkObjectResult>(await w.InvokeAsync(WebAuthnControllerName, "DeleteCredential", credentialId, stepUp));

        using (var db = w.Db())
            Assert.Empty(db.Fido2Credentials);
        Assert.False(w.StampCached);
        Assert.Contains(w.Audit.Entries, e => e.Action == AuditActionType.MfaWebAuthnRemoved);
        var ended = Assert.Single(w.Audit.Entries, e => e.Action == AuditActionType.UserSessionsEnded);
        Assert.Equal(w.UserId.ToString(), ended.TargetId);
        var details = System.Text.Json.JsonSerializer.Serialize(ended.Details);
        Assert.Contains("webauthn_credential_removed", details);
        Assert.Contains("\"refreshTokensRevoked\":1", details);
        await AssertSessionsEndedAsync(w);
    }

    /// <summary>A removal that is refused changes nothing: no step-up, or the account's only MFA method.</summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task A_refused_webauthn_removal_leaves_the_sessions_alone(bool steppedUp, bool hasAnotherMethod)
    {
        using var w = new World();
        var credentialId = Guid.NewGuid();
        w.Change((db, u) =>
        {
            db.Fido2Credentials.Add(new Fido2CredentialEntity { Id = credentialId, UserId = u.Id, CredentialId = [1, 2, 3], PublicKey = [4, 5, 6] });
            if (hasAnotherMethod) db.TotpSecrets.Add(new TotpSecretEntity { UserId = u.Id, IsVerified = true });
        });
        var stepUp = Guid.NewGuid().ToString("N");
        if (steppedUp) w.Cache.SetString($"mfa-stepup:{w.UserId}:{StepUpOps.WebAuthnDelete}:{credentialId}", stepUp);

        var refused = Assert.IsType<ObjectResult>(await w.InvokeAsync(WebAuthnControllerName, "DeleteCredential", credentialId, stepUp));

        Assert.Equal(steppedUp ? 409 : 403, refused.StatusCode);
        Assert.Equal("s", w.Stamp(w.UserId));
        Assert.DoesNotContain(w.Audit.Entries, e => e.Action == AuditActionType.UserSessionsEnded);
        await AssertSessionsCarryOnAsync(w);
    }

    /// <summary>
    /// Removing the TOTP authenticator from the account page signs the account out everywhere, as
    /// removing a WebAuthn or mTLS credential does, and is audited the same way.
    /// </summary>
    [Fact]
    public async Task Removing_totp_ends_the_sessions()
    {
        using var w = new World();
        w.Change((db, u) =>
        {
            db.TotpSecrets.Add(new TotpSecretEntity { UserId = u.Id, IsVerified = true });
            db.Fido2Credentials.Add(new Fido2CredentialEntity { UserId = u.Id, CredentialId = [1, 2, 3], PublicKey = [4, 5, 6] });
        });

        Assert.IsType<OkObjectResult>(await w.InvokeAsync(TotpControllerName, "Remove"));

        using (var db = w.Db())
            Assert.Empty(db.TotpSecrets);
        Assert.False(w.StampCached);
        Assert.Contains(w.Audit.Entries, e => e.Action == AuditActionType.MfaTotpRemoved);
        var ended = Assert.Single(w.Audit.Entries, e => e.Action == AuditActionType.UserSessionsEnded);
        Assert.Equal(w.UserId.ToString(), ended.TargetId);
        var details = System.Text.Json.JsonSerializer.Serialize(ended.Details);
        Assert.Contains("totp_removed", details);
        Assert.Contains("\"refreshTokensRevoked\":1", details);
        await AssertSessionsEndedAsync(w);
    }

    /// <summary>TOTP that is the account's only MFA method is not removed, and nothing ends.</summary>
    [Fact]
    public async Task A_refused_totp_removal_leaves_the_sessions_alone()
    {
        using var w = new World();
        w.Change((db, u) => db.TotpSecrets.Add(new TotpSecretEntity { UserId = u.Id, IsVerified = true }));

        var refused = Assert.IsType<ObjectResult>(await w.InvokeAsync(TotpControllerName, "Remove"));

        Assert.Equal(409, refused.StatusCode);
        Assert.Equal("s", w.Stamp(w.UserId));
        Assert.DoesNotContain(w.Audit.Entries, e => e.Action == AuditActionType.UserSessionsEnded);
        await AssertSessionsCarryOnAsync(w);
    }

    /// <summary>
    /// There is no per-device sign-out, so logging out on one device ends every session of the
    /// account: another device's refresh token is refused, and so is the access token it still
    /// holds, at once and not when it runs out. The token that logged out is refused by its jti
    /// as well. Another account is not touched.
    /// </summary>
    [Fact]
    public async Task Logging_out_ends_the_sessions_on_every_device()
    {
        using var w = new World();
        var otherDevice = w.Login(w.UserId);
        Assert.Equal(200, await w.AccessTokenStatusAsync());

        Assert.IsType<OkObjectResult>(await w.InvokeAsync(AuthControllerName, "Logout"));

        // Straight away: the logout dropped the cached stamp itself.
        Assert.False(w.StampCached);
        Assert.Equal(401, await w.AccessTokenStatusAsync());
        Assert.True(w.Row(otherDevice).IsRevoked);
        Assert.IsNotType<OkObjectResult>(await w.RefreshAsync(otherDevice));

        var logout = Assert.Single(w.Audit.Entries, e => e.Action == AuditActionType.UserLogout);
        var details = System.Text.Json.JsonSerializer.Serialize(logout.Details);
        Assert.Contains("\"allSessions\":true", details);
        Assert.Contains("\"refreshTokensRevoked\":2", details);
        await AssertSessionsEndedAsync(w);
    }

    /// <summary>A token carrying the account's current stamp is let through, so the 401s above are the stamp's doing.</summary>
    [Fact]
    public async Task An_access_token_with_the_current_stamp_is_accepted_and_a_stale_one_is_not()
    {
        using var w = new World();

        Assert.Equal(200, await w.AccessTokenStatusAsync("s"));
        Assert.Equal(401, await w.AccessTokenStatusAsync("stale"));
    }

    [Fact]
    public async Task The_host_unlock_command_ends_the_sessions()
    {
        using var w = new World();
        w.Change((_, u) => u.IsLocked = true);

        Assert.Equal(0, await w.HostCommandAsync("ModularCA.API.Startup.UnlockUserCommand", "rita"));

        await AssertSessionsEndedAsync(w);
    }

    [Fact]
    public async Task The_host_password_source_command_ends_the_sessions_only_when_the_source_changes()
    {
        using var w = new World();

        Assert.Equal(0, await w.HostCommandAsync("ModularCA.API.Startup.SetPasswordSourceCommand", "rita", "Local"));
        Assert.Equal("s", w.Stamp(w.UserId));
        Assert.False(w.Row(w.Before).IsRevoked);

        Assert.Equal(0, await w.HostCommandAsync("ModularCA.API.Startup.SetPasswordSourceCommand", "rita", "Inherit"));
        await AssertSessionsEndedAsync(w);
    }

    /// <summary>
    /// By design, a new username or email rotates the stamp so access tokens go stale, and the
    /// client refreshes to pick up the new claims: the session carries on.
    /// </summary>
    [Theory]
    [InlineData("username")]
    [InlineData("email")]
    public async Task A_username_or_email_change_rotates_the_stamp_and_keeps_the_sessions(string field)
    {
        using var w = new World();
        var request = field == "username" ? new UpdateUserRequest { Username = "rita-2" } : new UpdateUserRequest { Email = "rita-2@example.test" };

        Assert.True(await w.Users(s => s.UpdateUser(w.UserId, request)));

        Assert.NotEqual("s", w.Stamp(w.UserId));
        await AssertSessionsCarryOnAsync(w);
    }

    /// <summary>By design, a group change rotates the stamp and refresh re-reads the groups: the session carries on.</summary>
    [Fact]
    public async Task A_group_change_rotates_the_stamp_and_keeps_the_sessions()
    {
        using var w = new World();

        Assert.True(await w.Users(s => s.AddUserToGroup(w.UserId, w.GroupId)));
        var afterAdd = w.Stamp(w.UserId);
        Assert.NotEqual("s", afterAdd);
        Assert.False(w.Row(w.Before).IsRevoked);

        Assert.True(await w.Users(s => s.RemoveUserFromGroup(w.UserId, w.GroupId)));
        Assert.NotEqual(afterAdd, w.Stamp(w.UserId));
        await AssertSessionsCarryOnAsync(w);
    }
}
