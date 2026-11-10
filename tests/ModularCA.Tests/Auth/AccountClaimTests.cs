using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Models;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// One-time account claims, through the real <c>AuthController.Claim</c> and the host command
/// <c>--issue-claim-token</c>: a claim sets the password once and is then gone; a wrong, expired or
/// used token, and an account that cannot be claimed, all get the same answer; a weak password is
/// refused without using the claim; the claim is audited. Also the bootstrap's
/// <c>initial-admin-password</c> file, which the first password change deletes.
/// </summary>
public sealed class AccountClaimTests : IDisposable
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string StrongPassword = "Claimed-Passw0rd!horse-battery";
    private const string GeneratedPassword = "Generated-Initial-Pa55word!";

    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
    private readonly string _configDir = Directory.CreateTempSubdirectory("mca-claim-").FullName;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly SystemConfig _config = new()
    {
        JWT = new JwtConfig { Secret = new string('k', 64) },
        Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
    };
    private readonly RecordingAuditService _audit = new();
    private readonly IDistributedCache _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

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

    /// <summary>
    /// SQLite rather than the in-memory provider: redeeming a claim deletes it with ExecuteDelete
    /// inside a transaction, which the in-memory provider cannot execute.
    /// </summary>
    public AccountClaimTests()
    {
        _connection.Open();
        using var db = Db();
        db.Database.EnsureCreated();
        db.Users.Add(new UserEntity
        {
            Id = _userId, Username = "superadmin", Email = "admin@example.test", IsActive = true, SecurityStamp = "stamp-0",
            PasswordHash = string.Empty, PasswordSource = PasswordSource.Local,
        });
        db.RefreshTokens.Add(new RefreshTokenEntity { Id = Guid.NewGuid(), UserId = _userId, Token = "live", ExpiresAt = DateTime.UtcNow.AddDays(1) });
        db.SaveChanges();
    }

    public void Dispose()
    {
        _connection.Dispose();
        try { Directory.Delete(_configDir, recursive: true); } catch { /* best effort */ }
    }

    private ModularCADbContext Db() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

    private UserEntity User()
    {
        using var db = Db();
        return db.Users.AsNoTracking().Single(u => u.Id == _userId);
    }

    private void ChangeUser(Action<UserEntity> change)
    {
        using var db = Db();
        change(db.Users.Single(u => u.Id == _userId));
        db.SaveChanges();
    }

    /// <summary>Records a claim on the account for a fresh token and returns the token.</summary>
    private string Issue(DateTime? expiresAt = null)
    {
        var token = AccountClaims.NewToken();
        using var db = Db();
        var user = db.Users.Single(u => u.Id == _userId);
        AccountClaims.IssueAsync(db, user, AccountClaims.Hash(token), expiresAt ?? DateTime.UtcNow.AddDays(7), AccountClaims.IssuedByBootstrap, DateTime.UtcNow)
            .GetAwaiter().GetResult();
        return token;
    }

    private int ClaimCount()
    {
        using var db = Db();
        return db.UserClaimTokens.Count();
    }

    /// <summary>An <c>AuthController</c> over <paramref name="db"/>, with its config directory pointed at the test's.</summary>
    private (Type Type, object Controller) Controller(ModularCADbContext db)
    {
        var type = ApiAssembly.TypeNamed(ControllerName);
        var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
        var available = new object[]
        {
            db, new JwtTokenService(_config), _audit, _config, new FixedPolicy(), _cache, new NoLdap(), new PasswordPolicyService(db),
            Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.LoginRequestValidator"))!,
            Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.PreJwtChangePasswordRequestValidator"))!,
        };
        var args = ctor.GetParameters().Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a))).ToArray();
        var controller = ctor.Invoke(args);
        type.GetProperty("ConfigDirectory", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(controller, _configDir);
        var services = new ServiceCollection().BuildServiceProvider();
        type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = services } });
        return (type, controller);
    }

    private async Task<IActionResult> ClaimAsync(string token, string password, string? confirm = null)
    {
        using var db = Db();
        var (type, controller) = Controller(db);
        var request = new ClaimAccountRequest { Token = token, NewPassword = password, ConfirmNewPassword = confirm ?? password };
        return await (Task<IActionResult>)type.GetMethod("Claim")!.Invoke(controller, [request])!;
    }

    private async Task<IActionResult> ChangePasswordAsync(string oldPassword, string newPassword)
    {
        using var db = Db();
        var (type, controller) = Controller(db);
        var request = new PreJwtChangePasswordRequest
        {
            Username = "superadmin", OldPassword = oldPassword, NewPassword = newPassword, ConfirmNewPassword = newPassword,
        };
        return await (Task<IActionResult>)type.GetMethod("ChangePassword")!.Invoke(controller, [request])!;
    }

    private static string RefusedMessage =>
        (string)ApiAssembly.TypeNamed(ControllerName).GetField("ClaimRefusedMessage", BindingFlags.Static | BindingFlags.NonPublic)!.GetRawConstantValue()!;

    private static string? Error(IActionResult result)
        => ((ObjectResult)result).Value!.GetType().GetProperty("error")!.GetValue(((ObjectResult)result).Value) as string;

    [Fact]
    public async Task A_claim_sets_the_password_once_and_is_audited()
    {
        var token = Issue();
        // Guessing at an account with no password can lock it; the claim clears that.
        ChangeUser(u => { u.IsLocked = true; u.FailedLoginAttempts = 9; });

        var result = await ClaimAsync(token, StrongPassword);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.False(User().IsLocked);
        Assert.Equal(0, User().FailedLoginAttempts);
        Assert.Equal("superadmin", ok.Value!.GetType().GetProperty("username")!.GetValue(ok.Value));
        var user = User();
        Assert.True(PasswordUtil.VerifyPassword(StrongPassword, user.PasswordHash));
        Assert.False(user.PasswordChangeOnNextLogon);
        Assert.Equal(PasswordSource.Local, user.PasswordSource);
        Assert.NotEqual("stamp-0", user.SecurityStamp);
        Assert.Equal(0, ClaimCount());
        using (var db = Db())
            Assert.All(db.RefreshTokens.Where(t => t.UserId == _userId), t => Assert.True(t.IsRevoked));

        var audit = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.UserAccountClaimed);
        Assert.Equal(_userId.ToString(), audit.TargetId);
        Assert.Contains("bootstrap", audit.Details!.ToString());

        // Single use: the same token again is refused with the generic answer, and changes nothing.
        var again = await ClaimAsync(token, "Another-Passw0rd!different-one");
        Assert.IsType<BadRequestObjectResult>(again);
        Assert.Equal(RefusedMessage, Error(again));
        Assert.True(PasswordUtil.VerifyPassword(StrongPassword, User().PasswordHash));
        Assert.Single(_audit.Entries, e => e.Action == AuditActionType.UserAccountClaimed);
    }

    [Fact]
    public async Task A_wrong_or_expired_token_and_an_unclaimable_account_get_the_same_answer()
    {
        var expired = Issue(DateTime.UtcNow.AddMinutes(-1));
        var expiredAnswer = await ClaimAsync(expired, StrongPassword);
        var wrongAnswer = await ClaimAsync(AccountClaims.NewToken(), StrongPassword);

        var valid = Issue();
        ChangeUser(u => u.IsActive = false);
        var disabledAnswer = await ClaimAsync(valid, StrongPassword);
        ChangeUser(u => { u.IsActive = true; u.PasswordSource = PasswordSource.Directory; });
        var directoryAnswer = await ClaimAsync(valid, StrongPassword);

        foreach (var answer in new[] { expiredAnswer, wrongAnswer, disabledAnswer, directoryAnswer })
        {
            Assert.IsType<BadRequestObjectResult>(answer);
            Assert.Equal(RefusedMessage, Error(answer));
        }
        Assert.Equal(string.Empty, User().PasswordHash);
        Assert.Equal(1, ClaimCount());
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.UserAccountClaimed);

        // Each refusal is audited with its reason, which only the audit trail sees.
        var reasons = _audit.Entries.Where(e => e.Action == AuditActionType.UserLoginFailed).Select(e => e.Details!.ToString()!).ToList();
        Assert.Equal(4, reasons.Count);
        Assert.Contains(reasons, r => r.Contains("expired"));
        Assert.Contains(reasons, r => r.Contains("no_match"));
        Assert.Equal(2, reasons.Count(r => r.Contains("not_claimable")));
        Assert.All(reasons, r => Assert.Contains("claim", r));
    }

    [Fact]
    public async Task A_weak_password_is_refused_without_using_the_claim()
    {
        var token = Issue();

        var weak = await ClaimAsync(token, "short");

        var bad = Assert.IsType<BadRequestObjectResult>(weak);
        Assert.NotEqual(RefusedMessage, Error(weak));
        Assert.NotNull(bad.Value!.GetType().GetProperty("details")!.GetValue(bad.Value));
        Assert.Equal(1, ClaimCount());
        Assert.Equal(string.Empty, User().PasswordHash);

        // The same policy answer comes back for a token that matches nothing: it says nothing about the claim.
        Assert.Equal(Error(weak), Error(await ClaimAsync(AccountClaims.NewToken(), "short")));

        // A mismatched confirmation is refused before anything else.
        Assert.IsType<BadRequestObjectResult>(await ClaimAsync(token, StrongPassword, StrongPassword + "x"));
        Assert.Equal(1, ClaimCount());

        Assert.IsType<OkObjectResult>(await ClaimAsync(token, StrongPassword));
    }

    [Fact]
    public async Task A_token_pasted_with_surrounding_whitespace_still_claims()
    {
        var token = Issue();

        Assert.IsType<OkObjectResult>(await ClaimAsync($"  {token}\n", StrongPassword));
    }

    [Fact]
    public async Task The_first_password_change_deletes_the_bootstrap_password_file()
    {
        ChangeUser(u => { u.PasswordHash = PasswordUtil.HashPassword(GeneratedPassword); u.PasswordChangeOnNextLogon = true; });
        var file = InitialAdminPasswordFile.Write(_configDir, GeneratedPassword);

        var result = await ChangePasswordAsync(GeneratedPassword, StrongPassword);

        Assert.IsType<OkObjectResult>(result);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public async Task A_password_change_leaves_a_file_holding_some_other_password()
    {
        const string temporary = "Temporary-Admin-Reset-9!";
        ChangeUser(u => { u.PasswordHash = PasswordUtil.HashPassword(temporary); u.PasswordChangeOnNextLogon = true; });
        var file = InitialAdminPasswordFile.Write(_configDir, GeneratedPassword);

        Assert.IsType<OkObjectResult>(await ChangePasswordAsync(temporary, StrongPassword));

        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task Claiming_an_account_whose_password_is_in_the_bootstrap_file_deletes_the_file()
    {
        ChangeUser(u => { u.PasswordHash = PasswordUtil.HashPassword(GeneratedPassword); u.PasswordChangeOnNextLogon = true; });
        var file = InitialAdminPasswordFile.Write(_configDir, GeneratedPassword);
        var token = Issue();

        Assert.IsType<OkObjectResult>(await ClaimAsync(token, StrongPassword));

        Assert.False(File.Exists(file));
        Assert.False(User().PasswordChangeOnNextLogon);
    }

    [Fact]
    public async Task The_host_command_replaces_an_old_claim_and_prints_the_new_token_once()
    {
        var oldToken = Issue();
        using var auditDb = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase($"audit-{Guid.NewGuid():N}").Options);
        var issue = ApiAssembly.TypeNamed("ModularCA.API.Startup.ClaimTokenCommand").GetMethod("RunIssueAsync")!;
        var output = new StringWriter();
        var now = DateTime.UtcNow;

        int exit;
        using (var db = Db())
            exit = await (Task<int>)issue.Invoke(null, [db, auditDb, "superadmin", "48", output, now])!;

        Assert.Equal(0, exit);
        using (var db = Db())
        {
            var claim = Assert.Single(db.UserClaimTokens);
            Assert.Equal("host:break-glass", claim.IssuedBy);
            Assert.Equal(now.AddHours(48), claim.ExpiresAt, TimeSpan.FromSeconds(1));
        }

        // The token is the one 43-character base64url word on its own line; it is printed once.
        var printed = output.ToString();
        var newToken = printed.Split('\n').Select(l => l.Trim()).Single(l => l.Length == 43 && !l.Contains(' '));
        Assert.Equal(1, printed.Split(newToken).Length - 1);

        // The old token no longer works; the new one does.
        Assert.Equal(RefusedMessage, Error(await ClaimAsync(oldToken, StrongPassword)));
        Assert.IsType<OkObjectResult>(await ClaimAsync(newToken, StrongPassword));

        // Audited by the host, without the token.
        var record = Assert.Single(auditDb.AuditLogs.Where(a => a.ActionType == AuditActionType.UserClaimTokenIssuedOnHost));
        Assert.Equal("host:break-glass", record.ActorUsername);
        Assert.Equal(("User", _userId.ToString()), (record.TargetEntityType, record.TargetEntityId));
        Assert.Contains("\"Replaced\":true", record.DetailsJson);
        Assert.DoesNotContain(newToken, record.DetailsJson);
    }

    [Theory]
    [InlineData("no-such-user", null)]
    [InlineData("superadmin", "0")]
    [InlineData("superadmin", "8761")]
    [InlineData("superadmin", "seven")]
    public async Task The_host_command_refuses_an_unknown_account_or_lifetime(string username, string? lifetime)
    {
        var issue = ApiAssembly.TypeNamed("ModularCA.API.Startup.ClaimTokenCommand").GetMethod("RunIssueAsync")!;
        using var db = Db();

        Assert.Equal(1, await (Task<int>)issue.Invoke(null, [db, null, username, lifetime, new StringWriter(), null])!);
        Assert.Equal(0, ClaimCount());
    }

    [Fact]
    public async Task The_host_command_refuses_a_directory_account()
    {
        ChangeUser(u => u.PasswordSource = PasswordSource.Directory);
        var issue = ApiAssembly.TypeNamed("ModularCA.API.Startup.ClaimTokenCommand").GetMethod("RunIssueAsync")!;
        using var db = Db();

        Assert.Equal(1, await (Task<int>)issue.Invoke(null, [db, null, "superadmin", null, new StringWriter(), null])!);
        Assert.Equal(0, ClaimCount());
    }

    [Fact]
    public void The_new_token_command_prints_a_token_and_the_line_with_its_hash()
    {
        var run = ApiAssembly.TypeNamed("ModularCA.API.Startup.ClaimTokenCommand").GetMethod("RunNew")!;
        var output = new StringWriter();

        Assert.Equal(0, (int)run.Invoke(null, [output])!);

        var lines = output.ToString().Split('\n').Select(l => l.Trim()).ToList();
        var token = lines.Single(l => l.Length == 43 && !l.Contains(' '));
        Assert.Contains($"ClaimTokenSha256: \"{AccountClaims.HashHex(token)}\"", lines);
        Assert.True(AccountClaims.TryParseHashHex(AccountClaims.HashHex(token), out var hash));
        Assert.Equal(32, hash.Length);
        Assert.Equal(32, Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + "=").Length);
    }
}
