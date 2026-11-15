using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
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
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// The password policy a new install starts with (the NIST SP 800-63B preset), the preset an
/// existing install is offered, the bundled blocklist, and "never expires": what each sets, and
/// that a policy applies when a password is set or changed and never at sign-in.
/// </summary>
public sealed class PasswordPolicyDefaultsTests
{
    private const string AuthControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string PolicyControllerName = "ModularCA.API.Controllers.v1.Admin.AdminPasswordPolicyController";

    /// <summary>The policy every install had before 0.4.5, as its stored row holds it.</summary>
    private static PasswordPolicyEntity Legacy() => new()
    {
        MinLength = 12, MaxLength = 128, RequireUppercase = true, RequireLowercase = true, RequireDigit = true,
        RequireSymbol = true, MaxAgeDays = 90, HistoryCount = 0, UseBundledBlocklist = false,
    };

    // ── What a new install gets ─────────────────────────────────────────────────────────────

    [Fact]
    public void A_new_install_s_policy_is_the_nist_preset()
    {
        var policy = new PasswordPolicyEntity();

        Assert.Equal(15, policy.MinLength);
        Assert.Equal(128, policy.MaxLength);
        Assert.False(policy.RequireUppercase);
        Assert.False(policy.RequireLowercase);
        Assert.False(policy.RequireDigit);
        Assert.False(policy.RequireSymbol);
        Assert.Equal(0, policy.MinUppercase + policy.MinLowercase + policy.MinDigits + policy.MinSpecial);
        Assert.Equal(0, policy.MaxAgeDays);
        Assert.Equal(0, policy.HistoryCount);
        Assert.True(policy.UseBundledBlocklist);
        Assert.Null(policy.DictionaryPath);
        Assert.Empty(PasswordPolicyPresets.DifferencesFromNist80063B(policy));
    }

    [Fact]
    public void Bootstrap_seeds_that_policy_and_leaves_an_existing_row_alone()
    {
        using var fresh = InMemoryDbContextFactory.Create();
        ModularCA.Bootstrap.BootstrapProfileSeeder.SeedPasswordPolicy(fresh);
        var seeded = fresh.PasswordPolicies.AsNoTracking().Single();
        Assert.Equal((15, 0, true, false), (seeded.MinLength, seeded.MaxAgeDays, seeded.UseBundledBlocklist, seeded.RequireSymbol));

        using var installed = InMemoryDbContextFactory.Create();
        installed.PasswordPolicies.Add(Legacy());
        installed.SaveChanges();
        ModularCA.Bootstrap.BootstrapProfileSeeder.SeedPasswordPolicy(installed);
        var kept = installed.PasswordPolicies.AsNoTracking().Single();
        Assert.Equal((12, 90, false, true), (kept.MinLength, kept.MaxAgeDays, kept.UseBundledBlocklist, kept.RequireSymbol));
    }

    // ── The preset ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_preset_sets_exactly_the_documented_values_and_nothing_else()
    {
        var policy = Legacy();
        policy.MinUppercase = 2;
        policy.MinLowercase = 2;
        policy.MinDigits = 2;
        policy.MinSpecial = 2;
        policy.HistoryCount = 5;
        policy.DictionaryPath = "/opt/modularca/config/password-dictionaries/ours.txt";
        policy.DictionaryIsHashed = true;
        // Length, composition and expiry; its own dictionary already counts as a blocklist.
        Assert.Equal(3, PasswordPolicyPresets.DifferencesFromNist80063B(policy).Count);

        PasswordPolicyPresets.ApplyNist80063B(policy);

        Assert.Equal(15, policy.MinLength);
        Assert.Equal(128, policy.MaxLength);
        Assert.False(policy.RequireUppercase || policy.RequireLowercase || policy.RequireDigit || policy.RequireSymbol);
        Assert.Equal((0, 0, 0, 0), (policy.MinUppercase, policy.MinLowercase, policy.MinDigits, policy.MinSpecial));
        Assert.Equal(0, policy.MaxAgeDays);
        Assert.True(policy.UseBundledBlocklist);
        // Not the standard's business: kept as the administrator had them.
        Assert.Equal(5, policy.HistoryCount);
        Assert.Equal("/opt/modularca/config/password-dictionaries/ours.txt", policy.DictionaryPath);
        Assert.True(policy.DictionaryIsHashed);
        Assert.Empty(PasswordPolicyPresets.DifferencesFromNist80063B(policy));
    }

    [Theory]
    [InlineData(32, 128)]   // under 64: raised
    [InlineData(64, 64)]    // the least the standard allows: kept
    [InlineData(256, 256)]  // longer: kept
    [InlineData(0, 0)]      // no maximum: kept
    public void The_preset_raises_only_a_maximum_length_under_sixty_four(int before, int after)
    {
        var policy = Legacy();
        policy.MaxLength = before;

        PasswordPolicyPresets.ApplyNist80063B(policy);

        Assert.Equal(after, policy.MaxLength);
    }

    [Fact]
    public void A_stricter_length_still_meets_the_standard_and_composition_or_expiry_do_not()
    {
        Assert.Empty(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { MinLength = 20 }));
        Assert.Single(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { RequireDigit = true }));
        Assert.Single(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { MinSpecial = 1 }));
        Assert.Single(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { MaxAgeDays = 365 }));
        Assert.Single(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { UseBundledBlocklist = false }));
        // The administrator's own list counts as a blocklist.
        Assert.Empty(PasswordPolicyPresets.DifferencesFromNist80063B(new PasswordPolicyEntity { UseBundledBlocklist = false, DictionaryPath = "x" }));
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "admin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static (object Controller, ModularCADbContext Db, RecordingAuditService Audit) PolicyController(PasswordPolicyEntity? stored)
    {
        var db = InMemoryDbContextFactory.Create();
        if (stored != null)
        {
            db.PasswordPolicies.Add(stored);
            db.SaveChanges();
        }
        var audit = new RecordingAuditService();
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(PolicyControllerName), db, audit, new CurrentUserStub(Guid.NewGuid()))!;
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = new DefaultHttpContext() });
        return (controller, db, audit);
    }

    private static async Task<IActionResult> InvokeAsync(object controller, string action, params object?[] args) =>
        await (Task<IActionResult>)controller.GetType().GetMethod(action)!.Invoke(controller, args)!;

    [Fact]
    public async Task Applying_the_preset_through_the_api_rewrites_the_stored_policy_in_one_action_and_is_audited()
    {
        var (controller, db, audit) = PolicyController(Legacy());

        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "ApplyPreset", "nist-sp-800-63b"));

        db.ChangeTracker.Clear();
        var stored = await db.PasswordPolicies.AsNoTracking().SingleAsync();
        Assert.Equal((15, 128, 0, true), (stored.MinLength, stored.MaxLength, stored.MaxAgeDays, stored.UseBundledBlocklist));
        Assert.False(stored.RequireUppercase || stored.RequireLowercase || stored.RequireDigit || stored.RequireSymbol);
        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.PasswordPolicyUpdated, entry.Action);
        Assert.Contains("nist-sp-800-63b", JsonSerializer.Serialize(entry.Details));
    }

    [Fact]
    public async Task An_unknown_preset_is_not_found_and_changes_nothing()
    {
        var (controller, db, audit) = PolicyController(Legacy());

        Assert.IsType<NotFoundObjectResult>(await InvokeAsync(controller, "ApplyPreset", "pci-dss"));

        Assert.Equal(12, (await db.PasswordPolicies.AsNoTracking().SingleAsync()).MinLength);
        Assert.Empty(audit.Entries);
    }

    [Fact]
    public async Task Every_setting_stays_editable_after_the_preset()
    {
        var (controller, db, _) = PolicyController(Legacy());
        await InvokeAsync(controller, "ApplyPreset", "nist-sp-800-63b");

        // An organization required to keep rotation and a digit puts them back; the blocklist goes off.
        var requestType = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.PasswordPolicyUpdateRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("MaxAgeDays")!.SetValue(request, (int?)60);
        requestType.GetProperty("RequireDigit")!.SetValue(request, (bool?)true);
        requestType.GetProperty("UseBundledBlocklist")!.SetValue(request, (bool?)false);
        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "Update", request));

        db.ChangeTracker.Clear();
        var stored = await db.PasswordPolicies.AsNoTracking().SingleAsync();
        Assert.Equal((15, 60, true, false), (stored.MinLength, stored.MaxAgeDays, stored.RequireDigit, stored.UseBundledBlocklist));
    }

    [Fact]
    public async Task The_guidance_offers_the_preset_to_an_existing_install_and_changes_nothing()
    {
        var (controller, db, audit) = PolicyController(Legacy());

        var ok = Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "Guidance"));

        var json = JsonSerializer.SerializeToElement(ok.Value);
        Assert.False(json.GetProperty("nist80063B").GetProperty("meets").GetBoolean());
        Assert.Equal(4, json.GetProperty("nist80063B").GetProperty("differences").GetArrayLength());
        Assert.Equal("nist-sp-800-63b", json.GetProperty("nist80063B").GetProperty("preset").GetString());
        Assert.True(json.GetProperty("bundledBlocklist").GetProperty("available").GetBoolean());
        Assert.False(json.GetProperty("bundledBlocklist").GetProperty("inUse").GetBoolean());
        Assert.Equal(12, (await db.PasswordPolicies.AsNoTracking().SingleAsync()).MinLength);
        Assert.Empty(audit.Entries);
    }

    // ── Validation under the new default ────────────────────────────────────────────────────

    [Theory]
    [InlineData("a long phrase of plain words")]   // no upper case, digit or symbol: length is the requirement
    [InlineData("fifteen letters")]                // exactly 15
    [InlineData("Str0ng-Bootstrap-Pw!")]
    public void Length_is_the_requirement_and_no_character_class_is_needed(string password)
    {
        Assert.Empty(PasswordPolicyService.Validate(password, new PasswordPolicyEntity()));
    }

    [Fact]
    public void Fourteen_characters_are_too_few()
    {
        var errors = PasswordPolicyService.Validate("Sh0rt-But-Mix!", new PasswordPolicyEntity());

        Assert.Contains("at least 15", Assert.Single(errors));
    }

    // ── The bundled blocklist ───────────────────────────────────────────────────────────────

    [Fact]
    public void The_bundled_list_is_found_in_the_build_output()
    {
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "password-blocklist", "bundled-blocklist.txt"), BundledPasswordBlocklist.FilePath);
        Assert.True(File.Exists(BundledPasswordBlocklist.FilePath), $"not in the build output: {BundledPasswordBlocklist.FilePath}");

        var list = BundledPasswordBlocklist.Current;

        Assert.True(list.Available, list.Problem);
        Assert.True(list.Count >= 300, $"only {list.Count} entries");
        Assert.All(list.Entries, e => Assert.Equal(BundledPasswordBlocklist.Normalize(e), e));
        Assert.DoesNotContain(list.Entries, e => e.StartsWith('#') || e.Length == 0);
    }

    [Fact]
    public void The_api_s_own_build_output_carries_the_list_too()
    {
        var beside = Path.Combine(Path.GetDirectoryName(ApiAssembly.Instance.Location)!, "password-blocklist", "bundled-blocklist.txt");

        Assert.True(File.Exists(beside), $"not beside the API assembly: {beside}");
    }

    [Theory]
    [InlineData("password")]
    [InlineData("PASSWORD")]                       // case is ignored
    [InlineData("PaSsWoRd123")]
    [InlineData("qwertyuiopasdfgh")]               // long enough for a 15-character policy
    [InlineData("correcthorsebatterystaple")]
    [InlineData("ModularCA")]                      // the product's own name
    [InlineData("modularcaadmin123")]
    [InlineData("12345678901234567890")]
    [InlineData("passwordpassword")]               // an entry repeated
    [InlineData("PasswordPasswordPassword")]
    [InlineData("aaaaaaaaaaaaaaaa")]               // one character repeated
    [InlineData("abababababababab")]               // two characters repeated
    [InlineData("ｐａｓｓｗｏｒｄ")]                  // full-width forms normalize to "password"
    public void A_listed_password_is_on_the_list(string password)
    {
        Assert.True(BundledPasswordBlocklist.Contains(password));
    }

    [Theory]
    [InlineData("a long phrase of plain words")]
    [InlineData("password-but-with-more-to-it")]   // contains an entry, is not one
    [InlineData("xkq7 vmz2 plu9 wrt4")]
    [InlineData("abcabcabcabcabc-not-a-repeat")]
    [InlineData("")]
    public void Anything_else_is_not(string password)
    {
        Assert.False(BundledPasswordBlocklist.Contains(password));
    }

    [Fact]
    public void A_missing_list_is_reported_and_blocks_nothing()
    {
        var missing = BundledPasswordBlocklist.Load(Path.Combine(Path.GetTempPath(), $"mca-no-list-{Guid.NewGuid():N}.txt"));

        Assert.False(missing.Available);
        Assert.NotNull(missing.Problem);
        Assert.Equal(0, missing.Count);
        Assert.False(missing.Contains("password"));
    }

    [Fact]
    public void A_list_file_ignores_comments_and_blank_lines_and_folds_case()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mca-list-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "# a comment\n\n  Hunter2  \r\nSECRET-word\n#notanentry\n");
        try
        {
            var list = BundledPasswordBlocklist.Load(path);

            Assert.True(list.Available);
            Assert.Equal(2, list.Count);
            Assert.True(list.Contains("hunter2"));
            Assert.True(list.Contains("Secret-Word"));
            Assert.False(list.Contains("#notanentry"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void The_policy_refuses_a_listed_password_only_while_the_bundled_list_is_on()
    {
        const string listed = "qwertyuiopasdfgh";

        Assert.Equal([PasswordPolicyService.BlocklistedMessage], PasswordPolicyService.Validate(listed, new PasswordPolicyEntity()));
        Assert.Empty(PasswordPolicyService.Validate(listed, new PasswordPolicyEntity { UseBundledBlocklist = false }));
    }

    [Fact]
    public void The_administrator_s_own_list_adds_to_the_bundled_one()
    {
        var own = Path.Combine(Path.GetTempPath(), $"mca-own-{Guid.NewGuid():N}.txt");
        File.WriteAllText(own, "our-company-name-2026\n");
        try
        {
            var both = new PasswordPolicyEntity { DictionaryPath = own };
            var ownOnly = new PasswordPolicyEntity { DictionaryPath = own, UseBundledBlocklist = false };

            // Theirs is checked whether or not the bundled list is on, in any case of letters.
            Assert.Equal([PasswordPolicyService.BlocklistedMessage], PasswordPolicyService.Validate("Our-Company-Name-2026", both));
            Assert.Equal([PasswordPolicyService.BlocklistedMessage], PasswordPolicyService.Validate("our-company-name-2026", ownOnly));
            // The bundled list is still checked beside theirs: it adds, it does not replace.
            Assert.Equal([PasswordPolicyService.BlocklistedMessage], PasswordPolicyService.Validate("qwertyuiopasdfgh", both));
            Assert.Empty(PasswordPolicyService.Validate("qwertyuiopasdfgh", ownOnly));
            Assert.Empty(PasswordPolicyService.Validate("a long phrase of plain words", both));
        }
        finally
        {
            File.Delete(own);
        }
    }

    // ── "Never expires" ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void With_no_maximum_age_nobody_is_expired_whatever_date_an_earlier_policy_stamped()
    {
        var now = new DateTime(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
        var stale = new UserEntity { PasswordExpirationDate = now.AddDays(-400) };
        var never = new PasswordPolicyEntity { MaxAgeDays = 0 };
        var ninety = new PasswordPolicyEntity { MaxAgeDays = 90 };

        Assert.False(PasswordExpiry.IsExpired(stale, never, now));
        Assert.Null(PasswordExpiry.ExpiresAt(stale, never));
        Assert.True(PasswordExpiry.IsExpired(stale, ninety, now));
        Assert.Equal(now.AddDays(-400), PasswordExpiry.ExpiresAt(stale, ninety));
        Assert.False(PasswordExpiry.IsExpired(new UserEntity { PasswordExpirationDate = now.AddDays(-400), PasswordNeverExpires = true }, ninety, now));
        Assert.False(PasswordExpiry.IsExpired(new UserEntity { PasswordExpirationDate = null }, ninety, now));
        Assert.False(PasswordExpiry.IsExpired(new UserEntity { PasswordExpirationDate = now.AddDays(1) }, ninety, now));
    }

    [Fact]
    public void A_password_change_stamps_the_policy_s_age_or_clears_the_date()
    {
        var now = new DateTime(2026, 11, 12, 0, 0, 0, DateTimeKind.Utc);
        var user = new UserEntity { PasswordExpirationDate = now.AddDays(-1) };

        PasswordExpiry.Stamp(user, new PasswordPolicyEntity { MaxAgeDays = 30 }, now);
        Assert.Equal(now.AddDays(30), user.PasswordExpirationDate);

        PasswordExpiry.Stamp(user, new PasswordPolicyEntity { MaxAgeDays = 0 }, now);
        Assert.Null(user.PasswordExpirationDate);

        var exempt = new UserEntity { PasswordNeverExpires = true };
        PasswordExpiry.Stamp(exempt, new PasswordPolicyEntity { MaxAgeDays = 30 }, now);
        Assert.Null(exempt.PasswordExpirationDate);
    }

    // ── Set, change and sign-in, through the real service and controller ────────────────────

    private sealed class NoDpop : IDpopProofService
    {
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private sealed class NoLdap : ILdapAuthService
    {
        public Task<LdapBindOutcome> AuthenticateAsync(string username, string password) => Task.FromResult(LdapBindOutcome.UserNotFound);
        public Task<List<string>?> GetUserGroupsAsync(string username) => Task.FromResult<List<string>?>(null);
    }

    private sealed class FixedSecurityPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new() { SessionIdleTimeoutMinutes = 0, LoginResponseDelayMs = 0, MaxConcurrentSessions = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    /// <summary>One local account, rita, and a stored password policy, over SQLite.</summary>
    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        private readonly IDistributedCache _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        public World(PasswordPolicyEntity policy, string password, Action<UserEntity>? user = null)
        {
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.PasswordPolicies.Add(policy);
            var rita = new UserEntity
            {
                Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s",
                PasswordHash = PasswordUtil.HashPassword(password), PasswordSource = PasswordSource.Local, PasswordExpirationDate = null,
            };
            user?.Invoke(rita);
            db.Users.Add(rita);
            db.SaveChanges();
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        public UserEntity User()
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == UserId);
        }

        public void SetPolicy(Action<PasswordPolicyEntity> change)
        {
            using var db = Db();
            change(db.PasswordPolicies.Single());
            db.SaveChanges();
        }

        public async Task<T> Users<T>(Func<UserManagementService, Task<T>> act)
        {
            using var db = Db();
            return await act(new UserManagementService(db, NullLogger<UserManagementService>.Instance, Config, new FixedSecurityPolicy(), new PasswordPolicyService(db)));
        }

        public Task<IActionResult> LoginAsync(string password) =>
            AuthAsync("Login", new ModularCA.Auth.Models.LoginRequest { Username = "rita", Password = password });

        public Task<IActionResult> PreSessionChangeAsync(string oldPassword, string newPassword) =>
            AuthAsync("ChangePassword", new ModularCA.Auth.Models.PreJwtChangePasswordRequest
            {
                Username = "rita", OldPassword = oldPassword, NewPassword = newPassword, ConfirmNewPassword = newPassword,
            });

        private async Task<IActionResult> AuthAsync(string action, object request)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(AuthControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, new JwtTokenService(Config), new RecordingAuditService(), Config, new FixedSecurityPolicy(), _cache, new NoLdap(),
                new PasswordPolicyService(db), new NoopNotificationService(),
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.LoginRequestValidator"))!,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.PreJwtChangePasswordRequestValidator"))!,
            };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a))).ToArray());
            var configDirectory = type.GetProperty("ConfigDirectory", BindingFlags.Instance | BindingFlags.NonPublic);
            configDirectory?.SetValue(controller, Path.Combine(Path.GetTempPath(), "mca-no-such-config-" + Guid.NewGuid().ToString("N")));
            var services = new ServiceCollection()
                .AddSingleton(new ModularCA.Auth.Authorization.AccessBadgeService(db))
                .AddSingleton<IDpopProofService>(new NoDpop())
                .BuildServiceProvider();
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = services } });
            return await (Task<IActionResult>)type.GetMethod(action)!.Invoke(controller, [request])!;
        }
    }

    private static UpdatePasswordRequest Change(string from, string to) =>
        new() { OldPassword = from, NewPassword = to, ConfirmNewPassword = to };

    private static CreateUserRequest NewUser(string password) => new()
    {
        Username = "noor", Email = "noor@example.test", Password = password, FirstName = "Noor", LastName = "N", GroupIds = [],
    };

    [Fact]
    public async Task A_blocklisted_password_is_refused_when_an_account_is_created()
    {
        using var w = new World(new PasswordPolicyEntity(), "a long phrase of plain words");

        var (refused, error) = await w.Users(u => u.CreateUser(NewUser("correcthorsebatterystaple")));
        var (accepted, _) = await w.Users(u => u.CreateUser(NewUser("a different phrase entirely")));

        Assert.False(refused);
        Assert.Contains(PasswordPolicyService.BlocklistedMessage, error);
        Assert.True(accepted);
    }

    [Fact]
    public async Task A_blocklisted_password_is_refused_when_a_password_is_changed()
    {
        const string current = "a long phrase of plain words";
        using var w = new World(new PasswordPolicyEntity(), current);

        var changed = await w.Users(u => u.UpdateUserPassword(w.UserId, Change(current, "qwertyuiopasdfgh")));

        Assert.False(changed);
        Assert.True(PasswordUtil.VerifyPassword(current, w.User().PasswordHash));
    }

    [Fact]
    public async Task A_blocklisted_password_is_refused_at_the_forced_change_before_sign_in()
    {
        const string temporary = "Temporary-Passw0rd-From-Admin!";
        using var w = new World(new PasswordPolicyEntity(), temporary, u => u.PasswordChangeOnNextLogon = true);

        var refused = Assert.IsType<BadRequestObjectResult>(await w.PreSessionChangeAsync(temporary, "passwordpassword"));
        Assert.Contains(PasswordPolicyService.BlocklistedMessage, JsonSerializer.Serialize(refused.Value));
        Assert.True(w.User().PasswordChangeOnNextLogon);

        Assert.IsType<OkObjectResult>(await w.PreSessionChangeAsync(temporary, "a long phrase of plain words"));
        Assert.Null(w.User().PasswordExpirationDate);
    }

    /// <summary>
    /// The upgrade promise: a password set under the old policy keeps signing in after the policy
    /// tightens, though it is short, lacks nothing the old policy asked for, and is on the list.
    /// </summary>
    [Theory]
    [InlineData("Password123!")]       // 12 characters with all four classes: valid before, too short and listed now
    [InlineData("qwertyuiopasdfgh")]   // on the bundled list
    [InlineData("short")]
    public async Task A_password_stored_before_the_policy_tightened_still_signs_in(string existing)
    {
        using var w = new World(Legacy(), existing);
        Assert.IsType<OkObjectResult>(await w.LoginAsync(existing));

        w.SetPolicy(PasswordPolicyPresets.ApplyNist80063B);

        Assert.IsType<OkObjectResult>(await w.LoginAsync(existing));
        Assert.False(w.User().PasswordChangeOnNextLogon);
    }

    [Fact]
    public async Task An_account_past_its_stamped_date_signs_in_once_passwords_never_expire()
    {
        const string password = "a long phrase of plain words";
        using var w = new World(Legacy(), password, u => u.PasswordExpirationDate = DateTime.UtcNow.AddDays(-5));

        // Under 90 days it is expired, and the pre-session change is open to it.
        var expired = Assert.IsType<ObjectResult>(await w.LoginAsync(password));
        Assert.Equal(403, expired.StatusCode);
        Assert.Contains("expired", JsonSerializer.Serialize(expired.Value));

        w.SetPolicy(p => p.MaxAgeDays = 0);

        Assert.IsType<OkObjectResult>(await w.LoginAsync(password));
        // And it is no longer an account that may replace its password before signing in.
        var notRequired = Assert.IsType<ObjectResult>(await w.PreSessionChangeAsync(password, "another long phrase of words"));
        Assert.Equal(403, notRequired.StatusCode);
    }

    [Fact]
    public async Task A_new_account_and_a_changed_password_get_no_expiry_date_while_passwords_never_expire()
    {
        const string current = "a long phrase of plain words";
        using var w = new World(new PasswordPolicyEntity(), current, u => u.PasswordExpirationDate = DateTime.UtcNow.AddDays(3));

        await w.Users(u => u.CreateUser(NewUser("a different phrase entirely")));
        Assert.True(await w.Users(u => u.UpdateUserPassword(w.UserId, Change(current, "yet another phrase of words"))));

        using var db = w.Db();
        Assert.All(db.Users.AsNoTracking().ToList(), u => Assert.Null(u.PasswordExpirationDate));
        Assert.All(await w.Users(u => u.GetAllUsers()), u => Assert.Null(u.PasswordExpiration));
    }

    [Fact]
    public async Task A_policy_with_a_maximum_age_still_stamps_it_on_create_change_and_reset()
    {
        const string current = "Curr3nt-Passw0rd-Here!";
        using var w = new World(new PasswordPolicyEntity { MaxAgeDays = 30, UseBundledBlocklist = false }, current);

        await w.Users(u => u.CreateUser(NewUser("An0ther-Passw0rd-Here!")));
        Assert.True(await w.Users(u => u.UpdateUserPassword(w.UserId, Change(current, "Y3t-Another-Passw0rd!"))));

        using var db = w.Db();
        Assert.All(db.Users.AsNoTracking().ToList(), u =>
            Assert.True((u.PasswordExpirationDate!.Value - DateTime.UtcNow.AddDays(30)).Duration() < TimeSpan.FromMinutes(1)));
        var listed = await w.Users(u => u.GetAllUsers());
        Assert.All(listed, u => Assert.NotNull(u.PasswordExpiration));

        await w.Users(u => u.ResetUserPassword(w.UserId));
        Assert.True((w.User().PasswordExpirationDate!.Value - DateTime.UtcNow.AddDays(30)).Duration() < TimeSpan.FromMinutes(1));
    }
}
