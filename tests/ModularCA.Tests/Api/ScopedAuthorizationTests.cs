using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.AccessBadges;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Authorization that must be read at the target's own scope: group memberships (by group scope,
/// badge-aware, never from membership of an unrelated system group), the security policy, instance
/// configuration and password policy (system admin, not operator, step-up on every write),
/// policy-change approvals and rejections (admin rank), badges of a super, explicit instance scope
/// for a new group, the space of an SSH CA, and unreadable ceremony parameters.
/// </summary>
public sealed class ScopedAuthorizationTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    // ---- plumbing ----------------------------------------------------------------------------

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class FixedBadge(AccessBadgeFilter? filter) : IAccessBadgeContext
    {
        public Task<AccessBadgeFilter?> GetWornAsync(Guid userId) => Task.FromResult(filter);
    }

    private static FixedBadge? Badge(Guid[] groups)
        => groups.Length == 0 ? null : new FixedBadge(new AccessBadgeFilter(Guid.NewGuid(), "badge", groups, [], []));

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static string StepUp(IDistributedCache cache, Guid actor, string op, Guid? target = null)
    {
        var token = Guid.NewGuid().ToString("N");
        cache.SetString(target == null ? $"mfa-stepup:{actor}:{op}" : $"mfa-stepup:{actor}:{op}:{target}", token);
        return token;
    }

    private static object New(string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static int? Status(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static UserManagementService Users(ControlledUserWorld w)
        => new(w.Db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!, new ControlledUserBypassGuardTests.AllowAllPasswords());

    private static ControlledUserCeremonyService Controlled(ControlledUserWorld w, FixedBadge? badge)
        => new(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), Users(w), NullLogger<ControlledUserCeremonyService>.Instance, badge);

    private static CaGroupAuthorizationService GroupAuth(ControlledUserWorld w, FixedBadge? badge = null)
        => new(w.Db, NullLogger<CaGroupAuthorizationService>.Instance, badges: badge);

    /// <summary>The user manager as <paramref name="actor"/>, wearing a badge of <paramref name="badgeGroups"/> when given.</summary>
    private static object UserManager(ControlledUserWorld w, Guid actor, IDistributedCache cache, params Guid[] badgeGroups)
    {
        var badge = Badge(badgeGroups);
        return New(Ns + "Management.AdminUserManagerController", actor,
            w.Db, Users(w), new CurrentUserStub(actor), new RecordingAuditService(), cache, new RecordingAlertService(),
            Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.CreateUserRequestValidator")), null,
            Controlled(w, badge), GroupAuth(w, badge));
    }

    private static object GroupController(ControlledUserWorld w, Guid actor, params Guid[] badgeGroups)
    {
        var badge = Badge(badgeGroups);
        return New(Ns + "AdminGroupController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), NewCache(),
            GroupAuth(w, badge), Controlled(w, badge), new ModularCA.Core.Services.SshLoginNameService(w.Db, new RecordingAuditService()));
    }

    /// <summary>Creates an account named <paramref name="name"/> in <paramref name="group"/> as <paramref name="actor"/>.</summary>
    private static async Task<int?> CreateIn(ControlledUserWorld w, Guid actor, string name, CaGroupEntity group, params Guid[] badgeGroups)
    {
        var cache = NewCache();
        var request = new CreateUserRequest { Username = name, Email = $"{name}@example.com", Password = "Str0ng!Passw0rd", GroupIds = [group.Id] };
        return Status(await Call(UserManager(w, actor, cache, badgeGroups), "CreateUser", request, StepUp(cache, actor, StepUpOps.CreateUser)));
    }

    /// <summary>The groups the membership tests write to, none of them privilege-controlled.</summary>
    private sealed record Targets(CaGroupEntity A1Operators, CaGroupEntity A2Operators, CaGroupEntity B1Operators,
        CaGroupEntity ARequesters, CaGroupEntity InstanceRequesters);

    private static Targets SeedTargets(ControlledUserWorld w)
    {
        var t = new Targets(
            w.Group("org_a1_operator", w.SpaceA, w.CaA1, "Operator"),
            w.Group("org_a2_operator", w.SpaceA, w.CaA2, "Operator"),
            w.Group("org_b1_operator", w.SpaceB, w.CaB1, "Operator"),
            w.Group("space-a-requesters", w.SpaceA, null, "Requester"),
            w.Group("instance-requesters", null, null, "Requester"));
        w.Db.SaveChanges();
        return t;
    }

    // ---- group memberships -------------------------------------------------------------------

    /// <summary>
    /// The exploit: a system auditor who also operates one CA in space A read as a system admin,
    /// because any system group counted. They could create an account with a password of their
    /// choosing in space B's operator group, or add one there, then sign in as it.
    /// </summary>
    [Fact]
    public async Task A_system_auditor_who_operates_one_ca_cannot_place_an_account_in_another_spaces_group()
    {
        var w = new ControlledUserWorld();
        var t = SeedTargets(w);
        w.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = t.A1Operators.Id, UserId = w.Auditor });
        w.Db.SaveChanges();

        Assert.Equal(403, await CreateIn(w, w.Auditor, "puppet", t.B1Operators));
        Assert.False(w.Db.Users.Any(u => u.Username == "puppet"));

        var cache = NewCache();
        var add = await Call(UserManager(w, w.Auditor, cache), "AddUserToGroup", w.Plain, t.B1Operators.Id,
            StepUp(cache, w.Auditor, StepUpOps.AddGroupMember, w.Plain));
        Assert.Equal(403, Status(add));
        Assert.False(w.Db.CaGroupMembers.Any(m => m.UserId == w.Plain && m.GroupId == t.B1Operators.Id));

        // Operating a CA is not managing its groups either.
        Assert.Equal(403, await CreateIn(w, w.Auditor, "puppet-a1", t.A1Operators));
    }

    /// <summary>
    /// A system admin wearing a badge that keeps only their CA-A1 admin group has the rights of
    /// that group: A1's groups, not B's. Badgeless, the same account reaches B's.
    /// </summary>
    [Fact]
    public async Task A_badge_narrowed_system_admin_manages_only_the_groups_its_badge_covers()
    {
        var w = new ControlledUserWorld();
        var t = SeedTargets(w);
        var narrowed = w.User("narrowed-admin", w.SystemAdminGroup, w.A1Admin);

        Assert.Equal(403, await CreateIn(w, narrowed, "badged-b1", t.B1Operators, w.A1Admin.Id));
        Assert.Equal(403, await CreateIn(w, narrowed, "badged-instance", t.InstanceRequesters, w.A1Admin.Id));
        Assert.Equal(200, await CreateIn(w, narrowed, "badged-a1", t.A1Operators, w.A1Admin.Id));
        Assert.Equal(200, await CreateIn(w, narrowed, "badgeless-b1", t.B1Operators));

        var refused = await Call(GroupController(w, narrowed, w.A1Admin.Id), "AddMember", t.B1Operators.Id,
            Body("AddGroupMemberRequest", ("UserId", w.Plain)));
        Assert.Equal(403, Status(refused));
        Assert.False(w.Db.CaGroupMembers.Any(m => m.UserId == w.Plain && m.GroupId == t.B1Operators.Id));
        Assert.Equal(200, Status(await Call(GroupController(w, narrowed), "AddMember", t.B1Operators.Id,
            Body("AddGroupMemberRequest", ("UserId", w.Plain)))));
    }

    /// <summary>A CA admin manages the groups of their own CA and nothing else.</summary>
    [Fact]
    public async Task A_ca_admin_manages_the_groups_of_their_own_ca()
    {
        var w = new ControlledUserWorld();
        var t = SeedTargets(w);

        Assert.Equal(200, await CreateIn(w, w.A1AdminUser, "a1-op", t.A1Operators));
        Assert.Equal(403, await CreateIn(w, w.A1AdminUser, "a2-op", t.A2Operators));
        Assert.Equal(403, await CreateIn(w, w.A1AdminUser, "b1-op", t.B1Operators));
        Assert.Equal(403, await CreateIn(w, w.A1AdminUser, "space-req", t.ARequesters));
        Assert.Equal(403, await CreateIn(w, w.A1AdminUser, "instance-req", t.InstanceRequesters));
    }

    /// <summary>A space admin manages their space's groups, space-wide and per CA, and no other space's.</summary>
    [Fact]
    public async Task A_space_admin_manages_the_groups_of_their_own_space()
    {
        var w = new ControlledUserWorld();
        var t = SeedTargets(w);
        var spaceAdmin = w.User("space-a-admin", w.SpaceAdminA);

        Assert.Equal(200, await CreateIn(w, spaceAdmin, "space-req", t.ARequesters));
        Assert.Equal(200, await CreateIn(w, spaceAdmin, "a1-op", t.A1Operators));
        Assert.Equal(200, await CreateIn(w, spaceAdmin, "a2-op", t.A2Operators));
        Assert.Equal(403, await CreateIn(w, spaceAdmin, "b1-op", t.B1Operators));
        Assert.Equal(403, await CreateIn(w, spaceAdmin, "instance-req", t.InstanceRequesters));
    }

    /// <summary>
    /// A system admin manages every space's groups and the instance's non-system groups; a system
    /// group still needs system-super.
    /// </summary>
    [Fact]
    public async Task A_system_admin_manages_every_non_system_group_and_only_a_super_a_system_group()
    {
        var w = new ControlledUserWorld();
        var t = SeedTargets(w);

        Assert.Equal(200, await CreateIn(w, w.SystemAdmin, "b1-op", t.B1Operators));
        Assert.Equal(200, await CreateIn(w, w.SystemAdmin, "instance-req", t.InstanceRequesters));
        Assert.Equal(403, await CreateIn(w, w.SystemAdmin, "sys-aud", w.SystemAuditorGroup));
        Assert.Equal(200, await CreateIn(w, w.Super, "sys-aud-by-super", w.SystemAuditorGroup));
    }

    // ---- security policy ---------------------------------------------------------------------

    /// <summary>Evaluates the endpoint's authorization attributes through the real policies, as the matrix does.</summary>
    private static async Task<bool> PolicyAllows(ControlledUserWorld w, Guid userId, string controller, string action)
    {
        var type = ApiAssembly.TypeNamed(Ns + controller);
        var method = type.GetMethod(action)!;
        var claims = new List<Claim> { new("sub", userId.ToString()), new(ClaimTypes.NameIdentifier, userId.ToString()) };
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
        var accessor = new HttpContextAccessor { HttpContext = http };
        var groupAuth = new CaGroupAuthorizationService(w.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor);

        var services = new ServiceCollection().AddLogging().AddAuthorizationCore(options =>
        {
            PolicyDefinitions.AddTo(options);
            options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });
        services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, w.Db, NullLogger<CaGroupAuthorizationHandler>.Instance));
        var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
        var attributes = type.GetCustomAttributes(true).Concat(method.GetCustomAttributes(true)).OfType<IAuthorizeData>();
        var policy = await AuthorizationPolicy.CombineAsync(provider, attributes) ?? await provider.GetFallbackPolicyAsync();
        return (await sp.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, http, policy!)).Succeeded;
    }

    /// <summary>
    /// The security policy (lockout, MFA and step-up TTLs, OCSP, keystore cost) needs a system
    /// admin to read or write; a system operator or auditor is refused both.
    /// </summary>
    [Fact]
    public async Task Only_a_system_admin_reads_or_changes_the_security_policy()
    {
        var w = new ControlledUserWorld();
        foreach (var action in new[] { "Get", "Update" })
        {
            Assert.False(await PolicyAllows(w, w.Operator, "AdminSecurityPolicyController", action));
            Assert.False(await PolicyAllows(w, w.Auditor, "AdminSecurityPolicyController", action));
            Assert.False(await PolicyAllows(w, w.A1AdminUser, "AdminSecurityPolicyController", action));
            Assert.True(await PolicyAllows(w, w.SystemAdmin, "AdminSecurityPolicyController", action));
            Assert.True(await PolicyAllows(w, w.Super, "AdminSecurityPolicyController", action));
        }
    }

    /// <summary>
    /// Allowing system-supers to approve their own requests is super-only: a system admin's change
    /// is refused and nothing is saved, the stored value sent back unchanged is not a change, and a
    /// super may flip it.
    /// </summary>
    [Fact]
    public async Task Only_a_super_changes_whether_supers_may_approve_their_own_requests()
    {
        var w = new ControlledUserWorld();
        w.Db.SecurityPolicies.Add(new SecurityPolicyEntity { AllowSystemSuperSelfApproval = false, MaxFailedLoginAttempts = 5 });
        w.Db.SaveChanges();
        var cache = NewCache();
        object Controller(Guid actor) => New(Ns + "AdminSecurityPolicyController", actor,
            w.Db, InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            new RecordingAuditService(), new CurrentUserStub(actor), Controlled(w, null), GroupAuth(w),
            InstanceCeremonyEndpointTests.Fake<ISpacePolicyChangeService>.Create(), cache);
        object Request(bool allow, int? maxFailed = null)
            => Body("SecurityPolicyUpdateRequest", ("AllowSystemSuperSelfApproval", (bool?)allow), ("MaxFailedLoginAttempts", maxFailed));

        Assert.Equal(403, Status(await Call(Controller(w.SystemAdmin), "Update", Request(true, 9), StepUp(cache, w.SystemAdmin, StepUpOps.UpdateConfig))));
        var stored = w.Db.SecurityPolicies.Single();
        Assert.False(stored.AllowSystemSuperSelfApproval);
        Assert.Equal(5, stored.MaxFailedLoginAttempts);

        Assert.Equal(200, Status(await Call(Controller(w.SystemAdmin), "Update", Request(false, 9), StepUp(cache, w.SystemAdmin, StepUpOps.UpdateConfig))));
        Assert.Equal(9, w.Db.SecurityPolicies.Single().MaxFailedLoginAttempts);

        Assert.Equal(200, Status(await Call(Controller(w.Super), "Update", Request(true), StepUp(cache, w.Super, StepUpOps.UpdateConfig))));
        Assert.True(w.Db.SecurityPolicies.Single().AllowSystemSuperSelfApproval);
    }

    // ---- instance configuration and password policy -------------------------------------------

    private static IEnumerable<MethodInfo> Actions(string controller)
        => ApiAssembly.TypeNamed(Ns + controller).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes(true).Any(a => a.GetType().Name.StartsWith("Http", StringComparison.Ordinal)));

    private static bool IsWrite(MethodInfo action)
        => action.GetCustomAttributes(true).Any(a => a.GetType().Name is "HttpPutAttribute" or "HttpPostAttribute" or "HttpDeleteAttribute" or "HttpPatchAttribute");

    private static bool HasStepUp(MethodInfo action)
        => action.GetCustomAttributes(true).Any(a => a.GetType().Name == "RequireStepUpAttribute");

    /// <summary>
    /// Every read and write of the instance configuration needs a system admin: the configuration
    /// carries the security policy row, lockout thresholds, token binding, network trust, audit and
    /// alerting settings and integration keys. A system operator, auditor or CA admin is refused.
    /// </summary>
    [Fact]
    public async Task Only_a_system_admin_reads_or_changes_the_instance_configuration()
    {
        var w = new ControlledUserWorld();
        var actions = Actions("AdminConfigController").ToList();
        Assert.Contains(actions, a => a.Name == "GetConfig");
        foreach (var action in actions)
        {
            Assert.False(await PolicyAllows(w, w.Operator, "AdminConfigController", action.Name), $"{action.Name}: operator");
            Assert.False(await PolicyAllows(w, w.Auditor, "AdminConfigController", action.Name), $"{action.Name}: auditor");
            Assert.False(await PolicyAllows(w, w.A1AdminUser, "AdminConfigController", action.Name), $"{action.Name}: CA admin");
            Assert.True(await PolicyAllows(w, w.SystemAdmin, "AdminConfigController", action.Name), $"{action.Name}: system admin");
        }
    }

    /// <summary>Every write to the instance configuration and the password policy needs a step-up token.</summary>
    [Fact]
    public void Every_configuration_and_password_policy_write_needs_step_up()
    {
        var writes = Actions("AdminConfigController").Concat(Actions("AdminPasswordPolicyController")).Where(IsWrite).ToList();
        Assert.True(writes.Count > 20);
        Assert.All(writes, action => Assert.True(HasStepUp(action), $"{action.DeclaringType!.Name}.{action.Name} has no step-up"));
    }

    /// <summary>
    /// The refresh-token lifetime is bounded: 0 and anything over 30 days are refused with 400
    /// before anything is changed.
    /// </summary>
    [Fact]
    public async Task The_refresh_token_lifetime_is_bounded()
    {
        var w = new ControlledUserWorld();
        var config = new SystemConfig();
        var controller = New(Ns + "AdminConfigController", w.SystemAdmin, config, null, new RecordingAuditService(),
            new CurrentUserStub(w.SystemAdmin), NewCache(), new RecordingAlertService(), null, null, null, null);

        foreach (var days in new[] { 0, 31, 365, int.MaxValue })
        {
            var result = await Call(controller, "UpdateTokens", new TokenConfig { RefreshTokenDays = days });
            Assert.Equal(400, Status(result));
            Assert.Equal(7, config.Tokens.RefreshTokenDays);
        }
    }

    /// <summary>
    /// The notification page's email summary stays readable by a system operator, without any
    /// credential, while the full configuration does not.
    /// </summary>
    [Fact]
    public async Task A_system_operator_reads_the_email_summary_without_credentials()
    {
        var w = new ControlledUserWorld();
        Assert.True(await PolicyAllows(w, w.Operator, "AdminNotificationController", "GetDelivery"));
        Assert.False(await PolicyAllows(w, w.A1AdminUser, "AdminNotificationController", "GetDelivery"));

        var config = new SystemConfig();
        config.Email.SmtpHost = "smtp.example";
        config.Email.Password = "smtp-secret";
        config.Email.OAuth2ClientSecret = "oauth-secret";
        var controller = New(Ns + "AdminNotificationController", w.Operator, w.Db, null, null, config);
        var ok = Assert.IsType<OkObjectResult>(controller.GetType().GetMethod("GetDelivery")!.Invoke(controller, null));
        var json = JsonSerializer.Serialize(ok.Value);
        Assert.Contains("smtp.example", json);
        Assert.DoesNotContain("secret", json);
    }

    /// <summary>The password policy needs a system admin to read or write.</summary>
    [Fact]
    public async Task Only_a_system_admin_reads_or_changes_the_password_policy()
    {
        var w = new ControlledUserWorld();
        foreach (var action in new[] { "Get", "Update" })
        {
            Assert.False(await PolicyAllows(w, w.Operator, "AdminPasswordPolicyController", action));
            Assert.False(await PolicyAllows(w, w.A1AdminUser, "AdminPasswordPolicyController", action));
            Assert.True(await PolicyAllows(w, w.SystemAdmin, "AdminPasswordPolicyController", action));
        }
    }

    private static object PasswordPolicyController(ControlledUserWorld w)
        => New(Ns + "AdminPasswordPolicyController", w.SystemAdmin, w.Db, new RecordingAuditService(), new CurrentUserStub(w.SystemAdmin));

    /// <summary>
    /// A password policy out of bounds is refused with 400 and nothing is saved: a minimum length
    /// under 8, a minimum above the maximum, class minimums over the maximum, a negative count, or
    /// more than 24 remembered passwords.
    /// </summary>
    [Fact]
    public async Task A_password_policy_out_of_bounds_is_refused()
    {
        var w = new ControlledUserWorld();
        w.Db.PasswordPolicies.Add(new PasswordPolicyEntity { MinLength = 12, MaxLength = 128 });
        w.Db.SaveChanges();
        var controller = PasswordPolicyController(w);

        foreach (var bad in new[]
                 {
                     Body("PasswordPolicyUpdateRequest", ("MinLength", (int?)4)),
                     Body("PasswordPolicyUpdateRequest", ("MinLength", (int?)20), ("MaxLength", (int?)10)),
                     Body("PasswordPolicyUpdateRequest", ("MaxLength", (int?)16), ("MinUppercase", (int?)10), ("MinDigits", (int?)10)),
                     Body("PasswordPolicyUpdateRequest", ("MinDigits", (int?)-1)),
                     Body("PasswordPolicyUpdateRequest", ("MaxLength", (int?)-5)),
                     Body("PasswordPolicyUpdateRequest", ("HistoryCount", (int?)1000)),
                 })
        {
            Assert.Equal(400, Status(await Call(controller, "Update", bad)));
            var stored = w.Db.PasswordPolicies.AsNoTracking().Single();
            Assert.Equal((12, 128, 0, 0), (stored.MinLength, stored.MaxLength, stored.MinDigits, stored.HistoryCount));
        }

        Assert.Equal(200, Status(await Call(controller, "Update", Body("PasswordPolicyUpdateRequest", ("MinLength", (int?)14), ("MaxLength", (int?)0), ("HistoryCount", (int?)5)))));
        var saved = w.Db.PasswordPolicies.AsNoTracking().Single();
        Assert.Equal((14, 0, 5), (saved.MinLength, saved.MaxLength, saved.HistoryCount));
    }

    /// <summary>
    /// A password dictionary is a file in the dictionary directory named by its file name. Any
    /// other path, which would let the API read an arbitrary server file through password checks,
    /// is refused with 400 and nothing changes; an empty value clears it.
    /// </summary>
    [Fact]
    public async Task A_password_dictionary_is_only_read_from_the_dictionary_directory()
    {
        var w = new ControlledUserWorld();
        w.Db.PasswordPolicies.Add(new PasswordPolicyEntity());
        w.Db.SaveChanges();
        var controller = PasswordPolicyController(w);
        var directory = (string)ApiAssembly.TypeNamed(Ns + "PasswordPolicyBounds").GetProperty("DictionaryDirectory")!.GetValue(null)!;
        Directory.CreateDirectory(directory);
        var name = $"weak-{Guid.NewGuid():N}.txt";
        var inside = Path.Combine(directory, name);
        File.WriteAllText(inside, "password123\n");
        var outside = Path.Combine(Path.GetTempPath(), name);
        File.WriteAllText(outside, "password123\n");
        try
        {
            foreach (var path in new[] { outside, typeof(ScopedAuthorizationTests).Assembly.Location, $"../{name}", $"..{Path.DirectorySeparatorChar}{name}", "missing.txt" })
            {
                Assert.Equal(400, Status(await Call(controller, "Update", Body("PasswordPolicyUpdateRequest", ("DictionaryPath", path)))));
                Assert.Null(w.Db.PasswordPolicies.AsNoTracking().Single().DictionaryPath);
            }

            Assert.Equal(200, Status(await Call(controller, "Update", Body("PasswordPolicyUpdateRequest", ("DictionaryPath", name)))));
            var stored = w.Db.PasswordPolicies.AsNoTracking().Single().DictionaryPath;
            Assert.Equal(Path.GetFullPath(inside), stored);

            // The console sends the stored value back with every save; that keeps it.
            Assert.Equal(200, Status(await Call(controller, "Update", Body("PasswordPolicyUpdateRequest", ("DictionaryPath", stored), ("MinLength", (int?)13)))));
            Assert.Equal(stored, w.Db.PasswordPolicies.AsNoTracking().Single().DictionaryPath);

            Assert.Equal(200, Status(await Call(controller, "Update", Body("PasswordPolicyUpdateRequest", ("DictionaryPath", "")))));
            Assert.Null(w.Db.PasswordPolicies.AsNoTracking().Single().DictionaryPath);
        }
        finally
        {
            File.Delete(inside);
            File.Delete(outside);
        }
    }

    /// <summary>The System user quorum stays super-only: a system admin who may write the policy is refused that field.</summary>
    [Fact]
    public async Task The_system_user_quorum_still_needs_a_super()
    {
        var w = new ControlledUserWorld();
        w.Db.SecurityPolicies.Add(new SecurityPolicyEntity { UserQuorum = 1 });
        w.Db.SaveChanges();
        var cache = NewCache();
        object Controller(Guid actor) => New(Ns + "AdminSecurityPolicyController", actor,
            w.Db, InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            new RecordingAuditService(), new CurrentUserStub(actor), Controlled(w, null), GroupAuth(w),
            InstanceCeremonyEndpointTests.Fake<ISpacePolicyChangeService>.Create(), cache);
        object Request() => Body("SecurityPolicyUpdateRequest", ("UserQuorum", (int?)2));

        Assert.Equal(403, Status(await Call(Controller(w.SystemAdmin), "Update", Request(), StepUp(cache, w.SystemAdmin, StepUpOps.UpdateConfig))));
        Assert.Equal(1, w.Db.SecurityPolicies.Single().UserQuorum);
        Assert.Equal(200, Status(await Call(Controller(w.Super), "Update", Request(), StepUp(cache, w.Super, StepUpOps.UpdateConfig))));
        Assert.Equal(2, w.Db.SecurityPolicies.Single().UserQuorum);
    }

    // ---- policy-change ceremonies ------------------------------------------------------------

    private static KeyCeremonyEntity PolicyCeremony(ControlledUserWorld w, CeremonyType type, Guid? spaceId, Guid initiator)
    {
        var ceremony = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = type.ToString(), CeremonyType = type, Description = "policy change", TargetEntityId = "",
            InitiatedByUserId = initiator, InitiatedByUsername = "initiator", RequiredApprovals = 1, Status = "Pending",
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1), ParametersJson = "{}", ApprovalsJson = "[]", SpaceId = spaceId,
        };
        w.Db.KeyCeremonies.Add(ceremony);
        w.Db.SaveChanges();
        return ceremony;
    }

    private static object CeremonyController(ControlledUserWorld w, Guid actor, IDistributedCache cache)
    {
        var audit = new RecordingAuditService();
        return New(Ns + "AdminKeyCeremonyController", actor,
            new KeyCeremonyService(w.Db, audit), new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), null, w.Db,
            GroupAuth(w), null, null, null, Controlled(w, null));
    }

    private static async Task<int?> Approve(ControlledUserWorld w, Guid actor, Guid ceremonyId)
    {
        var cache = NewCache();
        return Status(await Call(CeremonyController(w, actor, cache), "Approve", ceremonyId, StepUp(cache, actor, StepUpOps.ApproveCeremony, ceremonyId)));
    }

    /// <summary>
    /// A space policy change is approved by an administrator of the space, not an operator of it
    /// (who still sees it, but without canApprove); the initiator never counts.
    /// </summary>
    [Fact]
    public async Task A_space_policy_change_is_approved_by_a_space_admin_not_a_space_operator()
    {
        var w = new ControlledUserWorld();
        var spaceOperator = w.User("space-a-operator", w.Group("space-a-operators", w.SpaceA, null, "Operator"));
        var initiator = w.User("space-a-admin-1", w.SpaceAdminA);
        var approver = w.User("space-a-admin-2", w.SpaceAdminA);
        var ceremony = PolicyCeremony(w, CeremonyType.SpacePolicyChange, w.SpaceA, initiator);

        var view = (ObjectResult)await Call(CeremonyController(w, spaceOperator, NewCache()), "GetById", ceremony.Id);
        Assert.Equal(200, view.StatusCode ?? 200);
        Assert.Contains("\"CanApprove\":false", JsonSerializer.Serialize(view.Value));

        Assert.Equal(403, await Approve(w, spaceOperator, ceremony.Id));
        Assert.Equal(400, await Approve(w, initiator, ceremony.Id));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == ceremony.Id).Status);

        Assert.Equal(200, await Approve(w, approver, ceremony.Id));
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == ceremony.Id).Status);
    }

    /// <summary>An instance policy change is approved by a system admin, not a system operator.</summary>
    [Fact]
    public async Task An_instance_policy_change_is_approved_by_a_system_admin_not_a_system_operator()
    {
        var w = new ControlledUserWorld();
        var ceremony = PolicyCeremony(w, CeremonyType.InstancePolicyChange, null, w.Super);

        Assert.Equal(403, await Approve(w, w.Operator, ceremony.Id));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == ceremony.Id).Status);
        Assert.Equal(400, await Approve(w, w.Super, ceremony.Id));
        Assert.Equal(200, await Approve(w, w.SystemAdmin, ceremony.Id));
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == ceremony.Id).Status);
    }

    private static async Task<int?> Reject(ControlledUserWorld w, Guid actor, Guid ceremonyId)
    {
        var cache = NewCache();
        return Status(await Call(CeremonyController(w, actor, cache), "Reject", ceremonyId, StepUp(cache, actor, StepUpOps.RejectCeremony, ceremonyId)));
    }

    /// <summary>
    /// Rejecting a policy-change ceremony follows the approval rule: an operator of its scope who
    /// may see it cannot reject it (403, still pending); an administrator of the scope can, and the
    /// initiator may withdraw their own.
    /// </summary>
    [Fact]
    public async Task A_policy_change_is_rejected_by_an_admin_of_its_scope_or_withdrawn_by_its_initiator()
    {
        var w = new ControlledUserWorld();
        var spaceOperator = w.User("space-a-operator", w.Group("space-a-operators", w.SpaceA, null, "Operator"));
        var initiator = w.User("space-a-admin-1", w.SpaceAdminA);
        var admin = w.User("space-a-admin-2", w.SpaceAdminA);

        var space = PolicyCeremony(w, CeremonyType.SpacePolicyChange, w.SpaceA, initiator);
        Assert.Equal(403, await Reject(w, spaceOperator, space.Id));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == space.Id).Status);
        Assert.Equal(200, await Reject(w, admin, space.Id));
        Assert.Equal("Rejected", w.Db.KeyCeremonies.Single(c => c.Id == space.Id).Status);

        var withdrawn = PolicyCeremony(w, CeremonyType.SpacePolicyChange, w.SpaceA, initiator);
        Assert.Equal(200, await Reject(w, initiator, withdrawn.Id));

        var instance = PolicyCeremony(w, CeremonyType.InstancePolicyChange, null, w.Super);
        Assert.Equal(403, await Reject(w, w.Operator, instance.Id));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == instance.Id).Status);
        Assert.Equal(200, await Reject(w, w.SystemAdmin, instance.Id));
    }

    // ---- badges of a super -------------------------------------------------------------------

    private static object BadgeController(ControlledUserWorld w, Guid actor)
        => New(Ns + "AdminUserBadgesController", actor, w.Db, new CurrentUserStub(actor), new AccessBadgeService(w.Db),
            new RecordingAuditService(), Controlled(w, null));

    private static AccessBadgeWriteRequest SuperBadge(ControlledUserWorld w, string name) => new()
    {
        Name = name, IsDefault = true,
        Sources = [new AccessBadgeSourceRef { Kind = AccessBadgeSourceKind.Group, SourceId = w.SuperGroup.Id }],
    };

    /// <summary>
    /// A system admin cannot create, replace or delete a badge of a system-super (whose default
    /// badge decides what their next session can do); another super can. A non-super's badges are
    /// unaffected.
    /// </summary>
    [Fact]
    public async Task Only_a_super_sets_or_replaces_the_badges_of_a_super()
    {
        var w = new ControlledUserWorld();
        var otherSuper = w.User("super-2", w.SuperGroup);
        var asAdmin = BadgeController(w, w.SystemAdmin);

        Assert.Equal(403, Status(await Call(asAdmin, "Create", w.Super, SuperBadge(w, "narrow"))));
        Assert.Empty(w.Db.AccessBadges.Where(b => b.UserId == w.Super));

        Assert.Equal(200, Status(await Call(BadgeController(w, otherSuper), "Create", w.Super, SuperBadge(w, "narrow"))));
        var badge = w.Db.AccessBadges.Single(b => b.UserId == w.Super);

        Assert.Equal(403, Status(await Call(asAdmin, "Update", w.Super, badge.Id, SuperBadge(w, "renamed"))));
        Assert.Equal(403, Status(await Call(asAdmin, "Delete", w.Super, badge.Id)));
        Assert.Equal("narrow", w.Db.AccessBadges.Single(b => b.Id == badge.Id).Name);

        var a1Badge = new AccessBadgeWriteRequest
        {
            Name = "a1", Sources = [new AccessBadgeSourceRef { Kind = AccessBadgeSourceKind.Group, SourceId = w.A1Admin.Id }],
        };
        Assert.Equal(200, Status(await Call(asAdmin, "Create", w.A1AdminUser, a1Badge)));
    }

    // ---- explicit scopes ---------------------------------------------------------------------

    /// <summary>
    /// A new group names its scope: a CA, a space, or scope "instance" for an instance (system)
    /// group. Neither, "instance" with a space or CA, or an unknown scope is a 400 and creates nothing.
    /// </summary>
    [Fact]
    public async Task A_group_create_that_does_not_name_its_scope_is_refused()
    {
        var w = new ControlledUserWorld();
        var controller = GroupController(w, w.SystemAdmin);
        object Request(string name, Guid? spaceId = null, Guid? caId = null, string? scope = null)
            => Body("CreateGroupRequest", ("Name", name), ("SpaceId", spaceId), ("CertificateAuthorityId", caId), ("Scope", scope));

        foreach (var (name, request) in new[]
                 {
                     ("unscoped", Request("unscoped")),
                     ("both", Request("both", spaceId: w.SpaceA, scope: "instance")),
                     ("ca-and-instance", Request("ca-and-instance", caId: w.CaA1, scope: "instance")),
                     ("unknown", Request("unknown", scope: "global")),
                 })
        {
            var bad = Assert.IsType<BadRequestObjectResult>(await Call(controller, "Create", request));
            Assert.Contains("scope", JsonSerializer.Serialize(bad.Value), StringComparison.OrdinalIgnoreCase);
            Assert.False(w.Db.CaGroups.Any(g => g.Name == name));
        }

        Assert.Equal(201, Status(await Call(controller, "Create", Request("instance-ops", scope: "Instance"))));
        var instance = w.Db.CaGroups.Single(g => g.Name == "instance-ops");
        Assert.True(instance.IsSystemGroup);
        Assert.Null(instance.SpaceId);

        Assert.Equal(201, Status(await Call(controller, "Create", Request("space-ops", spaceId: w.SpaceA))));
        var space = w.Db.CaGroups.Single(g => g.Name == "space-ops");
        Assert.False(space.IsSystemGroup);
        Assert.Equal(w.SpaceA, space.SpaceId);
    }

    /// <summary>
    /// An SSH CA is always an instance CA, so a space id in the body is refused (400) before any
    /// ceremony is opened, instead of being silently dropped.
    /// </summary>
    [Fact]
    public async Task An_ssh_ca_create_with_a_space_is_refused()
    {
        var w = new ControlledUserWorld();
        w.Db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 1 });
        w.Db.SaveChanges();
        var cache = NewCache();
        var controller = New(Ns + "AdminSshController", w.Operator,
            null, new CurrentUserStub(w.Operator), w.Db, new SystemConfig(),
            new KeyCeremonyService(w.Db, new RecordingAuditService()), cache, null, null, null);
        object Request(Guid? spaceId) => Body("GenerateSshCaKeyRequest", ("Name", "ops ssh"), ("SpaceId", spaceId));

        var bad = Assert.IsType<BadRequestObjectResult>(await Call(controller, "GenerateCaKey", Request(w.SpaceA), StepUp(cache, w.Operator, StepUpOps.CreateSshCa)));
        Assert.Contains("spaceId", JsonSerializer.Serialize(bad.Value), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(w.Db.KeyCeremonies);

        Assert.Equal(200, Status(await Call(controller, "GenerateCaKey", Request(null), StepUp(cache, w.Operator, StepUpOps.CreateSshCa))));
        Assert.Null(w.Db.KeyCeremonies.Single().SpaceId);
    }

    // ---- unreadable ceremony parameters ------------------------------------------------------

    private static void OpenCeremony(ControlledUserWorld w, string parametersJson, string status = "Pending")
    {
        w.Db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "ControlledUserChange", Description = "unreadable", TargetEntityId = "",
            InitiatedByUserId = w.SystemAdmin, InitiatedByUsername = "sysadmin", RequiredApprovals = 1, Status = status,
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1), ParametersJson = parametersJson, ApprovalsJson = "[]",
        });
        w.Db.SaveChanges();
    }

    /// <summary>
    /// A pending controlled-user ceremony naming the user whose parameters cannot be read (here a
    /// field of the wrong type, or a truncated body) blocks credential resets as a promotion would.
    /// </summary>
    [Fact]
    public async Task An_unreadable_ceremony_naming_a_user_counts_as_an_open_promotion()
    {
        var w = new ControlledUserWorld();
        Assert.False(await w.Controlled.HasOpenPromotionAsync(w.Plain));

        OpenCeremony(w, $"{{\"ChangeType\":\"AddGroupMember\",\"TargetUserId\":\"{w.Plain}\",\"MintedTierLevel\":\"not-a-number\"}}");
        Assert.True(await w.Controlled.HasOpenPromotionAsync(w.Plain));

        var other = w.User("other");
        OpenCeremony(w, $"{{\"ChangeType\":\"AddGroupMember\",\"TargetUserId\":\"{other}\"", status: "Approved");
        Assert.True(await w.Controlled.HasOpenPromotionAsync(other));

        var cache = NewCache();
        var reset = await Call(UserManager(w, w.A1AdminUser, cache), "ResetUserPassword", w.Plain,
            StepUp(cache, w.A1AdminUser, StepUpOps.ResetPassword, w.Plain));
        Assert.Equal(409, Status(reset));
    }

    /// <summary>
    /// An open ceremony naming a role whose parameters cannot be read counts as an instance-wide
    /// assignment of that role, so changing its controlled capabilities stays super-only.
    /// </summary>
    [Fact]
    public async Task An_unreadable_ceremony_naming_a_role_counts_as_an_instance_wide_assignment()
    {
        var w = new ControlledUserWorld();
        var role = w.Role(Capabilities.CaManage);
        Assert.Empty(await w.Controlled.TiersConferredByRoleAsync(role.Id, new[] { Capabilities.SystemManage, Capabilities.CaManage }));

        OpenCeremony(w, $"{{\"ChangeType\":\"AssignRole\",\"RoleId\":\"{role.Id}\",\"SpaceId\":");
        var tiers = await w.Controlled.TiersConferredByRoleAsync(role.Id, new[] { Capabilities.SystemManage, Capabilities.CaManage });
        Assert.Contains(new ControlledTier(ControlledTierLevel.SystemAdmin, null), tiers);
        Assert.Contains(new ControlledTier(ControlledTierLevel.SystemOperator, null), tiers);
    }
}
