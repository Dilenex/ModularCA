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
using ModularCA.Auth.Utils;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// User administration below system scope. The write routes of the user manager carry only a
/// user id, so a CA-scoped policy refused every one of them to anyone but a system administrator.
/// They now carry a gate of their own (the capability held at some scope) and decide inside the
/// action against the target account. These tests drive both layers for every kind of caller
/// against every kind of target: the route's real policy, and the real action called directly, as
/// if the policy were not there, because the action's checks must hold on their own.
/// </summary>
public sealed class ScopedUserAdministrationTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";
    private const string OriginalHash = "original-password-hash";

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

    /// <summary>
    /// Two spaces, three CAs and the system groups, with one caller of every kind and one target
    /// of every kind. Controllers are built with the caller's real space fence, the real
    /// authorization, ceremony and user services, and an audit service that writes the trail the
    /// 30-day rules read.
    /// </summary>
    private sealed class Lab
    {
        public ControlledUserWorld W { get; } = new();
        public AuditDbContext AuditDb { get; } =
            new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase($"audit-{Guid.NewGuid():N}").Options);
        public ModularCA.Shared.Interfaces.IAuditService Audit { get; }
        public RecordingAlertService Alerts { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public KeyCeremonyService Ceremonies { get; }
        public UserManagementService Users { get; }

        public CaGroupEntity A1Operators { get; }
        public CaGroupEntity A1Auditors { get; }
        public CaGroupEntity A2Requester { get; }
        public CaGroupEntity B1Admin { get; }

        public Dictionary<string, Guid> Callers { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, Guid> Targets { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, CaGroupEntity> Groups { get; } = new(StringComparer.Ordinal);

        public Lab()
        {
            Audit = new AuditService(NullLogger<AuditService>.Instance, AuditDb, hashChain: new AuditHashChainService());
            Ceremonies = new KeyCeremonyService(W.Db, new RecordingAuditService());
            Users = new UserManagementService(W.Db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!,
                new ControlledUserBypassGuardTests.AllowAllPasswords());

            A1Operators = W.Group("org_a1_operator", W.SpaceA, W.CaA1, "Operator");
            A1Auditors = W.Group("org_a1_auditor", W.SpaceA, W.CaA1, "Auditor");
            A2Requester = W.Group("org_a2_requester", W.SpaceA, W.CaA2, "Requester");
            B1Admin = W.Group("org_b1_admin", W.SpaceB, W.CaB1, "Administrator");
            W.Db.SaveChanges();

            Callers["no groups"] = W.User("c-nobody");
            Callers["requester"] = W.User("c-requester", W.A1Requester);
            Callers["CA auditor"] = W.User("c-ca-auditor", A1Auditors);
            Callers["CA operator"] = W.User("c-ca-operator", A1Operators);
            Callers["CA admin"] = W.A1AdminUser;
            Callers["space admin"] = W.User("c-space-admin", W.SpaceAdminA);
            Callers["system auditor"] = W.Auditor;
            Callers["system operator"] = W.Operator;
            Callers["system admin"] = W.SystemAdmin;
            Callers["system-super"] = W.Super;

            Targets["ungrouped"] = Target("t-ungrouped");
            Targets["requester of the CA"] = Target("t-a1-requester", W.A1Requester);
            Targets["operator of the CA"] = Target("t-a1-operator", A1Operators);
            Targets["administrator of the CA"] = Target("t-a1-admin", W.A1Admin);
            Targets["sibling CA"] = Target("t-a2-requester", A2Requester);
            Targets["other space"] = Target("t-b1-requester", W.B1Requester);
            Targets["both spaces"] = Target("t-a1-and-b1", W.A1Requester, W.B1Requester);
            Targets["system auditor"] = Target("t-system-auditor", W.SystemAuditorGroup);
            Targets["system administrator"] = Target("t-system-admin", W.SystemAdminGroup);
            Targets["system-super"] = Target("t-system-super", W.SuperGroup);
            Targets["administrator of another space"] = Target("t-b1-admin", B1Admin);

            Groups["own CA requesters"] = W.A1Requester;
            Groups["own CA administrators"] = W.A1Admin;
            Groups["sibling CA requesters"] = A2Requester;
            Groups["space administrators"] = W.SpaceAdminA;
            Groups["other space requesters"] = W.B1Requester;
            Groups["other space administrators"] = B1Admin;
            Groups["system administrators"] = W.SystemAdminGroup;
            Groups["system-super"] = W.SuperGroup;
        }

        /// <summary>An account with a password, an enrolled second factor and a live session, so a change to any of them shows.</summary>
        public Guid Target(string username, params CaGroupEntity[] groups)
        {
            var id = W.User(username, groups);
            var user = W.Db.Users.Single(u => u.Id == id);
            user.PasswordHash = OriginalHash;
            user.MfaEnrolledAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            W.Db.TotpSecrets.Add(new TotpSecretEntity { UserId = id, IsVerified = true });
            W.Db.RefreshTokens.Add(new RefreshTokenEntity { UserId = id, Token = Guid.NewGuid().ToString("N"), ExpiresAt = DateTime.UtcNow.AddDays(1) });
            W.Db.SaveChanges();
            return id;
        }

        /// <summary>Everything about the account these routes could change, as one comparable string.</summary>
        public string Snapshot(Guid id)
        {
            var u = W.Db.Users.AsNoTracking().SingleOrDefault(x => x.Id == id);
            if (u == null) return "(deleted)";
            var groups = W.Db.CaGroupMembers.AsNoTracking().Where(m => m.UserId == id).Select(m => m.GroupId).ToList().OrderBy(g => g);
            var totp = W.Db.TotpSecrets.AsNoTracking().Count(t => t.UserId == id);
            var sessions = W.Db.RefreshTokens.AsNoTracking().Count(t => t.UserId == id && !t.IsRevoked);
            return string.Join("|", u.Username, u.Email, u.DisplayName, u.PasswordHash, u.SecurityStamp, u.IsActive, u.IsLocked,
                u.PasswordSource, u.PasswordNeverExpires, u.PasswordChangeOnNextLogon, u.MfaEnrolledAt?.Ticks,
                string.Join(",", groups), $"totp={totp}", $"sessions={sessions}");
        }

        public UserEntity User(Guid id) => W.Db.Users.AsNoTracking().Single(u => u.Id == id);

        public bool InGroup(Guid user, CaGroupEntity group) => W.Db.CaGroupMembers.AsNoTracking().Any(m => m.UserId == user && m.GroupId == group.Id);

        public int LiveSessions(Guid user) => W.Db.RefreshTokens.AsNoTracking().Count(t => t.UserId == user && !t.IsRevoked);

        public string StepUp(Guid actor, string op, Guid? target = null)
        {
            var token = Guid.NewGuid().ToString("N");
            Cache.SetString(target == null ? $"mfa-stepup:{actor}:{op}" : $"mfa-stepup:{actor}:{op}:{target}", token);
            return token;
        }

        private IAccessBadgeContext? Badge(Guid[] badgeGroups)
            => badgeGroups.Length == 0 ? null : new FixedBadge(new AccessBadgeFilter(Guid.NewGuid(), "badge", badgeGroups, [], []));

        public CaGroupAuthorizationService GroupAuth(params Guid[] badgeGroups)
            => new(W.Db, NullLogger<CaGroupAuthorizationService>.Instance, badges: Badge(badgeGroups));

        public ControlledUserCeremonyService Controlled(params Guid[] badgeGroups)
            => new(W.Db, Ceremonies, Users, NullLogger<ControlledUserCeremonyService>.Instance, Badge(badgeGroups), AuditDb);

        /// <summary>The user manager as <paramref name="actor"/>, with the space fence the middleware would store for them.</summary>
        public async Task<object> Controller(Guid actor, params Guid[] badgeGroups)
        {
            var groupAuth = GroupAuth(badgeGroups);
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "Management.AdminUserManagerController"),
                W.Db, Users, new CurrentUserStub(actor), Audit, Cache, Alerts,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.CreateUserRequestValidator")),
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.UpdateUserRequestValidator")),
                Controlled(badgeGroups), groupAuth)!;
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
            };
            SpaceFence.Store(http, await groupAuth.GetFenceAsync(actor));
            controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return controller;
        }

        /// <summary>Whether the route's own authorization attributes admit <paramref name="actor"/>, through the real policy set and both handlers.</summary>
        public async Task<bool> Policy(Guid actor, string action)
        {
            var type = ApiAssembly.TypeNamed(Ns + "Management.AdminUserManagerController");
            var method = type.GetMethod(action)!;
            var claims = new List<Claim> { new("sub", actor.ToString()), new(ClaimTypes.NameIdentifier, actor.ToString()) };
            var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
            http.Request.Method = method.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>()
                .SelectMany(m => m.HttpMethods).First();
            http.Request.Path = "/api/v1/admin/users/" + Guid.NewGuid();
            http.Request.RouteValues["id"] = Guid.NewGuid().ToString();
            var accessor = new HttpContextAccessor { HttpContext = http };
            var groupAuth = new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor);

            var services = new ServiceCollection().AddLogging().AddAuthorizationCore(options =>
            {
                PolicyDefinitions.AddTo(options);
                options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            });
            services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, W.Db, NullLogger<CaGroupAuthorizationHandler>.Instance));
            services.AddSingleton<IAuthorizationHandler>(new AnyScopeCapabilityAuthorizationHandler(groupAuth));
            var sp = services.BuildServiceProvider();
            var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
            var attributes = type.GetCustomAttributes(true).Concat(method.GetCustomAttributes(true)).OfType<IAuthorizeData>();
            var policy = await AuthorizationPolicy.CombineAsync(provider, attributes) ?? await provider.GetFallbackPolicyAsync();
            return (await sp.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, http, policy!)).Succeeded;
        }

        /// <summary>Runs one account operation as <paramref name="actor"/> with a valid step-up token, calling the action directly.</summary>
        public async Task<IActionResult> Run(Guid actor, string op, Guid target, params Guid[] badgeGroups)
        {
            var c = await Controller(actor, badgeGroups);
            return op switch
            {
                "reset-password" => await Call(c, "ResetUserPassword", target, StepUp(actor, StepUpOps.ResetPassword, target)),
                "reset-mfa" => await Call(c, "ResetUserMfa", target, StepUp(actor, StepUpOps.ResetMfa, target)),
                "update-email" => await Call(c, "UpdateUser", target, new UpdateUserRequest { Email = "changed@example.com" }, StepUp(actor, StepUpOps.UpdateUser, target)),
                "rename" => await Call(c, "UpdateUser", target, new UpdateUserRequest { DisplayName = "Renamed" }, StepUp(actor, StepUpOps.UpdateUser, target)),
                "disable" => await Call(c, "UpdateUser", target, new UpdateUserRequest { IsActive = false }, StepUp(actor, StepUpOps.UpdateUser, target)),
                "set-password" => await Call(c, "UpdateUser", target, new UpdateUserRequest { Password = "Chosen-Passw0rd!" }, StepUp(actor, StepUpOps.UpdateUser, target)),
                "delete" => await Call(c, "DeleteUser", target, StepUp(actor, StepUpOps.DeleteUser, target)),
                _ => throw new ArgumentOutOfRangeException(nameof(op), op, null),
            };
        }

        /// <summary>The ceremony controller as <paramref name="actor"/>, to approve and execute what the user manager opened.</summary>
        private object CeremonyController(Guid actor)
        {
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminKeyCeremonyController"),
                Ceremonies, new CurrentUserStub(actor), Audit, Cache, Alerts, null, W.Db, GroupAuth(), null, null, null, Controlled())!;
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
            };
            controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return controller;
        }

        public Task<IActionResult> Approve(Guid actor, Guid ceremonyId)
            => Call(CeremonyController(actor), "Approve", ceremonyId, StepUp(actor, StepUpOps.ApproveCeremony, ceremonyId));

        public Task<IActionResult> Execute(Guid actor, Guid ceremonyId)
            => Call(CeremonyController(actor), "Execute", ceremonyId, StepUp(actor, StepUpOps.ExecuteCeremony, ceremonyId));

        public async Task<IActionResult> Add(Guid actor, Guid target, CaGroupEntity group)
            => await Call(await Controller(actor), "AddUserToGroup", target, group.Id, StepUp(actor, StepUpOps.AddGroupMember, target));

        public async Task<IActionResult> Remove(Guid actor, Guid target, CaGroupEntity group)
            => await Call(await Controller(actor), "RemoveUserFromGroup", target, group.Id, StepUp(actor, StepUpOps.RemoveGroupMember, target));

        public async Task<IActionResult> Bulk(Guid actor, Guid target, IEnumerable<CaGroupEntity> add, IEnumerable<CaGroupEntity> remove)
            => await Call(await Controller(actor), "BulkUpdateUserGroups", target,
                new BulkUserGroupsRequest { AddGroupIds = add.Select(g => g.Id).ToList(), RemoveGroupIds = remove.Select(g => g.Id).ToList() },
                StepUp(actor, StepUpOps.UpdateUserGroups, target));

        public async Task<IActionResult> Create(Guid actor, string username, params CaGroupEntity[] groups)
            => await Call(await Controller(actor), "CreateUser",
                new CreateUserRequest { Username = username, Email = $"{username}@example.com", Password = "Str0ng!Passw0rd", GroupIds = groups.Select(g => g.Id).ToList() },
                StepUp(actor, StepUpOps.CreateUser));
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static int? Status(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    private static object? Prop(IActionResult result, string name)
    {
        var value = ((ObjectResult)result).Value!;
        return value.GetType().GetProperty(name)?.GetValue(value);
    }

    private static string Body(IActionResult result) => JsonSerializer.Serialize(((ObjectResult)result).Value);

    /// <summary>The per-group statuses of a bulk answer, as "action:status" in order.</summary>
    private static List<string> BulkStatuses(IActionResult result)
        => ((System.Collections.IEnumerable)Prop(result, "results")!).Cast<object>()
            .Select(r => $"{r.GetType().GetProperty("action")!.GetValue(r)}:{r.GetType().GetProperty("status")!.GetValue(r)}")
            .ToList();

    private static readonly string[] CallerNames =
    [
        "no groups", "requester", "CA auditor", "CA operator", "CA admin", "space admin",
        "system auditor", "system operator", "system admin", "system-super",
    ];

    private static readonly string[] TargetNames =
    [
        "ungrouped", "requester of the CA", "operator of the CA", "administrator of the CA", "sibling CA", "other space",
        "both spaces", "system auditor", "system administrator", "system-super",
    ];

    /// <summary>The callers each gate admits: the Administrator role holds user.manage and group.manage, the others do not.</summary>
    private static readonly string[] Administrators = ["CA admin", "space admin", "system admin", "system-super"];
    private static readonly string[] SystemAdministrators = ["system admin", "system-super"];

    private static readonly (string Action, string[] Admitted)[] Gates =
    [
        ("CreateUser", Administrators), ("UpdateUser", Administrators), ("DeleteUser", Administrators),
        ("ResetUserPassword", Administrators), ("ResetUserMfa", SystemAdministrators),
        ("AddUserToGroup", Administrators), ("RemoveUserFromGroup", Administrators), ("BulkUpdateUserGroups", Administrators),
    ];

    private static string ActionOf(string op) => op switch
    {
        "reset-password" => "ResetUserPassword",
        "reset-mfa" => "ResetUserMfa",
        "delete" => "DeleteUser",
        _ => "UpdateUser",
    };

    // ---- the gates ---------------------------------------------------------------------------

    /// <summary>
    /// The policy layer of every write route, for every kind of caller. An administrator of a CA
    /// or a space now passes the gate; a requester, an auditor and an operator (at any scope) do
    /// not, and neither does an account in no group. Resetting MFA stays at system scope.
    /// </summary>
    [Fact]
    public async Task Each_write_route_admits_administrators_and_nobody_else()
    {
        var lab = new Lab();
        var wrong = new List<string>();
        foreach (var (action, admitted) in Gates)
            foreach (var caller in CallerNames)
            {
                var expected = admitted.Contains(caller);
                if (await lab.Policy(lab.Callers[caller], action) != expected)
                    wrong.Add($"{caller} {action}: expected {(expected ? "admitted" : "refused")}");
            }
        Assert.Empty(wrong);

        Assert.Equal(Capabilities.UserManage, PolicyDefinitions.HeldAtSomeScope["UserAdministrator"]);
        Assert.Equal(Capabilities.GroupManage, PolicyDefinitions.HeldAtSomeScope["GroupMembershipAdministrator"]);
        Assert.Equal((Capabilities.UserManage, true), PolicyDefinitions.All["SystemUserAdministrator"]);
    }

    /// <summary>
    /// Every write route of the controller carries one of the user-administration gates. None is
    /// left on a CA-scoped policy, which could never resolve a CA here, and none is open to any
    /// signed-in caller.
    /// </summary>
    [Fact]
    public void Every_write_route_carries_a_user_administration_gate()
    {
        var type = ApiAssembly.TypeNamed(Ns + "Management.AdminUserManagerController");
        var writes = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>()
                .Any(a => a.HttpMethods.Any(v => v is not "GET")))
            .ToList();
        Assert.Equal(Gates.Select(g => g.Action).OrderBy(n => n), writes.Select(m => m.Name).OrderBy(n => n));
        foreach (var write in writes)
        {
            var policies = write.GetCustomAttributes(true).OfType<IAuthorizeData>().Select(a => a.Policy).ToList();
            Assert.True(policies.Count == 1 && policies[0] is "UserAdministrator" or "GroupMembershipAdministrator" or "SystemUserAdministrator",
                $"{write.Name}: {string.Join(",", policies)}");
        }
    }

    /// <summary>
    /// The general containment is untouched: a CA-scoped policy on a write whose route names no CA
    /// still refuses an administrator of one CA, and the new requirement is a type of its own.
    /// </summary>
    [Fact]
    public async Task A_ca_scoped_policy_on_a_write_with_no_ca_still_refuses_a_ca_admin()
    {
        var lab = new Lab();
        foreach (var (caller, expected) in new[] { ("CA admin", false), ("space admin", false), ("system operator", false), ("system admin", true) })
        {
            var actor = lab.Callers[caller];
            var claims = new List<Claim> { new("sub", actor.ToString()) };
            var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
            http.Request.Method = "POST";
            http.Request.Path = $"/api/v1/admin/users/{Guid.NewGuid()}/reset-password";
            var accessor = new HttpContextAccessor { HttpContext = http };
            var services = new ServiceCollection().AddLogging().AddAuthorizationCore(PolicyDefinitions.AddTo);
            var groupAuth = lab.GroupAuth();
            services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, lab.W.Db, NullLogger<CaGroupAuthorizationHandler>.Instance));
            services.AddSingleton<IAuthorizationHandler>(new AnyScopeCapabilityAuthorizationHandler(groupAuth));
            var authz = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
            Assert.Equal(expected, (await authz.AuthorizeAsync(http.User, http, "CaAdmin")).Succeeded);
        }
    }

    // ---- account changes: the matrix ---------------------------------------------------------

    /// <summary>
    /// What the action answers for a password reset, an e-mail change, a disable and a delete
    /// (one column), and for an MFA reset (the other), per caller and target. 200 applies, 202
    /// opens a ceremony and applies nothing, 403 refuses an account the caller can see, 404
    /// answers for an account the caller cannot see.
    /// </summary>
    private static readonly Dictionary<string, (int[] Account, int[] Mfa)> Expected = new(StringComparer.Ordinal)
    {
        //                     ungrouped, requester, operator, admin, sibling CA, other space, both, sys auditor, sys admin, super
        ["no groups"] = ([404, 404, 404, 404, 404, 404, 404, 404, 404, 404], [404, 404, 404, 404, 404, 404, 404, 404, 404, 404]),
        ["requester"] = ([404, 404, 404, 404, 404, 404, 404, 404, 404, 404], [404, 404, 404, 404, 404, 404, 404, 404, 404, 404]),
        ["CA auditor"] = ([404, 403, 403, 403, 403, 404, 403, 404, 404, 404], [404, 403, 403, 403, 403, 404, 403, 404, 404, 404]),
        ["CA operator"] = ([404, 403, 403, 403, 403, 404, 403, 404, 404, 404], [404, 403, 403, 403, 403, 404, 403, 404, 404, 404]),
        // An operator of the CA holds a controlled tier, like its administrator: a change to its
        // account by anyone below system-super opens a ceremony.
        ["CA admin"] = ([404, 200, 202, 202, 403, 404, 403, 404, 404, 404], [404, 403, 403, 403, 403, 404, 403, 404, 404, 404]),
        ["space admin"] = ([404, 200, 202, 202, 200, 404, 403, 404, 404, 404], [404, 403, 403, 403, 403, 404, 403, 404, 404, 404]),
        ["system auditor"] = ([403, 403, 403, 403, 403, 403, 403, 403, 403, 403], [403, 403, 403, 403, 403, 403, 403, 403, 403, 403]),
        ["system operator"] = ([403, 403, 403, 403, 403, 403, 403, 403, 403, 403], [403, 403, 403, 403, 403, 403, 403, 403, 403, 403]),
        ["system admin"] = ([200, 200, 202, 202, 200, 200, 200, 200, 202, 403], [200, 200, 202, 202, 200, 200, 200, 200, 202, 403]),
        ["system-super"] = ([200, 200, 200, 200, 200, 200, 200, 200, 200, 200], [200, 200, 200, 200, 200, 200, 200, 200, 200, 200]),
    };

    public static TheoryData<string, string> CallersAndTargets()
    {
        var data = new TheoryData<string, string>();
        foreach (var caller in CallerNames)
            foreach (var target in TargetNames)
                data.Add(caller, target);
        return data;
    }

    /// <summary>
    /// Every caller against every target, for every account operation, on a fresh world each time.
    /// The policy must admit exactly the administrators; the action, called directly, must answer
    /// what <see cref="Expected"/> says; and whenever the answer is not 200 the account is exactly
    /// as it was: password hash, security stamp, memberships, state, MFA rows and sessions.
    /// </summary>
    [Theory]
    [MemberData(nameof(CallersAndTargets))]
    public async Task An_account_change_is_decided_by_the_callers_scope_over_the_target(string caller, string target)
    {
        var column = Array.IndexOf(TargetNames, target);
        foreach (var op in new[] { "reset-password", "update-email", "disable", "delete", "reset-mfa" })
        {
            var lab = new Lab();
            var actor = lab.Callers[caller];
            var account = lab.Targets[target];
            var expected = op == "reset-mfa" ? Expected[caller].Mfa[column] : Expected[caller].Account[column];
            var what = $"{caller} {op} {target}";

            var admitted = await lab.Policy(actor, ActionOf(op));
            Assert.True(admitted == (op == "reset-mfa" ? SystemAdministrators : Administrators).Contains(caller), $"{what}: policy");

            var before = lab.Snapshot(account);
            var result = await lab.Run(actor, op, account);
            Assert.True(Status(result) == expected, $"{what}: expected {expected}, got {Status(result)}");

            // The action alone refuses whoever the policy refuses.
            if (!admitted)
                Assert.True(expected is 403 or 404, $"{what}: the policy refuses but the action would answer {expected}");

            if (expected == 200)
            {
                Assert.True(before != lab.Snapshot(account), $"{what}: nothing changed");
                Assert.Empty(lab.W.Db.KeyCeremonies);
            }
            else
            {
                Assert.True(before == lab.Snapshot(account), $"{what}: the account changed");
                Assert.Equal(expected == 202 ? 1 : 0, lab.W.Db.KeyCeremonies.Count());
                Assert.DoesNotContain("newPassword", Body(result));
            }
        }
    }

    /// <summary>
    /// An account the caller cannot see answers exactly as an id that names nothing, on every
    /// write route, so the routes cannot be used to learn that an account exists elsewhere.
    /// </summary>
    [Theory]
    [InlineData("CA admin", "other space")]
    [InlineData("CA admin", "system administrator")]
    [InlineData("CA admin", "ungrouped")]
    [InlineData("space admin", "other space")]
    [InlineData("space admin", "system-super")]
    [InlineData("CA operator", "other space")]
    [InlineData("requester", "requester of the CA")]
    public async Task An_account_out_of_sight_answers_exactly_as_a_missing_one(string caller, string target)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var hidden = lab.Targets[target];
        var missing = Guid.NewGuid();
        var before = lab.Snapshot(hidden);

        var routes = new (string Name, Func<Guid, Task<IActionResult>> Send)[]
        {
            ("reset-password", id => lab.Run(actor, "reset-password", id)),
            ("reset-mfa", id => lab.Run(actor, "reset-mfa", id)),
            ("update-email", id => lab.Run(actor, "update-email", id)),
            ("rename", id => lab.Run(actor, "rename", id)),
            ("disable", id => lab.Run(actor, "disable", id)),
            ("delete", id => lab.Run(actor, "delete", id)),
            ("add", id => lab.Add(actor, id, lab.W.A1Requester)),
            ("add to a group the caller has no right on", id => lab.Add(actor, id, lab.B1Admin)),
            ("remove", id => lab.Remove(actor, id, lab.W.B1Requester)),
            ("bulk", id => lab.Bulk(actor, id, [lab.W.A1Requester], [lab.W.B1Requester])),
        };
        foreach (var (name, send) in routes)
        {
            var forHidden = await send(hidden);
            var forMissing = await send(missing);
            Assert.True(Status(forHidden) == 404, $"{name}: expected 404, got {Status(forHidden)}");
            Assert.Equal(404, Status(forMissing));
            Assert.Equal(Body(forMissing).Replace(missing.ToString(), "ID"), Body(forHidden).Replace(hidden.ToString(), "ID"));
        }
        Assert.Equal(before, lab.Snapshot(hidden));
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    // ---- account changes: the cases named one by one ------------------------------------------

    /// <summary>
    /// The takeover the containment closed stays closed: an administrator or operator of one CA,
    /// or an administrator of one space, cannot set or reset the password of, disable, delete or
    /// reset the MFA of a system administrator, a system auditor or an administrator of another
    /// space. Nothing applies and no ceremony opens.
    /// </summary>
    [Theory]
    [InlineData("CA admin")]
    [InlineData("CA operator")]
    [InlineData("space admin")]
    public async Task A_scoped_caller_cannot_touch_an_account_of_the_system_or_of_another_space(string caller)
    {
        foreach (var target in new[] { "system administrator", "system auditor", "administrator of another space", "system-super", "both spaces" })
            foreach (var op in new[] { "set-password", "reset-password", "update-email", "rename", "disable", "delete", "reset-mfa" })
            {
                var lab = new Lab();
                var actor = lab.Callers[caller];
                var account = lab.Targets[target];
                var before = lab.Snapshot(account);

                var result = await lab.Run(actor, op, account);

                Assert.True(Status(result) is 400 or 403 or 404, $"{caller} {op} {target}: got {Status(result)}");
                if (op != "set-password")
                    Assert.True(Status(result) is 403 or 404, $"{caller} {op} {target}: got {Status(result)}");
                Assert.True(before == lab.Snapshot(account), $"{caller} {op} {target}: the account changed");
                Assert.Empty(lab.W.Db.KeyCeremonies);
                Assert.DoesNotContain("newPassword", Body(result));
            }
    }

    /// <summary>
    /// An operator holds ca.manage and neither user.manage nor group.manage: it cannot set or
    /// reset the password of its own CA's administrator, or of a requester of its CA, cannot
    /// create an account, and cannot place itself or anyone in its CA's administrators.
    /// </summary>
    [Fact]
    public async Task A_ca_operator_stays_out_of_user_administration()
    {
        var lab = new Lab();
        var op = lab.Callers["CA operator"];
        var admin = lab.Targets["administrator of the CA"];
        var requester = lab.Targets["requester of the CA"];
        var adminBefore = lab.Snapshot(admin);
        var requesterBefore = lab.Snapshot(requester);
        var ownBefore = lab.Snapshot(op);

        Assert.Equal(400, Status(await lab.Run(op, "set-password", admin)));
        Assert.Equal(403, Status(await lab.Run(op, "reset-password", admin)));
        Assert.Equal(403, Status(await lab.Run(op, "reset-password", requester)));
        Assert.Equal(403, Status(await lab.Run(op, "rename", requester)));
        Assert.Equal(400, Status(await lab.Add(op, op, lab.W.A1Admin)));
        Assert.Equal(403, Status(await lab.Add(op, requester, lab.W.A1Admin)));
        Assert.Equal(403, Status(await lab.Add(op, requester, lab.A1Operators)));
        Assert.Equal(403, Status(await lab.Remove(op, requester, lab.W.A1Requester)));
        Assert.Equal(403, Status(await lab.Create(op, "made-by-operator")));
        Assert.Equal(403, Status(await lab.Create(op, "made-by-operator-2", lab.W.A1Requester)));

        Assert.Equal(adminBefore, lab.Snapshot(admin));
        Assert.Equal(requesterBefore, lab.Snapshot(requester));
        Assert.Equal(ownBefore, lab.Snapshot(op));
        Assert.False(lab.W.Db.Users.Any(u => u.Username.StartsWith("made-by-operator")));
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    /// <summary>
    /// The system operator and the system auditor see every account and change none: the Operator
    /// and Auditor roles hold no user.manage and no group.manage at any scope. Before, a system
    /// operator could reset the MFA of any account that held no tier.
    /// </summary>
    [Theory]
    [InlineData("system operator")]
    [InlineData("system auditor")]
    public async Task A_system_operator_or_auditor_changes_no_account(string caller)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var account = lab.Targets["requester of the CA"];
        var before = lab.Snapshot(account);

        foreach (var op in new[] { "reset-password", "reset-mfa", "update-email", "rename", "disable", "delete" })
            Assert.Equal(403, Status(await lab.Run(actor, op, account)));
        Assert.Equal(403, Status(await lab.Add(actor, account, lab.A1Operators)));
        Assert.Equal(403, Status(await lab.Remove(actor, account, lab.W.A1Requester)));
        Assert.Equal(403, Status(await lab.Create(actor, "made-by-" + caller.Replace(' ', '-'))));
        Assert.Equal(new[] { "add:denied", "remove:denied" }, BulkStatuses(await lab.Bulk(actor, account, [lab.A1Operators], [lab.W.A1Requester])));

        Assert.Equal(before, lab.Snapshot(account));
        Assert.False(lab.W.Db.Users.Any(u => u.Username.StartsWith("made-by-")));
        foreach (var (action, _) in Gates)
            Assert.False(await lab.Policy(actor, action), action);
    }

    /// <summary>
    /// A holding of any kind outside the caller's scope puts the account out of reach: a direct
    /// capability grant on another space's CA, a role on the user in another space, a grant at
    /// instance scope, a resource-scoped grant elsewhere, access to a certificate that resolves
    /// to no CA. The same account with holdings only inside the scope is the caller's to change.
    /// </summary>
    [Theory]
    [InlineData("grant on another space's CA")]
    [InlineData("resource grant on another space's CA")]
    [InlineData("role in another space")]
    [InlineData("grant at instance scope")]
    [InlineData("instance group")]
    [InlineData("certificate access that resolves to no CA")]
    public async Task One_holding_outside_the_callers_scope_is_enough_to_refuse(string holding)
    {
        foreach (var caller in new[] { "CA admin", "space admin" })
        {
            var lab = new Lab();
            var w = lab.W;
            var actor = lab.Callers[caller];
            var account = lab.Targets["requester of the CA"];
            switch (holding)
            {
                case "grant on another space's CA":
                    w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = account, Capability = Capabilities.CertView, SpaceId = w.SpaceB, CertificateAuthorityId = w.CaB1 });
                    break;
                case "resource grant on another space's CA":
                    w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
                    {
                        UserId = account, Capability = Capabilities.ProfileUse, CertificateAuthorityId = w.CaB1, ResourceType = "CertProfile", ResourceId = Guid.NewGuid(),
                    });
                    break;
                case "role in another space":
                    w.Db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = w.Role(Capabilities.CertView).Id, UserId = account, SpaceId = w.SpaceB });
                    break;
                case "grant at instance scope":
                    w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = account, Capability = Capabilities.AuditView });
                    break;
                case "instance group":
                    w.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = w.Group("instance-requesters", null, null, "Requester").Id, UserId = account });
                    break;
                default:
                    w.Db.CertificateAccessLists.Add(new CertificateAccessListEntity { Id = Guid.NewGuid(), CertificateId = Guid.NewGuid(), UserId = account });
                    break;
            }
            w.Db.SaveChanges();
            var before = lab.Snapshot(account);

            foreach (var op in new[] { "reset-password", "update-email", "rename", "disable", "delete", "reset-mfa" })
                Assert.True(Status(await lab.Run(actor, op, account)) == 403, $"{caller} {op} with a {holding}");
            Assert.Equal(before, lab.Snapshot(account));
            Assert.Empty(w.Db.KeyCeremonies);

            // A system administrator covers every scope.
            Assert.Equal(200, Status(await lab.Run(lab.Callers["system admin"], "reset-password", account)));
        }
    }

    /// <summary>The footprint itself: every source of a holding lands in the scope it is held at.</summary>
    [Fact]
    public async Task The_footprint_of_an_account_names_every_scope_it_holds_anything_in()
    {
        var lab = new Lab();
        var w = lab.W;

        var none = await UserAdministrationAccess.FootprintAsync(w.Db, lab.Targets["ungrouped"]);
        Assert.True(none.IsEmpty);

        var both = await UserAdministrationAccess.FootprintAsync(w.Db, lab.Targets["both spaces"]);
        Assert.False(both.Instance);
        Assert.Empty(both.SpaceIds);
        Assert.Equal(new[] { w.CaA1, w.CaB1 }.OrderBy(g => g), both.CaIds.OrderBy(g => g));

        var system = await UserAdministrationAccess.FootprintAsync(w.Db, lab.Targets["system auditor"]);
        Assert.True(system.Instance);

        var spaceWide = await UserAdministrationAccess.FootprintAsync(w.Db, lab.Callers["space admin"]);
        Assert.Equal(new[] { w.SpaceA }, spaceWide.SpaceIds);
        Assert.Empty(spaceWide.CaIds);

        var service = Guid.NewGuid();
        w.Db.Users.Add(new UserEntity { Id = service, Username = "svc", Email = "svc@x", IsServiceIdentity = true, ServiceScopeSpaceId = w.SpaceB });
        var instanceService = Guid.NewGuid();
        w.Db.Users.Add(new UserEntity { Id = instanceService, Username = "svc-i", Email = "svc-i@x", IsServiceIdentity = true });
        w.Db.SaveChanges();
        Assert.Equal(new[] { w.SpaceB }, (await UserAdministrationAccess.FootprintAsync(w.Db, service)).SpaceIds);
        Assert.True((await UserAdministrationAccess.FootprintAsync(w.Db, instanceService)).Instance);
    }

    /// <summary>
    /// A badge narrows the caller for these routes as for any other: a system administrator who
    /// wears a badge of their CA-A1 administrators group has that group's reach and no more.
    /// </summary>
    [Fact]
    public async Task A_badge_narrows_a_system_admin_to_the_scope_it_keeps()
    {
        var lab = new Lab();
        var narrowed = lab.W.User("narrowed-admin", lab.W.SystemAdminGroup, lab.W.A1Admin);
        var badge = lab.W.A1Admin.Id;
        var elsewhere = lab.Targets["other space"];
        var sibling = lab.Targets["sibling CA"];
        var own = lab.Targets["requester of the CA"];
        var before = (lab.Snapshot(elsewhere), lab.Snapshot(sibling));

        Assert.Equal(404, Status(await lab.Run(narrowed, "reset-password", elsewhere, badge)));
        Assert.Equal(403, Status(await lab.Run(narrowed, "reset-password", sibling, badge)));
        Assert.Equal(403, Status(await lab.Run(narrowed, "reset-mfa", own, badge)));
        Assert.Equal(before, (lab.Snapshot(elsewhere), lab.Snapshot(sibling)));
        Assert.Equal(200, Status(await lab.Run(narrowed, "reset-password", own, badge)));

        Assert.Equal(200, Status(await lab.Run(narrowed, "reset-password", elsewhere)));
    }

    /// <summary>
    /// The caller's own account: nobody deletes or disables themselves or changes their own
    /// memberships, and the scope rule holds for one's own account too, so an administrator of
    /// one CA who also holds something in another space does not edit their own identity here.
    /// </summary>
    [Fact]
    public async Task The_callers_own_account_follows_the_same_scope_rule()
    {
        var lab = new Lab();
        var admin = lab.Callers["CA admin"];
        var before = lab.Snapshot(admin);

        Assert.Equal(400, Status(await lab.Run(admin, "delete", admin)));
        Assert.Equal(400, Status(await lab.Run(admin, "disable", admin)));
        Assert.Equal(400, Status(await lab.Add(admin, admin, lab.W.A1Requester)));
        Assert.Equal(400, Status(await lab.Remove(admin, admin, lab.W.A1Admin)));
        Assert.Equal(403, Status(await lab.Run(admin, "reset-mfa", admin)));
        Assert.Equal(before, lab.Snapshot(admin));
        Assert.Equal(200, Status(await lab.Run(admin, "rename", admin)));

        var straddler = lab.W.User("a1-admin-and-b1-requester", lab.W.A1Admin, lab.W.B1Requester);
        var straddlerBefore = lab.Snapshot(straddler);
        Assert.Equal(403, Status(await lab.Run(straddler, "update-email", straddler)));
        Assert.Equal(403, Status(await lab.Run(straddler, "rename", straddler)));
        Assert.Equal(403, Status(await lab.Run(straddler, "reset-password", straddler)));
        Assert.Equal(straddlerBefore, lab.Snapshot(straddler));

        // An account in no group cannot even rename itself here: it holds user.manage nowhere.
        var nobody = lab.Callers["no groups"];
        Assert.Equal(403, Status(await lab.Run(nobody, "rename", nobody)));
        Assert.Equal(403, Status(await lab.Run(nobody, "reset-password", nobody)));
    }

    // ---- account changes: what a scoped administrator can now do ------------------------------

    /// <summary>
    /// An administrator of a CA resets the password of a requester of that CA: the temporary
    /// password works, the old one is gone and the account's sessions end. An administrator of a
    /// space does the same for an account of a sibling CA in the space. Neither resets MFA, which
    /// stays with the system administrators; a system administrator's MFA reset ends the sessions.
    /// </summary>
    [Theory]
    [InlineData("CA admin", "requester of the CA")]
    [InlineData("space admin", "sibling CA")]
    [InlineData("space admin", "requester of the CA")]
    public async Task A_scoped_admin_resets_the_password_of_an_account_of_its_scope_and_its_sessions_end(string caller, string target)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var account = lab.Targets[target];
        var stamp = lab.User(account).SecurityStamp;
        Assert.Equal(1, lab.LiveSessions(account));

        Assert.True(await lab.Policy(actor, "ResetUserPassword"));
        var reset = await lab.Run(actor, "reset-password", account);
        Assert.Equal(200, Status(reset));
        var temporary = (string)Prop(reset, "newPassword")!;
        Assert.True(PasswordUtil.VerifyPassword(temporary, lab.User(account).PasswordHash));
        Assert.True(lab.User(account).PasswordChangeOnNextLogon);
        Assert.NotEqual(stamp, lab.User(account).SecurityStamp);
        Assert.Equal(0, lab.LiveSessions(account));
        Assert.Contains(lab.AuditDb.AuditLogs, a => a.ActionType == AuditActionType.UserPasswordReset && a.TargetEntityId == account.ToString() && a.ActorUserId == actor);

        // The second factor is not the scoped administrator's to remove.
        Assert.False(await lab.Policy(actor, "ResetUserMfa"));
        Assert.Equal(403, Status(await lab.Run(actor, "reset-mfa", account)));
        Assert.True(lab.W.Db.TotpSecrets.Any(t => t.UserId == account));
        Assert.NotNull(lab.User(account).MfaEnrolledAt);

        // A system administrator removes it, and the sessions end again.
        lab.W.Db.RefreshTokens.Add(new RefreshTokenEntity { UserId = account, Token = Guid.NewGuid().ToString("N"), ExpiresAt = DateTime.UtcNow.AddDays(1) });
        lab.W.Db.SaveChanges();
        stamp = lab.User(account).SecurityStamp;
        Assert.Equal(200, Status(await lab.Run(lab.Callers["system admin"], "reset-mfa", account)));
        Assert.False(lab.W.Db.TotpSecrets.Any(t => t.UserId == account));
        Assert.Null(lab.User(account).MfaEnrolledAt);
        Assert.NotEqual(stamp, lab.User(account).SecurityStamp);
        Assert.Equal(0, lab.LiveSessions(account));
    }

    /// <summary>A scoped administrator updates, disables and deletes an account that lies wholly in its scope.</summary>
    [Theory]
    [InlineData("CA admin", "requester of the CA")]
    [InlineData("space admin", "sibling CA")]
    public async Task A_scoped_admin_updates_disables_and_deletes_an_account_of_its_scope(string caller, string target)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var account = lab.Targets[target];

        Assert.Equal(200, Status(await lab.Run(actor, "update-email", account)));
        Assert.Equal("changed@example.com", lab.User(account).Email);
        Assert.Equal(200, Status(await lab.Run(actor, "disable", account)));
        Assert.False(lab.User(account).IsActive);
        Assert.Equal(200, Status(await lab.Run(actor, "delete", account)));
        Assert.False(lab.W.Db.Users.Any(u => u.Id == account));
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    /// <summary>
    /// A change to a peer, an account holding a controlled tier in the caller's scope, opens a
    /// controlled-user ceremony (202) instead of applying: no password is returned and nothing on
    /// the account moves. The ceremony is minted at the peer's tier.
    /// </summary>
    [Theory]
    [InlineData("CA admin")]
    [InlineData("space admin")]
    public async Task A_change_to_a_controlled_account_of_the_scope_opens_a_ceremony(string caller)
    {
        foreach (var op in new[] { "reset-password", "update-email", "disable", "delete" })
        {
            var lab = new Lab();
            var actor = lab.Callers[caller];
            var peer = lab.Targets["administrator of the CA"];
            var before = lab.Snapshot(peer);

            var result = await lab.Run(actor, op, peer);

            Assert.Equal(202, Status(result));
            Assert.Null(Prop(result, "newPassword"));
            Assert.Equal(before, lab.Snapshot(peer));
            var ceremony = lab.W.Db.KeyCeremonies.Single();
            Assert.Equal((Guid)Prop(result, "ceremonyId")!, ceremony.Id);
            Assert.Equal(lab.W.SpaceA, ceremony.SpaceId);
            Assert.Equal(new ControlledTier(ControlledTierLevel.CaAdmin, lab.W.CaA1) { SpaceId = lab.W.SpaceA },
                lab.Controlled().DescribeCeremony(ceremony).Minted);
        }
    }

    /// <summary>
    /// A ceremony a scoped administrator opened for a peer was checked against the scopes the peer
    /// was in then. When the peer has since been given something in another space, executing it
    /// would reach into that space, so it expires and nothing applies; a system administrator's
    /// ceremony records no scopes and is not affected. With the account unchanged, it executes.
    /// </summary>
    [Theory]
    [InlineData("reset-password")]
    [InlineData("update-email")]
    [InlineData("delete")]
    public async Task A_scoped_admins_ceremony_expires_when_the_account_has_moved_outside_its_scope(string op)
    {
        foreach (var moves in new[] { true, false })
        {
            var lab = new Lab();
            var admin = lab.Callers["CA admin"];
            var approver = lab.Callers["system admin"];
            var peer = lab.Targets["administrator of the CA"];

            var opened = await lab.Run(admin, op, peer);
            Assert.Equal(202, Status(opened));
            var id = (Guid)Prop(opened, "ceremonyId")!;
            var parameters = JsonSerializer.Deserialize<ModularCA.Shared.Models.ControlledUserChangeParameters>(lab.W.Db.KeyCeremonies.Single().ParametersJson)!;
            Assert.Equal(new[] { $"ca:{lab.W.CaA1}" }, parameters.TargetScopes);
            Assert.Equal(200, Status(await lab.Approve(approver, id)));

            if (moves)
            {
                lab.W.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = lab.W.B1Requester.Id, UserId = peer });
                lab.W.Db.SaveChanges();
            }
            var before = lab.Snapshot(peer);

            var executed = await lab.Execute(admin, id);

            if (moves)
            {
                Assert.Equal(409, Status(executed));
                Assert.Null(Prop(executed, "temporaryPassword"));
                Assert.Equal("Expired", lab.W.Db.KeyCeremonies.Single().Status);
                Assert.Equal(before, lab.Snapshot(peer));
            }
            else
            {
                Assert.Equal(200, Status(executed));
                Assert.Equal("Executed", lab.W.Db.KeyCeremonies.Single().Status);
                Assert.NotEqual(before, lab.Snapshot(peer));
            }
        }

        // Opened at system scope, the ceremony records no scopes: a system administrator covers them all.
        var system = new Lab();
        var bySystem = await system.Run(system.Callers["system admin"], op, system.Targets["administrator of the CA"]);
        Assert.Equal(202, Status(bySystem));
        Assert.Null(JsonSerializer.Deserialize<ModularCA.Shared.Models.ControlledUserChangeParameters>(system.W.Db.KeyCeremonies.Single().ParametersJson)!.TargetScopes);
    }

    // ---- memberships -------------------------------------------------------------------------

    private static readonly string[] GroupNames =
    [
        "own CA requesters", "own CA administrators", "sibling CA requesters", "space administrators",
        "other space requesters", "system administrators", "system-super",
    ];

    /// <summary>
    /// What adding the CA's operator (an account every space-A caller can see, in none of these
    /// groups) to each group answers, per caller: 200 adds, 202 opens a ceremony for a controlled
    /// tier, 403 refuses a group the caller has no right on, 404 an account the caller cannot see.
    /// </summary>
    private static readonly Dictionary<string, int[]> ExpectedAdd = new(StringComparer.Ordinal)
    {
        //                     own req, own admin, sibling req, space admin, other space, sys admin, super
        ["no groups"] = [404, 404, 404, 404, 404, 404, 404],
        ["requester"] = [404, 404, 404, 404, 404, 404, 404],
        ["CA auditor"] = [403, 403, 403, 403, 403, 403, 403],
        ["CA operator"] = [403, 403, 403, 403, 403, 403, 403],
        ["CA admin"] = [200, 202, 403, 403, 403, 403, 403],
        ["space admin"] = [200, 202, 200, 202, 403, 403, 403],
        ["system auditor"] = [403, 403, 403, 403, 403, 403, 403],
        ["system operator"] = [403, 403, 403, 403, 403, 403, 403],
        ["system admin"] = [200, 202, 200, 202, 200, 403, 403],
        ["system-super"] = [200, 200, 200, 200, 200, 200, 200],
    };

    public static TheoryData<string> AllCallers()
    {
        var data = new TheoryData<string>();
        foreach (var caller in CallerNames) data.Add(caller);
        return data;
    }

    /// <summary>
    /// A membership is decided on the group's own scope, never on another one: every caller
    /// adding an account to every kind of group, through the single route and the bulk route.
    /// Unless the answer is 200 the memberships are unchanged; a ceremony opens only on 202.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllCallers))]
    public async Task A_membership_needs_the_right_on_the_groups_own_scope(string caller)
    {
        for (var i = 0; i < GroupNames.Length; i++)
        {
            var expected = ExpectedAdd[caller][i];
            var what = $"{caller} adds to {GroupNames[i]}";

            var lab = new Lab();
            var actor = lab.Callers[caller];
            var account = lab.Targets["operator of the CA"];
            var group = lab.Groups[GroupNames[i]];
            var before = lab.Snapshot(account);

            var admitted = await lab.Policy(actor, "AddUserToGroup");
            Assert.True(admitted == Administrators.Contains(caller), $"{what}: policy");
            if (!admitted)
                Assert.True(expected is 403 or 404, $"{what}: the policy refuses but the action would answer {expected}");

            var result = await lab.Add(actor, account, group);
            Assert.True(Status(result) == expected, $"{what}: expected {expected}, got {Status(result)}");
            Assert.Equal(expected == 200, lab.InGroup(account, group));
            if (expected != 200) Assert.True(before == lab.Snapshot(account), $"{what}: the account changed");
            Assert.Equal(expected == 202 ? 1 : 0, lab.W.Db.KeyCeremonies.Count());

            // The bulk route decides each group the same way.
            var bulkLab = new Lab();
            var bulkAccount = bulkLab.Targets["operator of the CA"];
            var bulkGroup = bulkLab.Groups[GroupNames[i]];
            var bulkBefore = bulkLab.Snapshot(bulkAccount);
            var bulk = await bulkLab.Bulk(bulkLab.Callers[caller], bulkAccount, [bulkGroup], []);
            if (expected == 404)
                Assert.Equal(404, Status(bulk));
            else
                Assert.Equal(new[] { expected switch { 200 => "add:added", 202 => "add:ceremony", _ => "add:denied" } }, BulkStatuses(bulk));
            Assert.Equal(expected == 200, bulkLab.InGroup(bulkAccount, bulkGroup));
            if (expected != 200) Assert.True(bulkBefore == bulkLab.Snapshot(bulkAccount), $"{what} (bulk): the account changed");
            Assert.Equal(expected == 202 ? 1 : 0, bulkLab.W.Db.KeyCeremonies.Count());
        }
    }

    /// <summary>
    /// Nobody promotes themselves: an administrator or operator of a CA, or an administrator of a
    /// space, adding itself to the system administrators, the system-supers, another CA's
    /// administrators, another space's groups, or (the operator) its own CA's administrators is
    /// refused on the single route and the bulk route, and no ceremony opens.
    /// </summary>
    [Theory]
    [InlineData("CA admin")]
    [InlineData("CA operator")]
    [InlineData("space admin")]
    public async Task Nobody_adds_themselves_to_a_group(string caller)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var before = lab.Snapshot(actor);
        var groups = new[]
        {
            lab.W.SystemAdminGroup, lab.W.SuperGroup, lab.W.A2Admin, lab.B1Admin, lab.W.B1Requester, lab.W.A1Admin, lab.W.SpaceAdminA,
            lab.A2Requester, lab.A1Auditors,
        }.Where(g => !lab.InGroup(actor, g)).ToArray();

        foreach (var group in groups)
        {
            Assert.True(Status(await lab.Add(actor, actor, group)) == 400, $"{caller} adds itself to {group.Name}");
            Assert.False(lab.InGroup(actor, group));
        }
        var bulk = await lab.Bulk(actor, actor, groups, []);
        Assert.All(BulkStatuses(bulk), s => Assert.Equal("add:denied", s));
        Assert.Equal(before, lab.Snapshot(actor));
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    /// <summary>
    /// A scoped caller cannot place anyone else in a group above or beside its scope either: an
    /// account of its CA into the system groups, another CA's administrators or another space's
    /// groups. And it cannot create an account that starts in one, or in a controlled group of its
    /// own scope.
    /// </summary>
    [Theory]
    [InlineData("CA admin")]
    [InlineData("CA operator")]
    [InlineData("space admin")]
    public async Task A_scoped_caller_places_nobody_outside_its_scope_and_creates_no_privileged_account(string caller)
    {
        var lab = new Lab();
        var actor = lab.Callers[caller];
        var account = lab.Targets["requester of the CA"];
        var before = lab.Snapshot(account);

        foreach (var group in new[] { lab.W.SystemAdminGroup, lab.W.SuperGroup, lab.W.SystemAuditorGroup, lab.W.SystemOperatorGroup, lab.B1Admin, lab.W.B1Requester })
        {
            Assert.True(Status(await lab.Add(actor, account, group)) == 403, $"{caller} adds to {group.Name}");
            Assert.True(Status(await lab.Create(actor, $"new-in-{group.Name}", group)) == 403, $"{caller} creates in {group.Name}");
        }
        if (caller != "space admin")
        {
            Assert.Equal(403, Status(await lab.Add(actor, account, lab.W.A2Admin)));
            Assert.Equal(403, Status(await lab.Add(actor, account, lab.W.SpaceAdminA)));
            Assert.Equal(403, Status(await lab.Create(actor, "new-space-admin", lab.W.SpaceAdminA)));
        }
        // A controlled group of its own scope cannot be given at creation: that needs a ceremony.
        Assert.Equal(403, Status(await lab.Create(actor, "new-a1-admin", lab.W.A1Admin)));

        Assert.Equal(before, lab.Snapshot(account));
        Assert.False(lab.W.Db.Users.Any(u => u.Username.StartsWith("new-")));
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    /// <summary>
    /// An account in no group is nobody's below system scope: an administrator or operator of a
    /// CA cannot see one, place one or change one. So an administrator below system scope cannot
    /// make one either. It must name a group when it creates an account, and it may not remove
    /// the last group an account is in; a system administrator may do both.
    /// </summary>
    [Fact]
    public async Task A_scoped_admin_neither_creates_nor_leaves_an_account_in_no_group()
    {
        var lab = new Lab();
        var admin = lab.Callers["CA admin"];
        var op = lab.Callers["CA operator"];
        var system = lab.Callers["system admin"];
        var stranger = lab.Targets["ungrouped"];
        var strangerBefore = lab.Snapshot(stranger);
        var a1Auditors = lab.W.Group("a1-auditors", lab.W.SpaceA, lab.W.CaA1, "Auditor");
        lab.W.Db.SaveChanges();

        // An ungrouped account: 404 for a scoped caller, whatever the group.
        foreach (var caller in new[] { admin, op })
        {
            Assert.Equal(404, Status(await lab.Add(caller, stranger, lab.W.SpaceAdminA)));
            Assert.Equal(404, Status(await lab.Add(caller, stranger, lab.W.A1Requester)));
            Assert.Equal(404, Status(await lab.Bulk(caller, stranger, [lab.W.A1Requester], [])));
        }
        Assert.Equal(strangerBefore, lab.Snapshot(stranger));

        // The CA admin cannot create an account with no groups, and nothing is created.
        Assert.Equal(400, Status(await lab.Create(admin, "fresh")));
        Assert.False(lab.W.Db.Users.Any(u => u.Username == "fresh"));

        // In a group it manages, it can; the account is in its scope from the start, for it and its peers.
        var created = await lab.Create(admin, "fresh", lab.W.A1Requester);
        Assert.Equal(200, Status(created));
        var fresh = (Guid)Prop(created, "id")!;
        Assert.True(lab.InGroup(fresh, lab.W.A1Requester));
        Assert.False((await UserAdministrationAccess.FootprintAsync(lab.W.Db, fresh)).IsEmpty);

        // It cannot take the account out of its last group, singly or in a batch ...
        Assert.Equal(409, Status(await lab.Remove(admin, fresh, lab.W.A1Requester)));
        Assert.Equal(200, Status(await lab.Bulk(admin, fresh, [], [lab.W.A1Requester])));
        Assert.True(lab.InGroup(fresh, lab.W.A1Requester));
        // ... but it can move it: into another group first, then out of the old one ...
        Assert.Equal(200, Status(await lab.Add(admin, fresh, a1Auditors)));
        Assert.Equal(200, Status(await lab.Remove(admin, fresh, lab.W.A1Requester)));
        Assert.False(lab.InGroup(fresh, lab.W.A1Requester));
        // ... and the group it is left in is again the last.
        Assert.Equal(409, Status(await lab.Remove(admin, fresh, a1Auditors)));
        Assert.True(lab.InGroup(fresh, a1Auditors));
        // A batch that adds one group and removes the other moves it too: the add comes first.
        Assert.Equal(200, Status(await lab.Bulk(admin, fresh, [lab.W.A1Requester], [a1Auditors])));
        Assert.True(lab.InGroup(fresh, lab.W.A1Requester));
        Assert.False(lab.InGroup(fresh, a1Auditors));

        // A system administrator creates ungrouped accounts, places them anywhere but a system
        // group, and may take an account out of its last group.
        Assert.Equal(200, Status(await lab.Create(system, "by-system")));
        Assert.Equal(200, Status(await lab.Add(system, stranger, lab.W.A1Requester)));
        Assert.Equal(200, Status(await lab.Remove(system, fresh, lab.W.A1Requester)));
        Assert.True((await UserAdministrationAccess.FootprintAsync(lab.W.Db, fresh)).IsEmpty);
        Assert.Empty(lab.W.Db.KeyCeremonies);
    }

    /// <summary>
    /// What an account would hold without one of its groups: the footprint leaves that
    /// membership out, and anything else the account holds still counts, so a grant or a second
    /// group keeps the removal from stranding it.
    /// </summary>
    [Fact]
    public async Task The_footprint_without_a_group_is_what_removing_it_would_leave()
    {
        var lab = new Lab();
        var only = lab.W.User("only-requester", lab.W.A1Requester);
        var granted = lab.W.User("granted-requester", lab.W.A1Requester);
        lab.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = granted, Capability = Capabilities.CertView, CertificateAuthorityId = lab.W.CaA2 });
        lab.W.Db.SaveChanges();

        Assert.True((await UserAdministrationAccess.FootprintAsync(lab.W.Db, only, exceptGroupId: lab.W.A1Requester.Id)).IsEmpty);
        Assert.False((await UserAdministrationAccess.FootprintAsync(lab.W.Db, only, exceptGroupId: lab.W.A2Admin.Id)).IsEmpty);
        Assert.False((await UserAdministrationAccess.FootprintAsync(lab.W.Db, only)).IsEmpty);
        Assert.False((await UserAdministrationAccess.FootprintAsync(lab.W.Db, granted, exceptGroupId: lab.W.A1Requester.Id)).IsEmpty);
    }

    /// <summary>
    /// The administrator of a CA adds an account of a sibling CA to its own CA's requesters and
    /// removes it again, and cannot remove it from the sibling CA's group. Being in the caller's
    /// group as well does not put the account in the caller's hands.
    /// </summary>
    [Fact]
    public async Task A_ca_admin_adds_and_removes_members_of_its_own_groups_only()
    {
        var lab = new Lab();
        var admin = lab.Callers["CA admin"];
        var sibling = lab.Targets["sibling CA"];

        Assert.Equal(200, Status(await lab.Add(admin, sibling, lab.W.A1Requester)));
        Assert.True(lab.InGroup(sibling, lab.W.A1Requester));
        Assert.Equal(403, Status(await lab.Remove(admin, sibling, lab.A2Requester)));
        Assert.True(lab.InGroup(sibling, lab.A2Requester));

        var before = lab.Snapshot(sibling);
        Assert.Equal(403, Status(await lab.Run(admin, "reset-password", sibling)));
        Assert.Equal(403, Status(await lab.Run(admin, "delete", sibling)));
        Assert.Equal(before, lab.Snapshot(sibling));

        // Both the operators and the administrators of its CA are controlled tiers: a ceremony each.
        Assert.Equal(new[] { "add:ceremony", "add:ceremony", "add:denied", "remove:removed", "remove:denied" },
            BulkStatuses(await lab.Bulk(admin, sibling, [lab.A1Operators, lab.W.A1Admin, lab.W.B1Requester], [lab.W.A1Requester, lab.A2Requester])));
        Assert.False(lab.InGroup(sibling, lab.A1Operators));
        Assert.False(lab.InGroup(sibling, lab.W.A1Admin));
        Assert.False(lab.InGroup(sibling, lab.W.B1Requester));
        Assert.False(lab.InGroup(sibling, lab.W.A1Requester));
        Assert.True(lab.InGroup(sibling, lab.A2Requester));
    }

    /// <summary>
    /// Adding to a controlled tier opens a ceremony instead of applying, and removing a peer from
    /// one does too. A peer whose only group is the administrators cannot be taken out of it by a
    /// scoped administrator at all, with or without a ceremony: the account would be left in no
    /// scope. Once it is in another group as well, the removal opens its ceremony.
    /// </summary>
    [Fact]
    public async Task A_controlled_membership_change_by_a_ca_admin_opens_a_ceremony()
    {
        var lab = new Lab();
        var admin = lab.Callers["CA admin"];
        var op = lab.Targets["operator of the CA"];
        var peer = lab.Targets["administrator of the CA"];

        var add = await lab.Add(admin, op, lab.W.A1Admin);
        Assert.Equal(202, Status(add));
        Assert.True((bool)Prop(add, "requiresCeremony")!);
        Assert.False(lab.InGroup(op, lab.W.A1Admin));

        // The peer is in the administrators and nothing else: no ceremony is opened.
        Assert.Equal(409, Status(await lab.Remove(admin, peer, lab.W.A1Admin)));
        Assert.Single(lab.W.Db.KeyCeremonies);

        Assert.Equal(200, Status(await lab.Add(admin, peer, lab.W.A1Requester)));
        var remove = await lab.Remove(admin, peer, lab.W.A1Admin);
        Assert.Equal(202, Status(remove));
        Assert.True(lab.InGroup(peer, lab.W.A1Admin));
        Assert.Equal(2, lab.W.Db.KeyCeremonies.Count());
    }

    /// <summary>
    /// Reset, then promote: an administrator of a CA who reset the password of a low account of
    /// its CA cannot open that account's promotion for 30 days, on the single route or the bulk
    /// route. Another administrator can, and the ceremony tells its approvers who reset it.
    /// </summary>
    [Fact]
    public async Task A_scoped_admin_who_reset_an_accounts_password_cannot_then_promote_it()
    {
        var lab = new Lab();
        var admin = lab.Callers["CA admin"];
        var peer = lab.W.User("a1-admin-peer", lab.W.A1Admin);
        var low = lab.Targets["requester of the CA"];

        Assert.Equal(200, Status(await lab.Run(admin, "reset-password", low)));
        var before = lab.Snapshot(low);

        var refused = await lab.Add(admin, low, lab.W.A1Admin);
        Assert.Equal(409, Status(refused));
        Assert.Contains("You reset this user's credentials", (string)Prop(refused, "error")!);
        Assert.Equal(new[] { "add:refused" }, BulkStatuses(await lab.Bulk(admin, low, [lab.W.A1Admin], [])));
        Assert.False(lab.InGroup(low, lab.W.A1Admin));
        Assert.Equal(before, lab.Snapshot(low));
        Assert.Empty(lab.W.Db.KeyCeremonies);

        var opened = await lab.Add(peer, low, lab.W.A1Admin);
        Assert.Equal(202, Status(opened));
        Assert.StartsWith($"WARNING: t-a1-requester's password was reset by user-{admin:N}", lab.W.Db.KeyCeremonies.Single().Description);
        Assert.False(lab.InGroup(low, lab.W.A1Admin));
    }
}
