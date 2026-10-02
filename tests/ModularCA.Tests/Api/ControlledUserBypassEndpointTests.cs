using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real admin controllers (loaded from the API build output, as the other endpoint
/// tests do) to pin the controlled-user ceremony bypass fixes: account resets of a privileged
/// user, deleting a controlled group with members, changing a controlled capability on an
/// assigned role, and writing user-approval quorums without a ceremony.
/// </summary>
public sealed class ControlledUserBypassEndpointTests
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

    private sealed class RecordingTenantPolicy : ITenantPolicyChangeService
    {
        public List<(Guid? TenantId, bool UserQuorumIncluded, int? ProposedUserQuorum, IReadOnlyList<CaUserQuorumChange>? Cas)> Calls { get; } = new();

        public bool IsDowngrade(bool currentRequireKeyCeremony, int currentCeremonyRequiredApprovals,
            bool? proposedRequireKeyCeremony, int? proposedCeremonyRequiredApprovals) => false;

        public Task<Guid> InitiateChangeAsync(Guid? tenantId, bool? proposedRequireKeyCeremony, int? proposedCeremonyRequiredApprovals,
            Guid initiatorUserId, string initiatorUsername, bool userQuorumIncluded = false, int? proposedUserQuorum = null,
            IReadOnlyList<CaUserQuorumChange>? caUserQuorums = null)
        {
            Calls.Add((tenantId, userQuorumIncluded, proposedUserQuorum, caUserQuorums));
            return Task.FromResult(Guid.NewGuid());
        }

        public Task<TenantPolicyChangeAppliedResult> ApplyApprovedChangeAsync(Guid ceremonyId) => throw new NotSupportedException();
    }

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static string SeedStepUp(IDistributedCache cache, Guid actor, string op, Guid target)
    {
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{op}:{target}", token);
        return token;
    }

    private static object New(string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        ModularCA.Auth.Authorization.TenantFence.Store(http, ModularCA.Auth.Authorization.TenantFence.Of([], instanceScope: true, isSystemAdmin: true));
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
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    // ---- account administration --------------------------------------------------------------

    private static object UserManager(ControlledUserWorld w, Guid actor, IDistributedCache cache, object? updateValidator = null)
        => New(Ns + "Management.AdminUserManagerController", actor,
            w.Db, null, new CurrentUserStub(actor), new RecordingAuditService(), cache, new RecordingAlertService(),
            null, updateValidator, w.Controlled);

    [Fact]
    public async Task A_system_admin_cannot_reset_a_supers_password_or_mfa()
    {
        var w = new ControlledUserWorld();
        var cache = NewCache();
        var controller = UserManager(w, w.SystemAdmin, cache);

        var pw = await Call(controller, "ResetUserPassword", w.Super, SeedStepUp(cache, w.SystemAdmin, StepUpOps.ResetPassword, w.Super));
        Assert.Equal(403, Status(pw));

        w.Db.TotpSecrets.Add(new TotpSecretEntity { UserId = w.Super, IsVerified = true });
        w.Db.SaveChanges();
        var mfa = await Call(controller, "ResetUserMfa", w.Super, SeedStepUp(cache, w.SystemAdmin, StepUpOps.ResetMfa, w.Super));
        Assert.Equal(403, Status(mfa));
        Assert.True(w.Db.TotpSecrets.Any(t => t.UserId == w.Super));
    }

    [Fact]
    public async Task A_super_may_reset_a_system_admins_mfa()
    {
        var w = new ControlledUserWorld();
        var cache = NewCache();
        var controller = UserManager(w, w.Super, cache);

        var mfa = await Call(controller, "ResetUserMfa", w.SystemAdmin, SeedStepUp(cache, w.Super, StepUpOps.ResetMfa, w.SystemAdmin));
        Assert.Equal(200, Status(mfa));
    }

    [Fact]
    public async Task A_system_admin_cannot_deactivate_a_super()
    {
        var w = new ControlledUserWorld();
        var cache = NewCache();
        var validator = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.UpdateUserRequestValidator"));
        var controller = UserManager(w, w.SystemAdmin, cache, validator);

        var result = await Call(controller, "UpdateUser", w.Super, new UpdateUserRequest { IsActive = false },
            SeedStepUp(cache, w.SystemAdmin, StepUpOps.UpdateUser, w.Super));
        Assert.Equal(403, Status(result));
        Assert.True(w.Db.Users.Single(u => u.Id == w.Super).IsActive);
    }

    [Fact]
    public async Task A_system_operator_or_auditor_cannot_reset_a_system_admins_password_or_mfa()
    {
        var w = new ControlledUserWorld();
        foreach (var actor in new[] { w.Operator, w.Auditor })
        {
            var cache = NewCache();
            var controller = UserManager(w, actor, cache);
            Assert.Equal(403, Status(await Call(controller, "ResetUserPassword", w.SystemAdmin, SeedStepUp(cache, actor, StepUpOps.ResetPassword, w.SystemAdmin))));
            Assert.Equal(403, Status(await Call(controller, "ResetUserMfa", w.SystemAdmin, SeedStepUp(cache, actor, StepUpOps.ResetMfa, w.SystemAdmin))));
        }
    }

    [Fact]
    public async Task A_ca_admin_cannot_reset_a_holder_of_system_manage_by_direct_grant()
    {
        var w = new ControlledUserWorld();
        var holder = w.User("granted");
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = holder, Capability = Capabilities.SystemManage });
        w.Db.SaveChanges();
        var cache = NewCache();

        var controller = UserManager(w, w.A1AdminUser, cache);
        Assert.Equal(403, Status(await Call(controller, "ResetUserPassword", holder, SeedStepUp(cache, w.A1AdminUser, StepUpOps.ResetPassword, holder))));
    }

    // ---- user creation -----------------------------------------------------------------------

    private static object Creator(ControlledUserWorld w, Guid actor, IDistributedCache cache)
    {
        var users = new ModularCA.Auth.Services.UserManagementService(w.Db, Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Services.UserManagementService>.Instance,
            new ModularCA.Shared.Models.Config.SystemConfig(), null!, new ControlledUserBypassGuardTests.AllowAllPasswords());
        var validator = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.CreateUserRequestValidator"));
        return New(Ns + "Management.AdminUserManagerController", actor,
            w.Db, users, new CurrentUserStub(actor), new RecordingAuditService(), cache, new RecordingAlertService(),
            validator, null, w.Controlled);
    }

    private static string SeedCreateStepUp(IDistributedCache cache, Guid actor)
    {
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.CreateUser}", token);
        return token;
    }

    private static CreateUserRequest NewUser(string name, params Guid[] groups) => new()
    {
        Username = name, Email = $"{name}@example.com", Password = "Str0ng!Passw0rd", GroupIds = groups.ToList(),
    };

    [Fact]
    public async Task Creating_a_user_in_a_controlled_group_is_super_only()
    {
        var w = new ControlledUserWorld();
        var cache = NewCache();

        var asAdmin = Creator(w, w.SystemAdmin, cache);
        Assert.Equal(403, Status(await Call(asAdmin, "CreateUser", NewUser("puppet", w.A1Admin.Id), SeedCreateStepUp(cache, w.SystemAdmin))));
        Assert.False(w.Db.Users.Any(u => u.Username == "puppet"));

        Assert.Equal(200, Status(await Call(asAdmin, "CreateUser", NewUser("requester", w.A1Requester.Id), SeedCreateStepUp(cache, w.SystemAdmin))));

        var asSuper = Creator(w, w.Super, cache);
        Assert.Equal(200, Status(await Call(asSuper, "CreateUser", NewUser("newadmin", w.A1Admin.Id), SeedCreateStepUp(cache, w.Super))));
        var created = w.Db.Users.Single(u => u.Username == "newadmin").Id;
        Assert.True(w.Db.CaGroupMembers.Any(m => m.UserId == created && m.GroupId == w.A1Admin.Id));

        Assert.Equal(200, Status(await Call(asAdmin, "CreateUser", NewUser("nogroups"), SeedCreateStepUp(cache, w.SystemAdmin))));
        var bare = w.Db.Users.Single(u => u.Username == "nogroups").Id;
        Assert.False(w.Db.CaGroupMembers.Any(m => m.UserId == bare));
    }

    // ---- last-user guard ---------------------------------------------------------------------

    private static object Groups(ControlledUserWorld w, Guid actor)
        => New(Ns + "AdminGroupController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), NewCache(), null, w.Controlled);

    [Fact]
    public async Task A_super_may_remove_the_only_system_admin_because_the_super_still_dominates()
    {
        var w = new ControlledUserWorld();

        Assert.Equal(200, Status(await Call(Groups(w, w.Super), "RemoveMember", w.SystemAdminGroup.Id, w.SystemAdmin)));
        Assert.False(w.Db.CaGroupMembers.Any(m => m.GroupId == w.SystemAdminGroup.Id && m.UserId == w.SystemAdmin));
    }

    [Fact]
    public async Task A_lone_super_may_remove_the_only_tenant_admin()
    {
        var w = new ControlledUserWorld();
        var tenantAdmin = w.User("tenant-admin", w.OrgAdminA);
        w.Db.Users.Single(u => u.Id == w.SystemAdmin).IsActive = false;
        w.Db.SaveChanges();

        Assert.Equal(200, Status(await Call(Groups(w, w.Super), "RemoveMember", w.OrgAdminA.Id, tenantAdmin)));
        Assert.False(w.Db.CaGroupMembers.Any(m => m.GroupId == w.OrgAdminA.Id && m.UserId == tenantAdmin));
    }

    [Fact]
    public async Task A_group_holding_a_system_manage_role_is_controlled_for_deletion()
    {
        var w = new ControlledUserWorld();
        var custom = w.Group("custom-with-role", w.TenantA, w.CaA1, "Requester");
        w.Db.SaveChanges();
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = w.Role(Capabilities.SystemManage).Id, GroupId = custom.Id });
        w.User("member", custom);

        Assert.Equal(403, Status(await Call(Groups(w, w.SystemAdmin), "Delete", custom.Id)));
        Assert.True(w.Db.CaGroups.Any(g => g.Id == custom.Id));
    }

    // ---- stored secrets and a changed server -------------------------------------------------

    private sealed class PlainProtector : ModularCA.Shared.Interfaces.ILdapSecretProtector
    {
        public string Protect(string? plaintext) => plaintext ?? string.Empty;
        public string Unprotect(string? stored) => stored ?? string.Empty;
    }

    [Fact]
    public async Task A_publisher_host_change_needs_the_password_re_entered()
    {
        var w = new ControlledUserWorld();
        var publisher = new LdapConfigurationEntity { Id = Guid.NewGuid(), Host = "ldap.example", Port = 636, UseSsl = true, Password = "stored", CertificateAuthorityId = w.CaA1 };
        w.Db.LdapConfigurations.Add(publisher);
        w.Db.SaveChanges();
        object Controller() => New(Ns + "AdminLdapPublishersController", w.SystemAdmin, w.Db, new CurrentUserStub(w.SystemAdmin),
            new RecordingAuditService(), new PlainProtector(), CreateLogger(ApiAssembly.TypeNamed(Ns + "AdminLdapPublishersController")));

        var redacted = Body(Ns + "UpdateLdapPublisherRequest", ("Host", "evil.example"), ("Password", "***"));
        Assert.Equal(400, Status(await Call(Controller(), "Update", w.CaA1, publisher.Id, redacted)));
        var portOnly = Body(Ns + "UpdateLdapPublisherRequest", ("Port", (int?)389));
        Assert.Equal(400, Status(await Call(Controller(), "Update", w.CaA1, publisher.Id, portOnly)));
        Assert.Equal("ldap.example", w.Db.LdapConfigurations.Single(c => c.Id == publisher.Id).Host);

        var withPassword = Body(Ns + "UpdateLdapPublisherRequest", ("Host", "new.example"), ("Password", "fresh"));
        Assert.Equal(200, Status(await Call(Controller(), "Update", w.CaA1, publisher.Id, withPassword)));
        Assert.Equal("new.example", w.Db.LdapConfigurations.Single(c => c.Id == publisher.Id).Host);
    }

    private static object CreateLogger(Type category)
        => Activator.CreateInstance(typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>).MakeGenericType(category))!;

    private static object Config(ControlledUserWorld w, Guid actor, ModularCA.Shared.Models.Config.SystemConfig config)
        => New(Ns + "AdminConfigController", actor, config, null, new RecordingAuditService(), new CurrentUserStub(actor), NewCache(),
            new RecordingAlertService(), null, null, null, null);

    [Fact]
    public async Task An_email_server_change_needs_the_stored_secret_re_entered()
    {
        var w = new ControlledUserWorld();
        var config = new ModularCA.Shared.Models.Config.SystemConfig();
        config.Email.SmtpHost = "smtp.example";
        config.Email.SmtpPort = 587;
        config.Email.Password = "stored";
        config.Email.OAuth2TokenUrl = "https://login.example/token";
        config.Email.OAuth2ClientSecret = "secret";
        var controller = Config(w, w.SystemAdmin, config);

        var host = Body(Ns + "EmailConfigUpdateRequest", ("SmtpHost", "evil.example"), ("Password", "***"));
        Assert.Equal(400, Status(await Call(controller, "UpdateEmail", host)));
        var tokenUrl = Body(Ns + "EmailConfigUpdateRequest", ("OAuth2TokenUrl", "https://evil.example/token"));
        Assert.Equal(400, Status(await Call(controller, "UpdateEmail", tokenUrl)));
        Assert.Equal("smtp.example", config.Email.SmtpHost);
        Assert.Equal("https://login.example/token", config.Email.OAuth2TokenUrl);
    }

    [Fact]
    public async Task Turning_email_tls_off_needs_the_stored_password_re_entered()
    {
        var w = new ControlledUserWorld();
        var config = new ModularCA.Shared.Models.Config.SystemConfig();
        config.Email.SmtpHost = "smtp.example";
        config.Email.SmtpPort = 587;
        config.Email.UseTls = true;
        config.Email.Password = "stored";
        var controller = Config(w, w.SystemAdmin, config);

        var downgrade = Body(Ns + "EmailConfigUpdateRequest", ("SmtpHost", "smtp.example"), ("SmtpPort", 587), ("UseTls", false), ("Password", "***"));
        Assert.Equal(400, Status(await Call(controller, "UpdateEmail", downgrade)));
        Assert.True(config.Email.UseTls);
    }

    [Fact]
    public async Task Ldap_auth_server_changes_need_system_manage_and_the_bind_password()
    {
        var w = new ControlledUserWorld();
        var config = new ModularCA.Shared.Models.Config.SystemConfig();
        config.LdapAuth.Host = "dc.example";
        config.LdapAuth.Port = 636;
        config.LdapAuth.UseSsl = true;
        config.LdapAuth.BindPassword = "stored";
        var sync = new LdapGroupSyncService(w.Db, config, null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapGroupSyncService>.Instance);
        var auth = new ModularCA.Auth.Authorization.CaGroupAuthorizationService(w.Db,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.CaGroupAuthorizationService>.Instance);

        ModularCA.Shared.Models.Config.LdapAuthConfig Change() => new() { Host = "evil.example", Port = 636, UseSsl = true, BindPassword = "***" };

        Assert.Equal(403, Status(await Call(Config(w, w.Operator, config), "UpdateLdapAuth", Change(), sync, auth)));
        Assert.Equal(400, Status(await Call(Config(w, w.SystemAdmin, config), "UpdateLdapAuth", Change(), sync, auth)));
        Assert.Equal("dc.example", config.LdapAuth.Host);
        Assert.Equal("stored", config.LdapAuth.BindPassword);
    }

    // ---- group deletion ----------------------------------------------------------------------

    [Fact]
    public async Task Deleting_a_controlled_group_with_members_is_super_only()
    {
        var w = new ControlledUserWorld();
        var custom = w.Group("custom-a1-admins", w.TenantA, w.CaA1, "Administrator");
        w.User("member", custom);

        var asAdmin = New(Ns + "AdminGroupController", w.SystemAdmin,
            w.Db, new CurrentUserStub(w.SystemAdmin), new RecordingAuditService(), NewCache(), null, w.Controlled);
        Assert.Equal(403, Status(await Call(asAdmin, "Delete", custom.Id)));
        Assert.True(w.Db.CaGroups.Any(g => g.Id == custom.Id));

        var asSuper = New(Ns + "AdminGroupController", w.Super,
            w.Db, new CurrentUserStub(w.Super), new RecordingAuditService(), NewCache(), null, w.Controlled);
        Assert.Equal(200, Status(await Call(asSuper, "Delete", custom.Id)));
        Assert.False(w.Db.CaGroups.Any(g => g.Id == custom.Id));
    }

    // ---- roles -------------------------------------------------------------------------------

    private static RoleEntity Role(ControlledUserWorld w, bool builtIn = false, bool assigned = true, params string[] caps)
    {
        var role = new RoleEntity { Name = $"role-{Guid.NewGuid():N}", IsBuiltIn = builtIn };
        w.Db.Roles.Add(role);
        foreach (var c in caps)
            w.Db.RoleCapabilities.Add(new RoleCapabilityEntity { RoleId = role.Id, Capability = c });
        if (assigned)
            w.Db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = role.Id, UserId = w.Plain });
        w.Db.SaveChanges();
        return role;
    }

    private static object Roles(ControlledUserWorld w, Guid actor)
        => New(Ns + "AdminRoleController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), w.Controlled);

    private static object AddCap(string capability) => Body(Ns + "AddRoleCapabilityRequest", ("Capability", capability));

    [Fact]
    public async Task Built_in_roles_refuse_added_capabilities()
    {
        var w = new ControlledUserWorld();
        var role = Role(w, builtIn: true, assigned: false);
        Assert.Equal(400, Status(await Call(Roles(w, w.Super), "AddCapability", role.Id, AddCap(Capabilities.CaManage))));
    }

    [Fact]
    public async Task Adding_a_controlled_capability_to_an_assigned_role_is_super_only()
    {
        var w = new ControlledUserWorld();
        var assigned = Role(w);
        var unassigned = Role(w, assigned: false);

        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "AddCapability", assigned.Id, AddCap(Capabilities.SystemManage))));
        Assert.False(w.Db.RoleCapabilities.Any(c => c.RoleId == assigned.Id));

        Assert.Equal(200, Status(await Call(Roles(w, w.SystemAdmin), "AddCapability", unassigned.Id, AddCap(Capabilities.SystemManage))));
        // The role is held at instance scope, so ca.manage on it is the controlled system-operator tier.
        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "AddCapability", assigned.Id, AddCap(Capabilities.CaManage))));
        Assert.False(w.Db.RoleCapabilities.Any(c => c.RoleId == assigned.Id));
        Assert.Equal(200, Status(await Call(Roles(w, w.Super), "AddCapability", assigned.Id, AddCap(Capabilities.CaManage))));
        Assert.Equal(200, Status(await Call(Roles(w, w.Super), "AddCapability", assigned.Id, AddCap(Capabilities.SystemManage))));
    }

    [Fact]
    public async Task Removing_a_controlled_capability_from_an_assigned_role_is_super_only()
    {
        var w = new ControlledUserWorld();
        var role = Role(w, caps: new[] { Capabilities.SystemManage });
        var update = Body(Ns + "UpdateRoleRequest");
        var list = Activator.CreateInstance(typeof(List<>).MakeGenericType(ApiAssembly.TypeNamed(Ns + "RoleCapabilityInput")))!;
        update.GetType().GetProperty("Capabilities")!.SetValue(update, list);

        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "Update", role.Id, update)));
        var capId = w.Db.RoleCapabilities.Single(c => c.RoleId == role.Id).Id;
        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "RemoveCapability", role.Id, capId)));
        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "Delete", role.Id)));
        Assert.True(w.Db.Roles.Any(r => r.Id == role.Id));
        Assert.True(w.Db.RoleCapabilities.Any(c => c.RoleId == role.Id));

        Assert.Equal(200, Status(await Call(Roles(w, w.Super), "Delete", role.Id)));
    }

    private static object CapabilityList(params (string Capability, string? ResourceType, Guid? ResourceId)[] caps)
    {
        var itemType = ApiAssembly.TypeNamed(Ns + "RoleCapabilityInput");
        var list = (System.Collections.IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(itemType))!;
        foreach (var (cap, rt, rid) in caps)
        {
            var item = Activator.CreateInstance(itemType)!;
            itemType.GetProperty("Capability")!.SetValue(item, cap);
            itemType.GetProperty("ResourceType")!.SetValue(item, rt);
            itemType.GetProperty("ResourceId")!.SetValue(item, rid);
            list.Add(item);
        }
        return list;
    }

    [Fact]
    public async Task Swapping_a_role_wide_controlled_capability_for_a_resource_scoped_one_is_a_removal()
    {
        var w = new ControlledUserWorld();
        var role = Role(w, caps: new[] { Capabilities.SystemManage });
        var update = Body(Ns + "UpdateRoleRequest");
        update.GetType().GetProperty("Capabilities")!.SetValue(update,
            CapabilityList((Capabilities.SystemManage, "Certificate", Guid.NewGuid())));

        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "Update", role.Id, update)));
        Assert.True(w.Db.RoleCapabilities.Any(c => c.RoleId == role.Id && c.ResourceType == null && c.Capability == Capabilities.SystemManage));

        // A resource-scoped binding confers no tier, so adding or removing one is not gated.
        var scoped = Body(Ns + "AddRoleCapabilityRequest", ("Capability", Capabilities.SystemManage), ("ResourceType", "Certificate"), ("ResourceId", (Guid?)Guid.NewGuid()));
        Assert.Equal(200, Status(await Call(Roles(w, w.SystemAdmin), "AddCapability", role.Id, scoped)));
    }

    [Fact]
    public async Task A_role_awaiting_a_ceremony_gated_assignment_counts_as_assigned()
    {
        var w = new ControlledUserWorld();
        var role = Role(w, assigned: false, caps: new[] { Capabilities.CaManage });
        w.Db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            OperationType = "ControlledUserChange", Status = "Pending", ExpiresAt = DateTime.UtcNow.AddHours(1),
            ParametersJson = System.Text.Json.JsonSerializer.Serialize(new ControlledUserChangeParameters
            {
                ChangeType = "AssignRole", TargetUserId = w.Plain, RoleId = role.Id, TenantId = w.TenantA,
            }),
        });
        w.Db.SaveChanges();

        Assert.Equal(403, Status(await Call(Roles(w, w.SystemAdmin), "AddCapability", role.Id, AddCap(Capabilities.SystemManage))));
        Assert.False(w.Db.RoleCapabilities.Any(c => c.RoleId == role.Id && c.Capability == Capabilities.SystemManage));
    }

    // ---- instance operator rank --------------------------------------------------------------

    private static ModularCA.Auth.Authorization.ControlledUserCeremonyService WithCeremonies(ControlledUserWorld w)
        => new(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), null!,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.ControlledUserCeremonyService>.Instance);

    [Fact]
    public async Task Granting_or_assigning_instance_ca_manage_opens_a_ceremony_unless_a_super_acts()
    {
        var w = new ControlledUserWorld();
        var controlled = WithCeremonies(w);
        object Grants(Guid actor) => New(Ns + "AdminUserGrantController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), controlled);
        object Assignments(Guid actor) => New(Ns + "AdminRoleAssignmentController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), controlled);
        var role = w.Role(Capabilities.CaManage);
        var grant = Body(Ns + "CreateUserGrantRequest", ("UserId", w.Plain), ("Capability", Capabilities.CaManage));
        var assign = Body(Ns + "CreateRoleAssignmentRequest", ("RoleId", role.Id), ("UserId", (Guid?)w.Plain));

        Assert.Equal(202, Status(await Call(Grants(w.SystemAdmin), "Create", grant)));
        Assert.Equal(202, Status(await Call(Assignments(w.SystemAdmin), "Create", assign)));
        Assert.False(w.Db.UserCapabilityGrants.Any(g => g.UserId == w.Plain));
        Assert.False(w.Db.RoleAssignments.Any(ra => ra.RoleId == role.Id));
        var opened = w.Db.KeyCeremonies.Where(c => c.OperationType == "ControlledUserChange").ToList();
        Assert.Equal(2, opened.Count);
        Assert.All(opened, c =>
        {
            Assert.Null(c.TenantId);
            Assert.Equal(new ControlledTier(ControlledTierLevel.SystemOperator, null), controlled.DescribeCeremony(c).Minted);
        });

        Assert.Equal(201, Status(await Call(Grants(w.Super), "Create", grant)));
        Assert.Equal(201, Status(await Call(Assignments(w.Super), "Create", assign)));
        Assert.True(w.Db.UserCapabilityGrants.Any(g => g.UserId == w.Plain && g.Capability == Capabilities.CaManage && g.TenantId == null));
        Assert.True(w.Db.RoleAssignments.Any(ra => ra.RoleId == role.Id && ra.UserId == w.Plain));
    }

    [Fact]
    public async Task A_pending_deletion_whose_target_gained_instance_ca_manage_expires_at_execute()
    {
        var w = new ControlledUserWorld();
        var audit = new RecordingAuditService();
        var ceremonies = new KeyCeremonyService(w.Db, audit);
        var controlled = new ModularCA.Auth.Authorization.ControlledUserCeremonyService(w.Db, ceremonies, null!,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.ControlledUserCeremonyService>.Instance);
        var groupAuth = new ModularCA.Auth.Authorization.CaGroupAuthorizationService(w.Db,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.CaGroupAuthorizationService>.Instance);
        object Controller(Guid actor, IDistributedCache cache) => New(Ns + "AdminKeyCeremonyController", actor,
            ceremonies, new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), null, w.Db, groupAuth, null, null, null, controlled);

        var target = w.User("a1-target", w.A1Admin);
        var approver = w.User("a1-approver", w.A1Admin);
        var minted = (await controlled.GetDeletionTierAsync(target))!.Value;
        Assert.Equal(ControlledTierLevel.CaAdmin, minted.Level);
        var id = await controlled.InitiateChangeAsync(
            new ControlledUserChangeParameters { ChangeType = "DeleteUser", TargetUserId = target, TargetUsername = "a1-target" },
            minted, w.A1AdminUser, "a1admin");
        var cache = NewCache();
        Assert.Equal(200, Status(await Call(Controller(approver, cache), "Approve", id,
            SeedStepUp(cache, approver, StepUpOps.ApproveCeremony, id))));
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);

        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = target, Capability = Capabilities.CaManage });
        w.Db.SaveChanges();

        Assert.Equal(409, Status(await Call(Controller(w.A1AdminUser, cache), "Execute", id,
            SeedStepUp(cache, w.A1AdminUser, StepUpOps.ExecuteCeremony, id))));
        Assert.Equal("Expired", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
        Assert.True(w.Db.Users.Any(u => u.Id == target));
    }

    // ---- ceremony scoping --------------------------------------------------------------------

    private static int Count(IActionResult result)
        => ((System.Collections.IEnumerable)((ObjectResult)result).Value!).Cast<object>().Count();

    [Fact]
    public async Task A_ca_admin_reaches_and_approves_only_the_controlled_user_ceremonies_of_their_ca()
    {
        var w = new ControlledUserWorld();
        var audit = new RecordingAuditService();
        var ceremonies = new KeyCeremonyService(w.Db, audit);
        var controlled = new ModularCA.Auth.Authorization.ControlledUserCeremonyService(w.Db, ceremonies, null!,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.ControlledUserCeremonyService>.Instance);
        var groupAuth = new ModularCA.Auth.Authorization.CaGroupAuthorizationService(w.Db,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Auth.Authorization.CaGroupAuthorizationService>.Instance);
        object Controller(Guid actor, IDistributedCache cache) => New(Ns + "AdminKeyCeremonyController", actor,
            ceremonies, new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), null, w.Db, groupAuth, null, null, null, controlled);

        var initiator = w.User("a1-initiator", w.A1Admin);
        var a2Admin = w.User("a2-admin", w.A2Admin);
        var minted = controlled.ClassifyCapabilityGrant(Capabilities.SystemManage, w.CaA1)!.Value;
        Guid Start() => controlled.InitiateCapabilityGrantAsync(w.Plain, "plain", Capabilities.SystemManage, null, w.CaA1, null, null,
            minted, initiator, "a1-initiator").GetAwaiter().GetResult();

        var id = Start();
        Assert.Equal(w.TenantA, w.Db.KeyCeremonies.Single(c => c.Id == id).TenantId);

        // Another CA's admin in the same tenant neither sees nor reaches it.
        Assert.Equal(403, Status(await Call(Controller(a2Admin, NewCache()), "GetById", id)));
        Assert.Equal(0, Count(await Call(Controller(a2Admin, NewCache()), "List", (string?)null)));

        // The CA's own admin, who holds no tenant-wide ca.manage, sees and approves it.
        Assert.Equal(200, Status(await Call(Controller(w.A1AdminUser, NewCache()), "GetById", id)));
        Assert.Equal(1, Count(await Call(Controller(w.A1AdminUser, NewCache()), "List", (string?)null)));
        var cache = NewCache();
        Assert.Equal(200, Status(await Call(Controller(w.A1AdminUser, cache), "Approve", id,
            SeedStepUp(cache, w.A1AdminUser, StepUpOps.ApproveCeremony, id))));
        Assert.Equal(200, Status(await Call(Controller(w.A1AdminUser, cache), "Execute", id,
            SeedStepUp(cache, w.A1AdminUser, StepUpOps.ExecuteCeremony, id))));
        Assert.True(w.Db.UserCapabilityGrants.Any(g => g.UserId == w.Plain && g.CertificateAuthorityId == w.CaA1));

        // An approval that goes stale before execution is refused with 409 and the ceremony expires.
        var approver = w.User("a1-approver", w.A1Admin);
        var second = Start();
        Assert.Equal(200, Status(await Call(Controller(approver, cache), "Approve", second,
            SeedStepUp(cache, approver, StepUpOps.ApproveCeremony, second))));
        w.Db.Users.Single(u => u.Id == approver).IsActive = false;
        w.Db.SaveChanges();
        Assert.Equal(409, Status(await Call(Controller(initiator, cache), "Execute", second,
            SeedStepUp(cache, initiator, StepUpOps.ExecuteCeremony, second))));
        Assert.Equal("Expired", w.Db.KeyCeremonies.Single(c => c.Id == second).Status);
    }

    // ---- user-approval quorum ----------------------------------------------------------------

    private static object Quorum(ControlledUserWorld w, Guid actor, ITenantPolicyChangeService policy)
        => New(Ns + "AdminUserQuorumController", actor, w.Db, new CurrentUserStub(actor), new RecordingAuditService(), policy, w.Controlled);

    [Fact]
    public async Task A_non_super_quorum_change_opens_a_tenant_policy_ceremony()
    {
        var w = new ControlledUserWorld();
        var policy = new RecordingTenantPolicy();
        var controller = Quorum(w, w.SystemAdmin, policy);

        Assert.Equal(202, Status(await Call(controller, "SetTenant", w.TenantA, Body(Ns + "QuorumValueRequest", ("Quorum", (int?)3)))));
        Assert.Null(w.Db.Tenants.Single(t => t.Id == w.TenantA).UserCeremonyRequiredApprovals);

        Assert.Equal(202, Status(await Call(controller, "SetCa", w.CaA1, Body(Ns + "QuorumValueRequest", ("Quorum", (int?)1)))));
        Assert.Null(w.Db.CertificateAuthorities.Single(c => c.Id == w.CaA1).UserCeremonyRequiredApprovals);

        Assert.Equal(2, policy.Calls.Count);
        Assert.True(policy.Calls[0].UserQuorumIncluded);
        Assert.Equal(3, policy.Calls[0].ProposedUserQuorum);
        Assert.Equal(w.TenantA, policy.Calls[1].TenantId);
        Assert.Equal(w.CaA1, Assert.Single(policy.Calls[1].Cas!).CaId);
    }

    [Fact]
    public async Task A_super_quorum_change_applies_directly()
    {
        var w = new ControlledUserWorld();
        var policy = new RecordingTenantPolicy();
        var controller = Quorum(w, w.Super, policy);

        Assert.Equal(200, Status(await Call(controller, "SetTenant", w.TenantA, Body(Ns + "QuorumValueRequest", ("Quorum", (int?)3)))));
        Assert.Equal(3, w.Db.Tenants.Single(t => t.Id == w.TenantA).UserCeremonyRequiredApprovals);
        Assert.Empty(policy.Calls);
    }
}
