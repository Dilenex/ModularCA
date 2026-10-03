using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
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
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Pins the fix for the account-takeover path that defeated the approval quorum: a lone non-super
/// admin could reset a peer approver's password and MFA, or re-enable, unlock or re-address the
/// account, then sign in as it and approve their own ceremonies. Each of those changes to an account
/// holding a controlled tier now opens a controlled-user ceremony; the temporary password exists
/// only in the execute response.
/// </summary>
public sealed class ControlledAccountTakeoverTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

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

    /// <summary>The controlled-user world plus real ceremony, user and audit services over it.</summary>
    private sealed class Harness
    {
        public ControlledUserWorld W { get; } = new();
        public RecordingAuditService Audit { get; } = new();

        /// <summary>Where the controllers write audit records: <see cref="Audit"/> unless a test swaps in a real service.</summary>
        public ModularCA.Shared.Interfaces.IAuditService AuditSink { get; set; }

        /// <summary>The audit trail the controlled-user service reads recent credential resets from.</summary>
        public AuditDbContext AuditDb { get; } = NewAuditDb();
        public RecordingAlertService Alerts { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public KeyCeremonyService Ceremonies { get; }
        public UserManagementService Users { get; }

        public Harness()
        {
            AuditSink = Audit;
            Ceremonies = new KeyCeremonyService(W.Db, Audit);
            Users = new UserManagementService(W.Db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!,
                new ControlledUserBypassGuardTests.AllowAllPasswords());
        }

        public ControlledUserCeremonyService Controlled(params Guid[] badgeGroups)
            => new(W.Db, Ceremonies, Users, NullLogger<ControlledUserCeremonyService>.Instance,
                badgeGroups.Length == 0 ? null : new FixedBadge(new AccessBadgeFilter(Guid.NewGuid(), "badge", badgeGroups, [], [])), AuditDb);

        /// <summary>Writes an audit record about account <paramref name="target"/> by <paramref name="actor"/>, as the controllers do.</summary>
        public void SeedAudit(string action, Guid target, Guid actor, object? details, DateTime at)
        {
            AuditDb.AuditLogs.Add(new AuditLogEntity
            {
                ActionType = action, ActorUserId = actor, ActorUsername = $"user-{actor:N}", TargetEntityType = "User",
                TargetEntityId = target.ToString(), DetailsJson = details == null ? null : JsonSerializer.Serialize(details),
                Timestamp = at, Success = true,
            });
            AuditDb.SaveChanges();
        }

        public string StepUp(Guid actor, string op, Guid target)
        {
            var token = Guid.NewGuid().ToString("N");
            Cache.SetString($"mfa-stepup:{actor}:{op}:{target}", token);
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

        public object UserManager(Guid actor, params Guid[] badgeGroups)
            => New(Ns + "Management.AdminUserManagerController", actor,
                W.Db, Users, new CurrentUserStub(actor), AuditSink, Cache, Alerts, null,
                Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Validation.Users.UpdateUserRequestValidator")),
                Controlled(badgeGroups));

        public object CeremonyController(Guid actor, params Guid[] badgeGroups)
            => New(Ns + "AdminKeyCeremonyController", actor,
                Ceremonies, new CurrentUserStub(actor), AuditSink, Cache, Alerts, null, W.Db,
                new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance), null, null, null,
                Controlled(badgeGroups));

        public Task<IActionResult> ResetPassword(Guid actor, Guid target, params Guid[] badge)
            => Call(UserManager(actor, badge), "ResetUserPassword", target, StepUp(actor, StepUpOps.ResetPassword, target));

        public Task<IActionResult> ResetMfa(Guid actor, Guid target, params Guid[] badge)
            => Call(UserManager(actor, badge), "ResetUserMfa", target, StepUp(actor, StepUpOps.ResetMfa, target));

        public Task<IActionResult> Update(Guid actor, Guid target, UpdateUserRequest request)
            => Call(UserManager(actor), "UpdateUser", target, request, StepUp(actor, StepUpOps.UpdateUser, target));

        public Task<IActionResult> AddToGroup(Guid actor, Guid target, Guid groupId)
            => Call(UserManager(actor), "AddUserToGroup", target, groupId, StepUp(actor, StepUpOps.AddGroupMember, target));

        public Task<IActionResult> Approve(Guid actor, Guid ceremonyId, params Guid[] badge)
            => Call(CeremonyController(actor, badge), "Approve", ceremonyId, StepUp(actor, StepUpOps.ApproveCeremony, ceremonyId));

        public Task<IActionResult> Execute(Guid actor, Guid ceremonyId)
            => Call(CeremonyController(actor), "Execute", ceremonyId, StepUp(actor, StepUpOps.ExecuteCeremony, ceremonyId));

        public UserEntity User(Guid id) => W.Db.Users.Single(u => u.Id == id);

        public KeyCeremonyEntity Ceremony(Guid id) => W.Db.KeyCeremonies.Single(c => c.Id == id);
    }

    private static AuditDbContext NewAuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase($"audit-{Guid.NewGuid():N}").Options);

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

    private static Guid CeremonyId(IActionResult result)
    {
        Assert.Equal(202, Status(result));
        Assert.Null(Prop(result, "newPassword"));
        return (Guid)Prop(result, "ceremonyId")!;
    }

    private static int Occurrences(string haystack, string needle)
    {
        var count = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
            count++;
        return count;
    }

    /// <summary>The password as it appears inside a JSON string written with default options.</summary>
    private static string Encoded(string password) => JsonSerializer.Serialize(password)[1..^1];

    [Fact]
    public async Task A_system_admin_can_no_longer_take_over_a_peer_system_admin()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        h.W.Db.TotpSecrets.Add(new TotpSecretEntity { UserId = b, IsVerified = true });
        h.User(b).PasswordHash = PasswordUtil.HashPassword("b-original-Passw0rd!");
        h.User(b).MfaEnrolledAt = DateTime.UtcNow;
        h.W.Db.SaveChanges();

        // Step 1 of the exploit, and step 2, now only open ceremonies: no password, nothing changed.
        var resetPassword = CeremonyId(await h.ResetPassword(a, b));
        var resetMfa = CeremonyId(await h.ResetMfa(a, b));
        Assert.True(PasswordUtil.VerifyPassword("b-original-Passw0rd!", h.User(b).PasswordHash));
        Assert.False(h.User(b).PasswordChangeOnNextLogon);
        Assert.True(h.W.Db.TotpSecrets.Any(t => t.UserId == b));
        Assert.NotNull(h.User(b).MfaEnrolledAt);

        // Re-addressing the account is gated the same way.
        var email = CeremonyId(await h.Update(a, b, new UpdateUserRequest { Email = "attacker@evil.example" }));
        CeremonyId(await h.Update(a, b, new UpdateUserRequest { Username = "bee" }));
        Assert.Equal("sysadmin-b", h.User(b).Username);
        Assert.Equal("sysadmin-b@x", h.User(b).Email);

        foreach (var id in new[] { resetPassword, resetMfa, email })
        {
            Assert.Equal(new ControlledTier(ControlledTierLevel.SystemAdmin, null), h.Controlled().DescribeCeremony(h.Ceremony(id)).Minted);
            Assert.Null(h.Ceremony(id).SpaceId);
        }

        // The initiator never counts, and the target may not approve its own takeover.
        Assert.Equal(400, Status(await h.Approve(a, resetPassword)));
        Assert.Equal(403, Status(await h.Approve(b, resetPassword)));
        Assert.Equal("Pending", h.Ceremony(resetPassword).Status);

        // A peer approves; the executor receives the temporary password exactly once.
        Assert.Equal(200, Status(await h.Approve(c, resetPassword)));
        Assert.Equal("Approved", h.Ceremony(resetPassword).Status);
        var executed = await h.Execute(a, resetPassword);
        Assert.Equal(200, Status(executed));
        var temporary = (string)Prop(executed, "temporaryPassword")!;
        Assert.False(string.IsNullOrEmpty(temporary));
        Assert.True(PasswordUtil.VerifyPassword(temporary, h.User(b).PasswordHash));
        Assert.True(h.User(b).PasswordChangeOnNextLogon);
        Assert.Equal(1, Occurrences(JsonSerializer.Serialize(((ObjectResult)executed).Value), Encoded(temporary)));

        var again = await h.Execute(a, resetPassword);
        Assert.Equal(409, Status(again));
        Assert.DoesNotContain(Encoded(temporary), JsonSerializer.Serialize(((ObjectResult)again).Value));

        // Neither the ceremony nor the audit trail holds it.
        var stored = h.Ceremony(resetPassword);
        Assert.DoesNotContain(temporary, stored.ParametersJson + stored.ApprovalsJson + stored.Description);
        Assert.All(h.Audit.Entries, e => Assert.DoesNotContain(Encoded(temporary), JsonSerializer.Serialize(e.Details)));
        Assert.Contains(h.Audit.Entries, e => e.Action == AuditActionType.UserPasswordReset && e.TargetId == b.ToString());
        Assert.Contains(h.Alerts.Raised, r => r.EventType == "AdminPasswordReset");

        // The approved MFA reset and email change apply at execute.
        Assert.Equal(200, Status(await h.Approve(c, resetMfa)));
        Assert.Equal(200, Status(await h.Execute(c, resetMfa)));
        Assert.False(h.W.Db.TotpSecrets.Any(t => t.UserId == b));
        Assert.Null(h.User(b).MfaEnrolledAt);
        Assert.Equal(200, Status(await h.Approve(c, email)));
        var emailExecuted = await h.Execute(a, email);
        Assert.Equal(200, Status(emailExecuted));
        Assert.Null(Prop(emailExecuted, "temporaryPassword"));
        Assert.Equal("attacker@evil.example", h.User(b).Email);
    }

    [Fact]
    public async Task Enabling_unlocking_disabling_and_locking_a_controlled_account_open_ceremonies()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var disabled = h.W.User("disabled-admin", h.W.SystemAdminGroup);
        var locked = h.W.User("locked-admin", h.W.SystemAdminGroup);
        var active = h.W.User("active-admin", h.W.SystemAdminGroup);
        h.User(disabled).IsActive = false;
        h.User(locked).IsLocked = true;
        h.W.Db.SaveChanges();

        CeremonyId(await h.Update(a, disabled, new UpdateUserRequest { IsActive = true }));
        CeremonyId(await h.Update(a, locked, new UpdateUserRequest { IsLocked = false }));
        CeremonyId(await h.Update(a, active, new UpdateUserRequest { IsActive = false }));
        CeremonyId(await h.Update(a, active, new UpdateUserRequest { IsLocked = true }));
        CeremonyId(await h.Update(a, active, new UpdateUserRequest { PasswordNeverExpires = true }));
        Assert.False(h.User(disabled).IsActive);
        Assert.True(h.User(locked).IsLocked);
        Assert.True(h.User(active).IsActive);
        Assert.False(h.User(active).IsLocked);
        Assert.False(h.User(active).PasswordNeverExpires);

        // A name change, or a value the account already has, is not identity-altering and applies directly.
        Assert.Equal(200, Status(await h.Update(a, active, new UpdateUserRequest { DisplayName = "Active Admin", IsActive = true, Email = "active-admin@x" })));
        Assert.Equal("Active Admin", h.User(active).DisplayName);

        // A password is never set through an update.
        Assert.Equal(400, Status(await h.Update(h.W.Super, active, new UpdateUserRequest { Password = "Chosen-Passw0rd!" })));
    }

    [Fact]
    public async Task Disabling_or_locking_the_last_other_dominator_is_refused()
    {
        var h = new Harness();
        h.User(h.W.Super).IsActive = false;
        h.W.Db.SaveChanges();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);

        Assert.Equal(400, Status(await h.Update(a, b, new UpdateUserRequest { IsActive = false })));
        Assert.Equal(400, Status(await h.Update(a, b, new UpdateUserRequest { IsLocked = true })));
        Assert.True(h.User(b).IsActive);
        Assert.False(h.User(b).IsLocked);
        Assert.Empty(h.W.Db.KeyCeremonies);

        // With a third admin left to approve, the same change opens a ceremony.
        h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        CeremonyId(await h.Update(a, b, new UpdateUserRequest { IsActive = false }));
    }

    [Fact]
    public async Task A_super_acts_directly_and_an_uncontrolled_or_own_account_is_direct()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);

        var bySuper = await h.ResetPassword(h.W.Super, b);
        Assert.Equal(200, Status(bySuper));
        Assert.True(PasswordUtil.VerifyPassword((string)Prop(bySuper, "newPassword")!, h.User(b).PasswordHash));
        Assert.Equal(200, Status(await h.ResetMfa(h.W.Super, b)));
        Assert.Equal(200, Status(await h.Update(h.W.Super, b, new UpdateUserRequest { Email = "b-new@x" })));
        Assert.Equal("b-new@x", h.User(b).Email);

        var plain = await h.ResetPassword(a, h.W.Plain);
        Assert.Equal(200, Status(plain));
        Assert.NotNull(Prop(plain, "newPassword"));
        Assert.Equal(200, Status(await h.ResetMfa(a, h.W.Plain)));
        Assert.Equal(200, Status(await h.Update(a, h.W.Plain, new UpdateUserRequest { Email = "plain-new@x", IsLocked = true })));
        Assert.True(h.User(h.W.Plain).IsLocked);

        Assert.Equal(200, Status(await h.ResetPassword(a, a)));
        Assert.Empty(h.W.Db.KeyCeremonies);
    }

    [Fact]
    public async Task A_target_whose_tier_rises_before_execute_expires_the_ceremony()
    {
        var h = new Harness();
        var target = h.W.User("sysop-target", h.W.SystemOperatorGroup);
        var originalHash = h.User(target).PasswordHash;
        var id = CeremonyId(await h.ResetPassword(h.W.SystemAdmin, target));
        Assert.Equal(new ControlledTier(ControlledTierLevel.SystemOperator, null), h.Controlled().DescribeCeremony(h.Ceremony(id)).Minted);
        Assert.Equal(200, Status(await h.Approve(h.W.Operator, id)));

        h.W.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = h.W.SystemAdminGroup.Id, UserId = target });
        h.W.Db.SaveChanges();

        var executed = await h.Execute(h.W.SystemAdmin, id);
        Assert.Equal(409, Status(executed));
        Assert.Null(Prop(executed, "temporaryPassword"));
        Assert.Equal("Expired", h.Ceremony(id).Status);
        Assert.Equal(originalHash, h.User(target).PasswordHash);
    }

    [Fact]
    public async Task Badges_narrow_the_initiator_and_the_approver()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup, h.W.A1Requester);
        h.W.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = h.W.A1Requester.Id, UserId = a });
        h.W.Db.SaveChanges();
        var requesterOnly = h.W.A1Requester.Id;

        Assert.Equal(403, Status(await h.ResetPassword(a, b, requesterOnly)));
        Assert.Equal(403, Status(await h.ResetMfa(a, b, requesterOnly)));
        Assert.Empty(h.W.Db.KeyCeremonies);

        var id = CeremonyId(await h.ResetPassword(a, b, h.W.SystemAdminGroup.Id));
        Assert.Equal(403, Status(await h.Approve(c, id, requesterOnly)));
        Assert.Equal("Pending", h.Ceremony(id).Status);
        Assert.Equal(200, Status(await h.Approve(c, id, h.W.SystemAdminGroup.Id)));
    }

    [Fact]
    public async Task Promote_then_seize_is_refused_at_the_direct_reset_and_at_execute()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");
        var group = h.W.A1Admin.Id;

        var id = CeremonyId(await h.AddToGroup(a, u, group));
        Assert.Equal(200, Status(await h.Approve(c, id)));
        Assert.Equal("Approved", h.Ceremony(id).Status);

        // The colleague is not yet controlled, but their credentials are frozen while the promotion is open.
        var stamp = h.User(u).SecurityStamp;
        foreach (var refused in new[]
                 {
                     await h.ResetPassword(a, u),
                     await h.ResetMfa(a, u),
                     await h.Update(a, u, new UpdateUserRequest { Email = "colleague-seized@x" }),
                 })
        {
            Assert.Equal(409, Status(refused));
            Assert.Contains("promotion of this user is pending", JsonSerializer.Serialize(((ObjectResult)refused).Value));
        }
        Assert.Equal(stamp, h.User(u).SecurityStamp);
        Assert.NotEqual("colleague-seized@x", h.User(u).Email);

        // Had the reset gone through by another route, execute still refuses the promotion.
        await h.Users.ResetUserPassword(u);
        var executed = await h.Execute(a, id);
        Assert.Equal(409, Status(executed));
        Assert.Equal("Expired", h.Ceremony(id).Status);
        Assert.False(h.W.Db.CaGroupMembers.Any(m => m.UserId == u && m.GroupId == group));

        // Nothing is pending any more, so the direct reset of the uncontrolled account applies again.
        Assert.Equal(200, Status(await h.ResetPassword(a, u)));
    }

    [Fact]
    public async Task A_promotion_expires_when_the_target_enrols_or_loses_mfa_and_applies_when_nothing_changed()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var enrolled = h.W.User("enrols-mfa");
        var reset = h.W.User("loses-mfa");
        var untouched = h.W.User("untouched");
        h.W.Db.TotpSecrets.Add(new TotpSecretEntity { UserId = reset, IsVerified = true });
        h.User(reset).MfaEnrolledAt = DateTime.UtcNow;
        h.W.Db.SaveChanges();

        var ids = new Dictionary<Guid, Guid>();
        foreach (var x in new[] { enrolled, reset, untouched })
        {
            ids[x] = CeremonyId(await h.AddToGroup(a, x, h.W.A1Admin.Id));
            Assert.Equal(200, Status(await h.Approve(c, ids[x])));
        }

        // Self-service enrolment does not rotate the stamp; the MFA marker still catches it.
        var stamp = h.User(enrolled).SecurityStamp;
        h.W.Db.TotpSecrets.Add(new TotpSecretEntity { UserId = enrolled, IsVerified = true });
        h.User(enrolled).MfaEnrolledAt = DateTime.UtcNow;
        h.W.Db.SaveChanges();
        Assert.Equal(stamp, h.User(enrolled).SecurityStamp);
        // A super is not held back by the pending promotion; the reset still expires it.
        Assert.Equal(200, Status(await h.ResetMfa(h.W.Super, reset)));

        Assert.Equal(409, Status(await h.Execute(a, ids[enrolled])));
        Assert.Equal(409, Status(await h.Execute(a, ids[reset])));
        Assert.Equal(200, Status(await h.Execute(a, ids[untouched])));
        Assert.True(h.W.Db.CaGroupMembers.Any(m => m.UserId == untouched && m.GroupId == h.W.A1Admin.Id));
        Assert.False(h.W.Db.CaGroupMembers.Any(m => m.UserId == enrolled && m.GroupId == h.W.A1Admin.Id));
    }

    [Fact]
    public async Task Every_admin_credential_reset_and_identity_change_rotates_the_stamp()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var u = h.W.Plain;
        foreach (var change in new Func<Task<IActionResult>>[]
                 {
                     () => h.ResetPassword(a, u),
                     () => h.ResetMfa(a, u),
                     () => h.Update(a, u, new UpdateUserRequest { Email = "plain-2@x" }),
                     () => h.Update(a, u, new UpdateUserRequest { Username = "plain-2" }),
                 })
        {
            var before = h.User(u).SecurityStamp;
            Assert.Equal(200, Status(await change()));
            Assert.NotEqual(before, h.User(u).SecurityStamp);
        }
    }

    [Fact]
    public async Task An_approved_identity_change_expires_when_the_account_changed_meanwhile()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);

        var id = CeremonyId(await h.Update(a, b, new UpdateUserRequest { Email = "b-new@x" }));
        Assert.Equal(200, Status(await h.Approve(c, id)));

        // During an incident a super disables the account; the approved change must not proceed.
        Assert.Equal(200, Status(await h.Update(h.W.Super, b, new UpdateUserRequest { IsActive = false })));
        var executed = await h.Execute(a, id);
        Assert.Equal(409, Status(executed));
        Assert.Equal("Expired", h.Ceremony(id).Status);
        Assert.Equal("sysadmin-b@x", h.User(b).Email);
        Assert.False(h.User(b).IsActive);
    }

    [Fact]
    public async Task An_empty_username_or_email_is_refused_on_the_direct_and_the_ceremony_paths()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);
        foreach (var target in new[] { h.W.Plain, b })
            foreach (var request in new[]
                     {
                         new UpdateUserRequest { Username = "" },
                         new UpdateUserRequest { Username = "   " },
                         new UpdateUserRequest { Email = "" },
                         new UpdateUserRequest { Email = " " },
                     })
                Assert.Equal(400, Status(await h.Update(a, target, request)));
        Assert.Empty(h.W.Db.KeyCeremonies);
        Assert.Equal("plain", h.User(h.W.Plain).Username);
        Assert.False(string.IsNullOrWhiteSpace(h.User(h.W.Plain).Email));

        // The service never writes one either.
        Assert.True(await h.Users.UpdateUser(h.W.Plain, new UpdateUserRequest { Username = " ", Email = "", DisplayName = "Plain" }));
        Assert.Equal("plain", h.User(h.W.Plain).Username);
        Assert.False(string.IsNullOrWhiteSpace(h.User(h.W.Plain).Email));
    }

    [Fact]
    public void The_change_results_text_form_never_holds_the_temporary_password()
    {
        var result = new ModularCA.Shared.Models.ControlledUserChangeResult("ResetPassword", Guid.NewGuid(), null, null, null)
        {
            TemporaryPassword = "Temporary-Passw0rd-7f3a",
        };
        Assert.DoesNotContain("Temporary-Passw0rd-7f3a", result.ToString());
        Assert.Contains("ResetPassword", result.ToString());
        Assert.Contains(result.TargetUserId.ToString(), result.ToString());
    }

    [Fact]
    public async Task Unlocking_clears_the_failed_login_count_on_both_paths()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var b = h.W.User("sysadmin-b", h.W.SystemAdminGroup);
        var tempLocked = h.W.User("temp-locked");
        foreach (var x in new[] { h.W.Plain, b })
        {
            h.User(x).IsLocked = true;
            h.User(x).FailedLoginAttempts = 5;
        }
        h.User(tempLocked).FailedLoginAttempts = 5;
        h.User(tempLocked).LockoutEndUtc = DateTime.UtcNow.AddMinutes(30);
        h.W.Db.SaveChanges();

        Assert.Equal(200, Status(await h.Update(a, h.W.Plain, new UpdateUserRequest { IsLocked = false })));
        Assert.Equal(200, Status(await h.Update(a, tempLocked, new UpdateUserRequest { IsLocked = false })));
        var id = CeremonyId(await h.Update(a, b, new UpdateUserRequest { IsLocked = false }));
        Assert.Equal(5, h.User(b).FailedLoginAttempts);
        Assert.Equal(200, Status(await h.Approve(c, id)));
        Assert.Equal(200, Status(await h.Execute(a, id)));

        foreach (var x in new[] { h.W.Plain, tempLocked, b })
        {
            Assert.False(h.User(x).IsLocked);
            Assert.Equal(0, h.User(x).FailedLoginAttempts);
            Assert.Null(h.User(x).LockoutEndUtc);
        }
    }

    [Fact]
    public async Task The_host_local_unlock_command_recovers_a_hard_locked_super()
    {
        var h = new Harness();
        var super = h.User(h.W.Super);
        super.IsLocked = true;
        super.FailedLoginAttempts = 9;
        var stamp = super.SecurityStamp;
        h.W.Db.SaveChanges();

        var unlock = ApiAssembly.TypeNamed("ModularCA.API.Startup.UnlockUserCommand").GetMethod("RunAsync")!;
        var output = new StringWriter();
        Assert.Equal(0, await (Task<int>)unlock.Invoke(null, [h.W.Db, h.AuditDb, super.Username, output])!);
        Assert.False(h.User(h.W.Super).IsLocked);
        Assert.Equal(0, h.User(h.W.Super).FailedLoginAttempts);
        Assert.NotEqual(stamp, h.User(h.W.Super).SecurityStamp);
        Assert.Equal(1, await (Task<int>)unlock.Invoke(null, [h.W.Db, h.AuditDb, "no-such-user", output])!);

        // The unlock is in the hash-chained audit trail, by the host rather than any account.
        var record = Assert.Single(h.AuditDb.AuditLogs.Where(a => a.ActionType == AuditActionType.UserUnlockedOnHost));
        Assert.Equal("host:break-glass", record.ActorUsername);
        Assert.Null(record.ActorUserId);
        Assert.Equal(("User", h.W.Super.ToString()), (record.TargetEntityType, record.TargetEntityId));
        Assert.False(string.IsNullOrEmpty(record.RecordHash));
        Assert.DoesNotContain("NO AUDIT RECORD", output.ToString());
    }

    [Fact]
    public async Task The_host_local_unlock_still_unlocks_but_warns_loudly_when_the_audit_trail_is_unreachable()
    {
        var h = new Harness();
        var unlock = ApiAssembly.TypeNamed("ModularCA.API.Startup.UnlockUserCommand").GetMethod("RunAsync")!;
        var unreachable = NewAuditDb();
        unreachable.Dispose();
        foreach (var audit in new[] { unreachable, null })
        {
            h.User(h.W.Super).IsLocked = true;
            h.W.Db.SaveChanges();
            var output = new StringWriter();
            Assert.Equal(0, await (Task<int>)unlock.Invoke(null, [h.W.Db, audit, h.User(h.W.Super).Username, output])!);
            Assert.False(h.User(h.W.Super).IsLocked);
            Assert.Contains("WARNING: NO AUDIT RECORD WAS WRITTEN FOR THIS UNLOCK", output.ToString());
        }
    }

    [Fact]
    public async Task A_promotion_discloses_recent_credential_resets_of_its_target_by_anyone()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var e = h.W.User("sysadmin-e", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");
        var mfaAt = DateTime.UtcNow.AddDays(-5);
        var passwordAt = DateTime.UtcNow.AddDays(-2);
        h.SeedAudit(AuditActionType.UserUpdated, u, c, new { Action = "MfaReset" }, mfaAt);
        // A ceremony-executed reset writes two records; it is disclosed once.
        h.SeedAudit(AuditActionType.UserPasswordReset, u, e, new { CeremonyId = Guid.NewGuid() }, passwordAt);
        h.SeedAudit(AuditActionType.ControlledUserChangeApplied, u, e, new { ChangeType = "ResetPassword" }, passwordAt);
        // Not disclosed: outside the window, not a reset, another account.
        h.SeedAudit(AuditActionType.UserPasswordReset, u, c, null, DateTime.UtcNow.AddDays(-31));
        h.SeedAudit(AuditActionType.UserUpdated, u, c, new { Action = "UpdateIdentity" }, mfaAt);
        h.SeedAudit(AuditActionType.UserPasswordReset, h.W.Plain, c, null, mfaAt);

        var ceremony = h.Ceremony(CeremonyId(await h.AddToGroup(a, u, h.W.A1Admin.Id)));
        var lines = ceremony.Description.Split('\n');
        Assert.Equal(3, lines.Length);
        Assert.Equal($"WARNING: colleague's password was reset by user-{e:N} on {passwordAt:yyyy-MM-dd}", lines[0]);
        Assert.Equal($"WARNING: colleague's MFA was reset by user-{c:N} on {mfaAt:yyyy-MM-dd}", lines[1]);
        Assert.StartsWith("Promote controlled user colleague", lines[2]);

        var p = JsonSerializer.Deserialize<ControlledUserChangeParameters>(ceremony.ParametersJson)!;
        Assert.False(p.RecentResetsUnchecked);
        Assert.Equal(new[] { (ControlledCredentialReset.Password, (Guid?)e), (ControlledCredentialReset.Mfa, (Guid?)c) },
            p.RecentCredentialResets!.Select(r => (r.What, r.ActorUserId)).ToArray());
    }

    [Fact]
    public async Task The_admin_who_reset_a_users_credentials_cannot_open_their_promotion()
    {
        var h = new Harness();
        h.AuditSink = new AuditService(NullLogger<AuditService>.Instance, h.AuditDb, hashChain: new AuditHashChainService());
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");

        // The colleague holds no tier, so the reset is direct; it lands in the audit trail.
        Assert.Equal(200, Status(await h.ResetPassword(a, u)));
        var refused = await h.AddToGroup(a, u, h.W.A1Admin.Id);
        Assert.Equal(409, Status(refused));
        Assert.Equal($"You reset this user's credentials on {DateTime.UtcNow:yyyy-MM-dd}; another administrator must open the promotion.",
            (string)Prop(refused, "error")!);
        Assert.Empty(h.W.Db.KeyCeremonies);

        // Another administrator may open it, and its approvers see who reset the password.
        var ceremony = h.Ceremony(CeremonyId(await h.AddToGroup(c, u, h.W.A1Admin.Id)));
        Assert.StartsWith($"WARNING: colleague's password was reset by user-{a:N} on {DateTime.UtcNow:yyyy-MM-dd}\n", ceremony.Description);

        // A super who reset an account may still open its promotion; it is disclosed all the same.
        var v = h.W.User("other-colleague");
        Assert.Equal(200, Status(await h.ResetMfa(h.W.Super, v)));
        var minted = (await h.Controlled().ClassifyGroupAsync(h.W.A1Admin))!.Value;
        var bySuper = await h.Controlled().InitiateChangeAsync(
            new ControlledUserChangeParameters { ChangeType = "AddGroupMember", TargetUserId = v, TargetUsername = "other-colleague", GroupId = h.W.A1Admin.Id },
            minted, h.W.Super, "super");
        Assert.StartsWith($"WARNING: other-colleague's MFA was reset by user-{h.W.Super:N}", h.Ceremony(bySuper).Description);
    }

    [Fact]
    public async Task A_promotion_discloses_that_recent_resets_could_not_be_checked_when_the_audit_trail_is_unreachable()
    {
        var h = new Harness();
        h.AuditDb.Dispose();
        var ceremony = h.Ceremony(CeremonyId(await h.AddToGroup(h.W.SystemAdmin, h.W.User("colleague"), h.W.A1Admin.Id)));
        Assert.StartsWith("WARNING: could not check recent resets\nPromote controlled user colleague", ceremony.Description);
        var p = JsonSerializer.Deserialize<ControlledUserChangeParameters>(ceremony.ParametersJson)!;
        Assert.True(p.RecentResetsUnchecked);
        Assert.Null(p.RecentCredentialResets);
    }

    [Fact]
    public async Task A_promotion_discloses_a_password_an_administrator_set_when_the_audit_record_of_the_reset_was_lost()
    {
        var h = new Harness();
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");

        // The reset applies, but its audit write never reaches the audit trail.
        Assert.Equal(200, Status(await h.ResetPassword(a, u)));
        Assert.Empty(h.AuditDb.AuditLogs);
        var lines = h.Ceremony(CeremonyId(await h.AddToGroup(c, u, h.W.A1Admin.Id))).Description.Split('\n');
        Assert.Equal(2, lines.Length);
        Assert.Equal("WARNING: colleague's password was set by an administrator and has not been changed since", lines[0]);
        Assert.StartsWith("Promote controlled user colleague", lines[1]);

        // Once the user chose a password of their own, there is nothing to disclose.
        var v = h.W.User("other-colleague");
        Assert.DoesNotContain("WARNING", h.Ceremony(CeremonyId(await h.AddToGroup(c, v, h.W.A1Admin.Id))).Description);

        // Where the audit trail names the reset, that line alone discloses it.
        var w = h.W.User("third-colleague");
        h.User(w).PasswordChangeOnNextLogon = true;
        h.W.Db.SaveChanges();
        h.SeedAudit(AuditActionType.UserPasswordReset, w, a, null, DateTime.UtcNow.AddDays(-1));
        lines = h.Ceremony(CeremonyId(await h.AddToGroup(c, w, h.W.A1Admin.Id))).Description.Split('\n');
        Assert.Equal(2, lines.Length);
        Assert.StartsWith("WARNING: third-colleague's password was reset by", lines[0]);

        // With the audit trail unreachable, both warnings show.
        h.AuditDb.Dispose();
        var x = h.W.User("fourth-colleague");
        h.User(x).PasswordChangeOnNextLogon = true;
        h.W.Db.SaveChanges();
        Assert.StartsWith("WARNING: could not check recent resets\nWARNING: fourth-colleague's password was set by an administrator and has not been changed since\nPromote",
            h.Ceremony(CeremonyId(await h.AddToGroup(c, x, h.W.A1Admin.Id))).Description);
    }

    [Fact]
    public async Task The_admin_who_reset_a_users_credentials_cannot_approve_their_promotion()
    {
        var h = new Harness();
        h.AuditSink = new AuditService(NullLogger<AuditService>.Instance, h.AuditDb, hashChain: new AuditHashChainService());
        var a = h.W.SystemAdmin;
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var d = h.W.User("sysadmin-d", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");

        Assert.Equal(200, Status(await h.ResetMfa(a, u)));
        var id = CeremonyId(await h.AddToGroup(c, u, h.W.A1Admin.Id));

        var reason = $"You reset colleague's credentials on {DateTime.UtcNow:yyyy-MM-dd}; another administrator must approve this promotion.";
        var refused = await h.Approve(a, id);
        Assert.Equal(403, Status(refused));
        Assert.Equal(reason, (string)Prop(refused, "error")!);
        Assert.Equal("Pending", h.Ceremony(id).Status);
        Assert.False(await h.Controlled().CanApproveAsync(a, h.Ceremony(id)));

        // The resetter still sees the ceremony, and why they cannot approve it.
        Assert.True(await h.Controlled().HoldsApprovingTierAsync(a, h.Ceremony(id)));
        var detail = await Call(h.CeremonyController(a), "GetById", id);
        Assert.Equal(false, Prop(detail, "CanApprove"));
        Assert.Equal(reason, Prop(detail, "ApprovalRefusal"));
        Assert.Null(Prop(await Call(h.CeremonyController(d), "GetById", id), "ApprovalRefusal"));

        Assert.Equal(200, Status(await h.Approve(d, id)));
        Assert.Equal(200, Status(await h.Execute(c, id)));
        Assert.True(h.W.Db.CaGroupMembers.Any(m => m.UserId == u && m.GroupId == h.W.A1Admin.Id));
    }

    [Fact]
    public async Task An_approval_by_an_admin_found_at_execute_to_have_reset_the_users_credentials_no_longer_counts()
    {
        var h = new Harness();
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var d = h.W.User("sysadmin-d", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");

        var id = CeremonyId(await h.AddToGroup(c, u, h.W.A1Admin.Id));
        Assert.Equal(200, Status(await h.Approve(d, id)));
        Assert.Equal("Approved", h.Ceremony(id).Status);

        // The audit record of d's earlier MFA reset of the colleague is readable only now.
        h.SeedAudit(AuditActionType.UserUpdated, u, d, new { Action = "MfaReset" }, DateTime.UtcNow.AddDays(-3));
        var executed = await h.Execute(c, id);
        Assert.Equal(409, Status(executed));
        Assert.Contains("did not reset the credentials of a user it promotes", (string)Prop(executed, "error")!);
        Assert.Equal("Expired", h.Ceremony(id).Status);
        Assert.False(h.W.Db.CaGroupMembers.Any(m => m.UserId == u && m.GroupId == h.W.A1Admin.Id));
    }

    [Fact]
    public async Task With_the_audit_trail_unreachable_at_execute_the_resets_recorded_at_initiation_still_bar_an_approval()
    {
        var h = new Harness();
        var c = h.W.User("sysadmin-c", h.W.SystemAdminGroup);
        var d = h.W.User("sysadmin-d", h.W.SystemAdminGroup);
        var u = h.W.User("colleague");
        h.SeedAudit(AuditActionType.UserPasswordReset, u, d, null, DateTime.UtcNow.AddDays(-2));

        var id = CeremonyId(await h.AddToGroup(c, u, h.W.A1Admin.Id));
        Assert.Equal(403, Status(await h.Approve(d, id)));
        // An approval recorded by another route, as before this check existed.
        await h.Ceremonies.ApproveAsync(id, d, "sysadmin-d");
        Assert.Equal("Approved", h.Ceremony(id).Status);

        h.AuditDb.Dispose();
        Assert.Equal(409, Status(await h.Execute(c, id)));
        Assert.Equal("Expired", h.Ceremony(id).Status);
        Assert.False(h.W.Db.CaGroupMembers.Any(m => m.UserId == u && m.GroupId == h.W.A1Admin.Id));
    }

    public static TheoryData<string> DominatedApprovers => new() { "SysOp", "SpaceAdmin", "SpaceOperator", "CaAdmin" };

    [Theory]
    [MemberData(nameof(DominatedApprovers))]
    public async Task A_system_admin_seizing_a_strictly_dominated_approver_goes_through_a_ceremony(string kind)
    {
        var h = new Harness();
        Guid target;
        ControlledTier expected;
        switch (kind)
        {
            case "SysOp":
                target = h.W.User("sysop", h.W.SystemOperatorGroup);
                expected = new ControlledTier(ControlledTierLevel.SystemOperator, null);
                break;
            case "SpaceAdmin":
                target = h.W.User("org-admin", h.W.SpaceAdminA);
                expected = new ControlledTier(ControlledTierLevel.SpaceAdmin, null) { SpaceId = h.W.SpaceA };
                break;
            case "SpaceOperator":
                target = h.W.User("org-operator");
                h.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = target, Capability = Capabilities.CaManage, SpaceId = h.W.SpaceA });
                h.W.Db.SaveChanges();
                expected = new ControlledTier(ControlledTierLevel.SpaceOperator, null) { SpaceId = h.W.SpaceA };
                break;
            default:
                target = h.W.User("ca-admin", h.W.A1Admin);
                expected = new ControlledTier(ControlledTierLevel.CaAdmin, h.W.CaA1) { SpaceId = h.W.SpaceA };
                break;
        }
        var hash = h.User(target).PasswordHash;

        var ids = new[]
        {
            CeremonyId(await h.ResetPassword(h.W.SystemAdmin, target)),
            CeremonyId(await h.ResetMfa(h.W.SystemAdmin, target)),
            CeremonyId(await h.Update(h.W.SystemAdmin, target, new UpdateUserRequest { Email = $"{kind}-seized@x" })),
        };
        foreach (var id in ids)
            Assert.Equal(expected, h.Controlled().DescribeCeremony(h.Ceremony(id)).Minted);
        Assert.Equal(hash, h.User(target).PasswordHash);
        Assert.NotEqual($"{kind}-seized@x", h.User(target).Email);

        var detail = await Call(h.CeremonyController(h.W.SystemAdmin), "GetById", ids[0]);
        var scope = (string)Prop(detail, "TierScope")!;
        Assert.Equal(kind switch { "SysOp" => "instance", "CaAdmin" => "on CA a1", _ => "in space A" }, scope);
    }
}
