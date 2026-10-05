using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// An install as setup leaves it: one administrator, in system-super, with the first space, its
/// space-wide groups and one CA. Tests add the accounts they need.
/// </summary>
internal sealed class SingleAdminWorld
{
    public ModularCADbContext Db { get; }
    public Guid Space { get; } = Guid.NewGuid();
    public Guid OtherSpace { get; } = Guid.NewGuid();
    public Guid Ca { get; } = Guid.NewGuid();
    public Guid CaCertificate { get; } = Guid.NewGuid();

    public CaGroupEntity SuperGroup { get; }
    public CaGroupEntity SystemAdminGroup { get; }
    public CaGroupEntity SystemOperatorGroup { get; }
    public CaGroupEntity SystemAuditorGroup { get; }
    public CaGroupEntity SpaceAdminGroup { get; }
    public CaGroupEntity SpaceOperatorGroup { get; }
    public CaGroupEntity OtherSpaceOperatorGroup { get; }
    public CaGroupEntity CaAdminGroup { get; }

    /// <summary>The lone administrator.</summary>
    public Guid Admin { get; }

    public SingleAdminWorld(bool requireCeremony = true, int quorum = 1)
    {
        Db = InMemoryDbContextFactory.Create();
        Db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = requireCeremony, CeremonyRequiredApprovals = quorum });
        Db.Spaces.AddRange(
            new SpaceEntity { Id = Space, Name = "First", Slug = "first", RequireKeyCeremony = requireCeremony, CeremonyRequiredApprovals = quorum },
            new SpaceEntity { Id = OtherSpace, Name = "Other", Slug = "other", RequireKeyCeremony = requireCeremony, CeremonyRequiredApprovals = quorum });
        Db.Certificates.Add(new CertificateEntity
        {
            CertificateId = CaCertificate, SerialNumber = "01", SubjectDN = "CN=Root", Issuer = "CN=Root", Pem = "x", IsCA = true,
            NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddYears(5),
        });
        Db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = Ca, Name = "Root", Label = "root", SpaceId = Space, IsEnabled = true, CertificateId = CaCertificate });

        SuperGroup = Group("system-super", null, null, Capabilities.AdministratorTemplate, system: true, super: true);
        SystemAdminGroup = Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true);
        SystemOperatorGroup = Group("system-operator", null, null, Capabilities.OperatorTemplate, system: true);
        SystemAuditorGroup = Group("system-auditor", null, null, Capabilities.AuditorTemplate, system: true);
        SpaceAdminGroup = Group("space-first-admin", Space, null, Capabilities.AdministratorTemplate);
        SpaceOperatorGroup = Group("space-first-operator", Space, null, Capabilities.OperatorTemplate);
        OtherSpaceOperatorGroup = Group("space-other-operator", OtherSpace, null, Capabilities.OperatorTemplate);
        CaAdminGroup = Group("first_root_admin", Space, Ca, Capabilities.AdministratorTemplate);

        Admin = User("superadmin", SuperGroup);
    }

    public CaGroupEntity Group(string name, Guid? spaceId, Guid? caId, string[] capabilities, bool system = false, bool super = false)
    {
        var g = new CaGroupEntity
        {
            Id = Guid.NewGuid(), Name = name, DisplayName = name, SpaceId = spaceId, CertificateAuthorityId = caId,
            IsSystemGroup = system, IsSystemTierSuper = super,
        };
        Db.CaGroups.Add(g);
        foreach (var c in capabilities)
            Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = g.Id, Capability = c });
        Db.SaveChanges();
        return g;
    }

    public Guid User(string username, params CaGroupEntity[] groups) => User(username, null, groups);

    public Guid User(string username, Action<UserEntity>? configure, params CaGroupEntity[] groups)
    {
        var user = new UserEntity { Id = Guid.NewGuid(), Username = username, Email = $"{username}@example.test" };
        configure?.Invoke(user);
        Db.Users.Add(user);
        foreach (var g in groups)
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = g.Id, UserId = user.Id });
        Db.SaveChanges();
        return user.Id;
    }

    public RoleEntity Role(params string[] capabilities)
    {
        var role = new RoleEntity { Name = $"role-{Guid.NewGuid():N}" };
        Db.Roles.Add(role);
        foreach (var c in capabilities)
            Db.RoleCapabilities.Add(new RoleCapabilityEntity { RoleId = role.Id, Capability = c });
        Db.SaveChanges();
        return role;
    }

    /// <summary>Stored parameters naming <paramref name="spaceId"/>, or the instance for null.</summary>
    public static string Parameters(Guid? spaceId) => JsonSerializer.Serialize(new { SpaceId = spaceId });
}

/// <summary>
/// A ceremony that could never reach its quorum is refused when it is opened, by the one check in
/// <see cref="KeyCeremonyService.InitiateAsync"/>: too few accounts other than the initiator can
/// approve it. Who can approve follows the approve endpoint's rules.
/// </summary>
public class CeremonyQuorumGuardTests
{
    /// <summary>Every operation type <see cref="KeyCeremonyService.InitiateAsync"/> is called with, and whether it is opened in a space.</summary>
    public static TheoryData<string, bool> Operations() => new()
    {
        { "CreateRootCA", true }, { "CreateRootCA", false },
        { "CreateIntermediateCA", true }, { "CreateIntermediateCA", false },
        { "CreateSshCa", false }, { "DeleteSshCa", false },
        { "RevokeCa", true }, { "RevokeCa", false },
        { nameof(CeremonyType.SpacePolicyChange), true },
        { nameof(CeremonyType.InstancePolicyChange), false },
    };

    private static Task<KeyCeremonyEntity> Open(SingleAdminWorld w, RecordingAuditService audit, string operation, Guid? spaceId, Guid initiator)
        => new KeyCeremonyService(w.Db, audit).InitiateAsync(operation, "test", string.Empty, initiator, "initiator", SingleAdminWorld.Parameters(spaceId));

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task A_lone_administrator_is_refused_and_nothing_is_opened(string operation, bool inSpace)
    {
        var w = new SingleAdminWorld();
        var audit = new RecordingAuditService();
        Guid? spaceId = inSpace ? w.Space : null;

        var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => Open(w, audit, operation, spaceId, w.Admin));

        Assert.Equal(409, ex.Status);
        Assert.Equal(ErrorCodes.CeremonyNoApprover, ex.Code);
        Assert.StartsWith("You're the only administrator who can approve this", ex.Message);
        Assert.Equal(operation, ex.OperationType);
        Assert.Equal(1, ex.RequiredApprovals);
        Assert.Equal(0, ex.EligibleApprovers);
        if (CeremonyQuorumGuard.IsGovernedByRequirement(operation))
        {
            Assert.Equal(inSpace ? CeremonyQuorumUnreachableException.SpaceScope : CeremonyQuorumUnreachableException.InstanceScope, ex.RequirementScope);
            Assert.Equal(spaceId, ex.SpaceId);
            Assert.Equal(inSpace ? "First" : null, ex.SpaceName);
        }
        else
        {
            Assert.Null(ex.RequirementScope);
            Assert.Null(ex.SpaceId);
        }
        Assert.Empty(w.Db.KeyCeremonies);
        Assert.Empty(audit.Entries);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task A_second_administrator_lets_it_open(string operation, bool inSpace)
    {
        var w = new SingleAdminWorld();
        w.User("second", w.SystemAdminGroup);

        var ceremony = await Open(w, new RecordingAuditService(), operation, inSpace ? w.Space : null, w.Admin);

        Assert.Equal("Pending", ceremony.Status);
        Assert.Equal(1, ceremony.RequiredApprovals);
        Assert.Single(w.Db.KeyCeremonies);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    [InlineData("service")]
    [InlineData("deleted")]
    public async Task An_account_that_cannot_act_is_not_an_approver(string state)
    {
        var w = new SingleAdminWorld();
        w.User("second", u =>
        {
            switch (state)
            {
                case "disabled": u.IsActive = false; break;
                case "locked": u.IsLocked = true; break;
                case "service": u.IsServiceIdentity = true; break;
                case "deleted": u.IsDeleted = true; break;
            }
        }, w.SystemAdminGroup);

        foreach (var operation in new[] { "CreateIntermediateCA", nameof(CeremonyType.SpacePolicyChange) })
        {
            var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(
                () => Open(w, new RecordingAuditService(), operation, w.Space, w.Admin));
            Assert.Equal(ErrorCodes.CeremonyNoApprover, ex.Code);
        }
        Assert.Empty(w.Db.KeyCeremonies);
    }

    [Fact]
    public async Task A_quorum_above_the_eligible_count_is_refused_with_both_numbers()
    {
        var w = new SingleAdminWorld(quorum: 2);
        w.User("second", w.SystemAdminGroup);

        var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(
            () => Open(w, new RecordingAuditService(), "CreateIntermediateCA", w.Space, w.Admin));
        Assert.Equal(ErrorCodes.CeremonyQuorumUnreachable, ex.Code);
        Assert.StartsWith("This needs 2 approvals and only 1 other administrator can approve", ex.Message);
        Assert.Equal(2, ex.RequiredApprovals);
        Assert.Equal(1, ex.EligibleApprovers);
        Assert.Empty(w.Db.KeyCeremonies);

        w.User("third", w.SpaceOperatorGroup);
        var ceremony = await Open(w, new RecordingAuditService(), "CreateIntermediateCA", w.Space, w.Admin);
        Assert.Equal(2, ceremony.RequiredApprovals);
    }

    /// <summary>
    /// A CA ceremony is approved by <c>system.manage</c> or <c>ca.manage</c> at system scope, or
    /// <c>ca.manage</c> space-wide in its space; a policy change by a system administrator, or a
    /// space administrator who also holds <c>ca.manage</c> for the space.
    /// </summary>
    [Fact]
    public async Task Who_can_approve_follows_the_ceremony_kind_and_scope()
    {
        var w = new SingleAdminWorld();
        var systemAdmin = w.User("system-admin", w.SystemAdminGroup);
        var systemOperator = w.User("system-operator", w.SystemOperatorGroup);
        w.User("system-auditor", w.SystemAuditorGroup);
        var spaceAdmin = w.User("space-admin", w.SpaceAdminGroup);
        var spaceOperator = w.User("space-operator", w.SpaceOperatorGroup);
        w.User("other-space-operator", w.OtherSpaceOperatorGroup);
        w.User("ca-admin", w.CaAdminGroup);
        // system.manage space-wide without ca.manage: not enough for a policy change either.
        var bareSpaceAdmin = w.User("bare-space-admin", w.Group("space-first-policy", w.Space, null, [Capabilities.SystemManage]));
        var guard = new CeremonyQuorumGuard(w.Db);

        async Task<Guid[]> Eligible(string operation, Guid? spaceId)
            => (await guard.EligibleApproversAsync(operation, spaceId, null, w.Admin)).Order().ToArray();
        Guid[] Set(params Guid[] ids) => ids.Order().ToArray();

        Assert.Equal(Set(systemAdmin, systemOperator, spaceAdmin, spaceOperator), await Eligible("CreateIntermediateCA", w.Space));
        Assert.Equal(Set(systemAdmin, systemOperator), await Eligible("RevokeCa", null));
        Assert.Equal(Set(systemAdmin, systemOperator), await Eligible("CreateSshCa", null));
        Assert.Equal(Set(systemAdmin, spaceAdmin), await Eligible(nameof(CeremonyType.SpacePolicyChange), w.Space));
        Assert.Equal(Set(systemAdmin), await Eligible(nameof(CeremonyType.InstancePolicyChange), null));
        Assert.DoesNotContain(bareSpaceAdmin, await Eligible(nameof(CeremonyType.SpacePolicyChange), w.Space));

        // The initiator never counts, even when eligible.
        Assert.DoesNotContain(systemAdmin, await guard.EligibleApproversAsync("CreateIntermediateCA", w.Space, null, systemAdmin));
    }

    /// <summary>
    /// The guard reads holdings; the approve endpoint asks <see cref="CaGroupAuthorizationService"/>.
    /// Across every grant source (group grant, role on a group, grant on the user, role on the user)
    /// at system, space and CA scope, both give the same answer.
    /// </summary>
    [Fact]
    public async Task The_guard_agrees_with_the_authorization_service_for_every_grant_source()
    {
        var w = new SingleAdminWorld();
        foreach (var capability in new[] { Capabilities.CaManage, Capabilities.SystemManage })
        {
            var role = w.Role(capability);
            foreach (var (scope, spaceId, caId) in new (string, Guid?, Guid?)[] { ("system", null, null), ("space", w.Space, null), ("other", w.OtherSpace, null), ("ca", w.Space, w.Ca) })
            {
                var tag = $"{capability}-{scope}";
                w.User($"group-grant-{tag}", w.Group($"g-grant-{tag}", spaceId, caId, [capability], system: scope == "system"));

                var roleGroup = w.Group($"g-role-{tag}", spaceId, caId, [], system: scope == "system");
                w.Db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = role.Id, GroupId = roleGroup.Id });
                w.User($"group-role-{tag}", roleGroup);

                var granted = w.User($"user-grant-{tag}");
                w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = granted, Capability = capability, SpaceId = caId == null ? spaceId : null, CertificateAuthorityId = caId });

                var assigned = w.User($"user-role-{tag}");
                w.Db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = role.Id, UserId = assigned, SpaceId = caId == null ? spaceId : null, CertificateAuthorityId = caId });
            }
        }
        // A non-system group with neither space nor CA confers nothing.
        w.User("orphan-group", w.Group("orphan", null, null, [Capabilities.CaManage, Capabilities.SystemManage]));
        w.Db.SaveChanges();

        var auth = new CaGroupAuthorizationService(w.Db, NullLogger<CaGroupAuthorizationService>.Instance);
        var guard = new CeremonyQuorumGuard(w.Db);
        var users = await w.Db.Users.AsNoTracking().Select(u => u.Id).ToListAsync();

        foreach (var spaceId in new Guid?[] { null, w.Space, w.OtherSpace })
        {
            var canAccess = new List<Guid>();
            var canApprovePolicy = new List<Guid>();
            foreach (var id in users)
            {
                // CanAccessCeremonyAsync, then PolicyApprovalRefusalAsync, as the approve endpoint applies them.
                if (!(await auth.IsSystemAdminAsync(id) || await auth.HasScopeCapabilityAsync(id, spaceId, Capabilities.CaManage)))
                    continue;
                canAccess.Add(id);
                if (await auth.HasScopeCapabilityAsync(id, spaceId, Capabilities.SystemManage))
                    canApprovePolicy.Add(id);
            }

            Assert.Equal(canAccess.Order(), (await guard.EligibleApproversAsync("CreateIntermediateCA", spaceId, null, Guid.Empty)).Order());
            var policyOperation = spaceId == null ? nameof(CeremonyType.InstancePolicyChange) : nameof(CeremonyType.SpacePolicyChange);
            Assert.Equal(canApprovePolicy.Order(), (await guard.EligibleApproversAsync(policyOperation, spaceId, null, Guid.Empty)).Order());
            Assert.True(canAccess.Count > canApprovePolicy.Count && canApprovePolicy.Count > 1);
        }
    }

    /// <summary>
    /// A controlled-user change is approved by an account whose tier dominates the affected one,
    /// other than its initiator, the user it changes, and (for a promotion) whoever reset that
    /// user's credentials, unless system-super.
    /// </summary>
    [Fact]
    public async Task A_controlled_user_change_counts_dominating_accounts_only()
    {
        var w = new SingleAdminWorld();
        var caAdmin = w.User("ca-admin", w.CaAdminGroup);
        var target = w.User("target", w.CaAdminGroup);
        var spaceAdmin = w.User("space-admin", w.SpaceAdminGroup);
        w.User("space-operator", w.SpaceOperatorGroup);
        var guard = new CeremonyQuorumGuard(w.Db);

        string Parameters(string changeType, params ControlledCredentialReset[] resets) => JsonSerializer.Serialize(new ControlledUserChangeParameters
        {
            ChangeType = changeType,
            TargetUserId = target,
            MintedTierLevel = (int)ControlledTierLevel.CaAdmin,
            MintedTierCaId = w.Ca,
            MintedTierSpaceId = w.Space,
            RecentCredentialResets = resets.ToList(),
        });
        ControlledCredentialReset Reset(Guid actor) => new(target, "target", ControlledCredentialReset.Password, actor, "actor", DateTime.UtcNow);

        // The lone super, and the space administrator, dominate a CA administrator; the target never counts.
        var eligible = await guard.EligibleApproversAsync("ControlledUserChange", null, Parameters("RemoveGroupMember"), caAdmin);
        Assert.Equal(new[] { w.Admin, spaceAdmin }.Order(), eligible.Order());

        // A promotion bars whoever reset the promoted account's credentials, except a super.
        eligible = await guard.EligibleApproversAsync("ControlledUserChange", null, Parameters("AddGroupMember", Reset(spaceAdmin), Reset(w.Admin)), caAdmin);
        Assert.Equal([w.Admin], eligible);

        // Unreadable parameters: nobody can approve.
        Assert.Empty(await guard.EligibleApproversAsync("ControlledUserChange", null, "{", caAdmin));
    }

    [Fact]
    public async Task A_controlled_user_change_nobody_else_dominates_is_refused()
    {
        var w = new SingleAdminWorld();
        var caAdmin = w.User("ca-admin", w.CaAdminGroup);
        var newcomer = w.User("newcomer");
        // The only other dominating account cannot sign in.
        w.Db.Users.Single(u => u.Id == w.Admin).IsLocked = true;
        w.Db.SaveChanges();
        var audit = new RecordingAuditService();
        var controlled = new ControlledUserCeremonyService(w.Db, new KeyCeremonyService(w.Db, audit), null!, NullLogger<ControlledUserCeremonyService>.Instance);

        var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => controlled.InitiateChangeAsync(
            new ControlledUserChangeParameters { ChangeType = "AddGroupMember", TargetUserId = newcomer, TargetUsername = "newcomer", GroupId = w.CaAdminGroup.Id, CertificateAuthorityId = w.Ca },
            new ControlledTier(ControlledTierLevel.CaAdmin, w.Ca) { SpaceId = w.Space }, caAdmin, "ca-admin"));

        Assert.Equal(ErrorCodes.CeremonyNoApprover, ex.Code);
        Assert.Null(ex.RequirementScope);
        Assert.Empty(w.Db.KeyCeremonies);

        w.Db.Users.Single(u => u.Id == w.Admin).IsLocked = false;
        w.Db.SaveChanges();
        var id = await controlled.InitiateChangeAsync(
            new ControlledUserChangeParameters { ChangeType = "AddGroupMember", TargetUserId = newcomer, TargetUsername = "newcomer", GroupId = w.CaAdminGroup.Id, CertificateAuthorityId = w.Ca },
            new ControlledTier(ControlledTierLevel.CaAdmin, w.Ca) { SpaceId = w.Space }, caAdmin, "ca-admin");
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
    }

    [Fact]
    public async Task A_policy_change_pre_check_refuses_before_anything_is_opened()
    {
        var w = new SingleAdminWorld();
        var changes = new SpacePolicyChangeService(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), NullLogger<SpacePolicyChangeService>.Instance);

        foreach (var spaceId in new Guid?[] { w.Space, null })
        {
            var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => changes.EnsureChangeApprovableAsync(spaceId, w.Admin));
            Assert.Equal(ErrorCodes.CeremonyNoApprover, ex.Code);
            await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => changes.InitiateChangeAsync(spaceId, false, null, w.Admin, "superadmin"));
        }
        Assert.Empty(w.Db.KeyCeremonies);

        w.User("second", w.SystemAdminGroup);
        await changes.EnsureChangeApprovableAsync(w.Space, w.Admin);
        await changes.EnsureChangeApprovableAsync(null, w.Admin);
    }

    /// <summary>
    /// A ceremony already pending (opened before the guard existed) reports the approvals it still
    /// needs against the accounts that could still give one.
    /// </summary>
    [Fact]
    public async Task A_pending_ceremony_reports_whether_it_can_still_be_approved()
    {
        var w = new SingleAdminWorld();
        var guard = new CeremonyQuorumGuard(w.Db);
        var ceremony = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateIntermediateCA", InitiatedByUserId = w.Admin, SpaceId = w.Space,
            RequiredApprovals = 2, Status = "Pending", ExpiresAt = DateTime.UtcNow.AddHours(1), ParametersJson = SingleAdminWorld.Parameters(w.Space), ApprovalsJson = "[]",
        };

        var stuck = await guard.AssessPendingAsync(ceremony);
        Assert.False(stuck.Reachable);
        Assert.Equal(2, stuck.RequiredApprovals);
        Assert.Equal(0, stuck.EligibleApprovers);

        var second = w.User("second", w.SystemAdminGroup);
        ceremony.ApprovalsJson = JsonSerializer.Serialize(new[] { new ApprovalRecord { UserId = second, Username = "second", Decision = "Approved", Timestamp = DateTime.UtcNow } });
        var half = await guard.AssessPendingAsync(ceremony);
        Assert.False(half.Reachable);
        Assert.Equal(1, half.RequiredApprovals);
        Assert.Equal(0, half.EligibleApprovers);

        w.User("third", w.SpaceOperatorGroup);
        Assert.True((await guard.AssessPendingAsync(ceremony)).Reachable);
    }

    /// <summary>
    /// Every initiation path ends in <see cref="KeyCeremonyService.InitiateAsync"/>: nothing else in
    /// the product creates a ceremony row, and that method checks the quorum before it creates one.
    /// </summary>
    [Fact]
    public void Ceremonies_are_created_in_one_place_behind_the_guard()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !root.EnumerateFiles("*.sln").Any())
            root = root.Parent;
        Assert.NotNull(root);

        var creators = new List<string>();
        var initiators = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var project in root!.EnumerateDirectories("ModularCA.*"))
        {
            foreach (var file in project.EnumerateFiles("*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(root.FullName, file.FullName).Replace('\\', '/');
                if (relative.Contains("/bin/") || relative.Contains("/obj/") || relative.Contains("/Migrations/"))
                    continue;
                var text = File.ReadAllText(file.FullName);
                if (text.Contains("new KeyCeremonyEntity") || text.Contains("KeyCeremonies.Add"))
                    creators.Add(relative);
                if (System.Text.RegularExpressions.Regex.IsMatch(text, @"[cC]eremonyS(vc|ervice)\.InitiateAsync\("))
                    initiators.Add(relative);
            }
        }

        Assert.Equal(["ModularCA.Core/Services/KeyCeremonyService.cs"], creators);

        var source = File.ReadAllText(Path.Combine(root.FullName, "ModularCA.Core", "Services", "KeyCeremonyService.cs"));
        var guardAt = source.IndexOf("_quorumGuard.EnsureReachableAsync(", StringComparison.Ordinal);
        var createAt = source.IndexOf("new KeyCeremonyEntity", StringComparison.Ordinal);
        Assert.True(guardAt > 0 && guardAt < createAt, "InitiateAsync must check the quorum before it creates the ceremony.");

        // The callers of InitiateAsync. A new one is covered by the guard already; list it here and
        // give it a lone-administrator test in SingleAdministratorCeremonyTests.
        Assert.Equal(
            [
                "ModularCA.API/Controllers/v1/Admin/AdminCaController.cs",
                "ModularCA.API/Controllers/v1/Admin/AdminKeyCeremonyController.cs",
                "ModularCA.API/Controllers/v1/Admin/AdminRevocationController.cs",
                "ModularCA.API/Controllers/v1/Admin/AdminSshController.cs",
                "ModularCA.Auth/Authorization/ControlledUserCeremonyService.cs",
                "ModularCA.Core/Services/SpacePolicyChangeService.cs",
            ],
            initiators);
    }
}
