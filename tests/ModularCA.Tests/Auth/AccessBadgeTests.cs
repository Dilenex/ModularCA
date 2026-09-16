using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.AccessBadges;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Access badges: a worn badge narrows the resolver to the grant sources it names, a badge that
/// cannot be honoured grants nothing, badgeless is unfiltered; switching broadens exactly when
/// the target keeps a source the current badge does not; and a badge can only be built from
/// sources its owner holds.
/// </summary>
public class AccessBadgeTests
{
    private static readonly Guid Tenant = Guid.NewGuid();

    private sealed class FixedBadge(AccessBadgeFilter? filter) : IAccessBadgeContext
    {
        public Task<AccessBadgeFilter?> GetWornAsync(Guid userId) => Task.FromResult(filter);
    }

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public Guid UserId { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity CaA { get; }
        public CertificateAuthorityEntity CaB { get; }
        public CaGroupEntity OperatorOnA { get; }
        public CaGroupEntity AuditorOnB { get; }
        public UserCapabilityGrantEntity DirectBackup { get; }
        public RoleAssignmentEntity DirectRole { get; }

        public World()
        {
            Db.Users.Add(new UserEntity { Id = UserId, Username = "sam", Email = "sam@example.test" });
            CaA = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "A", Label = "ca-a", TenantId = Tenant };
            CaB = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "B", Label = "ca-b", TenantId = Tenant };
            Db.CertificateAuthorities.AddRange(CaA, CaB);

            OperatorOnA = Group("op-a", CaA.Id, Capabilities.CertRevoke, Capabilities.CaManage);
            AuditorOnB = Group("aud-b", CaB.Id, Capabilities.AuditView);

            DirectBackup = new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = UserId, Capability = Capabilities.BackupManage };
            Db.UserCapabilityGrants.Add(DirectBackup);

            var role = new RoleEntity { Id = Guid.NewGuid(), Name = "profile-viewer" };
            Db.Roles.Add(role);
            Db.RoleCapabilities.Add(new RoleCapabilityEntity { Id = Guid.NewGuid(), RoleId = role.Id, Capability = Capabilities.ProfileView });
            DirectRole = new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = UserId, RoleId = role.Id };
            Db.RoleAssignments.Add(DirectRole);
            Db.SaveChanges();
        }

        private CaGroupEntity Group(string name, Guid caId, params string[] caps)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = name, DisplayName = name, TenantId = Tenant, CertificateAuthorityId = caId };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = UserId });
            foreach (var c in caps)
                Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = c });
            return g;
        }

        public CaGroupAuthorizationService Resolver(AccessBadgeFilter? worn)
            => new(Db, NullLogger<CaGroupAuthorizationService>.Instance, badges: new FixedBadge(worn));
    }

    [Fact]
    public async Task Badgeless_walks_every_grant_source()
    {
        var w = new World();
        var caps = await w.Resolver(null).GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Equal(new[] { Capabilities.BackupManage, Capabilities.ProfileView }, caps.System);
        Assert.Contains(Capabilities.CertRevoke, caps.Cas.Single(c => c.Id == w.CaA.Id).Capabilities);
        Assert.Contains(Capabilities.AuditView, caps.Cas.Single(c => c.Id == w.CaB.Id).Capabilities);
    }

    [Fact]
    public async Task A_worn_badge_keeps_only_the_sources_it_names()
    {
        var w = new World();
        var badge = new AccessBadgeFilter(Guid.NewGuid(), "auditor on b", [w.AuditorOnB.Id], [], []);
        var resolver = w.Resolver(badge);

        var caps = await resolver.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Empty(caps.System);                                           // the direct grant and role are set aside
        Assert.Equal(new[] { w.CaB.Id }, caps.Cas.Select(c => c.Id));        // the operator group on A is set aside
        Assert.Equal(new[] { Capabilities.AuditView }, caps.Cas.Single().Capabilities);
        Assert.False(await resolver.HasCaCapabilityAsync(w.UserId, w.CaA.Id, Capabilities.CertRevoke));
        Assert.True(await resolver.HasCaCapabilityAsync(w.UserId, w.CaB.Id, Capabilities.AuditView));
        Assert.False(await resolver.HasSystemCapabilityAsync(w.UserId, Capabilities.BackupManage));
        Assert.Equal(new[] { w.AuditorOnB.Id }, (await resolver.GetUserGroupsAsync(w.UserId)).Select(g => g.Id));
    }

    [Fact]
    public async Task Direct_grants_and_roles_count_only_when_the_badge_names_them()
    {
        var w = new World();
        var badge = new AccessBadgeFilter(Guid.NewGuid(), "direct only", [], [w.DirectRole.Id], [w.DirectBackup.Id]);
        var resolver = w.Resolver(badge);

        var caps = await resolver.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Equal(new[] { Capabilities.BackupManage, Capabilities.ProfileView }, caps.System);
        Assert.All(caps.Cas, ca => Assert.Equal(caps.System, ca.Capabilities)); // nothing CA-specific survives
        Assert.True(await resolver.HasSystemCapabilityAsync(w.UserId, Capabilities.BackupManage));

        var onlyRole = w.Resolver(new AccessBadgeFilter(Guid.NewGuid(), "role only", [], [w.DirectRole.Id], []));
        Assert.False(await onlyRole.HasSystemCapabilityAsync(w.UserId, Capabilities.BackupManage));
        Assert.True(await onlyRole.HasSystemCapabilityAsync(w.UserId, Capabilities.ProfileView));
    }

    [Fact]
    public async Task A_badge_that_cannot_be_honoured_grants_nothing()
    {
        var w = new World();
        var resolver = w.Resolver(AccessBadgeFilter.Nothing(Guid.NewGuid()));

        var caps = await resolver.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Empty(caps.System);
        Assert.Empty(caps.Cas);
        Assert.False(await resolver.IsSystemAdminAsync(w.UserId));
        Assert.Empty(await resolver.GetAccessibleCaIdsAsync(w.UserId, Capabilities.CertRevoke));
    }

    [Fact]
    public async Task System_manage_set_aside_by_a_badge_does_not_bypass_ca_checks()
    {
        var w = new World();
        var system = new CaGroupEntity { Id = Guid.NewGuid(), Name = "sys", DisplayName = "sys", TenantId = Tenant, IsSystemGroup = true };
        w.Db.CaGroups.Add(system);
        w.Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = system.Id, UserId = w.UserId });
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = system.Id, Capability = Capabilities.SystemManage });
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Resolver(null).IsSystemAdminAsync(w.UserId));
        var narrowed = w.Resolver(new AccessBadgeFilter(Guid.NewGuid(), "auditor on b", [w.AuditorOnB.Id], [], []));
        Assert.False(await narrowed.IsSystemAdminAsync(w.UserId));
        Assert.False(await narrowed.HasCaCapabilityAsync(w.UserId, w.CaA.Id, Capabilities.CertView));
    }

    [Fact]
    public void Switching_broadens_exactly_when_the_target_keeps_a_source_the_current_badge_does_not()
    {
        var g1 = new AccessBadgePolicy.SourceKey(AccessBadgeSourceKind.Group, Guid.NewGuid());
        var g2 = new AccessBadgePolicy.SourceKey(AccessBadgeSourceKind.Group, Guid.NewGuid());
        HashSet<AccessBadgePolicy.SourceKey> wide = [g1, g2];
        HashSet<AccessBadgePolicy.SourceKey> narrow = [g1];

        Assert.False(AccessBadgePolicy.IsBroadening(null, narrow));    // putting a badge on
        Assert.True(AccessBadgePolicy.IsBroadening(narrow, null));     // taking it off
        Assert.False(AccessBadgePolicy.IsBroadening(null, null));      // staying badgeless
        Assert.False(AccessBadgePolicy.IsBroadening(wide, narrow));    // narrowing
        Assert.True(AccessBadgePolicy.IsBroadening(narrow, wide));     // widening
        Assert.False(AccessBadgePolicy.IsBroadening(narrow, narrow));  // same set
    }

    [Fact]
    public async Task A_badge_may_only_keep_sources_its_owner_holds()
    {
        var w = new World();
        var service = new AccessBadgeService(w.Db);
        var stranger = new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), Capability = Capabilities.SystemManage };
        w.Db.UserCapabilityGrants.Add(stranger);
        await w.Db.SaveChangesAsync();

        var request = new AccessBadgeWriteRequest
        {
            Name = "escalation",
            Sources = [new AccessBadgeSourceRef { Kind = AccessBadgeSourceKind.CapabilityGrant, SourceId = stranger.Id }],
        };

        var ex = await Assert.ThrowsAsync<AccessBadgeService.BadgeValidationException>(() => service.CreateAsync(w.UserId, request, w.UserId));
        Assert.Contains("already holds", ex.Message);
        Assert.Empty(w.Db.AccessBadges);
    }

    [Fact]
    public async Task Sources_the_owner_holds_are_offered_with_their_scope_and_capabilities()
    {
        var w = new World();
        var options = await new AccessBadgeService(w.Db).ListSourceOptionsAsync(w.UserId);

        var group = options.Single(o => o.Kind == AccessBadgeSourceKind.Group && o.SourceId == w.OperatorOnA.Id);
        Assert.Equal("ca-a", group.Scope);
        Assert.Equal(new[] { Capabilities.CaManage, Capabilities.CertRevoke }, group.Capabilities);
        var grant = options.Single(o => o.Kind == AccessBadgeSourceKind.CapabilityGrant);
        Assert.Equal("System", grant.Scope);
        Assert.Equal(Capabilities.BackupManage, grant.Label);
        Assert.Single(options, o => o.Kind == AccessBadgeSourceKind.RoleAssignment);
    }

    [Fact]
    public async Task Only_one_badge_is_the_default_and_deleting_a_badge_takes_it_off_every_session()
    {
        var w = new World();
        var service = new AccessBadgeService(w.Db);
        var groupSource = new AccessBadgeSourceRef { Kind = AccessBadgeSourceKind.Group, SourceId = w.AuditorOnB.Id };

        var first = await service.CreateAsync(w.UserId, new AccessBadgeWriteRequest { Name = "one", IsDefault = true, Sources = [groupSource] }, w.UserId);
        var second = await service.CreateAsync(w.UserId, new AccessBadgeWriteRequest { Name = "two", IsDefault = true, Sources = [groupSource] }, w.UserId);
        Assert.Equal(second.Id, (await service.GetDefaultAsync(w.UserId))!.Id);
        Assert.False((await service.GetAsync(w.UserId, first.Id))!.IsDefault);

        w.Db.RefreshTokens.Add(new RefreshTokenEntity { Id = Guid.NewGuid(), UserId = w.UserId, Token = "h", ExpiresAt = DateTime.UtcNow.AddDays(1), AccessBadgeId = second.Id });
        await w.Db.SaveChangesAsync();

        Assert.True(await service.DeleteAsync(w.UserId, second.Id));
        Assert.Null(w.Db.RefreshTokens.Single().AccessBadgeId);
        Assert.Null(await service.GetDefaultAsync(w.UserId));
        Assert.False(await service.DeleteAsync(Guid.NewGuid(), first.Id)); // someone else's id cannot delete it
    }
}
