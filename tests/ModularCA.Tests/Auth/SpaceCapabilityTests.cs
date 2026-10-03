using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A space administrator is someone holding a capability space-wide. Pins what counts as
/// space-wide (a space group, a space-scoped role or grant on the user, or system scope),
/// what does not (a grant on one CA of the space), and the CA-creation rule built on it: an
/// intermediate may be created in a space the caller administers, under a parent in that
/// space or one they hold <c>ca.manage</c> on.
/// </summary>
public class SpaceCapabilityTests
{
    private static readonly Guid SpaceA = Guid.NewGuid();
    private static readonly Guid SpaceB = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Service => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public Guid UserId { get; } = Guid.NewGuid();

        public CertificateAuthorityEntity Ca(string label, Guid spaceId)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label.ToUpperInvariant(), Label = label, SpaceId = spaceId };
            Db.CertificateAuthorities.Add(ca);
            return ca;
        }

        public CaGroupEntity Group(Guid spaceId, Guid? caId = null, bool system = false)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", SpaceId = spaceId, CertificateAuthorityId = caId, IsSystemGroup = system };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = UserId });
            return g;
        }

        public void Grant(CaGroupEntity g, string capability)
            => Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = capability });

        public RoleEntity Role(params string[] capabilities)
        {
            var r = new RoleEntity { Id = Guid.NewGuid(), Name = $"r-{Guid.NewGuid():N}" };
            Db.Roles.Add(r);
            foreach (var c in capabilities)
                Db.RoleCapabilities.Add(new RoleCapabilityEntity { Id = Guid.NewGuid(), RoleId = r.Id, Capability = c });
            return r;
        }
    }

    [Fact]
    public async Task A_space_group_grant_holds_for_that_space_only()
    {
        var w = new World();
        w.Grant(w.Group(SpaceA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasSpaceCapabilityAsync(w.UserId, SpaceA, Capabilities.CaManage));
        Assert.False(await w.Service.HasSpaceCapabilityAsync(w.UserId, SpaceB, Capabilities.CaManage));
        Assert.False(await w.Service.HasSpaceCapabilityAsync(w.UserId, SpaceA, Capabilities.SystemManage));
    }

    [Fact]
    public async Task A_grant_on_one_ca_of_the_space_is_not_space_wide()
    {
        var w = new World();
        var ca = w.Ca("ca-a", SpaceA);
        w.Grant(w.Group(SpaceA, caId: ca.Id), Capabilities.CaManage);
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.CaManage, CertificateAuthorityId = ca.Id });
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasCaCapabilityAsync(w.UserId, ca.Id, Capabilities.CaManage));
        Assert.False(await w.Service.HasSpaceCapabilityAsync(w.UserId, SpaceA, Capabilities.CaManage));
    }

    [Fact]
    public async Task Space_roles_and_grants_on_the_user_count_as_do_system_scope()
    {
        var viaGroupRole = new World();
        viaGroupRole.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = viaGroupRole.Group(SpaceA).Id, RoleId = viaGroupRole.Role(Capabilities.CaManage).Id });
        await viaGroupRole.Db.SaveChangesAsync();
        Assert.True(await viaGroupRole.Service.HasSpaceCapabilityAsync(viaGroupRole.UserId, SpaceA, Capabilities.CaManage));

        var viaUserGrant = new World();
        viaUserGrant.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = viaUserGrant.UserId, Capability = Capabilities.CaManage, SpaceId = SpaceA });
        await viaUserGrant.Db.SaveChangesAsync();
        Assert.True(await viaUserGrant.Service.HasSpaceCapabilityAsync(viaUserGrant.UserId, SpaceA, Capabilities.CaManage));
        Assert.False(await viaUserGrant.Service.HasSpaceCapabilityAsync(viaUserGrant.UserId, SpaceB, Capabilities.CaManage));

        var viaUserRole = new World();
        viaUserRole.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = viaUserRole.UserId, RoleId = viaUserRole.Role(Capabilities.CaManage).Id, SpaceId = SpaceA });
        await viaUserRole.Db.SaveChangesAsync();
        Assert.True(await viaUserRole.Service.HasSpaceCapabilityAsync(viaUserRole.UserId, SpaceA, Capabilities.CaManage));

        var viaSystem = new World();
        viaSystem.Grant(viaSystem.Group(SpaceB, system: true), Capabilities.CaManage);
        await viaSystem.Db.SaveChangesAsync();
        Assert.True(await viaSystem.Service.HasSpaceCapabilityAsync(viaSystem.UserId, SpaceA, Capabilities.CaManage));
    }

    [Fact]
    public async Task The_spaces_held_space_wide_come_from_all_four_sources_and_no_ca_grant()
    {
        var w = new World();
        var spaceC = Guid.NewGuid();
        var spaceD = Guid.NewGuid();
        w.Grant(w.Group(SpaceA), Capabilities.CaManage);
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = w.Group(SpaceB).Id, RoleId = w.Role(Capabilities.CaManage).Id });
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.CaManage, SpaceId = spaceC });
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = w.UserId, RoleId = w.Role(Capabilities.CaManage).Id, SpaceId = spaceD });
        var ca = w.Ca("ca-e", Guid.NewGuid());
        w.Grant(w.Group(ca.SpaceId!.Value, caId: ca.Id), Capabilities.CaManage); // on one CA: not space-wide
        w.Grant(w.Group(Guid.NewGuid(), system: true), Capabilities.CaManage); // system scope: not a space
        await w.Db.SaveChangesAsync();

        var ids = await w.Service.GetSpaceIdsWithCapabilityAsync(w.UserId, Capabilities.CaManage);

        Assert.Equal(new[] { SpaceA, SpaceB, spaceC, spaceD }.OrderBy(x => x), ids.OrderBy(x => x));
        Assert.Empty(await w.Service.GetSpaceIdsWithCapabilityAsync(w.UserId, Capabilities.SystemManage));
    }

    [Fact]
    public async Task The_effective_payload_lists_space_wide_grants_even_for_a_space_with_no_ca()
    {
        var w = new World();
        w.Db.Spaces.Add(new SpaceEntity { Id = SpaceA, Name = "Space A", Slug = "space-a" });
        w.Grant(w.Group(SpaceA), Capabilities.CaManage);
        var cb = w.Ca("ca-b", SpaceB);
        w.Grant(w.Group(SpaceB, caId: cb.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        var t = Assert.Single(result.Spaces);
        Assert.Equal(SpaceA, t.Id);
        Assert.Equal("Space A", t.Name);
        Assert.Equal("space-a", t.Slug);
        Assert.Equal(new[] { Capabilities.CaManage }, t.Capabilities);
        Assert.Equal("ca-b", Assert.Single(result.Cas).Label); // the per-CA grant in B is on the CA, not space-wide
    }

    [Fact]
    public async Task A_space_admin_may_create_an_intermediate_under_a_parent_in_their_space()
    {
        var w = new World();
        var parent = w.Ca("root-a", SpaceA);
        w.Grant(w.Group(SpaceA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, SpaceA, parent.Id));
        Assert.False(await CaCreationAccess.MayCreateRootAsync(w.Service, w.UserId, SpaceA));
    }

    [Fact]
    public async Task A_parent_in_another_space_needs_ca_manage_on_that_parent()
    {
        var w = new World();
        var foreignParent = w.Ca("root-b", SpaceB);
        w.Grant(w.Group(SpaceA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();
        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, SpaceA, foreignParent.Id));

        w.Grant(w.Group(SpaceB, caId: foreignParent.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();
        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, SpaceA, foreignParent.Id));
    }

    [Fact]
    public async Task A_single_ca_admin_cannot_create_a_sibling_and_an_unknown_parent_is_refused()
    {
        var w = new World();
        var parent = w.Ca("root-a", SpaceA);
        w.Grant(w.Group(SpaceA, caId: parent.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, SpaceA, parent.Id));

        var admin = new World();
        admin.Grant(admin.Group(SpaceA), Capabilities.CaManage);
        await admin.Db.SaveChangesAsync();
        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(admin.Service, admin.Db, admin.UserId, SpaceA, Guid.NewGuid()));
    }

    [Fact]
    public async Task System_manage_passes_everything()
    {
        var w = new World();
        w.Grant(w.Group(SpaceB, system: true), Capabilities.SystemManage);
        var foreignParent = w.Ca("root-b", SpaceB);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasSpaceCapabilityAsync(w.UserId, SpaceA, Capabilities.CaManage));
        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, SpaceA, foreignParent.Id));
        Assert.True(await CaCreationAccess.MayCreateRootAsync(w.Service, w.UserId, SpaceA));
    }
}
