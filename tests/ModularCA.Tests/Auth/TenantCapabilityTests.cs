using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A tenant administrator is someone holding a capability tenant-wide. Pins what counts as
/// tenant-wide (a tenant group, a tenant-scoped role or grant on the user, or system scope),
/// what does not (a grant on one CA of the tenant), and the CA-creation rule built on it: an
/// intermediate may be created in a tenant the caller administers, under a parent in that
/// tenant or one they hold <c>ca.manage</c> on.
/// </summary>
public class TenantCapabilityTests
{
    private static readonly Guid TenantA = Guid.NewGuid();
    private static readonly Guid TenantB = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Service => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public Guid UserId { get; } = Guid.NewGuid();

        public CertificateAuthorityEntity Ca(string label, Guid tenantId)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label.ToUpperInvariant(), Label = label, TenantId = tenantId };
            Db.CertificateAuthorities.Add(ca);
            return ca;
        }

        public CaGroupEntity Group(Guid tenantId, Guid? caId = null, bool system = false)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", TenantId = tenantId, CertificateAuthorityId = caId, IsSystemGroup = system };
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
    public async Task A_tenant_group_grant_holds_for_that_tenant_only()
    {
        var w = new World();
        w.Grant(w.Group(TenantA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasTenantCapabilityAsync(w.UserId, TenantA, Capabilities.CaManage));
        Assert.False(await w.Service.HasTenantCapabilityAsync(w.UserId, TenantB, Capabilities.CaManage));
        Assert.False(await w.Service.HasTenantCapabilityAsync(w.UserId, TenantA, Capabilities.SystemManage));
    }

    [Fact]
    public async Task A_grant_on_one_ca_of_the_tenant_is_not_tenant_wide()
    {
        var w = new World();
        var ca = w.Ca("ca-a", TenantA);
        w.Grant(w.Group(TenantA, caId: ca.Id), Capabilities.CaManage);
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.CaManage, CertificateAuthorityId = ca.Id });
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasCaCapabilityAsync(w.UserId, ca.Id, Capabilities.CaManage));
        Assert.False(await w.Service.HasTenantCapabilityAsync(w.UserId, TenantA, Capabilities.CaManage));
    }

    [Fact]
    public async Task Tenant_roles_and_grants_on_the_user_count_as_do_system_scope()
    {
        var viaGroupRole = new World();
        viaGroupRole.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = viaGroupRole.Group(TenantA).Id, RoleId = viaGroupRole.Role(Capabilities.CaManage).Id });
        await viaGroupRole.Db.SaveChangesAsync();
        Assert.True(await viaGroupRole.Service.HasTenantCapabilityAsync(viaGroupRole.UserId, TenantA, Capabilities.CaManage));

        var viaUserGrant = new World();
        viaUserGrant.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = viaUserGrant.UserId, Capability = Capabilities.CaManage, TenantId = TenantA });
        await viaUserGrant.Db.SaveChangesAsync();
        Assert.True(await viaUserGrant.Service.HasTenantCapabilityAsync(viaUserGrant.UserId, TenantA, Capabilities.CaManage));
        Assert.False(await viaUserGrant.Service.HasTenantCapabilityAsync(viaUserGrant.UserId, TenantB, Capabilities.CaManage));

        var viaUserRole = new World();
        viaUserRole.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = viaUserRole.UserId, RoleId = viaUserRole.Role(Capabilities.CaManage).Id, TenantId = TenantA });
        await viaUserRole.Db.SaveChangesAsync();
        Assert.True(await viaUserRole.Service.HasTenantCapabilityAsync(viaUserRole.UserId, TenantA, Capabilities.CaManage));

        var viaSystem = new World();
        viaSystem.Grant(viaSystem.Group(TenantB, system: true), Capabilities.CaManage);
        await viaSystem.Db.SaveChangesAsync();
        Assert.True(await viaSystem.Service.HasTenantCapabilityAsync(viaSystem.UserId, TenantA, Capabilities.CaManage));
    }

    [Fact]
    public async Task The_tenants_held_tenant_wide_come_from_all_four_sources_and_no_ca_grant()
    {
        var w = new World();
        var tenantC = Guid.NewGuid();
        var tenantD = Guid.NewGuid();
        w.Grant(w.Group(TenantA), Capabilities.CaManage);
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = w.Group(TenantB).Id, RoleId = w.Role(Capabilities.CaManage).Id });
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.CaManage, TenantId = tenantC });
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = w.UserId, RoleId = w.Role(Capabilities.CaManage).Id, TenantId = tenantD });
        var ca = w.Ca("ca-e", Guid.NewGuid());
        w.Grant(w.Group(ca.TenantId, caId: ca.Id), Capabilities.CaManage); // on one CA: not tenant-wide
        w.Grant(w.Group(Guid.NewGuid(), system: true), Capabilities.CaManage); // system scope: not a tenant
        await w.Db.SaveChangesAsync();

        var ids = await w.Service.GetTenantIdsWithCapabilityAsync(w.UserId, Capabilities.CaManage);

        Assert.Equal(new[] { TenantA, TenantB, tenantC, tenantD }.OrderBy(x => x), ids.OrderBy(x => x));
        Assert.Empty(await w.Service.GetTenantIdsWithCapabilityAsync(w.UserId, Capabilities.SystemManage));
    }

    [Fact]
    public async Task The_effective_payload_lists_tenant_wide_grants_even_for_a_tenant_with_no_ca()
    {
        var w = new World();
        w.Db.Tenants.Add(new TenantEntity { Id = TenantA, Name = "Tenant A", Slug = "tenant-a" });
        w.Grant(w.Group(TenantA), Capabilities.CaManage);
        var cb = w.Ca("ca-b", TenantB);
        w.Grant(w.Group(TenantB, caId: cb.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        var t = Assert.Single(result.Tenants);
        Assert.Equal(TenantA, t.Id);
        Assert.Equal("Tenant A", t.Name);
        Assert.Equal("tenant-a", t.Slug);
        Assert.Equal(new[] { Capabilities.CaManage }, t.Capabilities);
        Assert.Equal("ca-b", Assert.Single(result.Cas).Label); // the per-CA grant in B is on the CA, not tenant-wide
    }

    [Fact]
    public async Task A_tenant_admin_may_create_an_intermediate_under_a_parent_in_their_tenant()
    {
        var w = new World();
        var parent = w.Ca("root-a", TenantA);
        w.Grant(w.Group(TenantA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, TenantA, parent.Id));
        Assert.False(await CaCreationAccess.MayCreateRootAsync(w.Service, w.UserId, TenantA));
    }

    [Fact]
    public async Task A_parent_in_another_tenant_needs_ca_manage_on_that_parent()
    {
        var w = new World();
        var foreignParent = w.Ca("root-b", TenantB);
        w.Grant(w.Group(TenantA), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();
        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, TenantA, foreignParent.Id));

        w.Grant(w.Group(TenantB, caId: foreignParent.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();
        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, TenantA, foreignParent.Id));
    }

    [Fact]
    public async Task A_single_ca_admin_cannot_create_a_sibling_and_an_unknown_parent_is_refused()
    {
        var w = new World();
        var parent = w.Ca("root-a", TenantA);
        w.Grant(w.Group(TenantA, caId: parent.Id), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();

        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, TenantA, parent.Id));

        var admin = new World();
        admin.Grant(admin.Group(TenantA), Capabilities.CaManage);
        await admin.Db.SaveChangesAsync();
        Assert.False(await CaCreationAccess.MayCreateIntermediateAsync(admin.Service, admin.Db, admin.UserId, TenantA, Guid.NewGuid()));
    }

    [Fact]
    public async Task System_manage_passes_everything()
    {
        var w = new World();
        w.Grant(w.Group(TenantB, system: true), Capabilities.SystemManage);
        var foreignParent = w.Ca("root-b", TenantB);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Service.HasTenantCapabilityAsync(w.UserId, TenantA, Capabilities.CaManage));
        Assert.True(await CaCreationAccess.MayCreateIntermediateAsync(w.Service, w.Db, w.UserId, TenantA, foreignParent.Id));
        Assert.True(await CaCreationAccess.MayCreateRootAsync(w.Service, w.UserId, TenantA));
    }
}
