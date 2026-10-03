using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A service identity is a user that holds permissions and can never sign in. Pins the two
/// halves: no token is ever minted for one, and who may create one is decided by the scope it
/// is confined to (system, space or CA), with its groups confined the same way and system
/// groups out of reach for good.
/// </summary>
public class ServiceIdentityTests
{
    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Auth => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public ServiceIdentityService Service => new(Db, Auth);
        public Guid SpaceA { get; } = Guid.NewGuid();
        public Guid SpaceB { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity CaA1 { get; }
        public CertificateAuthorityEntity CaA2 { get; }
        public CertificateAuthorityEntity CaB1 { get; }
        public CaGroupEntity SystemGroup { get; }
        public CaGroupEntity SpaceAGroup { get; }
        public CaGroupEntity CaA1Requesters { get; }
        public CaGroupEntity CaB1Requesters { get; }

        public World()
        {
            Db.Spaces.AddRange(new SpaceEntity { Id = SpaceA, Name = "A", Slug = "a" }, new SpaceEntity { Id = SpaceB, Name = "B", Slug = "b" });
            CaA1 = Ca("a1", SpaceA); CaA2 = Ca("a2", SpaceA); CaB1 = Ca("b1", SpaceB);
            SystemGroup = Group("system-admin", Guid.NewGuid(), null, system: true);
            SpaceAGroup = Group("space-a-ops", SpaceA, null);
            CaA1Requesters = Group("a1-requester", SpaceA, CaA1.Id);
            CaB1Requesters = Group("b1-requester", SpaceB, CaB1.Id);
            Db.SaveChanges();
        }

        private CertificateAuthorityEntity Ca(string label, Guid spaceId)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label, Label = label, SpaceId = spaceId };
            Db.CertificateAuthorities.Add(ca);
            return ca;
        }

        private CaGroupEntity Group(string name, Guid spaceId, Guid? caId, bool system = false)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = name, DisplayName = name, SpaceId = spaceId, CertificateAuthorityId = caId, IsSystemGroup = system };
            Db.CaGroups.Add(g);
            return g;
        }

        /// <summary>A caller holding ca.manage at the given scope: system group, space-wide group, or one CA's group.</summary>
        public Guid Caller(Guid? spaceId = null, Guid? caId = null, bool system = false)
        {
            var id = Guid.NewGuid();
            Db.Users.Add(new UserEntity { Id = id, Username = $"admin-{id:N}", Email = $"{id:N}@x" });
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{id:N}", DisplayName = "g", SpaceId = spaceId ?? Guid.NewGuid(), CertificateAuthorityId = caId, IsSystemGroup = system };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = id });
            Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = Capabilities.CaManage });
            Db.SaveChanges();
            return id;
        }

        public static ServiceIdentitySpec Spec(string name, Guid? spaceId = null, Guid? caId = null, params Guid[] groups)
            => new(name, null, null, new ServiceIdentityScope(spaceId, caId), groups);
    }

    [Fact]
    public void No_token_is_ever_minted_for_a_service_identity()
    {
        var jwt = new JwtTokenService(new SystemConfig());
        var identity = new UserEntity { Id = Guid.NewGuid(), Username = "svc", IsServiceIdentity = true };
        Assert.Throws<ServiceIdentityCannotSignInException>(() => jwt.GenerateToken(identity, []));
    }

    [Fact]
    public async Task A_ca_admin_creates_an_identity_confined_to_that_ca_and_nothing_wider()
    {
        var w = new World();
        var caAdmin = w.Caller(w.SpaceA, w.CaA1.Id);

        var created = await w.Service.CreateAsync(caAdmin, World.Spec("svc-a1", caId: w.CaA1.Id, groups: w.CaA1Requesters.Id));
        Assert.True(created.IsServiceIdentity);
        Assert.Equal(string.Empty, created.PasswordHash);
        Assert.True(created.PasswordNeverExpires);
        Assert.Equal(w.SpaceA, created.ServiceScopeSpaceId); // a CA scope carries its space
        Assert.Equal(w.CaA1.Id, created.ServiceScopeCaId);
        Assert.EndsWith("@" + ServiceIdentityService.MailDomain, created.Email);
        Assert.Single(w.Db.CaGroupMembers.Where(m => m.UserId == created.Id));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(caAdmin, World.Spec("svc-space", spaceId: w.SpaceA)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(caAdmin, World.Spec("svc-a2", caId: w.CaA2.Id)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(caAdmin, World.Spec("svc-system")));
    }

    [Fact]
    public async Task A_space_admin_reaches_the_space_and_its_cas_but_not_another_space()
    {
        var w = new World();
        var spaceAdmin = w.Caller(w.SpaceA);

        var spaceWide = await w.Service.CreateAsync(spaceAdmin, World.Spec("svc-a", spaceId: w.SpaceA, groups: new[] { w.SpaceAGroup.Id, w.CaA1Requesters.Id }));
        Assert.Null(spaceWide.ServiceScopeCaId);
        Assert.Equal(2, w.Db.CaGroupMembers.Count(m => m.UserId == spaceWide.Id));
        Assert.NotNull(await w.Service.CreateAsync(spaceAdmin, World.Spec("svc-a2", caId: w.CaA2.Id)));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(spaceAdmin, World.Spec("svc-b", spaceId: w.SpaceB)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(spaceAdmin, World.Spec("svc-b1", caId: w.CaB1.Id)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.CreateAsync(spaceAdmin, World.Spec("svc-system")));
    }

    [Fact]
    public async Task Groups_must_fit_the_scope_and_system_groups_never_do()
    {
        var w = new World();
        var system = w.Caller(system: true);

        // A CA identity cannot hold a space-wide group or another CA's group.
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(system, World.Spec("svc-x", caId: w.CaA1.Id, groups: w.SpaceAGroup.Id)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(system, World.Spec("svc-y", caId: w.CaA1.Id, groups: w.CaB1Requesters.Id)));
        // A space identity cannot hold another space's CA group.
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(system, World.Spec("svc-z", spaceId: w.SpaceA, groups: w.CaB1Requesters.Id)));
        // Even system scope, even a system caller: never a system group.
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(system, World.Spec("svc-s", groups: w.SystemGroup.Id)));

        // What does fit.
        var ok = await w.Service.CreateAsync(system, World.Spec("svc-ok", groups: new[] { w.SpaceAGroup.Id, w.CaA1Requesters.Id, w.CaB1Requesters.Id }));
        Assert.Equal(3, w.Db.CaGroupMembers.Count(m => m.UserId == ok.Id));
        Assert.False(ServiceIdentityService.GroupFitsScope(w.SystemGroup, ServiceIdentityScope.System, groupIsInstance: false));
        Assert.False(ServiceIdentityService.GroupFitsScope(w.CaA1Requesters, ServiceIdentityScope.System, groupIsInstance: true));

        // An instance CA's group (no space, as the system tenant's were) is system infrastructure,
        // refused like a system group.
        var systemCaGroup = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-signing-ca-admin", DisplayName = "x", SpaceId = null, CertificateAuthorityId = Guid.NewGuid() };
        w.Db.CaGroups.Add(systemCaGroup);
        await w.Db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(system, World.Spec("svc-sysca", groups: systemCaGroup.Id)));
    }

    [Fact]
    public async Task The_list_shows_each_admin_only_their_scope_and_group_changes_stay_inside_it()
    {
        var w = new World();
        var system = w.Caller(system: true);
        var a1 = await w.Service.CreateAsync(system, World.Spec("svc-a1", caId: w.CaA1.Id));
        var a = await w.Service.CreateAsync(system, World.Spec("svc-a", spaceId: w.SpaceA));
        var b1 = await w.Service.CreateAsync(system, World.Spec("svc-b1", caId: w.CaB1.Id));
        var sys = await w.Service.CreateAsync(system, World.Spec("svc-sys"));

        Assert.Equal(4, (await w.Service.ListAsync(system)).Count);
        Assert.Equal(new[] { "svc-a", "svc-a1" }, (await w.Service.ListAsync(w.Caller(w.SpaceA))).Select(u => u.Username));
        Assert.Equal(new[] { "svc-a1" }, (await w.Service.ListAsync(w.Caller(w.SpaceA, w.CaA1.Id))).Select(u => u.Username));

        // A CA admin may add its own CA's group to its own CA's identity, and nothing else.
        var caAdmin = w.Caller(w.SpaceA, w.CaA1.Id);
        var updated = await w.Service.SetGroupsAsync(caAdmin, a1.Id, [w.CaA1Requesters.Id]);
        Assert.Single(updated.GroupMemberships);
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.SetGroupsAsync(caAdmin, a1.Id, [w.SpaceAGroup.Id]));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.SetGroupsAsync(caAdmin, a.Id, [w.SpaceAGroup.Id]));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.SetGroupsAsync(caAdmin, b1.Id, []));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => w.Service.DeleteAsync(caAdmin, sys.Id));
    }

    [Fact]
    public async Task Deleting_is_refused_while_a_kerberos_realm_acts_as_the_identity()
    {
        var w = new World();
        var system = w.Caller(system: true);
        var svc = await w.Service.CreateAsync(system, World.Spec("svc-lab", spaceId: w.SpaceA));
        w.Db.KerberosRealms.Add(new KerberosRealmEntity { SpaceId = w.SpaceA, Realm = "LAB.MSAE.TEST", DnsDomain = "lab.msae.test", ServicePrincipal = "HTTP/ca4", EnrollmentUserId = svc.Id });
        await w.Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.DeleteAsync(system, svc.Id));
        Assert.Contains("LAB.MSAE.TEST", ex.Message);

        w.Db.KerberosRealms.RemoveRange(w.Db.KerberosRealms);
        await w.Db.SaveChangesAsync();
        await w.Service.DeleteAsync(system, svc.Id);
        Assert.Null(await w.Service.GetAsync(svc.Id));
    }
}
