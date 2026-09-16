using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins how the four grant sources fold into the capabilities payload the console reads from
/// <c>GET /api/v1/me</c>: what counts as system scope, how tenant-wide and CA-scoped grants
/// land on each CA, that a CA with nothing granted is left out, and that <c>system.manage</c>
/// at system scope reports as everything, the way the per-request checks treat it.
/// </summary>
public class EffectiveCapabilitiesTests
{
    private static readonly Guid TenantA = Guid.NewGuid();
    private static readonly Guid TenantB = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Service => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public Guid UserId { get; } = Guid.NewGuid();

        public CertificateAuthorityEntity Ca(string label, Guid tenantId, bool ssh = false)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label.ToUpperInvariant(), Label = label, TenantId = tenantId, IsSshCa = ssh };
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

        public RoleEntity Role(params string[] capabilities)
        {
            var r = new RoleEntity { Id = Guid.NewGuid(), Name = $"r-{Guid.NewGuid():N}" };
            Db.Roles.Add(r);
            foreach (var c in capabilities)
                Db.RoleCapabilities.Add(new RoleCapabilityEntity { Id = Guid.NewGuid(), RoleId = r.Id, Capability = c });
            return r;
        }
    }

    private static string[] Sorted(params string[] caps) => caps.OrderBy(c => c, StringComparer.Ordinal).ToArray();

    [Fact]
    public async Task Grants_land_on_the_scope_they_were_made_at()
    {
        var w = new World();
        var a = w.Ca("ca-a", TenantA);
        var b = w.Ca("ca-b", TenantA);
        var c = w.Ca("ca-c", TenantB);
        w.Ca("ca-d", Guid.NewGuid()); // a third tenant: nothing granted anywhere near it

        // Source 1: a direct grant on a CA-scoped group.
        var caGroup = w.Group(TenantA, caId: a.Id);
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = caGroup.Id, Capability = Capabilities.CertApprove });
        // Source 2: a role on that same group.
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = caGroup.Id, RoleId = w.Role(Capabilities.CertRevoke).Id });
        // Source 1 again, tenant-wide: a non-system group with no CA.
        var tenantGroup = w.Group(TenantA);
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = tenantGroup.Id, Capability = Capabilities.ProfileView });
        // Source 3: a grant on the user, on one CA in the other tenant.
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.AuditView, CertificateAuthorityId = c.Id });
        // Source 4: a role on the user, tenant-wide in the other tenant.
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = w.UserId, RoleId = w.Role(Capabilities.CertView).Id, TenantId = TenantB });
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Empty(result.System);
        Assert.Equal(new[] { "ca-a", "ca-b", "ca-c" }, result.Cas.Select(x => x.Label));
        Assert.Equal(Sorted(Capabilities.CertApprove, Capabilities.CertRevoke, Capabilities.ProfileView), result.Cas[0].Capabilities);
        Assert.Equal(new[] { Capabilities.ProfileView }, result.Cas[1].Capabilities);
        Assert.Equal(Sorted(Capabilities.AuditView, Capabilities.CertView), result.Cas[2].Capabilities);
        Assert.Equal(b.Id, result.Cas[1].Id);
    }

    [Fact]
    public async Task System_scope_comes_from_system_groups_and_global_user_grants_and_applies_to_every_ca()
    {
        var w = new World();
        w.Ca("one", TenantA);
        w.Ca("two", TenantB, ssh: true);
        var systemGroup = w.Group(TenantA, system: true);
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), GroupId = systemGroup.Id, RoleId = w.Role(Capabilities.AuditView).Id });
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.CertView });
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Equal(Sorted(Capabilities.AuditView, Capabilities.CertView), result.System);
        Assert.Equal(2, result.Cas.Count);
        Assert.All(result.Cas, ca => Assert.Equal(result.System, ca.Capabilities));
        Assert.True(result.Cas.Single(x => x.Label == "two").IsSshCa);
    }

    [Fact]
    public async Task System_manage_at_system_scope_reports_as_every_capability()
    {
        // HasCaCapabilityAsync passes any check for such a user, so the literal grant list
        // would understate what the API lets them do.
        var w = new World();
        w.Ca("one", TenantA);
        var systemGroup = w.Group(TenantA, system: true);
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = systemGroup.Id, Capability = Capabilities.SystemManage });
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Equal(Sorted(Capabilities.All), result.System);
        Assert.Equal(Sorted(Capabilities.All), result.Cas.Single().Capabilities);
    }

    [Fact]
    public async Task System_manage_on_one_ca_does_not_widen_anything()
    {
        var w = new World();
        var a = w.Ca("one", TenantA);
        w.Ca("other", TenantA);
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = w.UserId, Capability = Capabilities.SystemManage, CertificateAuthorityId = a.Id });
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Empty(result.System);
        Assert.Equal(new[] { Capabilities.SystemManage }, result.Cas.Single().Capabilities);
    }

    [Fact]
    public async Task Resource_scoped_grants_and_other_users_grants_are_ignored()
    {
        var w = new World();
        var a = w.Ca("one", TenantA);
        var g = w.Group(TenantA, caId: a.Id);
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = Capabilities.ProfileUse, ResourceType = "CertProfile", ResourceId = Guid.NewGuid() });
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), Capability = Capabilities.CaManage });
        w.Db.RoleAssignments.Add(new RoleAssignmentEntity { Id = Guid.NewGuid(), UserId = w.UserId, RoleId = w.Role().Id });
        await w.Db.SaveChangesAsync();

        var result = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);

        Assert.Equal(EffectiveCapabilities.None.System, result.System);
        Assert.Empty(result.Cas);
    }
}
