using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// After 0.4.0 S3 a null tenant means instance scope. It must never widen privilege: a
/// non-system group with neither tenant nor CA confers nothing (and never system scope), the
/// instance is administered only at system scope, and seeing instance CAs follows membership of
/// an instance group, as membership of a System-tenant group did.
/// </summary>
public class InstanceScopeTests
{
    private static readonly Guid Space = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Service => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public Guid UserId { get; } = Guid.NewGuid();

        public CaGroupEntity Group(Guid? tenantId, Guid? caId = null, bool system = false, string? template = null)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", TenantId = tenantId, CertificateAuthorityId = caId, IsSystemGroup = system, TemplateName = template };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = UserId });
            return g;
        }

        public void Grant(CaGroupEntity g, string capability)
            => Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = capability });
    }

    [Fact]
    public void A_non_system_group_with_no_tenant_and_no_ca_confers_no_tier()
    {
        Assert.Null(ControlledTierResolver.TierForGroupCapability(Capabilities.SystemManage, isSystemGroup: false, groupTenantId: null, groupCaId: null));
        Assert.Null(ControlledTierResolver.TierForGroupCapability(Capabilities.CaManage, isSystemGroup: false, groupTenantId: null, groupCaId: null));

        var system = ControlledTierResolver.TierForGroupCapability(Capabilities.SystemManage, isSystemGroup: true, groupTenantId: null, groupCaId: null);
        Assert.Equal(ControlledTierLevel.SystemAdmin, system!.Value.Level);

        var instanceCa = Guid.NewGuid();
        var caAdmin = ControlledTierResolver.TierForGroupCapability(Capabilities.SystemManage, isSystemGroup: false, groupTenantId: null, groupCaId: instanceCa);
        Assert.Equal(ControlledTierLevel.CaAdmin, caAdmin!.Value.Level);
        Assert.Equal(instanceCa, caAdmin.Value.CaId);
        Assert.Null(caAdmin.Value.TenantId);
    }

    [Fact]
    public void Changing_such_a_group_is_gated_at_the_system_tier()
    {
        var stray = new CaGroupEntity { Name = "stray", TemplateName = "Administrator", TenantId = null, CertificateAuthorityId = null, IsSystemGroup = false };
        Assert.Equal(ControlledTierLevel.SystemAdmin, ControlledGroupClassifier.Classify(stray)!.Value.Level);
        Assert.Null(ControlledGroupClassifier.Classify(new CaGroupEntity { Name = "r", TemplateName = "Requester", TenantId = null }));
    }

    [Fact]
    public async Task A_stray_group_with_system_manage_is_not_a_system_admin_and_sees_no_tenant()
    {
        var w = new World();
        w.Grant(w.Group(null, template: "Administrator"), Capabilities.SystemManage);
        await w.Db.SaveChangesAsync();

        Assert.False(await w.Service.IsSystemAdminAsync(w.UserId));
        Assert.Empty(await w.Service.GetTenantIdsWithCapabilityAsync(w.UserId, Capabilities.SystemManage));
        var effective = await w.Service.GetEffectiveCapabilitiesAsync(w.UserId);
        Assert.Empty(effective.System);
        Assert.Empty(effective.Tenants);
        Assert.Empty(await ControlledTierResolver.GetUserTiersAsync(w.Db, w.UserId));
    }

    [Fact]
    public async Task The_instance_is_administered_at_system_scope_only()
    {
        var w = new World();
        w.Grant(w.Group(Space), Capabilities.CaManage);
        await w.Db.SaveChangesAsync();
        Assert.True(await w.Service.HasScopeCapabilityAsync(w.UserId, Space, Capabilities.CaManage));
        Assert.False(await w.Service.HasScopeCapabilityAsync(w.UserId, null, Capabilities.CaManage));

        var system = new World();
        system.Grant(system.Group(null, system: true, template: "Operator"), Capabilities.CaManage);
        await system.Db.SaveChangesAsync();
        Assert.True(await system.Service.HasScopeCapabilityAsync(system.UserId, null, Capabilities.CaManage));
    }

    [Fact]
    public async Task An_instance_ca_is_reported_with_no_tenant()
    {
        var w = new World();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", TenantId = null };
        w.Db.CertificateAuthorities.Add(ca);
        w.Grant(w.Group(null, caId: ca.Id, template: "Auditor"), Capabilities.AuditView);
        await w.Db.SaveChangesAsync();

        var entry = Assert.Single((await w.Service.GetEffectiveCapabilitiesAsync(w.UserId)).Cas);
        Assert.Null(entry.TenantId);
        Assert.Equal(string.Empty, entry.TenantName);
        Assert.Equal(string.Empty, entry.TenantSlug);
        Assert.Contains(Capabilities.AuditView, entry.Capabilities);
    }

    /// <summary>
    /// A system auditor holds audit.view at system scope, so their fence is instance-wide for that
    /// capability: they see every space's audit views (owner decision Q1), but no operator
    /// configuration through a capability they hold nowhere. An instance CA's auditor has instance
    /// scope only, and an organisation operator their space only.
    /// </summary>
    [Fact]
    public async Task A_system_auditor_sees_every_space_and_an_organisation_operator_only_theirs()
    {
        var auditor = new World();
        auditor.Grant(auditor.Group(null, system: true, template: "Auditor"), Capabilities.AuditView);
        await auditor.Db.SaveChangesAsync();
        var auditorFence = await auditor.Service.GetFenceAsync(auditor.UserId);
        Assert.True(auditorFence.InstanceWideFor(Capabilities.AuditView));
        Assert.False(auditorFence.InstanceWide);
        Assert.False(auditorFence.IsSystemAdmin);
        Assert.True(auditorFence.For(Capabilities.AuditView).Allows(Space));
        Assert.True(auditorFence.For(Capabilities.AuditView).Allows(null));
        Assert.False(auditorFence.For(Capabilities.CertRevoke).Allows(Space));
        Assert.False(auditorFence.For(Capabilities.CertRevoke).Allows(null));

        var signingCaAuditor = new World();
        signingCaAuditor.Grant(signingCaAuditor.Group(null, caId: Guid.NewGuid(), template: "Auditor"), Capabilities.CertView);
        await signingCaAuditor.Db.SaveChangesAsync();
        var signingFence = await signingCaAuditor.Service.GetFenceAsync(signingCaAuditor.UserId);
        Assert.False(signingFence.InstanceWideFor(Capabilities.CertView));
        Assert.True(signingFence.Allows(null));
        Assert.False(signingFence.Allows(Space));

        var orgOperator = new World();
        orgOperator.Grant(orgOperator.Group(Space, template: "Operator"), Capabilities.CertRevoke);
        await orgOperator.Db.SaveChangesAsync();
        var operatorFence = await orgOperator.Service.GetFenceAsync(orgOperator.UserId);
        Assert.False(operatorFence.Allows(null));
        Assert.Equal([Space], operatorFence.TenantIds);
    }

    [Fact]
    public async Task A_stray_null_tenant_group_that_is_neither_system_nor_an_instance_cas_confers_no_instance_scope()
    {
        var stray = new World();
        stray.Group(null);
        await stray.Db.SaveChangesAsync();
        var fence = await stray.Service.GetFenceAsync(stray.UserId);
        Assert.True(fence.IsEmpty);

        var withSpace = new World();
        withSpace.Group(null);
        withSpace.Group(Space);
        await withSpace.Db.SaveChangesAsync();
        var spaceFence = await withSpace.Service.GetFenceAsync(withSpace.UserId);
        Assert.False(spaceFence.Allows(null));
        Assert.Equal([Space], spaceFence.TenantIds);
    }

    [Theory]
    [InlineData(true, false, new[] { "instance-ca" })]
    [InlineData(false, true, new[] { "space-ca" })]
    [InlineData(true, true, new[] { "instance-ca", "space-ca" })]
    [InlineData(false, false, new string[0])]
    public void The_fence_admits_instance_rows_only_with_instance_scope(bool instanceScope, bool inSpace, string[] expected)
    {
        var fence = TenantFence.Of(inSpace ? [Space] : [], instanceScope);
        var rows = new[]
        {
            new CertificateAuthorityEntity { Label = "instance-ca", TenantId = null },
            new CertificateAuthorityEntity { Label = "space-ca", TenantId = Space },
            new CertificateAuthorityEntity { Label = "other-ca", TenantId = Guid.NewGuid() },
        };

        Assert.Equal(expected, rows.AsQueryable().Where(fence.Predicate<CertificateAuthorityEntity>(c => c.TenantId)).Select(c => c.Label).ToArray());
        Assert.Equal(expected, rows.Where(c => fence.Allows(c.TenantId)).Select(c => c.Label).ToArray());
        Assert.True(TenantFence.Of([], false, isSystemAdmin: true).Allows(null));
        var auditor = TenantFence.Of([], false, systemCapabilities: [Capabilities.CertView]);
        Assert.True(auditor.For(Capabilities.CertView).Allows(Guid.NewGuid()));
        Assert.False(auditor.For(Capabilities.CertRevoke).Allows(Guid.NewGuid()));
        Assert.False(auditor.Allows(Guid.NewGuid()));
        Assert.True(TenantFence.None.IsEmpty);
    }

    [Fact]
    public async Task The_fence_translates_against_the_database_for_groups()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CaGroups.AddRange(
            new CaGroupEntity { Name = "system-auditor", IsSystemGroup = true, TenantId = null },
            new CaGroupEntity { Name = "org-acme-operator", TenantId = Space });
        await db.SaveChangesAsync();

        var names = db.CaGroups.Where(TenantFence.Of([Space], instanceScope: false).Predicate<CaGroupEntity>(g => g.TenantId)).Select(g => g.Name).ToList();

        Assert.Equal(["org-acme-operator"], names);
    }
}
