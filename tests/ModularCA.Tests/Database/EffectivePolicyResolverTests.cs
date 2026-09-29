using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The one place a scope's CA policy is read. A null tenant is the instance and gets the
/// instance's own values; a space gets its own; nothing merges; and there is never "no policy",
/// which is what let a null tenant skip a ceremony or a ceiling before the fold.
/// </summary>
public class EffectivePolicyResolverTests
{
    [Fact]
    public async Task The_instance_gets_its_own_values_and_a_space_its_own()
    {
        using var db = InMemoryDbContextFactory.Create();
        var space = new TenantEntity { Name = "Acme", Slug = "acme", RequireKeyCeremony = false, CeremonyRequiredApprovals = 2, MaxValidityDays = 825, ValidityCeilingBehavior = ValidityCeilingBehavior.Refuse };
        db.Tenants.Add(space);
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 3, MaxValidityDays = 0, UserCeremonyRequiredApprovals = 2 });
        db.SaveChanges();
        var resolver = new EffectivePolicyResolver(db);

        var instance = await resolver.ResolveAsync(null);
        Assert.True(instance.Found);
        Assert.Null(instance.TenantId);
        Assert.Equal(EffectivePolicy.InstanceScope, instance.Scope);
        Assert.Equal("the instance", instance.Describe());
        Assert.True(instance.RequireKeyCeremony);
        Assert.Equal(3, instance.CeremonyRequiredApprovals);
        Assert.Equal(0, instance.MaxValidityDays);
        Assert.Equal(2, instance.UserCeremonyRequiredApprovals);

        var own = await resolver.ResolveAsync(space.Id);
        Assert.Equal("tenant 'Acme'", own.Describe());
        Assert.False(own.RequireKeyCeremony);
        Assert.Equal(2, own.CeremonyRequiredApprovals);
        Assert.Equal(825, own.MaxValidityDays);
        Assert.Equal(ValidityCeilingBehavior.Refuse, own.ValidityCeilingBehavior);
        Assert.Null(own.UserCeremonyRequiredApprovals);
    }

    [Fact]
    public async Task With_no_policy_row_the_instance_gets_the_strict_defaults_not_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();

        var instance = await new EffectivePolicyResolver(db).ResolveAsync(null);

        Assert.True(instance.Found);
        Assert.True(instance.RequireKeyCeremony);
        Assert.Equal(2, instance.CeremonyRequiredApprovals);
    }

    [Fact]
    public async Task An_unknown_or_soft_deleted_space_is_reported_not_found_with_strict_values()
    {
        using var db = InMemoryDbContextFactory.Create();
        var gone = new TenantEntity { Name = "Gone", Slug = "gone", IsDeleted = true, RequireKeyCeremony = false };
        db.Tenants.Add(gone);
        db.SaveChanges();
        var resolver = new EffectivePolicyResolver(db);

        foreach (var id in new[] { Guid.NewGuid(), gone.Id })
        {
            var policy = await resolver.ResolveAsync(id);
            Assert.False(policy.Found);
            Assert.False(policy.IsEnabled);
            Assert.True(policy.RequireKeyCeremony);
        }
    }

    [Fact]
    public async Task A_ca_with_no_tenant_resolves_to_the_instance_and_an_unknown_ca_to_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", TenantId = null };
        db.CertificateAuthorities.Add(ca);
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = false });
        db.SaveChanges();
        var resolver = new EffectivePolicyResolver(db);

        var policy = await resolver.ResolveForCaAsync(ca.Id);
        Assert.NotNull(policy);
        Assert.Null(policy!.TenantId);
        Assert.False(policy.RequireKeyCeremony);
        Assert.Null(await resolver.ResolveForCaAsync(Guid.NewGuid()));
    }
}
