using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// From 0.4.0 S4 the only global query filters are soft-delete ones: every read sees every
/// space, so isolation is the explicit <see cref="TenantFence"/>. Pins that the filters hide
/// deleted CAs and tenants, that they name no tenant, that the fence's translatable predicates
/// give the visibility the filter used to, and that a profile's inheritance parent is fenced
/// explicitly (N3).
/// </summary>
public class TenantFilterTests
{
    private static readonly Guid TenantA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");
    private static readonly Guid InstanceBoundProfile = Guid.Parse("cccccccc-0000-0000-0000-000000000003");

    /// <summary>Seeds a CA and a profile in each of two spaces, an instance CA with a profile bound to it, and an unbound profile.</summary>
    private static string Seed()
    {
        var dbName = $"tenant-filter-{Guid.NewGuid():N}";
        using var seed = InMemoryDbContextFactory.Create(dbName);
        var instanceCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", TenantId = null };
        seed.Tenants.AddRange(new TenantEntity { Id = TenantA, Name = "A", Slug = "a" }, new TenantEntity { Id = TenantB, Name = "B", Slug = "b" });
        seed.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ca-a", Label = "ca-a", TenantId = TenantA },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ca-b", Label = "ca-b", TenantId = TenantB },
            instanceCa);
        seed.CertProfiles.AddRange(
            new CertProfileEntity { Id = InstanceBoundProfile, Name = "instance-bound", TenantId = null, CertificateAuthorityId = instanceCa.Id },
            new CertProfileEntity { Name = "instance-wide", TenantId = null, CertificateAuthorityId = null },
            new CertProfileEntity { Name = "space-a", TenantId = TenantA },
            new CertProfileEntity { Name = "space-b", TenantId = TenantB });
        seed.SaveChanges();
        return dbName;
    }

    [Fact]
    public void Deleted_cas_and_tenants_stay_hidden()
    {
        var dbName = Seed();
        using (var db = InMemoryDbContextFactory.Create(dbName))
        {
            db.CertificateAuthorities.Single(c => c.Label == "ca-b").IsDeleted = true;
            db.Tenants.Single(t => t.Id == TenantB).IsDeleted = true;
            db.SaveChanges();
        }

        using var read = InMemoryDbContextFactory.Create(dbName);
        Assert.Equal(["ca-a", "system-signing-ca"], read.CertificateAuthorities.Select(c => c.Label!).OrderBy(l => l).ToList());
        Assert.Equal([TenantA], read.Tenants.Select(t => t.Id).ToList());
        Assert.Equal(3, read.CertificateAuthorities.IgnoreQueryFilters().Count());
        Assert.Equal(2, read.Tenants.IgnoreQueryFilters().Count());
    }

    /// <summary>
    /// A context in an authenticated request sees both spaces through the DbSet: there is
    /// nothing behind the fences any more, which is why every list applies one.
    /// </summary>
    [Fact]
    public void Every_space_is_visible_through_the_DbSet()
    {
        using var db = InMemoryDbContextFactory.Create(Seed());
        Assert.Equal(["ca-a", "ca-b", "system-signing-ca"], db.CertificateAuthorities.Select(c => c.Label!).OrderBy(l => l).ToList());
        Assert.Equal(4, db.CertProfiles.Count());
        Assert.Equal(2, db.Tenants.Count());
    }

    [Fact]
    public void The_model_filters_are_soft_delete_only_and_name_no_tenant()
    {
        using var db = InMemoryDbContextFactory.Create();
        var filtered = db.Model.GetEntityTypes()
            .SelectMany(e => e.GetDeclaredQueryFilters().Select(f => (Entity: e.ClrType.Name, Expression: f.Expression!.ToString())))
            .ToList();

        Assert.Equal(["CertificateAuthorityEntity", "TenantEntity", "UserEntity"], filtered.Select(f => f.Entity).OrderBy(n => n).ToList());
        Assert.All(filtered, f =>
        {
            Assert.DoesNotContain("TenantId", f.Expression);
            Assert.Contains("IsDeleted", f.Expression);
        });
    }

    /// <summary>
    /// The fence's predicate gives what the filter used to: an instance CA needs instance scope,
    /// a space's CAs need the space, and an instance-wide fence sees all.
    /// </summary>
    [Theory]
    [InlineData(true, false, false, new[] { "system-signing-ca" })]
    [InlineData(true, true, false, new[] { "ca-a", "system-signing-ca" })]
    [InlineData(false, true, false, new[] { "ca-a" })]
    [InlineData(false, false, false, new string[0])]
    [InlineData(false, false, true, new[] { "ca-a", "ca-b", "system-signing-ca" })]
    public void Instance_cas_follow_instance_scope(bool instanceScope, bool memberOfA, bool instanceWide, string[] expected)
    {
        using var db = InMemoryDbContextFactory.Create(Seed());
        var fence = TenantFence.Of(memberOfA ? [TenantA] : [], instanceScope,
            systemCapabilities: instanceWide ? [ModularCA.Shared.Authorization.Capabilities.CertView] : null)
            .For(ModularCA.Shared.Authorization.Capabilities.CertView);
        Assert.Equal(expected, db.CertificateAuthorities.Where(fence.Predicate<CertificateAuthorityEntity>(c => c.TenantId))
            .Select(c => c.Label!).OrderBy(l => l).ToList());
    }

    /// <summary>
    /// An unbound profile (no space, no CA) is visible to every caller; one bound to an instance
    /// CA follows instance scope, and a space's follows the space.
    /// </summary>
    [Theory]
    [InlineData(false, false, new[] { "instance-wide" })]
    [InlineData(false, true, new[] { "instance-wide", "space-a" })]
    [InlineData(true, false, new[] { "instance-bound", "instance-wide" })]
    [InlineData(true, true, new[] { "instance-bound", "instance-wide", "space-a" })]
    public void A_profile_bound_to_an_instance_ca_follows_instance_scope(bool instanceScope, bool memberOfA, string[] expected)
    {
        using var db = InMemoryDbContextFactory.Create(Seed());
        var fence = TenantFence.Of(memberOfA ? [TenantA] : [], instanceScope);
        Assert.Equal(expected, db.CertProfiles.Where(fence.ProfilePredicate<CertProfileEntity>(p => p.TenantId, p => p.CertificateAuthorityId))
            .Select(p => p.Name).OrderBy(n => n).ToList());
        Assert.All(db.CertProfiles.ToList(), p => Assert.Equal(expected.Contains(p.Name), fence.AllowsProfile(p.TenantId, p.CertificateAuthorityId)));
    }

    /// <summary>
    /// A profile cannot inherit from a parent outside the caller's fence: a space member without
    /// instance scope naming a profile bound to an instance CA, or another space's profile, is
    /// refused as not found, on create and update.
    /// </summary>
    [Fact]
    public async Task An_inheritance_parent_the_caller_cannot_see_is_refused()
    {
        using var db = InMemoryDbContextFactory.Create(Seed());
        var fence = TenantFence.Of([TenantA], instanceScope: false);
        var service = new ModularCA.Core.Services.CertProfileService(db);
        var spaceB = db.CertProfiles.Single(p => p.Name == "space-b");

        foreach (var parent in new[] { InstanceBoundProfile, spaceB.Id })
            await Assert.ThrowsAsync<ModularCA.Shared.Errors.ResourceNotFoundException>(() => service.CreateAsync(
                new ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest { Name = "child", InheritsFromId = parent, InheritanceEnabled = true }, TenantA, fence.AllowsProfile));

        var spaceProfile = db.CertProfiles.Single(p => p.Name == "space-a");
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ResourceNotFoundException>(() => service.UpdateAsync(spaceProfile.Id,
            new ModularCA.Shared.Models.CertProfiles.UpdateCertProfileRequest { Name = "space-a", InheritsFromId = InstanceBoundProfile, InheritanceEnabled = true }, fence.AllowsProfile));

        var wide = db.CertProfiles.Single(p => p.Name == "instance-wide");
        var child = await service.CreateAsync(
            new ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest { Name = "child", InheritsFromId = wide.Id, InheritanceEnabled = true }, TenantA, fence.AllowsProfile);
        Assert.Equal(wide.Id, child.InheritsFromId);
    }

    /// <summary>
    /// A parent the caller can see must still be in the child's own scope, or instance-wide: a
    /// caller in two spaces cannot make one space's profile inherit from the other's, a space
    /// profile cannot inherit from one bound to an instance CA, and a CA-bound parent must be
    /// bound to the child's own CA.
    /// </summary>
    [Fact]
    public async Task An_inheritance_parent_from_another_scope_is_refused_even_when_visible()
    {
        using var db = InMemoryDbContextFactory.Create(Seed());
        var fence = TenantFence.Of([TenantA, TenantB], instanceScope: true);
        var service = new ModularCA.Core.Services.CertProfileService(db);
        var spaceA = db.CertProfiles.Single(p => p.Name == "space-a");
        var instanceCa = db.CertificateAuthorities.Single(c => c.Label == "system-signing-ca").Id;
        ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest Child(Guid parent, Guid? ca = null) =>
            new() { Name = "child", InheritsFromId = parent, InheritanceEnabled = true, CertificateAuthorityId = ca };

        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(spaceA.Id), TenantB, fence.AllowsProfile));
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(spaceA.Id), null, fence.AllowsProfile));
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(InstanceBoundProfile), TenantA, fence.AllowsProfile));
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(InstanceBoundProfile), null, fence.AllowsProfile));

        var spaceB = db.CertProfiles.Single(p => p.Name == "space-b");
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.UpdateAsync(spaceB.Id,
            new ModularCA.Shared.Models.CertProfiles.UpdateCertProfileRequest { Name = "space-b", InheritsFromId = spaceA.Id, InheritanceEnabled = true }, fence.AllowsProfile));

        Assert.Equal(spaceA.Id, (await service.CreateAsync(Child(spaceA.Id), TenantA, fence.AllowsProfile)).InheritsFromId);
        Assert.Equal(InstanceBoundProfile, (await service.CreateAsync(Child(InstanceBoundProfile, instanceCa), null, fence.AllowsProfile)).InheritsFromId);
    }
}
