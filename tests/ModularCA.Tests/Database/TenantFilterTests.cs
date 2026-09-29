using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Covers the EF global tenant filter, and specifically the ordering hazard that disabled it
/// entirely on every authenticated request.
/// <para>
/// <c>TenantResolutionMiddleware</c> takes <c>ModularCADbContext</c> as a method-injected
/// parameter, so DI constructs the scoped context <em>before</em> the middleware body runs and
/// therefore before it calls <see cref="ITenantContext.Set"/>. When the context snapshotted
/// "should I bypass the filter?" into a readonly field in its constructor, that snapshot was
/// taken while <c>HasContext</c> was still false — so it latched to "bypass" and, because the
/// context is scoped, every downstream controller and service reused that same unfenced
/// instance. Every test here populates the tenant context <em>after</em> construction, which is
/// what production does.
/// </para>
/// </summary>
public class TenantFilterTests
{
    /// <summary>Mutable stand-in for the API's scoped TenantContext (not referenced from this project).</summary>
    private sealed class MutableTenantContext : ITenantContext
    {
        public bool HasContext { get; private set; }
        public bool IsSystemAdmin { get; private set; }
        public IReadOnlySet<Guid> AccessibleTenantIds { get; private set; } = new HashSet<Guid>();
        public bool HasInstanceScope { get; private set; }
        public Guid? UserId { get; private set; }

        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin, bool hasInstanceScope = false)
        {
            UserId = userId;
            AccessibleTenantIds = accessibleTenantIds ?? new HashSet<Guid>();
            IsSystemAdmin = isSystemAdmin;
            HasInstanceScope = isSystemAdmin || hasInstanceScope;
            HasContext = true;
        }
    }

    private static readonly Guid TenantA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");

    private static ModularCADbContext BuildContext(ITenantContext tenantContext, string dbName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(
                Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options, tenantContext);
    }

    /// <summary>Seeds one CA in each of two tenants, through an unfenced context.</summary>
    private static string SeedTwoTenants()
    {
        var dbName = $"tenant-filter-{Guid.NewGuid():N}";
        using var seed = BuildContext(new MutableTenantContext(), dbName);
        seed.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ca-a", Label = "ca-a", TenantId = TenantA },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ca-b", Label = "ca-b", TenantId = TenantB });
        seed.SaveChanges();
        return dbName;
    }

    /// <summary>
    /// The regression. Populating the tenant context after construction — exactly what the
    /// middleware does — must still fence the query. Against the previous field-snapshot
    /// implementation this returned both CAs.
    /// </summary>
    [Fact]
    public void Context_populated_after_construction_still_fences_queries()
    {
        var dbName = SeedTwoTenants();
        var tenantContext = new MutableTenantContext();

        using var db = BuildContext(tenantContext, dbName);

        // Construction happened first; the middleware resolves memberships only now.
        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid> { TenantA }, isSystemAdmin: false);

        var visible = db.CertificateAuthorities.Select(c => c.Label).ToList();

        Assert.Equal(new[] { "ca-a" }, visible);
    }

    /// <summary>A system admin legitimately sees across tenants.</summary>
    [Fact]
    public void System_admin_sees_every_tenant()
    {
        var dbName = SeedTwoTenants();
        var tenantContext = new MutableTenantContext();

        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid> { TenantA }, isSystemAdmin: true);

        Assert.Equal(2, db.CertificateAuthorities.Count());
    }

    /// <summary>
    /// Background jobs, migrations, and anonymous public routes (CRL, OCSP, ACME) run with an
    /// unresolved context and must keep seeing every row.
    /// </summary>
    [Fact]
    public void Unresolved_context_sees_every_tenant()
    {
        var dbName = SeedTwoTenants();
        using var db = BuildContext(new MutableTenantContext(), dbName);

        Assert.Equal(2, db.CertificateAuthorities.Count());
    }

    /// <summary>
    /// A caller with memberships in neither tenant sees nothing — the filter must fail closed
    /// rather than falling back to "allow all" when the accessible set is empty.
    /// </summary>
    [Fact]
    public void Caller_with_no_memberships_sees_nothing()
    {
        var dbName = SeedTwoTenants();
        var tenantContext = new MutableTenantContext();

        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid>(), isSystemAdmin: false);

        Assert.Empty(db.CertificateAuthorities.ToList());
    }

    /// <summary>
    /// The filter is consulted per query, not once per context, so a context that has already
    /// served a query still reflects the caller it was populated with.
    /// </summary>
    [Fact]
    public void Filter_is_evaluated_per_query()
    {
        var dbName = SeedTwoTenants();
        var tenantContext = new MutableTenantContext();

        using var db = BuildContext(tenantContext, dbName);

        // First query runs while unresolved — infra semantics, sees everything.
        Assert.Equal(2, db.CertificateAuthorities.Count());

        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid> { TenantB }, isSystemAdmin: false);

        Assert.Equal(new[] { "ca-b" }, db.CertificateAuthorities.Select(c => c.Label).ToList());
    }

    /// <summary>Seeds one space CA, one instance CA (no tenant) and a profile bound to the instance CA.</summary>
    private static string SeedSpaceAndInstance()
    {
        var dbName = $"tenant-filter-{Guid.NewGuid():N}";
        using var seed = BuildContext(new MutableTenantContext(), dbName);
        var instanceCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", TenantId = null };
        seed.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ca-a", Label = "ca-a", TenantId = TenantA },
            instanceCa);
        seed.CertProfiles.Add(new CertProfileEntity { Id = InstanceBoundProfile, Name = "instance-bound", TenantId = null, CertificateAuthorityId = instanceCa.Id });
        seed.CertProfiles.Add(new CertProfileEntity { Name = "instance-wide", TenantId = null, CertificateAuthorityId = null });
        seed.CertProfiles.Add(new CertProfileEntity { Name = "space-a", TenantId = TenantA });
        seed.SaveChanges();
        return dbName;
    }

    private static readonly Guid InstanceBoundProfile = Guid.Parse("cccccccc-0000-0000-0000-000000000003");

    /// <summary>
    /// A system-auditor (a system group: no tenant) keeps seeing the system signing CA after the
    /// fold, as membership of the System tenant's group let them before; the space's CAs follow
    /// their own memberships.
    /// </summary>
    [Theory]
    [InlineData(true, false, new[] { "system-signing-ca" })]
    [InlineData(true, true, new[] { "ca-a", "system-signing-ca" })]
    [InlineData(false, true, new[] { "ca-a" })]
    [InlineData(false, false, new string[0])]
    public void Instance_cas_follow_instance_scope(bool instanceScope, bool memberOfA, string[] expected)
    {
        var dbName = SeedSpaceAndInstance();
        var tenantContext = new MutableTenantContext();
        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), memberOfA ? new HashSet<Guid> { TenantA } : new HashSet<Guid>(), isSystemAdmin: false, hasInstanceScope: instanceScope);

        Assert.Equal(expected, db.CertificateAuthorities.Select(c => c.Label).OrderBy(l => l).ToList());
    }

    /// <summary>
    /// An instance-wide profile (no tenant, no CA) stays visible to every caller: it is
    /// configuration only. One bound to an instance CA follows instance scope, as the CA does.
    /// </summary>
    [Theory]
    [InlineData(false, false, new[] { "instance-wide" })]
    [InlineData(false, true, new[] { "instance-wide", "space-a" })]
    [InlineData(true, false, new[] { "instance-bound", "instance-wide" })]
    [InlineData(true, true, new[] { "instance-bound", "instance-wide", "space-a" })]
    public void A_profile_bound_to_an_instance_ca_follows_instance_scope(bool instanceScope, bool memberOfA, string[] expected)
    {
        var dbName = SeedSpaceAndInstance();
        var tenantContext = new MutableTenantContext();
        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), memberOfA ? new HashSet<Guid> { TenantA } : new HashSet<Guid>(), isSystemAdmin: false, hasInstanceScope: instanceScope);

        Assert.Equal(expected, db.CertProfiles.Select(p => p.Name).OrderBy(n => n).ToList());
    }

    /// <summary>
    /// A profile cannot inherit from a parent the caller cannot see: a space member without
    /// instance scope naming a profile bound to an instance CA is refused, on create and update.
    /// </summary>
    [Fact]
    public async Task An_inheritance_parent_the_caller_cannot_see_is_refused()
    {
        var dbName = SeedSpaceAndInstance();
        var tenantContext = new MutableTenantContext();
        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid> { TenantA }, isSystemAdmin: false, hasInstanceScope: false);
        var service = new ModularCA.Core.Services.CertProfileService(db);

        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ResourceNotFoundException>(() => service.CreateAsync(
            new ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest { Name = "child", InheritsFromId = InstanceBoundProfile, InheritanceEnabled = true }, TenantA));

        var spaceProfile = db.CertProfiles.Single(p => p.Name == "space-a");
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ResourceNotFoundException>(() => service.UpdateAsync(spaceProfile.Id,
            new ModularCA.Shared.Models.CertProfiles.UpdateCertProfileRequest { Name = "space-a", InheritsFromId = InstanceBoundProfile, InheritanceEnabled = true }));

        var wide = db.CertProfiles.Single(p => p.Name == "instance-wide");
        var child = await service.CreateAsync(
            new ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest { Name = "child", InheritsFromId = wide.Id, InheritanceEnabled = true }, TenantA);
        Assert.Equal(wide.Id, child.InheritsFromId);
    }

    /// <summary>
    /// A parent the caller can see must still be in the child's own scope, or instance-wide: a
    /// caller in two spaces cannot make one space's profile inherit from the other's, and a space
    /// profile cannot inherit from one bound to an instance CA, on create or update.
    /// </summary>
    [Fact]
    public async Task An_inheritance_parent_from_another_scope_is_refused_even_when_visible()
    {
        var dbName = SeedSpaceAndInstance();
        var tenantContext = new MutableTenantContext();
        using var db = BuildContext(tenantContext, dbName);
        tenantContext.Set(Guid.NewGuid(), new HashSet<Guid> { TenantA, TenantB }, isSystemAdmin: false, hasInstanceScope: true);
        var service = new ModularCA.Core.Services.CertProfileService(db);
        var spaceA = db.CertProfiles.Single(p => p.Name == "space-a");
        ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest Child(Guid parent) => new() { Name = "child", InheritsFromId = parent, InheritanceEnabled = true };

        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(spaceA.Id), TenantB));
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(spaceA.Id), null));
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.CreateAsync(Child(InstanceBoundProfile), TenantA));

        var spaceB = await service.CreateAsync(new ModularCA.Shared.Models.CertProfiles.CreateCertProfileRequest { Name = "space-b" }, TenantB);
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(() => service.UpdateAsync(spaceB.Id,
            new ModularCA.Shared.Models.CertProfiles.UpdateCertProfileRequest { Name = "space-b", InheritsFromId = spaceA.Id, InheritanceEnabled = true }));

        Assert.Equal(spaceA.Id, (await service.CreateAsync(Child(spaceA.Id), TenantA)).InheritsFromId);
        Assert.Equal(InstanceBoundProfile, (await service.CreateAsync(Child(InstanceBoundProfile), null)).InheritsFromId);
    }
}
