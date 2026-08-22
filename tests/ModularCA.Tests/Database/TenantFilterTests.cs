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
        public Guid? UserId { get; private set; }

        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin)
        {
            UserId = userId;
            AccessibleTenantIds = accessibleTenantIds ?? new HashSet<Guid>();
            IsSystemAdmin = isSystemAdmin;
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
}
