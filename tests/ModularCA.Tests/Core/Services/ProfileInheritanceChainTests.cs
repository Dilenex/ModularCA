using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Inheritance clamps a profile against its parent's effective values, the whole chain up, not
/// against the parent's stored row. Resolution used to look one level up only, so a grandchild
/// under a middle profile that left a field unset, or stored one looser than its own parent
/// allowed, came out looser than the grandparent.
/// </summary>
public sealed class ProfileInheritanceChainTests
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string CodeSigning = "1.3.6.1.5.5.7.3.3";

    private static ProfileResolutionService Service(ModularCADbContext db) => new(db, NullLogger<ProfileResolutionService>.Instance);

    private static string Json(params string[] items) => JsonSerializer.Serialize(items);

    private static List<string> List(string json) => JsonSerializer.Deserialize<List<string>>(json) ?? [];

    /// <summary>A grandparent, a middle profile inheriting from it, and a child inheriting from the middle.</summary>
    private static (CertProfileEntity Grandparent, CertProfileEntity Middle, CertProfileEntity Child) CertChain(
        ModularCADbContext db, Action<CertProfileEntity> grandparent, Action<CertProfileEntity> middle, Action<CertProfileEntity> child)
    {
        var g = new CertProfileEntity { Id = Guid.NewGuid(), Name = "system-baseline" };
        grandparent(g);
        var m = new CertProfileEntity { Id = Guid.NewGuid(), Name = "space-profile", InheritanceEnabled = true, InheritsFromId = g.Id };
        middle(m);
        var c = new CertProfileEntity { Id = Guid.NewGuid(), Name = "ca-profile", InheritanceEnabled = true, InheritsFromId = m.Id };
        child(c);
        db.CertProfiles.AddRange(g, m, c);
        db.SaveChanges();
        return (g, m, c);
    }

    [Fact]
    public async Task Validity_is_clamped_by_the_grandparent_when_the_middle_leaves_it_unset()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db, g => g.ValidityPeriodMax = "P90D", m => m.ValidityPeriodMax = null, c => c.ValidityPeriodMax = "P365D");

        Assert.Equal("P90D", (await Service(db).ResolveCertProfileAsync(child.Id)).ValidityPeriodMax);
    }

    [Fact]
    public async Task Validity_is_clamped_by_the_grandparent_when_the_middle_stores_a_looser_value()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, middle, child) = CertChain(db, g => g.ValidityPeriodMax = "P90D", m => m.ValidityPeriodMax = "P400D", c => c.ValidityPeriodMax = "P200D");

        Assert.Equal("P90D", (await Service(db).ResolveCertProfileAsync(middle.Id)).ValidityPeriodMax);
        Assert.Equal("P90D", (await Service(db).ResolveCertProfileAsync(child.Id)).ValidityPeriodMax);
    }

    [Fact]
    public async Task Validity_minimum_is_held_by_the_grandparent()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db, g => g.ValidityPeriodMin = "P7D", m => m.ValidityPeriodMin = null, c => c.ValidityPeriodMin = "P1D");

        Assert.Equal("P7D", (await Service(db).ResolveCertProfileAsync(child.Id)).ValidityPeriodMin);
    }

    [Fact]
    public async Task Key_sizes_are_clamped_by_the_grandparent_when_the_middle_leaves_them_unset()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db,
            g => g.AllowedKeySizes = Json("2048", "3072"),
            m => m.AllowedKeySizes = "[]",
            c => c.AllowedKeySizes = Json("1024", "2048"));

        Assert.Equal(["2048"], List((await Service(db).ResolveCertProfileAsync(child.Id)).AllowedKeySizes));
    }

    [Fact]
    public async Task Extended_key_usages_are_clamped_by_the_grandparent_when_the_middle_leaves_them_unset()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db,
            g => g.ExtendedKeyUsages = Json(ServerAuth),
            m => m.ExtendedKeyUsages = "[]",
            c => c.ExtendedKeyUsages = Json(ServerAuth, CodeSigning));

        Assert.Equal([ServerAuth], List((await Service(db).ResolveCertProfileAsync(child.Id)).ExtendedKeyUsages));
    }

    [Fact]
    public async Task A_child_that_sets_nothing_inherits_the_grandparents_values_through_an_unset_middle()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db,
            g => { g.ValidityPeriodMax = "P90D"; g.AllowedKeySizes = Json("3072"); g.ExtendedKeyUsages = Json(ServerAuth); g.CtEnabled = true; },
            m => { },
            c => { });

        var effective = await Service(db).ResolveCertProfileAsync(child.Id);

        Assert.Equal("P90D", effective.ValidityPeriodMax);
        Assert.Equal(["3072"], List(effective.AllowedKeySizes));
        Assert.Equal([ServerAuth], List(effective.ExtendedKeyUsages));
        Assert.True(effective.CtEnabled);
    }

    [Fact]
    public async Task A_boolean_restriction_holds_through_the_chain()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db, g => g.AllowWildcard = false, m => m.AllowWildcard = true, c => c.AllowWildcard = true);

        Assert.False((await Service(db).ResolveCertProfileAsync(child.Id)).AllowWildcard);
    }

    [Fact]
    public async Task A_cycle_resolves_without_looping()
    {
        using var db = InMemoryDbContextFactory.Create();
        var a = new CertProfileEntity { Id = Guid.NewGuid(), Name = "a", InheritanceEnabled = true, ValidityPeriodMax = "P30D" };
        var b = new CertProfileEntity { Id = Guid.NewGuid(), Name = "b", InheritanceEnabled = true, ValidityPeriodMax = "P60D", InheritsFromId = a.Id };
        a.InheritsFromId = b.Id;
        db.CertProfiles.AddRange(a, b);
        db.SaveChanges();

        Assert.Equal("P30D", (await Service(db).ResolveCertProfileAsync(a.Id)).ValidityPeriodMax);
        Assert.Equal("P30D", (await Service(db).ResolveCertProfileAsync(b.Id)).ValidityPeriodMax);
    }

    [Fact]
    public async Task The_inheritance_check_judges_the_child_against_the_middles_effective_values()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db,
            g => { g.ValidityPeriodMax = "P90D"; g.AllowedKeySizes = Json("2048"); },
            m => { },
            c => { c.ValidityPeriodMax = "P365D"; c.AllowedKeySizes = Json("1024"); });

        var errors = await Service(db).ValidateCertProfileInheritanceAsync(child.Id);

        Assert.Contains(errors, e => e.Contains("ValidityPeriodMax"));
        Assert.Contains(errors, e => e.Contains("AllowedKeySizes"));
    }

    [Fact]
    public async Task The_infrastructure_profile_checks_see_the_parent_as_issuance_does()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db, g => g.ExtendedKeyUsages = Json(ServerAuth), m => { }, c => { });

        var parent = await InfrastructureCertProfiles.ParentOfAsync(db, child);

        Assert.NotNull(parent);
        Assert.Equal([ServerAuth], List(InfrastructureCertProfiles.Effective(child, parent, db).ExtendedKeyUsages));
    }

    [Fact]
    public async Task Expiry_warnings_are_held_by_the_grandparent()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (_, _, child) = CertChain(db, g => g.ExpiryWarningPercent = 40, m => { }, c => c.ExpiryWarningPercent = 20);

        Assert.Equal(40, (await Service(db).ResolveCertProfileAsync(child.Id)).ExpiryWarningPercent);
        Assert.Equal(40, (await CertificateExpiry.EffectiveSettingsAsync(db, child)).WarningPercent);
    }

    // ── Request profiles ────────────────────────────────────────────────

    [Fact]
    public async Task Request_approval_is_held_by_the_grandparent_through_an_inheriting_middle()
    {
        using var db = InMemoryDbContextFactory.Create();
        var g = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "baseline", RequireApproval = true, RequiredApprovalCount = 3 };
        var m = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "space", InheritanceEnabled = true, InheritsFromId = g.Id, RequireApproval = false, RequiredApprovalCount = 0 };
        var c = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "ca", InheritanceEnabled = true, InheritsFromId = m.Id, RequireApproval = false, RequiredApprovalCount = 1 };
        db.RequestProfiles.AddRange(g, m, c);
        db.SaveChanges();

        var effective = await Service(db).ResolveRequestProfileAsync(c.Id);

        Assert.True(effective.RequireApproval);
        Assert.Equal(3, effective.RequiredApprovalCount);
    }

    [Fact]
    public async Task Request_cert_profiles_are_clamped_by_the_grandparent_when_the_middle_leaves_them_unset()
    {
        using var db = InMemoryDbContextFactory.Create();
        var allowed = Guid.NewGuid().ToString();
        var other = Guid.NewGuid().ToString();
        var g = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "baseline", AllowedCertProfileIds = Json(allowed) };
        var m = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "space", InheritanceEnabled = true, InheritsFromId = g.Id };
        var c = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "ca", InheritanceEnabled = true, InheritsFromId = m.Id, AllowedCertProfileIds = Json(allowed, other) };
        db.RequestProfiles.AddRange(g, m, c);
        db.SaveChanges();

        Assert.Equal([allowed], List((await Service(db).ResolveRequestProfileAsync(c.Id)).AllowedCertProfileIds));
        Assert.Contains(await Service(db).ValidateRequestProfileInheritanceAsync(c.Id), e => e.Contains("AllowedCertProfileIds"));
    }
}
