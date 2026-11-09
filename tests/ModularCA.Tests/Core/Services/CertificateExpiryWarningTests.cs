using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The expiry warning instants a certificate is given and kept up to date with: computed from
/// the effective profile at issuance and reissue, by the context's save for rows written
/// elsewhere, merged through inheritance as issuance resolves it, and re-computed for the live
/// certificates of a profile and its inheriting children when its settings change.
/// </summary>
public sealed class CertificateExpiryWarningTests
{
    private static void AssertInstants(CertificateEntity cert, ExpiryWarningSettings? settings)
    {
        var (warningAt, alertAt) = ExpiryWarningRule.Compute(cert.NotBefore, cert.NotAfter, cert.IsCA, settings);
        Assert.Equal(warningAt, cert.ExpiryWarningAt);
        Assert.Equal(alertAt, cert.ExpiryAlertAt);
    }

    // ── Issuance ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Issuance_and_reissue_stamp_the_instants_from_the_effective_profile()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var profile = w.Db.CertProfiles.Single(p => p.Id == w.LeafProfileId);
        profile.ExpiryWarningPercent = 50;
        profile.ExpiryAlertMaxWindow = "P2D";
        w.Db.SaveChanges();
        var settings = new ExpiryWarningSettings(WarningPercent: 50, AlertMaxWindow: "P2D");

        var ca = await w.CreateRootAsync("Expiry Root", null, null);
        await w.IssueLeafAsync(ca, "CN=leaf", ["DNS:leaf.acme.test"]);
        var request = w.Db.CertificateRequests.AsNoTracking().Single(r => r.CertProfileId == w.LeafProfileId);
        var issued = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == request.IssuedCertificateId);
        AssertInstants(issued, settings);
        Assert.Equal(issued.NotAfter.AddDays(-2), issued.ExpiryAlertAt);
        Assert.True(issued.ExpiryWarningAt < issued.ExpiryAlertAt);

        await w.Issuance.ReissueCertificateAsync(null, null, request.Id, null, null);
        var successor = w.Db.Certificates.AsNoTracking()
            .Single(c => c.CertProfileId == w.LeafProfileId && c.CertificateId != issued.CertificateId);
        AssertInstants(successor, settings);
    }

    [Fact]
    public async Task A_never_warn_profile_issues_certificates_whose_instants_are_their_expiry()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        w.Db.CertProfiles.Single(p => p.Id == w.LeafProfileId).ExpiryNeverWarn = true;
        w.Db.SaveChanges();

        var ca = await w.CreateRootAsync("Never Root", null, null);
        await w.IssueLeafAsync(ca, "CN=quiet", ["DNS:quiet.acme.test"]);
        var cert = w.Db.Certificates.AsNoTracking().Single(c => c.CertProfileId == w.LeafProfileId);

        Assert.Equal(cert.NotAfter, cert.ExpiryWarningAt);
        Assert.Equal(cert.NotAfter, cert.ExpiryAlertAt);
    }

    [Fact]
    public async Task Ca_certificates_keep_30_and_7_days_from_a_profile_that_sets_nothing()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var root = await w.CreateRootAsync("Ca Root", null, null);
        var intermediate = await w.CreateIntermediateAsync(root, "Ca Intermediate", null, null);

        foreach (var caCertId in new[] { root.CertificateId, intermediate.CertificateId })
        {
            var cert = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == caCertId);
            Assert.True(cert.IsCA);
            Assert.Equal(cert.NotAfter.AddDays(-30), cert.ExpiryWarningAt);
            Assert.Equal(cert.NotAfter.AddDays(-7), cert.ExpiryAlertAt);
        }
    }

    [Fact]
    public void The_save_fills_missing_instants_from_the_tracked_profile_or_the_defaults_and_keeps_set_ones()
    {
        using var db = InMemoryDbContextFactory.Create();
        var quiet = new CertProfileEntity { Name = "quiet", ExpiryNeverWarn = true };
        db.CertProfiles.Add(quiet);
        var start = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        CertificateEntity Cert(bool isCa = false, Guid? profile = null) => new()
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..16], SubjectDN = "CN=x", Issuer = "CN=ca",
            NotBefore = start, NotAfter = start.AddDays(100), IsCA = isCa, CertProfileId = profile,
        };
        var leaf = Cert();
        var ca = Cert(isCa: true);
        var underQuiet = Cert(profile: quiet.Id);
        var preset = Cert();
        preset.ExpiryWarningAt = start.AddDays(1);
        preset.ExpiryAlertAt = start.AddDays(2);
        db.Certificates.AddRange(leaf, ca, underQuiet, preset);
        db.SaveChanges();

        Assert.Equal((start.AddDays(70), start.AddDays(90)), (leaf.ExpiryWarningAt, leaf.ExpiryAlertAt));
        Assert.Equal((start.AddDays(70), start.AddDays(93)), (ca.ExpiryWarningAt, ca.ExpiryAlertAt));
        Assert.Equal((underQuiet.NotAfter, underQuiet.NotAfter), (underQuiet.ExpiryWarningAt, underQuiet.ExpiryAlertAt));
        Assert.Equal((start.AddDays(1), start.AddDays(2)), (preset.ExpiryWarningAt, preset.ExpiryAlertAt));
    }

    // ── Inheritance, as issuance resolves it ────────────────────────────────────────────────

    [Fact]
    public async Task Resolution_merges_the_expiry_settings_and_names_each_source()
    {
        using var db = InMemoryDbContextFactory.Create();
        var parent = new CertProfileEntity { Name = "parent", ExpiryWarningPercent = 40, ExpiryAlertMaxWindow = "P5D" };
        var strict = new CertProfileEntity
        {
            Name = "strict", InheritanceEnabled = true, InheritsFromId = parent.Id,
            ExpiryWarningPercent = 20, ExpiryWarningMaxWindow = "P60D",
        };
        var own = new CertProfileEntity
        {
            Name = "own", InheritanceEnabled = true, InheritsFromId = parent.Id, ExpiryWarningOverridesParent = true,
            ExpiryWarningPercent = 20, ExpiryNeverWarn = true,
        };
        db.CertProfiles.AddRange(parent, strict, own);
        db.SaveChanges();
        var resolver = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);

        var clamped = await resolver.ResolveCertProfileAsync(strict.Id);
        Assert.Equal(new ExpiryWarningSettings(40, null, null, "P5D"), clamped.ExpiryWarnings);
        Assert.Equal("clamped", clamped.FieldSources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Equal("clamped", clamped.FieldSources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("inherited", clamped.FieldSources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);
        Assert.NotEmpty(await resolver.ValidateCertProfileInheritanceAsync(strict.Id));

        var overridden = await resolver.ResolveCertProfileAsync(own.Id);
        Assert.Equal(new ExpiryWarningSettings(20, null, null, "P5D", true), overridden.ExpiryWarnings);
        Assert.True(overridden.ExpiryWarningOverridesParent);
        Assert.Equal("overridden", overridden.FieldSources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Empty(await resolver.ValidateCertProfileInheritanceAsync(own.Id));

        var standalone = await resolver.ResolveCertProfileAsync(parent.Id);
        Assert.Equal(new ExpiryWarningSettings(40, null, null, "P5D"), standalone.ExpiryWarnings);
    }

    // ── Profile edits ───────────────────────────────────────────────────────────────────────

    internal static UpdateCertProfileRequest Request(CertProfileEntity p) => new()
    {
        Name = p.Name, Description = p.Description, IsCaProfile = p.IsCaProfile, KeyUsages = p.KeyUsages, ExtendedKeyUsages = p.ExtendedKeyUsages,
        ValidityPeriodMin = p.ValidityPeriodMin, ValidityPeriodMax = p.ValidityPeriodMax, AllowedKeyAlgorithms = p.AllowedKeyAlgorithms,
        AllowedKeySizes = p.AllowedKeySizes, AllowedSignatureAlgorithms = p.AllowedSignatureAlgorithms, CertificateAuthorityId = p.CertificateAuthorityId,
        InheritsFromId = p.InheritsFromId, InheritanceEnabled = p.InheritanceEnabled,
        ExpiryWarningPercent = p.ExpiryWarningPercent, ExpiryWarningMaxWindow = p.ExpiryWarningMaxWindow,
        ExpiryAlertPercent = p.ExpiryAlertPercent, ExpiryAlertMaxWindow = p.ExpiryAlertMaxWindow,
        ExpiryNeverWarn = p.ExpiryNeverWarn, ExpiryWarningOverridesParent = p.ExpiryWarningOverridesParent,
    };

    /// <summary>A parent and an inheriting child, each with live, revoked and expired certificates.</summary>
    internal sealed class EditWorld
    {
        public required CertProfileEntity Parent { get; init; }
        public required CertProfileEntity Child { get; init; }
        public required CertProfileEntity Other { get; init; }
        public required CertificateEntity ParentLive { get; init; }
        public required CertificateEntity ParentCa { get; init; }
        public required CertificateEntity ChildLive { get; init; }
        public required CertificateEntity Revoked { get; init; }
        public required CertificateEntity Expired { get; init; }
        public required CertificateEntity OtherLive { get; init; }

        /// <summary>Seeds the world into <paramref name="db"/>; every certificate starts with the default instants.</summary>
        public static EditWorld Seed(ModularCADbContext db)
        {
            CertProfileEntity Profile(string name) => new() { Name = $"{name}-{Guid.NewGuid():N}"[..30], KeyUsages = "[]", ExtendedKeyUsages = "[]" };
            var parent = Profile("parent");
            var child = Profile("child");
            child.InheritanceEnabled = true;
            child.InheritsFromId = parent.Id;
            var other = Profile("other");
            db.CertProfiles.AddRange(parent, child, other);
            db.SaveChanges();

            var now = DateTime.UtcNow;
            CertificateEntity Cert(CertProfileEntity profile, double fromDays, double toDays, bool revoked = false, bool isCa = false) => new()
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..20], SubjectDN = "CN=edit", Issuer = "CN=edit ca",
                NotBefore = now.AddDays(fromDays), NotAfter = now.AddDays(toDays), Revoked = revoked, IsCA = isCa, CertProfileId = profile.Id,
            };
            var world = new EditWorld
            {
                Parent = parent, Child = child, Other = other,
                ParentLive = Cert(parent, -10, 90), ParentCa = Cert(parent, -10, 3000, isCa: true), ChildLive = Cert(child, -50, 50),
                Revoked = Cert(parent, -10, 90, revoked: true), Expired = Cert(parent, -100, -1), OtherLive = Cert(other, -10, 90),
            };
            db.Certificates.AddRange(world.ParentLive, world.ParentCa, world.ChildLive, world.Revoked, world.Expired, world.OtherLive);
            db.SaveChanges();
            return world;
        }
    }

    [Fact]
    public async Task A_profile_edit_recomputes_the_live_certificates_of_the_profile_and_its_inheriting_children()
    {
        var name = $"edit-{Guid.NewGuid():N}";
        EditWorld w;
        using (var seed = InMemoryDbContextFactory.Create(name))
            w = EditWorld.Seed(seed);

        using (var db = InMemoryDbContextFactory.Create(name))
        {
            var service = new CertProfileService(db);
            var unchanged = await service.UpdateAsync(w.Parent.Id, Request(w.Parent));
            Assert.Equal(0, unchanged);

            var edit = Request(w.Parent);
            edit.ExpiryWarningPercent = 60;
            edit.ExpiryAlertMaxWindow = "P1D";
            Assert.Equal(3, await service.UpdateAsync(w.Parent.Id, edit));
        }

        using var read = InMemoryDbContextFactory.Create(name);
        CertificateEntity Read(CertificateEntity c) => read.Certificates.AsNoTracking().Single(x => x.CertificateId == c.CertificateId);
        var settings = new ExpiryWarningSettings(WarningPercent: 60, AlertMaxWindow: "P1D");
        AssertInstants(Read(w.ParentLive), settings);
        AssertInstants(Read(w.ParentCa), settings);
        AssertInstants(Read(w.ChildLive), settings);
        Assert.Equal(Read(w.ParentCa).NotAfter.AddDays(-1), Read(w.ParentCa).ExpiryAlertAt);
        AssertInstants(Read(w.Revoked), null);
        AssertInstants(Read(w.Expired), null);
        AssertInstants(Read(w.OtherLive), null);
    }

    [Fact]
    public async Task A_profile_with_invalid_expiry_settings_is_refused_with_its_code()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = EditWorld.Seed(db);
        var service = new CertProfileService(db);

        var edit = Request(w.Parent);
        edit.ExpiryWarningPercent = 10;
        edit.ExpiryAlertPercent = 20;
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => service.UpdateAsync(w.Parent.Id, edit));
        Assert.Equal(ErrorCodes.ExpiryWarningSettingsInvalid, ex.Code);

        var create = Request(w.Parent);
        create.Name = "bad window";
        create.ExpiryWarningMaxWindow = "a month";
        Assert.Equal(ErrorCodes.ExpiryWarningSettingsInvalid,
            (await Assert.ThrowsAsync<ConfigurationValidationException>(() => service.CreateAsync(create))).Code);
    }

    [Fact]
    public async Task The_relational_recompute_matches_the_rule_and_a_never_warn_profile_moves_both_instants_to_expiry()
    {
        // The in-memory path; PostgresLifecycleQueryTests runs the SQL one against the same rule.
        using var db = InMemoryDbContextFactory.Create();
        var w = EditWorld.Seed(db);
        var never = new ExpiryWarningSettings(NeverWarn: true);
        Assert.Equal(2, await CertificateExpiry.RecomputeAsync(db, w.Parent.Id, never, DateTime.UtcNow));
        var live = db.Certificates.AsNoTracking().Single(c => c.CertificateId == w.ParentLive.CertificateId);
        Assert.Equal((live.NotAfter, live.NotAfter), (live.ExpiryWarningAt, live.ExpiryAlertAt));
    }

    // ── Policy sync ─────────────────────────────────────────────────────────────────────────

    /// <summary>A profile that a YAML entry naming only <paramref name="name"/> and <c>extendedKeyUsages: '[]'</c> leaves unchanged.</summary>
    private static CertProfileEntity SyncedProfile(string name) => new() { Name = name, ExtendedKeyUsages = "[]" };

    private static async Task<PolicySyncResult> SyncAsync(ModularCADbContext db, string entry) =>
        await new PolicySyncService(db, NullLogger<PolicySyncService>.Instance).SyncFromYamlAsync($"""
            profiles:
              - name: Synced
                extendedKeyUsages: '[]'
            {entry}
            """, "cert");

    [Fact]
    public async Task Policy_sync_keeps_the_expiry_settings_a_file_leaves_out()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = SyncedProfile("Synced");
        profile.ExpiryNeverWarn = true;
        profile.ExpiryWarningPercent = 40;
        profile.ExpiryAlertMaxWindow = "P5D";
        profile.ExpiryWarningOverridesParent = true;
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();

        // A file written before 0.4.3 has no expiry keys: nothing changes.
        var result = await SyncAsync(db, "");
        Assert.Equal((0, 1), (result.Updated, result.Unchanged));
        Assert.Empty(result.Errors);

        // Another change is applied and the expiry settings stay.
        result = await SyncAsync(db, "    description: changed");
        Assert.Equal((1, 0), (result.Updated, result.ExpiryWarningsRecomputed));
        var stored = db.CertProfiles.AsNoTracking().Single(p => p.Id == profile.Id);
        Assert.Equal("changed", stored.Description);
        Assert.Equal((true, 40, (string?)"P5D", true),
            (stored.ExpiryNeverWarn, stored.ExpiryWarningPercent, stored.ExpiryAlertMaxWindow, stored.ExpiryWarningOverridesParent));
    }

    [Fact]
    public async Task Policy_sync_sets_and_clears_the_expiry_keys_a_file_carries_and_recomputes()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = SyncedProfile("Synced");
        profile.ExpiryNeverWarn = true;
        profile.ExpiryWarningPercent = 40;
        profile.ExpiryAlertMaxWindow = "P5D";
        db.CertProfiles.Add(profile);
        var now = DateTime.UtcNow;
        var live = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "synced-live", SubjectDN = "CN=synced", Issuer = "CN=ca",
            NotBefore = now.AddDays(-10), NotAfter = now.AddDays(90), CertProfileId = profile.Id,
        };
        db.Certificates.Add(live);
        await db.SaveChangesAsync();

        var result = await SyncAsync(db, """
                expiryNeverWarn: false
                expiryWarningPercent: ~
                expiryWarningMaxWindow: P20D
                expiryAlertMaxWindow: ''
                expiryWarningOverridesParent: true
            """);
        Assert.Empty(result.Errors);
        Assert.Equal((1, 1), (result.Updated, result.ExpiryWarningsRecomputed));
        var stored = db.CertProfiles.AsNoTracking().Single(p => p.Id == profile.Id);
        Assert.Equal((false, (int?)null, (string?)"P20D", (string?)null, true),
            (stored.ExpiryNeverWarn, stored.ExpiryWarningPercent, stored.ExpiryWarningMaxWindow, stored.ExpiryAlertMaxWindow, stored.ExpiryWarningOverridesParent));
        AssertInstants(db.Certificates.AsNoTracking().Single(c => c.CertificateId == live.CertificateId),
            new ExpiryWarningSettings(WarningMaxWindow: "P20D"));
    }

    [Fact]
    public async Task Policy_sync_checks_the_settings_a_file_leaves_on_the_profile()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = SyncedProfile("Synced");
        profile.ExpiryWarningPercent = 20;
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();

        // The alert percent alone is valid, but not with the warning percent the profile keeps.
        var result = await SyncAsync(db, "    expiryAlertPercent: 30");
        Assert.Equal(0, result.Updated);
        Assert.Contains(result.Errors, e => e.Contains("was not synced") && e.Contains("cannot be larger"));
        Assert.Null(db.CertProfiles.AsNoTracking().Single(p => p.Id == profile.Id).ExpiryAlertPercent);
    }
}
