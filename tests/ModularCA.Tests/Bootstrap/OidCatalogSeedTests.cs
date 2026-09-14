using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Pins that the OID catalog seeder reconciles rather than skipping.
/// </summary>
/// <remarks>
/// <para>
/// The guard was <c>if (db.OIDOptions.Any()) return;</c>, which cannot distinguish a complete
/// catalog from a half-built one. An installation holding Extended entries and no Standard ones
/// was stranded there permanently, because seeding is a first-run operation and never ran again.
/// </para>
/// <para>
/// Every enrollment then failed. <c>IssuanceValidationService</c> resolves a profile's key usages
/// against this table, nothing resolved, and issuance refused rather than emitting a certificate
/// with no KeyUsage extension — correct behaviour whose message points at the profile's spelling
/// when the profile is fine and the catalog is empty. That misdirection is the expensive part, and
/// it is why this is worth a test rather than a fix and a shrug.
/// </para>
/// </remarks>
public class OidCatalogSeedTests
{
    private static ModularCADbContext NewDb()
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase($"oid-catalog-{Guid.NewGuid()}")
            .Options;
        return new ModularCADbContext(options);
    }

    /// <summary>The built-in defaults, which is what an install without config/OIDSeed.yaml uses.</summary>
    private static YamlOIDLoader.OIDSeedConfig Defaults() => YamlOIDLoader.Load("does-not-exist.yaml");

    [Fact]
    public void An_empty_catalog_gets_both_categories()
    {
        using var db = NewDb();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());

        Assert.NotEmpty(db.OIDOptions.Where(o => o.KeyUsage == "Standard"));
        Assert.NotEmpty(db.OIDOptions.Where(o => o.KeyUsage == "Extended"));
    }

    [Fact]
    public void A_catalog_holding_only_extended_entries_still_gets_the_standard_ones()
    {
        // The exact state that stranded a live installation: Extended present, Standard absent,
        // and the old guard seeing a non-empty table and returning.
        using var db = NewDb();
        db.OIDOptions.Add(new OIDOptionEntity
        {
            OID = "1.3.6.1.5.5.7.3.1",
            FriendlyName = "serverAuth",
            IsDefaultEntry = true,
            KeyUsage = "Extended",
        });
        db.SaveChanges();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());

        var standard = db.OIDOptions.Where(o => o.KeyUsage == "Standard").Select(o => o.FriendlyName).ToList();
        Assert.Contains("digitalSignature", standard);
        Assert.Contains("keyEncipherment", standard);
        Assert.Contains("keyCertSign", standard);
    }

    [Fact]
    public void Seeding_twice_adds_nothing_the_second_time()
    {
        // Idempotence matters because this now runs as reconciliation rather than a one-shot, so a
        // repeated bootstrap must not accumulate duplicate rows.
        using var db = NewDb();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());
        var afterFirst = db.OIDOptions.Count();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());

        Assert.Equal(afterFirst, db.OIDOptions.Count());
    }

    [Fact]
    public void An_operator_renamed_entry_is_left_alone()
    {
        // Matching is on OID, which is the primary key and the stable identity. Someone who renamed
        // an entry in their own catalog meant it, and a reconciliation pass must not quietly revert
        // their name to the shipped default.
        using var db = NewDb();
        db.OIDOptions.Add(new OIDOptionEntity
        {
            OID = "2.5.29.15.0",
            FriendlyName = "Digital Signature (house style)",
            IsDefaultEntry = false,
            KeyUsage = "Standard",
        });
        db.SaveChanges();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());

        var row = db.OIDOptions.Single(o => o.OID == "2.5.29.15.0");
        Assert.Equal("Digital Signature (house style)", row.FriendlyName);
        Assert.False(row.IsDefaultEntry);
    }

    [Fact]
    public void The_four_usages_that_failed_in_production_all_resolve()
    {
        // Named individually rather than asserted as a count: these are the four from the refusal
        // that prompted this, and a future edit to the defaults that drops one of them should fail
        // here with the name rather than with an off-by-one.
        using var db = NewDb();

        BootstrapProfileSeeder.LoadOidsToDb(db, Defaults());

        var standard = db.OIDOptions
            .Where(o => o.KeyUsage == "Standard")
            .Select(o => o.FriendlyName)
            .ToList();

        foreach (var usage in new[] { "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment" })
            Assert.Contains(usage, standard);
    }
}
