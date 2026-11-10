using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The policy sync checks the key usages and extended key usages of the certificate profiles it
/// creates or updates against the OID catalog, as the console's create and update do
/// (<c>MCA-PRF-002</c>). A bad entry is reported the way the sync reports other invalid profile
/// content: the profile is skipped with an error in the result naming it, and the rest of the
/// file is synced. Entries a profile already stores are not checked again; a new profile is
/// checked in full. Any policy example the repository ships passes.
/// </summary>
public sealed class PolicySyncUsageCatalogTests
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string CustomOid = "1.3.6.1.4.1.66874.9.1";

    /// <summary>A database whose catalog is the one a new install gets.</summary>
    private static ModularCADbContext Catalogued()
    {
        var db = InMemoryDbContextFactory.Create();
        BootstrapProfileSeeder.LoadOidsToDb(db, YamlOIDLoader.GetDefaultOIDConfig());
        return db;
    }

    private static Task<PolicySyncResult> SyncAsync(ModularCADbContext db, string yaml)
        => new PolicySyncService(db, NullLogger<PolicySyncService>.Instance).SyncFromYamlAsync(yaml, "cert");

    [Fact]
    public async Task A_new_profile_with_an_unknown_usage_is_skipped_with_an_error_and_the_others_are_synced()
    {
        using var db = Catalogued();

        var result = await SyncAsync(db, $"""
            profiles:
              - name: Good before
                keyUsages: '["digitalSignature","keyEncipherment"]'
                extendedKeyUsages: '["{ServerAuth}"]'
              - name: Bad key usage
                keyUsages: '["digitalSignature","warpDrive"]'
                extendedKeyUsages: '["{ServerAuth}"]'
              - name: Bad extended key usage
                keyUsages: '["digitalSignature"]'
                extendedKeyUsages: '["{ServerAuth}","{CustomOid}"]'
              - name: Good after
                keyUsages: 'Digital Signature, Key Encipherment'
                extendedKeyUsages: 'serverAuth, clientAuth'
            """);

        Assert.Equal(2, result.Created);
        Assert.Equal(2, result.Errors.Count);
        var keyUsage = Assert.Single(result.Errors, e => e.Contains("'Bad key usage'"));
        Assert.Contains("was not synced", keyUsage);
        Assert.Contains("KeyUsages contains warpDrive", keyUsage);
        Assert.Contains("not in the OID catalog", keyUsage);
        Assert.EndsWith("(MCA-PRF-002)", keyUsage);
        var extended = Assert.Single(result.Errors, e => e.Contains("'Bad extended key usage'"));
        Assert.Contains($"ExtendedKeyUsages contains {CustomOid}", extended);
        Assert.EndsWith("(MCA-PRF-002)", extended);

        Assert.Equal(["Good after", "Good before"], db.CertProfiles.Select(p => p.Name).AsEnumerable().Order());
    }

    [Fact]
    public async Task Any_extended_key_usage_is_refused_whatever_the_catalog_says()
    {
        using var db = Catalogued();

        var result = await SyncAsync(db, $"""
            profiles:
              - name: Anything
                keyUsages: '["digitalSignature"]'
                extendedKeyUsages: '["{CertProfileUsageValidation.AnyExtendedKeyUsageOid}"]'
            """);

        Assert.Equal(0, result.Created);
        Assert.Contains("anyExtendedKeyUsage", Assert.Single(result.Errors));
        Assert.Empty(db.CertProfiles);
    }

    [Fact]
    public async Task A_custom_usage_syncs_once_the_catalog_has_it()
    {
        using var db = Catalogued();
        var sync = new PolicySyncService(db, NullLogger<PolicySyncService>.Instance);
        var yaml = $"""
            profiles:
              - name: Custom
                keyUsages: '["digitalSignature"]'
                extendedKeyUsages: '["{CustomOid}"]'
            """;

        Assert.Single((await sync.SyncFromYamlAsync(yaml, "cert")).Errors);

        db.OIDOptions.Add(new OIDOptionEntity { OID = CustomOid, FriendlyName = "Custom Usage", KeyUsage = "Extended" });
        await db.SaveChangesAsync();

        // The same service: the catalog is read again for each sync.
        var result = await sync.SyncFromYamlAsync(yaml, "cert");
        Assert.Empty(result.Errors);
        Assert.Equal(1, result.Created);
    }

    [Fact]
    public async Task An_update_that_adds_an_unknown_usage_is_skipped_and_the_profile_keeps_what_it_had()
    {
        using var db = Catalogued();
        var profile = new CertProfileEntity
        {
            Name = "Server",
            Description = "before",
            KeyUsages = "[\"digitalSignature\"]",
            ExtendedKeyUsages = $"[\"{ServerAuth}\"]",
        };
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();

        var result = await SyncAsync(db, $"""
            profiles:
              - name: Server
                description: after
                keyUsages: '["digitalSignature","warpDrive"]'
                extendedKeyUsages: '["{ServerAuth}"]'
            """);

        Assert.Equal(0, result.Updated);
        var error = Assert.Single(result.Errors);
        Assert.Contains("Cert profile 'Server' was not updated", error);
        Assert.Contains("warpDrive", error);
        Assert.EndsWith("(MCA-PRF-002)", error);

        db.ChangeTracker.Clear();
        var stored = db.CertProfiles.Single();
        Assert.Equal(("before", "[\"digitalSignature\"]", 0), (stored.Description, stored.KeyUsages, stored.Revision));
    }

    /// <summary>
    /// The console's exemption: a profile that already stores a usage the catalog does not hold
    /// (written before the check, or its catalog row removed since) still takes other changes,
    /// and only a usage the file adds is checked.
    /// </summary>
    [Fact]
    public async Task Usages_a_profile_already_stores_are_not_checked_again_but_added_ones_are()
    {
        using var db = Catalogued();
        db.CertProfiles.Add(new CertProfileEntity
        {
            Name = "Legacy",
            Description = "before",
            KeyUsages = "[\"digitalSignature\",\"warpDrive\"]",
            ExtendedKeyUsages = $"[\"{CustomOid}\"]",
        });
        await db.SaveChangesAsync();

        var kept = await SyncAsync(db, $"""
            profiles:
              - name: Legacy
                description: after
                keyUsages: '["digitalSignature","warpDrive","keyEncipherment"]'
                extendedKeyUsages: '["{CustomOid}","{ClientAuth}"]'
            """);
        Assert.Empty(kept.Errors);
        Assert.Equal(1, kept.Updated);
        Assert.Equal("after", db.CertProfiles.Single().Description);

        var added = await SyncAsync(db, $"""
            profiles:
              - name: Legacy
                description: again
                keyUsages: '["digitalSignature","warpDrive","keyEncipherment","tractorBeam"]'
                extendedKeyUsages: '["{CustomOid}","{ClientAuth}"]'
            """);
        Assert.Equal(0, added.Updated);
        var error = Assert.Single(added.Errors);
        Assert.Contains("tractorBeam", error);
        Assert.DoesNotContain("warpDrive", error);
        Assert.Equal("after", db.CertProfiles.Single().Description);
    }

    /// <summary>An entry that matches what is stored is unchanged, whatever it stores: nothing is written, so nothing is checked.</summary>
    [Fact]
    public async Task An_unchanged_profile_is_not_reported_however_it_was_written()
    {
        using var db = Catalogued();
        db.CertProfiles.Add(new CertProfileEntity
        {
            Name = "Legacy",
            Description = string.Empty,
            KeyUsages = "[\"warpDrive\"]",
            ExtendedKeyUsages = "[]",
        });
        await db.SaveChangesAsync();

        var result = await SyncAsync(db, """
            profiles:
              - name: Legacy
                keyUsages: '["warpDrive"]'
                extendedKeyUsages: '[]'
            """);

        Assert.Empty(result.Errors);
        Assert.Equal((0, 1), (result.Updated, result.Unchanged));
    }

    /// <summary>
    /// The bootstrap copies <c>config/policies/*.yaml.example</c> into place when the build ships
    /// any. The repository ships none today; one that is added must sync cleanly into a new
    /// install's catalog, since it is synced at the first start.
    /// </summary>
    [Fact]
    public async Task Every_policy_example_the_repository_ships_syncs_without_error()
    {
        var root = RepoRoot();
        var examples = new[] { "config", Path.Combine("ModularCA.Bootstrap", "config"), Path.Combine("ModularCA.API", "config") }
            .Select(dir => Path.Combine(root, dir, "policies"))
            .Where(Directory.Exists)
            .SelectMany(dir => Directory.GetFiles(dir, "*-profiles.yaml.example"))
            .ToList();

        foreach (var example in examples)
        {
            using var db = Catalogued();
            var type = Path.GetFileName(example).Split('-')[0];
            var result = await new PolicySyncService(db, NullLogger<PolicySyncService>.Instance)
                .SyncFromYamlAsync(await File.ReadAllTextAsync(example), type);
            Assert.True(result.Errors.Count == 0, $"{example}: {string.Join(" | ", result.Errors)}");
        }
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
