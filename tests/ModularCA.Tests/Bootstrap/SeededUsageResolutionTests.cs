using ModularCA.Bootstrap;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Pins the bootstrap seeder's usage lookups against the catalog it actually runs with.
/// <para>
/// The seeder resolved usages with an ordinal <c>HashSet.Contains</c> against the catalog's
/// FriendlyName, and its callers pass display names ("Digital Signature", "Key Certificate
/// Signing"). Since <c>config/OIDSeed.yaml</c> is not present in this repository,
/// <c>YamlOIDLoader</c> falls back to built-in defaults whose friendly names are camelCase
/// ("digitalSignature", "keyCertSign"). The two vocabularies never intersect, so every lookup
/// returned an empty list — and <c>BouncyCastleCertificateAuthority</c> skips the extension
/// entirely when the list is empty, so the root CA was issued with no KeyUsage and no
/// ExtendedKeyUsage extension.
/// </para>
/// <para>
/// These tests seed from <see cref="YamlOIDLoader.GetDefaultOIDConfig"/> rather than a
/// hand-written catalog, so they fail if that fallback vocabulary is ever changed out from under
/// the seeder again.
/// </para>
/// </summary>
public class SeededUsageResolutionTests
{
    /// <summary>Builds the catalog exactly as bootstrap does when no OIDSeed.yaml exists.</summary>
    private static ModularCA.Database.ModularCADbContext SeededFromDefaults()
    {
        var db = InMemoryDbContextFactory.Create();
        var defaults = YamlOIDLoader.GetDefaultOIDConfig();

        foreach (var (name, oid) in defaults.OID!.StandardKeyUsage!)
            db.OIDOptions.Add(new OIDOptionEntity { OID = oid, FriendlyName = name, KeyUsage = "Standard" });
        foreach (var (name, oid) in defaults.OID!.ExtendedKeyUsage!)
            db.OIDOptions.Add(new OIDOptionEntity { OID = oid, FriendlyName = name, KeyUsage = "Extended" });

        db.SaveChanges();
        return db;
    }

    /// <summary>
    /// The exact array BootstrapModularCA.Run passes for the root CA. Every one of these must
    /// resolve, or the root ships without a KeyUsage extension.
    /// </summary>
    [Fact]
    public void Root_CA_standard_usages_all_resolve()
    {
        using var db = SeededFromDefaults();

        var resolved = BootstrapProfileSeeder.SetupAllowedStandardOids(
            new[] { "Digital Signature", "Key Encipherment", "Key Certificate Signing", "CRL Signing" }, db);

        Assert.Equal(4, resolved.Count);
        Assert.Contains("digitalSignature", resolved);
        Assert.Contains("keyCertSign", resolved);
        Assert.Contains("crlSign", resolved);
        Assert.Contains("keyEncipherment", resolved);
    }

    /// <summary>The root CA's extended usages, as passed by the CLI bootstrap path.</summary>
    [Fact]
    public void Root_CA_extended_usages_all_resolve()
    {
        using var db = SeededFromDefaults();

        var resolved = BootstrapProfileSeeder.SetupAllowedExtendedOids(
            new[] { "Server Authentication", "Client Authentication", "Code Signing",
                    "Email Protection", "Time Stamping", "OCSP Signer" }, db);

        Assert.Equal(6, resolved.Count);
        Assert.Contains("1.3.6.1.5.5.7.3.1", resolved);   // serverAuth
        Assert.Contains("1.3.6.1.5.5.7.3.9", resolved);   // OCSPSigning
    }

    /// <summary>
    /// The seeder must accept all three vocabularies, since the catalog can come from an
    /// operator-supplied OIDSeed.yaml using any of them.
    /// </summary>
    [Theory]
    [InlineData("Digital Signature")]   // display name — what the seeder's callers pass
    [InlineData("digitalSignature")]    // catalog camelCase
    [InlineData("digital_signature")]   // separator variant
    [InlineData("2.5.29.15.0")]         // by OID
    public void Standard_usage_resolves_from_any_spelling(string spelling)
    {
        using var db = SeededFromDefaults();
        Assert.Equal(new[] { "digitalSignature" },
            BootstrapProfileSeeder.SetupAllowedStandardOids(new[] { spelling }, db));
    }

    [Theory]
    [InlineData("Server Authentication")]
    [InlineData("serverAuth")]
    [InlineData("1.3.6.1.5.5.7.3.1")]
    public void Extended_usage_resolves_from_any_spelling(string spelling)
    {
        using var db = SeededFromDefaults();
        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.1" },
            BootstrapProfileSeeder.SetupAllowedExtendedOids(new[] { spelling }, db));
    }

    /// <summary>Tolerance must not become permissiveness — an unknown usage is still dropped.</summary>
    [Fact]
    public void Unknown_usage_is_dropped()
    {
        using var db = SeededFromDefaults();
        Assert.Empty(BootstrapProfileSeeder.SetupAllowedStandardOids(new[] { "Telepathy" }, db));
    }

    /// <summary>
    /// The normalizer is shared by the seeder, KeyUsageFriendlyNames and IssuanceValidationService.
    /// Three hand-synchronized copies is how the seeder was left behind; this pins the contract.
    /// </summary>
    [Theory]
    [InlineData("Server Auth", "serverauth")]
    [InlineData("serverAuth", "serverauth")]
    [InlineData("server_auth", "serverauth")]
    [InlineData("Key Certificate Signing", "keycertificatesigning")]
    [InlineData("", "")]
    public void Normalizer_collapses_spellings_consistently(string input, string expected)
        => Assert.Equal(expected, UsageCatalogResolver.Normalize(input));
}
