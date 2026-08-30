using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the spelling-independence of cert-profile inheritance clamping.
/// <para>
/// The subset comparison was an ordinal string match, and the two sides are written by different
/// producers: the bootstrap seeder stores <b>OIDs</b> on the system profiles that act as parents,
/// while the admin UI's cert-profile editor writes <b>friendly names</b> on the CA-scoped
/// children. Nothing matched.
/// </para>
/// <para>
/// The failure was not a dropped entry but an inverted one. With no child value matching, the
/// clamp concluded the child's whole list was disallowed and fell back to the parent's — so a
/// child requesting <c>clientAuth, smartcardLogon</c> under the six-EKU bootstrap parent produced
/// a certificate carrying the parent's six. The profile listed Smart Card Logon; the certificate
/// did not have it, and the only trace was a log line.
/// </para>
/// </summary>
public class CertProfileUsageSpellingTests
{
    /// <summary>The catalog rows a real database carries, as the bootstrap seeder writes them.</summary>
    private static readonly (string Oid, string Name, string Kind)[] Catalog =
    {
        ("1.3.6.1.5.5.7.3.1", "serverAuth", "Extended"),
        ("1.3.6.1.5.5.7.3.2", "clientAuth", "Extended"),
        ("1.3.6.1.5.5.7.3.3", "codeSigning", "Extended"),
        ("1.3.6.1.5.5.7.3.4", "emailProtection", "Extended"),
        ("1.3.6.1.5.5.7.3.8", "timeStamping", "Extended"),
        ("1.3.6.1.5.5.7.3.9", "OCSPSigning", "Extended"),
        ("1.3.6.1.4.1.311.20.2.2", "smartcardLogon", "Extended"),
        ("2.5.29.15.0", "digitalSignature", "Standard"),
        ("2.5.29.15.2", "keyEncipherment", "Standard"),
        ("2.5.29.15.5", "keyCertSign", "Standard"),
    };

    private static ProfileResolutionService Service(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<ProfileResolutionService>.Instance);

    private static (ModularCA.Database.ModularCADbContext Db, Guid ChildId) Hierarchy(
        Action<CertProfileEntity> configureParent,
        Action<CertProfileEntity> configureChild)
    {
        var db = InMemoryDbContextFactory.Create();
        foreach (var (oid, name, kind) in Catalog)
            db.OIDOptions.Add(new OIDOptionEntity { OID = oid, FriendlyName = name, KeyUsage = kind });

        var parent = new CertProfileEntity { Id = Guid.NewGuid(), Name = "system-parent" };
        configureParent(parent);

        var child = new CertProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = "ca-child",
            InheritanceEnabled = true,
            InheritsFromId = parent.Id,
        };
        configureChild(child);

        db.CertProfiles.AddRange(parent, child);
        db.SaveChanges();
        return (db, child.Id);
    }

    private static List<string> Parse(string json)
        => System.Text.Json.JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();

    /// <summary>
    /// The regression: a child spelling its usages by friendly name, under a parent spelling the
    /// same usages by OID, must keep what it asked for.
    /// </summary>
    [Fact]
    public async Task A_child_spelled_by_name_survives_a_parent_spelled_by_oid()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.2\"]",
            c => c.ExtendedKeyUsages = "[\"clientAuth\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        var result = Parse(effective.ExtendedKeyUsages);
        Assert.Single(result);
        Assert.Equal("clientAuth", result[0]);
    }

    /// <summary>
    /// The specific report: Smart Card Logon set on the child, under a parent that allows it,
    /// must reach the certificate. Before the fix the child's list was replaced wholesale by the
    /// parent's and the usage vanished.
    /// </summary>
    [Fact]
    public async Task Smartcard_logon_survives_inheritance_when_the_parent_allows_it()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.2\",\"1.3.6.1.4.1.311.20.2.2\"]",
            c => c.ExtendedKeyUsages = "[\"clientAuth\",\"smartcardLogon\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        Assert.Contains("smartcardLogon", Parse(effective.ExtendedKeyUsages));
    }

    /// <summary>
    /// The clamp must still clamp. A usage the parent genuinely does not permit is removed however
    /// it is spelled — this is what stops the fix from becoming "inheritance no longer restricts".
    /// </summary>
    [Fact]
    public async Task A_usage_the_parent_does_not_permit_is_still_removed()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.2\"]",
            c => c.ExtendedKeyUsages = "[\"clientAuth\",\"smartcardLogon\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        var result = Parse(effective.ExtendedKeyUsages);
        Assert.Equal(new[] { "clientAuth" }, result);
        Assert.DoesNotContain("smartcardLogon", result);
    }

    /// <summary>The same comparison applies to standard key usages, which use a separate catalog.</summary>
    [Fact]
    public async Task Standard_key_usages_compare_by_catalog_too()
    {
        var (db, childId) = Hierarchy(
            p => p.KeyUsages = "[\"2.5.29.15.0\",\"2.5.29.15.2\"]",
            c => c.KeyUsages = "[\"digitalSignature\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        Assert.Equal(new[] { "digitalSignature" }, Parse(effective.KeyUsages));
    }

    /// <summary>
    /// Display-label spelling — what the UI's editor historically wrote — must also resolve, since
    /// those rows exist in databases already.
    /// </summary>
    [Fact]
    public async Task Display_label_spelling_also_resolves()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.2\"]",
            c => c.ExtendedKeyUsages = "[\"Client Authentication\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        Assert.Equal(new[] { "Client Authentication" }, Parse(effective.ExtendedKeyUsages));
    }

    /// <summary>
    /// Fields that are not key usages keep plain string comparison — the canonicalizer is applied
    /// only where a catalog exists, and must not start folding unrelated values together.
    /// </summary>
    [Fact]
    public async Task Non_usage_lists_are_unaffected()
    {
        var (db, childId) = Hierarchy(
            p => p.AllowedKeyAlgorithms = "[\"RSA\",\"ECDSA\"]",
            c => c.AllowedKeyAlgorithms = "[\"ECDSA\"]");

        var effective = await Service(db).ResolveCertProfileAsync(childId);

        Assert.Equal(new[] { "ECDSA" }, Parse(effective.AllowedKeyAlgorithms));
    }
}
