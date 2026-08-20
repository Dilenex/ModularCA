using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Regression cover for EKU/key-usage inheritance in <see cref="ProfileResolutionService"/>.
/// <para>
/// These two fields used to merge via <c>MergeString</c>, which tests only
/// <c>string.IsNullOrEmpty</c> — and <c>"[]"</c> is a two-character string. An empty child array
/// therefore counted as a deliberate override and the parent's list was discarded. Downstream,
/// <c>IssuanceValidationService.SetupAllowedExtendedOids</c> short-circuits on an empty
/// cert-profile list and emits no EKU extension, so certificates issued under an inheriting
/// profile silently came out with no extended key usages at all. Nothing errored and nothing
/// logged, which is precisely why it needs a test rather than a comment.
/// </para>
/// </summary>
public class ProfileInheritanceEkuTests
{
    private const string ServerAndClientAuth = "[\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.2\"]";
    private const string ClientAuthOnly = "[\"1.3.6.1.5.5.7.3.2\"]";
    private const string DigitalSignature = "[\"digitalSignature\"]";

    private static CertProfileEntity Profile(string name, string ekus, string keyUsages = DigitalSignature) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        Description = name,
        ExtendedKeyUsages = ekus,
        KeyUsages = keyUsages,
    };

    private static ProfileResolutionService Resolver(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<ProfileResolutionService>.Instance);

    [Theory]
    [InlineData("[]")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[ ]")]
    public async Task Empty_child_EKUs_inherit_from_the_parent(string childEkus)
    {
        using var db = InMemoryDbContextFactory.Create();
        var parent = Profile("parent", ServerAndClientAuth);
        var child = Profile("child", childEkus);
        child.InheritsFromId = parent.Id;
        child.InheritanceEnabled = true;
        db.CertProfiles.AddRange(parent, child);
        await db.SaveChangesAsync();

        var effective = await Resolver(db).ResolveCertProfileAsync(child.Id);

        Assert.Equal(ServerAndClientAuth, effective.ExtendedKeyUsages);
        Assert.Equal("inherited", effective.FieldSources[nameof(effective.ExtendedKeyUsages)]);
    }

    [Fact]
    public async Task Non_empty_child_EKUs_still_override_the_parent()
    {
        using var db = InMemoryDbContextFactory.Create();
        var parent = Profile("parent", ServerAndClientAuth);
        var child = Profile("child", ClientAuthOnly);
        child.InheritsFromId = parent.Id;
        child.InheritanceEnabled = true;
        db.CertProfiles.AddRange(parent, child);
        await db.SaveChangesAsync();

        var effective = await Resolver(db).ResolveCertProfileAsync(child.Id);

        Assert.Equal(ClientAuthOnly, effective.ExtendedKeyUsages);
        Assert.Equal("overridden", effective.FieldSources[nameof(effective.ExtendedKeyUsages)]);
    }

    [Fact]
    public async Task Empty_child_key_usages_inherit_too()
    {
        // KeyUsages shared the same MergeString path, so it had the same defect.
        using var db = InMemoryDbContextFactory.Create();
        var parent = Profile("parent", ServerAndClientAuth, keyUsages: "[\"digitalSignature\",\"keyEncipherment\"]");
        var child = Profile("child", ClientAuthOnly, keyUsages: "[]");
        child.InheritsFromId = parent.Id;
        child.InheritanceEnabled = true;
        db.CertProfiles.AddRange(parent, child);
        await db.SaveChangesAsync();

        var effective = await Resolver(db).ResolveCertProfileAsync(child.Id);

        Assert.Equal("[\"digitalSignature\",\"keyEncipherment\"]", effective.KeyUsages);
    }

    [Fact]
    public async Task A_profile_with_inheritance_disabled_keeps_its_own_empty_list()
    {
        // Without a parent to inherit from, empty stays empty — the fix must not invent usages.
        using var db = InMemoryDbContextFactory.Create();
        var standalone = Profile("standalone", "[]");
        standalone.InheritanceEnabled = false;
        db.CertProfiles.Add(standalone);
        await db.SaveChangesAsync();

        var effective = await Resolver(db).ResolveCertProfileAsync(standalone.Id);

        Assert.Equal("[]", effective.ExtendedKeyUsages);
    }
}
