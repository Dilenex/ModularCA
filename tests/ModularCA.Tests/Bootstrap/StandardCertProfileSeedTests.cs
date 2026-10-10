using System.Text.Json;
using ModularCA.Bootstrap;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// A new install is given a certificate profile for each kind of certificate its seeded request
/// profiles describe, and each of those request profiles defaults to the one made for it.
/// </summary>
public sealed class StandardCertProfileSeedTests
{
    [Fact]
    public void Bootstrap_seeds_the_standard_profiles_and_the_request_profiles_default_to_them()
    {
        using var db = InMemoryDbContextFactory.Create();
        BootstrapProfileSeeder.LoadOidsToDb(db, YamlOIDLoader.GetDefaultOIDConfig());
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        db.SigningProfiles.Add(signing);
        db.SaveChanges();

        BootstrapProfileSeeder.SeedInfrastructureCertProfiles(db);
        BootstrapProfileSeeder.SeedStandardCertProfiles(db, signing);
        BootstrapProfileSeeder.SeedStandardCertProfiles(db, signing);
        var requestProfiles = BootstrapProfileSeeder.SeedDefaultRequestProfiles(db);

        foreach (var standard in StandardCertProfiles.All)
        {
            var profile = Assert.Single(db.CertProfiles, p => p.Name == standard.Name);
            Assert.False(profile.IsCaProfile);
            Assert.True(profile.CanBeDeleted);
            Assert.Equal(standard.KeyUsages, JsonSerializer.Deserialize<string[]>(profile.KeyUsages));
            Assert.Equal(standard.ExtendedKeyUsageOids, JsonSerializer.Deserialize<string[]>(profile.ExtendedKeyUsages));
            Assert.Equal(StandardCertProfiles.ValidityPeriodMin, profile.ValidityPeriodMin);
            Assert.Equal(standard.ValidityPeriodMax, profile.ValidityPeriodMax);
            Assert.Single(db.AllowedCertProfileSigningProfiles, l => l.CertProfileId == profile.Id && l.SigningProfileId == signing.Id);
            Assert.Null(SystemCertProfiles.PurposeOf(profile.Name));
        }

        Assert.Equal(6, requestProfiles.Count);
        Assert.Equal(6, StandardCertProfiles.DefaultForRequestProfile.Count);
        foreach (var (requestProfileName, certProfileName) in StandardCertProfiles.DefaultForRequestProfile)
        {
            var requestProfile = Assert.Single(db.RequestProfiles, p => p.Name == requestProfileName);
            Assert.Equal(db.CertProfiles.Single(p => p.Name == certProfileName).Id, requestProfile.DefaultCertProfileId);
            // Only the default: an allowed list would also override a protocol's configured profile.
            Assert.Equal("[]", requestProfile.AllowedCertProfileIds);
        }
    }
}
