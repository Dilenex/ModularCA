using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
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
/// Creating or updating a certificate profile checks its key usages and extended key usages
/// against the OID catalog, in the forms the field really arrives in: the comma-separated list
/// the console sends and the JSON array the profile is stored as. What the catalog cannot resolve
/// is refused with 400 (<c>MCA-PRF-002</c>) naming it, because issuance would leave it out of the
/// certificate; every spelling issuance resolves is accepted, a custom OID included once the
/// catalog has it; and every profile the bootstrap seeds passes.
/// </summary>
public sealed class CertProfileUsageCatalogTests
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

    private static CreateCertProfileRequest Create(string keyUsages, string extendedKeyUsages, string? name = null) => new()
    {
        Name = name ?? $"profile-{Guid.NewGuid():N}",
        KeyUsages = keyUsages,
        ExtendedKeyUsages = extendedKeyUsages,
        ValidityPeriodMax = "P1Y",
    };

    private static UpdateCertProfileRequest Update(CertProfileEntity p, string keyUsages, string extendedKeyUsages) => new()
    {
        Name = p.Name,
        Description = p.Description,
        IsCaProfile = p.IsCaProfile,
        KeyUsages = keyUsages,
        ExtendedKeyUsages = extendedKeyUsages,
        ValidityPeriodMin = p.ValidityPeriodMin,
        ValidityPeriodMax = p.ValidityPeriodMax,
        AllowedKeyAlgorithms = p.AllowedKeyAlgorithms,
        AllowedKeySizes = p.AllowedKeySizes,
        AllowedSignatureAlgorithms = p.AllowedSignatureAlgorithms,
        CertificateAuthorityId = p.CertificateAuthorityId,
        InheritsFromId = p.InheritsFromId,
        InheritanceEnabled = p.InheritanceEnabled,
    };

    private static async Task<ConfigurationValidationException> RefusedAsync(Func<Task> act)
    {
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(act);
        Assert.Equal(ErrorCodes.CertProfileUsageNotInCatalog, ex.Code);
        Assert.Equal("MCA-PRF-002", ex.Code);
        return ex;
    }

    // ── the forms that work today keep working ──────────────────────────

    /// <summary>The console joins its ticked options with ", "; an API client may send the stored JSON array.</summary>
    [Theory]
    [InlineData("digitalSignature, keyEncipherment", ServerAuth + ", " + ClientAuth)]
    [InlineData("[\"digitalSignature\",\"keyEncipherment\"]", "[\"" + ServerAuth + "\",\"" + ClientAuth + "\"]")]
    [InlineData("digitalSignature,keyEncipherment", "serverAuth,clientAuth")]
    [InlineData("Digital Signature, Key Encipherment", "Server Auth, Client Authentication")]
    [InlineData("[\"2.5.29.15.0\"]", "[\"SERVERAUTH\", \"ocspSigning\"]")]
    [InlineData("", "")]
    [InlineData("[]", "[]")]
    public async Task A_profile_whose_usages_the_catalog_resolves_is_saved_in_either_form(string keyUsages, string extendedKeyUsages)
    {
        using var db = Catalogued();
        var created = await new CertProfileService(db).CreateAsync(Create(keyUsages, extendedKeyUsages));

        var stored = db.CertProfiles.Single(p => p.Id == created.Id);
        // Stored as a JSON array whichever form arrived.
        var expected = CertProfileUsageValidation.ParseField(keyUsages).Count;
        Assert.Equal(expected, JsonSerializer.Deserialize<List<string>>(stored.KeyUsages)!.Count);
        Assert.Equal(CertProfileUsageValidation.ParseField(extendedKeyUsages).Count,
            JsonSerializer.Deserialize<List<string>>(stored.ExtendedKeyUsages)!.Count);
    }

    /// <summary>
    /// The check accepts at least what issuance resolves: every entry the issuance path keeps for
    /// a profile is one the catalog check passes.
    /// </summary>
    [Theory]
    [InlineData("[\"digitalSignature\",\"Key Encipherment\",\"2.5.29.15.4\",\"crl_sign\"]", "[\"" + ServerAuth + "\",\"client auth\",\"OCSPSIGNING\",\"kdc-authentication\"]")]
    public void Whatever_issuance_resolves_the_check_accepts(string keyUsages, string extendedKeyUsages)
    {
        using var db = Catalogued();
        var issuance = new IssuanceValidationService(db, NullLogger<IssuanceValidationService>.Instance);
        var issuedKeyUsages = issuance.SetupAllowedStandardOids(keyUsages);
        var issuedExtended = issuance.SetupAllowedExtendedOids(extendedKeyUsages, "[]");
        Assert.Equal(4, issuedKeyUsages.Count);
        Assert.Equal(4, issuedExtended.Count);

        var standard = db.OIDOptions.Where(o => o.KeyUsage == "Standard").AsEnumerable().Select(o => ((string?)o.OID, (string?)o.FriendlyName)).ToList();
        var extended = db.OIDOptions.Where(o => o.KeyUsage == "Extended").AsEnumerable().Select(o => ((string?)o.OID, (string?)o.FriendlyName)).ToList();
        Assert.True(CertProfileUsageValidation.CheckKeyUsages(keyUsages, standard).IsValid);
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages(extendedKeyUsages, extended).IsValid);
    }

    /// <summary>A custom EKU in dotted form is accepted exactly when the catalog has a row for it, which is when issuance emits it.</summary>
    [Theory]
    [InlineData(ClientAuth + ", " + CustomOid)]
    [InlineData("[\"" + ClientAuth + "\",\"" + CustomOid + "\"]")]
    public async Task A_custom_EKU_OID_is_accepted_once_the_catalog_has_it(string extendedKeyUsages)
    {
        using var db = Catalogued();
        var service = new CertProfileService(db);
        var issuance = new IssuanceValidationService(db, NullLogger<IssuanceValidationService>.Instance);

        // Without a catalog row issuance leaves the OID out of the certificate, so the profile is refused.
        Assert.Equal([ClientAuth], issuance.SetupAllowedExtendedOids(JsonSerializer.Serialize(CertProfileUsageValidation.ParseField(extendedKeyUsages)), "[]"));
        var ex = await RefusedAsync(() => service.CreateAsync(Create("digitalSignature", extendedKeyUsages)));
        Assert.Contains(CustomOid, ex.Message);
        Assert.DoesNotContain(ClientAuth, ex.Message);
        Assert.Empty(db.CertProfiles);

        db.OIDOptions.Add(new OIDOptionEntity { OID = CustomOid, FriendlyName = "dilenexDeviceAttestation", KeyUsage = "Extended" });
        db.SaveChanges();

        var created = await service.CreateAsync(Create("digitalSignature", extendedKeyUsages));
        var stored = db.CertProfiles.Single(p => p.Id == created.Id).ExtendedKeyUsages;
        Assert.Equal([ClientAuth, CustomOid], issuance.SetupAllowedExtendedOids(stored, "[]"));
    }

    // ── what is refused ─────────────────────────────────────────────────

    [Theory]
    [InlineData("digitalSignature, signEverything", ServerAuth, "KeyUsages", "signEverything")]
    [InlineData("[\"digitalSignature\",\"signEverything\"]", "[\"" + ServerAuth + "\"]", "KeyUsages", "signEverything")]
    [InlineData("digitalSignature", ServerAuth + ", teleportAuth", "ExtendedKeyUsages", "teleportAuth")]
    [InlineData("[\"digitalSignature\"]", "[\"" + ServerAuth + "\",\"1.2.3.4.5\"]", "ExtendedKeyUsages", "1.2.3.4.5")]
    // A key usage is not an extended one, and the other way round.
    [InlineData("serverAuth", "", "KeyUsages", "serverAuth")]
    [InlineData("", "digitalSignature", "ExtendedKeyUsages", "digitalSignature")]
    public async Task An_unknown_usage_is_refused_by_name_on_create_and_on_update(string keyUsages, string extendedKeyUsages, string field, string unknown)
    {
        using var db = Catalogued();
        var service = new CertProfileService(db);

        var ex = await RefusedAsync(() => service.CreateAsync(Create(keyUsages, extendedKeyUsages)));
        Assert.Contains(field, ex.Message);
        Assert.Contains(unknown, ex.Message);
        Assert.Contains("OID Options", ex.Message);
        Assert.Empty(db.CertProfiles);

        var created = await service.CreateAsync(Create("digitalSignature", ServerAuth));
        var profile = db.CertProfiles.Single(p => p.Id == created.Id);
        var before = (profile.KeyUsages, profile.ExtendedKeyUsages);
        ex = await RefusedAsync(() => service.UpdateAsync(profile.Id, Update(profile, keyUsages, extendedKeyUsages)));
        Assert.Contains(unknown, ex.Message);
        db.ChangeTracker.Clear();
        var after = db.CertProfiles.Single(p => p.Id == created.Id);
        Assert.Equal(before, (after.KeyUsages, after.ExtendedKeyUsages));
    }

    [Fact]
    public async Task Both_fields_are_named_when_both_are_wrong()
    {
        using var db = Catalogued();
        var ex = await RefusedAsync(() => new CertProfileService(db).CreateAsync(Create("signEverything", "teleportAuth, warpAuth")));
        Assert.Contains("KeyUsages contains signEverything, which is not", ex.Message);
        Assert.Contains("ExtendedKeyUsages contains teleportAuth, warpAuth, which are not", ex.Message);
    }

    [Theory]
    [InlineData("2.5.29.37.0")]
    [InlineData("[\"" + ServerAuth + "\",\"2.5.29.37.0\"]")]
    public async Task AnyExtendedKeyUsage_is_refused(string extendedKeyUsages)
    {
        using var db = Catalogued();
        var ex = await RefusedAsync(() => new CertProfileService(db).CreateAsync(Create("digitalSignature", extendedKeyUsages)));
        Assert.Contains("anyExtendedKeyUsage", ex.Message);
        Assert.Contains("forbidden", ex.Message);
    }

    // ── an existing profile can still be edited ─────────────────────────

    /// <summary>
    /// A profile written before the check may store a usage the catalog lacks (issuance leaves it
    /// out, with a warning). Saving it again with that usage still there is not refused; adding
    /// another unknown one is.
    /// </summary>
    [Fact]
    public async Task An_update_is_refused_only_for_an_unknown_usage_it_adds()
    {
        using var db = Catalogued();
        var legacy = new CertProfileEntity
        {
            Id = Guid.NewGuid(), Name = "legacy", ValidityPeriodMax = "P1Y",
            KeyUsages = "[\"digitalSignature\",\"legacySign\"]",
            ExtendedKeyUsages = "[\"" + ServerAuth + "\",\"1.2.3.4.5\"]",
        };
        db.CertProfiles.Add(legacy);
        db.SaveChanges();
        var service = new CertProfileService(db);

        // As the stored JSON, and as a client that joins with commas would send it back.
        await service.UpdateAsync(legacy.Id, Update(legacy, legacy.KeyUsages, legacy.ExtendedKeyUsages));
        await service.UpdateAsync(legacy.Id, Update(legacy, "digitalSignature, legacySign, keyEncipherment", ServerAuth + ", 1.2.3.4.5, " + ClientAuth));
        Assert.Contains("legacySign", db.CertProfiles.Single().KeyUsages);
        Assert.Contains(ClientAuth, db.CertProfiles.Single().ExtendedKeyUsages);

        var ex = await RefusedAsync(() => service.UpdateAsync(legacy.Id, Update(legacy, "digitalSignature, legacySign", ServerAuth + ", 1.2.3.4.5, 1.2.3.4.6")));
        Assert.Contains("1.2.3.4.6", ex.Message);
        Assert.DoesNotContain("1.2.3.4.5", ex.Message);
        Assert.DoesNotContain("legacySign", ex.Message);

        // Dropping the unknown ones is always possible.
        await service.UpdateAsync(legacy.Id, Update(legacy, "digitalSignature", ServerAuth));
        Assert.Equal("[\"digitalSignature\"]", db.CertProfiles.Single().KeyUsages.Replace(" ", ""));
    }

    // ── every profile the bootstrap seeds passes ────────────────────────

    [Fact]
    public async Task Every_profile_the_bootstrap_seeds_passes_the_check_as_stored_and_as_the_console_sends_it()
    {
        using var db = Catalogued();
        // The same calls, with the same usage arrays, as BootstrapModularCA makes.
        BootstrapProfileSeeder.CreateCertProfile(db, "Main CA Certificate Profile", "ca",
            ["Digital Signature", "Key Certificate Signing", "CRL Signing"], [], false, true, "[]", "[]", "[]", "P5Y", "P25Y");
        BootstrapProfileSeeder.CreateCertProfile(db, "Main Certificate Profile", "leaf",
            ["Digital Signature", "Key Encipherment"], ["Server Authentication", "Client Authentication", "Email Protection"], false, false, "[]", "[]", "[]", "P47D", "P397D");
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        db.SigningProfiles.Add(signing);
        db.SaveChanges();
        BootstrapProfileSeeder.SeedInfrastructureCertProfiles(db);
        BootstrapProfileSeeder.SeedStandardCertProfiles(db, signing);

        var seeded = db.CertProfiles.AsEnumerable().ToList();
        Assert.True(seeded.Count >= 2 + 4 + StandardCertProfiles.All.Count, $"only {seeded.Count} profiles seeded");
        var standard = db.OIDOptions.Where(o => o.KeyUsage == "Standard").AsEnumerable().Select(o => ((string?)o.OID, (string?)o.FriendlyName)).ToList();
        var extended = db.OIDOptions.Where(o => o.KeyUsage == "Extended").AsEnumerable().Select(o => ((string?)o.OID, (string?)o.FriendlyName)).ToList();
        var service = new CertProfileService(db);

        foreach (var profile in seeded)
        {
            var keyUsages = CertProfileUsageValidation.ParseField(profile.KeyUsages);
            var extendedKeyUsages = CertProfileUsageValidation.ParseField(profile.ExtendedKeyUsages);
            Assert.True(profile.IsCaProfile || keyUsages.Count > 0, $"{profile.Name} seeds no key usage");

            // Against the catalog alone, with nothing excused for being stored already.
            foreach (var form in new[] { profile.KeyUsages, string.Join(", ", keyUsages) })
            {
                var check = CertProfileUsageValidation.CheckKeyUsages(form, standard);
                Assert.True(check.IsValid, $"{profile.Name} key usages: {string.Join(", ", check.Unknown)}");
            }
            foreach (var form in new[] { profile.ExtendedKeyUsages, string.Join(", ", extendedKeyUsages) })
            {
                var check = CertProfileUsageValidation.CheckExtendedKeyUsages(form, extended);
                Assert.True(check.IsValid, $"{profile.Name} extended key usages: {string.Join(", ", check.Unknown)}");
            }

            // And a profile of the same usages can be created through the service, as the console
            // would send it. A CA profile is stored with keyCertSign and cRLSign under the names
            // the service adds, which must pass when it is read and saved back.
            var copy = await service.CreateAsync(new CreateCertProfileRequest
            {
                Name = profile.Name + " (copy)",
                IsCaProfile = profile.IsCaProfile,
                KeyUsages = string.Join(", ", keyUsages),
                ExtendedKeyUsages = string.Join(", ", extendedKeyUsages),
                ValidityPeriodMin = profile.ValidityPeriodMin,
                ValidityPeriodMax = profile.ValidityPeriodMax,
            });
            var stored = db.CertProfiles.Single(p => p.Id == copy.Id);
            Assert.True(CertProfileUsageValidation.CheckKeyUsages(stored.KeyUsages, standard).IsValid, $"{profile.Name} copy");
        }
    }
}
