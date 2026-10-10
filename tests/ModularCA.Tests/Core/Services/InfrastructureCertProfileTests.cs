using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A CA issues its timestamp signer, its OCSP responder and its CMP signer from the certificate
/// profile it names, or from the seeded default when it names none. The profiles the application
/// finds by name, and the ones a CA names, cannot be changed into something that leaves one of
/// those certificates unable to be issued.
/// </summary>
public sealed class InfrastructureCertProfileTests
{
    private const string OcspSigning = "1.3.6.1.5.5.7.3.9";
    private const string TimeStamping = "1.3.6.1.5.5.7.3.8";

    private static CertProfileEntity Profile(string name, string ekus = "[]", bool ca = false, Guid? spaceId = null, Guid? caId = null) => new()
    {
        Name = name,
        IsCaProfile = ca,
        KeyUsages = ca ? "[\"Key Certificate Signing\",\"CRL Signing\"]" : "[\"Digital Signature\"]",
        ExtendedKeyUsages = ekus,
        AllowedKeySizes = "[]",
        AllowedSignatureAlgorithms = "[]",
        SpaceId = spaceId,
        CertificateAuthorityId = caId,
    };

    private static UpdateCertProfileRequest RequestFor(CertProfileEntity p) => new()
    {
        Name = p.Name,
        Description = p.Description,
        IsCaProfile = p.IsCaProfile,
        KeyUsages = p.KeyUsages,
        ExtendedKeyUsages = p.ExtendedKeyUsages,
        AllowedKeyAlgorithms = p.AllowedKeyAlgorithms,
        AllowedKeySizes = p.AllowedKeySizes,
        AllowedSignatureAlgorithms = p.AllowedSignatureAlgorithms,
        CertificateAuthorityId = p.CertificateAuthorityId,
        InheritsFromId = p.InheritsFromId,
        InheritanceEnabled = p.InheritanceEnabled,
    };

    // ---- which profile is in effect -------------------------------------------------------

    [Fact]
    public async Task The_default_is_the_seeded_profile_and_a_named_profile_replaces_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var seeded = Profile(SystemCertProfiles.Tsa, $"[\"{TimeStamping}\"]");
        var own = Profile("Long-lived TSA", $"[\"{TimeStamping}\"]");
        db.CertProfiles.AddRange(seeded, own);
        await db.SaveChangesAsync();
        var ca = new CertificateAuthorityEntity { Name = "ca" };

        Assert.Equal(seeded.Id, (await InfrastructureCertProfiles.ResolveAsync(db, InfrastructureCertProfiles.ChosenId(ca, InfrastructureCertProfiles.Tsa), InfrastructureCertProfiles.Tsa))!.Id);

        InfrastructureCertProfiles.Choose(ca, InfrastructureCertProfiles.Tsa, own.Id);
        Assert.Equal(own.Id, ca.TsaCertProfileId);
        Assert.Null(ca.OcspResponderCertProfileId);
        Assert.Null(ca.CmpSignerCertProfileId);
        Assert.Equal(own.Id, (await InfrastructureCertProfiles.ResolveAsync(db, InfrastructureCertProfiles.ChosenId(ca, InfrastructureCertProfiles.Tsa), InfrastructureCertProfiles.Tsa))!.Id);

        Assert.Null(await InfrastructureCertProfiles.ResolveAsync(db, null, InfrastructureCertProfiles.CmpSigner));
    }

    [Fact]
    public void A_profile_suits_a_role_only_when_it_lists_what_the_certificate_exists_for()
    {
        var tsa = InfrastructureCertProfiles.Tsa;
        var ocsp = InfrastructureCertProfiles.OcspResponder;
        var cmp = InfrastructureCertProfiles.CmpSigner;

        Assert.Null(InfrastructureCertProfiles.WhyUnsuitable(Profile("p", $"[\"{TimeStamping}\"]"), tsa));
        Assert.Null(InfrastructureCertProfiles.WhyUnsuitable(Profile("p", "[\"timeStamping\"]"), tsa));
        Assert.Null(InfrastructureCertProfiles.WhyUnsuitable(Profile("p", "[\"OCSPSigning\"]"), ocsp));
        Assert.Null(InfrastructureCertProfiles.WhyUnsuitable(Profile("p"), cmp));

        Assert.Contains("time stamping", InfrastructureCertProfiles.WhyUnsuitable(Profile("p", $"[\"{OcspSigning}\"]"), tsa));
        Assert.Contains("OCSP signing", InfrastructureCertProfiles.WhyUnsuitable(Profile("p"), ocsp));
        Assert.Contains("OCSP signing", InfrastructureCertProfiles.WhyUnsuitable(Profile("p", "not json"), ocsp));
        Assert.Contains("CA profile", InfrastructureCertProfiles.WhyUnsuitable(Profile("p", $"[\"{TimeStamping}\"]", ca: true), tsa));

        var noSignature = Profile("p");
        noSignature.KeyUsages = "[\"Key Encipherment\"]";
        Assert.Contains("digitalSignature", InfrastructureCertProfiles.WhyUnsuitable(noSignature, cmp));
        noSignature.KeyUsages = "[\"no such usage\"]";
        Assert.Contains("digitalSignature", InfrastructureCertProfiles.WhyUnsuitable(noSignature, cmp));
    }

    [Fact]
    public void A_ca_may_name_only_a_profile_it_may_issue_under()
    {
        var space = Guid.NewGuid();
        var ca = new CertificateAuthorityEntity { Name = "ca", SpaceId = space };
        var role = InfrastructureCertProfiles.OcspResponder;
        var usages = $"[\"{OcspSigning}\"]";

        Assert.Null(InfrastructureCertProfiles.WhyNotChoosable(Profile("instance-wide", usages), role, ca));
        Assert.Null(InfrastructureCertProfiles.WhyNotChoosable(Profile("own space", usages, spaceId: space), role, ca));
        Assert.Null(InfrastructureCertProfiles.WhyNotChoosable(Profile("own", usages, spaceId: space, caId: ca.Id), role, ca));
        Assert.Contains("another scope", InfrastructureCertProfiles.WhyNotChoosable(Profile("other space", usages, spaceId: Guid.NewGuid()), role, ca));
        Assert.Contains("another scope", InfrastructureCertProfiles.WhyNotChoosable(Profile("other ca", usages, spaceId: space, caId: Guid.NewGuid()), role, ca));
    }

    // ---- reissue ---------------------------------------------------------------------------

    /// <summary>The responder is issued from the profile the CA names, and from the default when it names none.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_responder_is_issued_from_the_profile_the_ca_names(bool named)
    {
        var world = SignerTestWorld.Create();
        var caId = world.CaEcId;
        Guid seededId, ownId;
        using (var seed = world.OpenDb())
        {
            var seeded = Profile(SystemCertProfiles.OcspResponder, $"[\"{OcspSigning}\"]");
            var own = Profile("Short OCSP", $"[\"{OcspSigning}\"]");
            seed.CertProfiles.AddRange(seeded, own);
            seed.SigningProfiles.Add(new SigningProfileEntity { Name = "ca-ec signing", AllowedAlgorithms = "[]", IssuerId = world["ca-ec"].Ref.CertificateId });
            if (named)
                seed.CertificateAuthorities.Single(c => c.Id == caId).OcspResponderCertProfileId = own.Id;
            await seed.SaveChangesAsync();
            (seededId, ownId) = (seeded.Id, own.Id);
        }

        using var db = world.OpenDb();
        await Service(world, db).ReissueInfrastructureCertsAsync(caId, reissueOcsp: true, reissueTsa: false);

        using var check = world.OpenDb();
        var request = Assert.Single(check.CertificateRequests);
        Assert.Equal(named ? ownId : seededId, request.CertProfileId);
        Assert.NotNull(check.CertificateAuthorities.Single(c => c.Id == caId).OcspResponderCertificateId);
    }

    /// <summary>A named profile that cannot do the job is refused before a key is generated or a pointer moved.</summary>
    [Theory]
    [InlineData("no usage", "OCSP signing")]
    [InlineData("ca profile", "CA profile")]
    [InlineData("other scope", "another scope")]
    public async Task A_named_profile_that_cannot_work_changes_nothing(string kind, string named)
    {
        var world = SignerTestWorld.Create();
        var caId = world.CaEcId;
        var previousResponder = Guid.NewGuid();
        using (var seed = world.OpenDb())
        {
            var own = kind switch
            {
                "no usage" => Profile("Broken", "[]"),
                "ca profile" => Profile("Broken", $"[\"{OcspSigning}\"]", ca: true),
                _ => Profile("Broken", $"[\"{OcspSigning}\"]", spaceId: world.SpaceA),
            };
            seed.CertProfiles.AddRange(Profile(SystemCertProfiles.OcspResponder, $"[\"{OcspSigning}\"]"), own);
            seed.SigningProfiles.Add(new SigningProfileEntity { Name = "ca-ec signing", AllowedAlgorithms = "[]", IssuerId = world["ca-ec"].Ref.CertificateId });
            var ca = seed.CertificateAuthorities.Single(c => c.Id == caId);
            ca.OcspResponderCertProfileId = own.Id;
            ca.OcspResponderCertificateId = previousResponder;
            await seed.SaveChangesAsync();
        }

        using var db = world.OpenDb();
        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Service(world, db).ReissueInfrastructureCertsAsync(caId, reissueOcsp: true, reissueTsa: false));

        Assert.Contains("Broken", refused.Message);
        Assert.Contains(named, refused.Message);
        using var check = world.OpenDb();
        Assert.Equal(previousResponder, check.CertificateAuthorities.Single(c => c.Id == caId).OcspResponderCertificateId);
        Assert.Empty(check.CertificateRequests);
        Assert.Empty(world.Persistence.Appended);
    }

    /// <summary>
    /// The lifetime follows the profile where the profile is shorter than the ten years asked
    /// for. Issuance refuses a date past the profile's maximum, so a CA that named such a
    /// profile could not issue the certificate at all.
    /// </summary>
    [Fact]
    public void The_lifetime_is_ten_years_unless_the_profile_or_the_ca_ends_sooner()
    {
        var start = new DateTime(2026, 10, 10, 0, 0, 0, DateTimeKind.Utc);
        var farCa = start.AddYears(25);

        Assert.Equal(start.AddYears(10), CaCreationService.InfrastructureNotAfter(start, null, farCa));
        Assert.Equal(start.AddYears(10), CaCreationService.InfrastructureNotAfter(start, "P25Y", farCa));
        Assert.Equal(start.AddYears(10), CaCreationService.InfrastructureNotAfter(start, "not a duration", farCa));
        Assert.Equal(start.AddHours(10), CaCreationService.InfrastructureNotAfter(start, "PT10H", farCa));
        Assert.InRange(CaCreationService.InfrastructureNotAfter(start, "P30D", farCa), start.AddDays(30).AddMinutes(-1), start.AddDays(30).AddMinutes(1));
        Assert.Equal(start.AddYears(2), CaCreationService.InfrastructureNotAfter(start, "P25Y", start.AddYears(2)));
        Assert.Equal(start.AddDays(5), CaCreationService.InfrastructureNotAfter(start, "P30D", start.AddDays(5)));
    }

    [Fact]
    public async Task A_responder_issued_from_a_short_profile_lives_as_long_as_the_profile_allows()
    {
        var world = SignerTestWorld.Create();
        var caId = world.CaEcId;
        using (var seed = world.OpenDb())
        {
            var own = Profile("Thirty-day OCSP", $"[\"{OcspSigning}\"]");
            own.ValidityPeriodMax = "P30D";
            seed.CertProfiles.Add(own);
            seed.SigningProfiles.Add(new SigningProfileEntity { Name = "ca-ec signing", AllowedAlgorithms = "[]", IssuerId = world["ca-ec"].Ref.CertificateId });
            seed.CertificateAuthorities.Single(c => c.Id == caId).OcspResponderCertProfileId = own.Id;
            await seed.SaveChangesAsync();
        }

        using var db = world.OpenDb();
        await Service(world, db).ReissueInfrastructureCertsAsync(caId, reissueOcsp: true, reissueTsa: false);

        using var check = world.OpenDb();
        var responder = check.Certificates.Single(c => c.CertificateId == check.CertificateAuthorities.Single(a => a.Id == caId).OcspResponderCertificateId);
        Assert.InRange(responder.NotAfter, DateTime.UtcNow.AddDays(29), DateTime.UtcNow.AddDays(31));
    }

    [Fact]
    public void The_key_of_a_cas_own_certificates_follows_the_cas_key()
    {
        var world = SignerTestWorld.Create();
        using var db = world.OpenDb();
        string KeyFor(Guid caId) => CaCreationService.InfrastructureKeyFor(CertificateUtil.ParseFromPem(
            db.Certificates.Single(c => c.CertificateId == db.CertificateAuthorities.Single(a => a.Id == caId).CertificateId).Pem));

        Assert.Equal("ECDSA P-256", KeyFor(world.CaEcId));
        Assert.Equal("RSA 3072", KeyFor(world.CaRsaId));
    }

    // ---- the lock --------------------------------------------------------------------------

    public static TheoryData<string, bool> NameBound() => new()
    {
        { SystemCertProfiles.Tsa, false }, { SystemCertProfiles.OcspResponder, false }, { SystemCertProfiles.CmpSigner, false },
        { SystemCertProfiles.WebTls, false }, { SystemCertProfiles.MainCa, true },
    };

    [Theory]
    [MemberData(nameof(NameBound))]
    public async Task A_profile_found_by_name_keeps_its_name_kind_and_scope_and_is_not_deleted(string name, bool isCa)
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = Profile(name, $"[\"{TimeStamping}\",\"{OcspSigning}\"]", ca: isCa);
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();
        var service = new CertProfileService(db);

        var renamed = RequestFor(profile);
        renamed.Name = name + " 2";
        var rekinded = RequestFor(profile);
        rekinded.IsCaProfile = !isCa;
        var bound = RequestFor(profile);
        bound.CertificateAuthorityId = Guid.NewGuid();
        foreach (var (request, word) in new[] { (renamed, "renamed"), (rekinded, "turned into"), (bound, "bound to one CA") })
        {
            var refused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(profile.Id, request));
            Assert.Equal(ErrorCodes.CertProfileInUse, refused.Code);
            Assert.Contains(word, refused.Message);
        }
        var deleteRefused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.DeleteAsync(profile.Id));
        Assert.Equal(ErrorCodes.CertProfileInUse, deleteRefused.Code);

        var described = RequestFor(profile);
        described.Description = "still editable";
        described.ValidityPeriodMax = "P5Y";
        await service.UpdateAsync(profile.Id, described);

        var stored = Assert.Single(db.CertProfiles);
        Assert.Equal(name, stored.Name);
        Assert.Equal(isCa, stored.IsCaProfile);
        Assert.Null(stored.CertificateAuthorityId);
        Assert.Equal("still editable", stored.Description);
        Assert.NotNull((await service.GetByIdAsync(profile.Id))!.SystemPurpose);
    }

    [Theory]
    [InlineData(SystemCertProfiles.Tsa, "time stamping")]
    [InlineData(SystemCertProfiles.OcspResponder, "OCSP signing")]
    public async Task A_default_profile_cannot_lose_the_usage_its_certificate_exists_for(string name, string usage)
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = Profile(name, $"[\"{TimeStamping}\",\"{OcspSigning}\"]");
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();

        var stripped = RequestFor(profile);
        stripped.ExtendedKeyUsages = "[]";
        var refused = await Assert.ThrowsAsync<ResourceConflictException>(() => new CertProfileService(db).UpdateAsync(profile.Id, stripped));

        Assert.Contains(usage, refused.Message);
        Assert.Contains("Every CA that names no other profile", refused.Message);
        Assert.Contains(TimeStamping, db.CertProfiles.Single().ExtendedKeyUsages);
    }

    [Fact]
    public async Task A_profile_a_ca_names_stays_usable_by_that_ca_and_is_not_deleted()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = Profile("Short OCSP", $"[\"{OcspSigning}\"]");
        var ca = new CertificateAuthorityEntity { Name = "Issuing CA", Label = "issuing", OcspResponderCertProfileId = profile.Id };
        var other = new CertificateAuthorityEntity { Name = "Other CA", Label = "other" };
        db.CertProfiles.Add(profile);
        db.CertificateAuthorities.AddRange(ca, other);
        await db.SaveChangesAsync();
        var service = new CertProfileService(db);

        var deleteRefused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.DeleteAsync(profile.Id));
        Assert.Equal(ErrorCodes.CertProfileInUse, deleteRefused.Code);
        Assert.Contains("Issuing CA issues its OCSP Responder certificate from it", deleteRefused.Message);

        var stripped = RequestFor(profile);
        stripped.ExtendedKeyUsages = "[]";
        Assert.Contains("Issuing CA issues its OCSP Responder certificate from it",
            (await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(profile.Id, stripped))).Message);
        var asCa = RequestFor(profile);
        asCa.IsCaProfile = true;
        await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(profile.Id, asCa));
        var boundElsewhere = RequestFor(profile);
        boundElsewhere.CertificateAuthorityId = other.Id;
        Assert.Contains("Issuing CA", (await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(profile.Id, boundElsewhere))).Message);

        var dto = (await service.GetAllAsync()).Single();
        Assert.Null(dto.SystemPurpose);
        Assert.Equal(["Issuing CA: OCSP Responder"], dto.InfrastructureUses);

        var renamedAndBound = RequestFor(profile);
        renamedAndBound.Name = "Shorter OCSP";
        renamedAndBound.CertificateAuthorityId = ca.Id;
        await service.UpdateAsync(profile.Id, renamedAndBound);
        Assert.Equal("Shorter OCSP", db.CertProfiles.Single().Name);

        ca.OcspResponderCertProfileId = null;
        await db.SaveChangesAsync();
        await service.DeleteAsync(profile.Id);
        Assert.Empty(db.CertProfiles);
    }

    [Fact]
    public async Task A_profile_nothing_depends_on_is_changed_and_deleted_as_before()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = Profile("Web server", "[\"1.3.6.1.5.5.7.3.1\"]");
        db.CertProfiles.Add(profile);
        await db.SaveChangesAsync();
        var service = new CertProfileService(db);

        var changed = RequestFor(profile);
        changed.Name = "Web servers";
        changed.ExtendedKeyUsages = "[]";
        await service.UpdateAsync(profile.Id, changed);
        Assert.Empty((await service.GetByIdAsync(profile.Id))!.InfrastructureUses);

        await service.DeleteAsync(profile.Id);
        Assert.Empty(db.CertProfiles);
    }

    // ---- the endpoints ---------------------------------------------------------------------

    [Fact]
    public async Task The_ca_page_reads_and_sets_the_three_profiles()
    {
        using var db = InMemoryDbContextFactory.Create();
        var space = new SpaceEntity { Name = "s", Slug = "s" };
        var ca = new CertificateAuthorityEntity { Name = "Issuing CA", Label = "issuing", SpaceId = space.Id };
        var seededTsa = Profile(SystemCertProfiles.Tsa, $"[\"{TimeStamping}\"]");
        var seededOcsp = Profile(SystemCertProfiles.OcspResponder, "[]");
        var ownTsa = Profile("Long-lived TSA", $"[\"{TimeStamping}\"]", spaceId: space.Id);
        var foreign = Profile("Foreign TSA", $"[\"{TimeStamping}\"]", spaceId: Guid.NewGuid());
        var caProfile = Profile("Some CA profile", ca: true);
        var user = new UserEntity { Id = Guid.NewGuid(), Username = "op", Email = "op@x" };
        db.Spaces.Add(space);
        db.CertificateAuthorities.Add(ca);
        db.CertProfiles.AddRange(seededTsa, seededOcsp, ownTsa, foreign, caProfile);
        db.Users.Add(user);
        db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = user.Id, Capability = Capabilities.CaManage, CertificateAuthorityId = ca.Id });
        await db.SaveChangesAsync();

        var read = Json(await InvokeAsync(db, user.Id, "GetInfrastructureProfiles", ca.Id));
        var roles = read.GetProperty("Roles").EnumerateArray().ToDictionary(r => r.GetProperty("Key").GetString()!);
        Assert.Equal(["ocspResponder", "tsa", "cmpSigner"], read.GetProperty("Roles").EnumerateArray().Select(r => r.GetProperty("Key").GetString()));
        Assert.Equal(JsonValueKind.Null, roles["tsa"].GetProperty("ChosenProfileId").ValueKind);
        Assert.Equal(seededTsa.Id, roles["tsa"].GetProperty("ProfileId").GetGuid());
        Assert.Equal(JsonValueKind.Null, roles["tsa"].GetProperty("Problem").ValueKind);
        Assert.Contains("OCSP signing", roles["ocspResponder"].GetProperty("Problem").GetString());
        Assert.Contains("does not exist yet", roles["cmpSigner"].GetProperty("Problem").GetString());
        var candidates = read.GetProperty("Candidates").EnumerateArray().ToDictionary(c => c.GetProperty("Name").GetString()!);
        Assert.Equal(["Long-lived TSA", SystemCertProfiles.OcspResponder, SystemCertProfiles.Tsa], candidates.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["tsa", "cmpSigner"], candidates["Long-lived TSA"].GetProperty("Suits").EnumerateArray().Select(s => s.GetString()));

        // What the panel beside the pickers shows: each profile's usages, and what all three certificates get.
        Assert.Equal(seededTsa.Id, roles["tsa"].GetProperty("DefaultProfileId").GetGuid());
        Assert.Equal(JsonValueKind.Null, roles["cmpSigner"].GetProperty("DefaultProfileId").ValueKind);
        Assert.Equal(["Digital Signature"], candidates["Long-lived TSA"].GetProperty("KeyUsages").EnumerateArray().Select(s => s.GetString()));
        var usage = Assert.Single(candidates["Long-lived TSA"].GetProperty("ExtendedKeyUsages").EnumerateArray());
        Assert.Equal(TimeStamping, usage.GetProperty("Value").GetString());
        Assert.Equal(10, read.GetProperty("LifetimeYears").GetInt32());
        Assert.Equal(JsonValueKind.Null, read.GetProperty("SubjectKey").ValueKind);

        foreach (var (profileId, word) in new[] { (foreign.Id, "another scope"), (caProfile.Id, "CA profile"), (seededOcsp.Id, "time stamping"), (Guid.NewGuid(), "does not exist") })
        {
            var refused = Assert.IsType<BadRequestObjectResult>(await InvokeAsync(db, user.Id, "SetInfrastructureProfiles", ca.Id, tsa: profileId));
            Assert.Contains(word, Json(refused).GetProperty("error").GetString());
        }
        Assert.Null(db.CertificateAuthorities.Single().TsaCertProfileId);

        Assert.Equal(1, Json(await InvokeAsync(db, user.Id, "SetInfrastructureProfiles", ca.Id, tsa: ownTsa.Id)).GetProperty("changed").GetInt32());
        Assert.Equal(ownTsa.Id, db.CertificateAuthorities.Single().TsaCertProfileId);
        Assert.Equal(0, Json(await InvokeAsync(db, user.Id, "SetInfrastructureProfiles", ca.Id, tsa: ownTsa.Id)).GetProperty("changed").GetInt32());
        var reread = Json(await InvokeAsync(db, user.Id, "GetInfrastructureProfiles", ca.Id));
        Assert.Equal(ownTsa.Id, reread.GetProperty("Roles").EnumerateArray().Single(r => r.GetProperty("Key").GetString() == "tsa").GetProperty("ChosenProfileId").GetGuid());

        Assert.Equal(1, Json(await InvokeAsync(db, user.Id, "SetInfrastructureProfiles", ca.Id)).GetProperty("changed").GetInt32());
        Assert.Null(db.CertificateAuthorities.Single().TsaCertProfileId);

        var stranger = new UserEntity { Id = Guid.NewGuid(), Username = "stranger", Email = "s@x" };
        db.Users.Add(stranger);
        await db.SaveChangesAsync();
        Assert.Equal(403, Assert.IsType<ObjectResult>(await InvokeAsync(db, stranger.Id, "SetInfrastructureProfiles", ca.Id, tsa: ownTsa.Id)).StatusCode);
        Assert.IsType<NotFoundObjectResult>(await InvokeAsync(db, user.Id, "GetInfrastructureProfiles", Guid.NewGuid()));
    }

    private static JsonElement Json(IActionResult result)
        => JsonSerializer.SerializeToElement(Assert.IsAssignableFrom<ObjectResult>(result).Value);

    /// <summary>Invokes the real <c>AdminCaController</c> action <paramref name="action"/> on <paramref name="caId"/> as <paramref name="userId"/>.</summary>
    private static async Task<IActionResult> InvokeAsync(ModularCADbContext db, Guid userId, string action, Guid caId, Guid? tsa = null)
    {
        var services = new SpaceIsolationMatrixTests.Resolver(db);
        services.Add(typeof(ModularCA.Auth.Interfaces.ICurrentUserService), new CurrentUser(db, userId));
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminCaController");
        var controller = ActivatorUtilities.CreateInstance(services, type);
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", userId.ToString())], "test")), RequestServices = services };
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });
        if (action == "GetInfrastructureProfiles")
            return await (Task<IActionResult>)type.GetMethod(action)!.Invoke(controller, [caId])!;
        var request = Activator.CreateInstance(ApiAssembly.Instance.GetTypes().Single(t => t.Name == "SetInfrastructureProfilesRequest"))!;
        request.GetType().GetProperty("TsaCertProfileId")!.SetValue(request, tsa);
        return await (Task<IActionResult>)type.GetMethod(action)!.Invoke(controller, [caId, request])!;
    }

    private sealed class CurrentUser(ModularCADbContext db, Guid id) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; private set; }
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync()
        {
            User ??= db.Users.Single(u => u.Id == id);
            return Task.CompletedTask;
        }
    }

    private static CaCreationService Service(SignerTestWorld world, ModularCADbContext db)
    {
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence);
        return new CaCreationService(
            db,
            InstanceCeremonyEndpointTests.Fake<ICrlService>.Create(),
            InstanceCeremonyEndpointTests.Fake<ICaServiceUrlService>.Create(),
            new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService())),
            new SignerIssuance(db, signer),
            new SystemConfig(),
            NullLogger<CaCreationService>.Instance,
            signer);
    }

    /// <summary>Issues the requested certificate with the CA key through the signer and links it to its request, as issuance does.</summary>
    private sealed class SignerIssuance(ModularCADbContext db, ISigningService signer) : ICertificateIssuanceService
    {
        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCert, KeyRef caKey, SigningContext caSigningContext, CancellationToken cancellationToken = default)
        {
            var request = db.CertificateRequests.Single(c => c.Id == csrId);
            using var reader = new StringReader(request.CSR);
            var csr = (Pkcs10CertificationRequest)new PemReader(reader).ReadObject();

            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
            gen.SetIssuerDN(caCert.SubjectDN);
            gen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
            gen.SetNotBefore(notBefore ?? DateTime.UtcNow.AddMinutes(-1));
            gen.SetNotAfter(notAfter ?? DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(csr.GetPublicKey());
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
            var cert = gen.Generate(new SigningServiceSignatureFactory(signer, caKey, SignatureAlgorithm.ForPublicKey(caCert.GetPublicKey()), caSigningContext));

            var pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE");
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
                SubjectDN = cert.SubjectDN.ToString(),
                Issuer = cert.IssuerDN.ToString(),
                Pem = pem,
                RawCertificate = cert.GetEncoded(),
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
            };
            db.Certificates.Add(row);
            request.IssuedCertificateId = row.CertificateId;
            request.Status = "Issued";
            db.SaveChanges();
            return Task.FromResult(new IssuanceResult(pem));
        }

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> IssueCaCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId,
            DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten)
            => throw new NotSupportedException();
    }
}
