using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Msae;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins how ModularCA templates and profiles become the policy a Windows client sees: which
/// templates are offered, what each says about key, validity and extensions, and where the client
/// is told to enroll.
/// </summary>
/// <remarks>
/// The extension values matter most. A client copies them into its CSR, so an EKU or key usage
/// that does not decode to what the certificate profile says would let a client ask for one
/// thing and be issued another. Each is decoded back from DER and compared to the profile.
/// </remarks>
public class XcepPolicyServiceTests
{
    private sealed class RecordingAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public List<(string Username, Guid CaId)> Asked { get; } = [];
        public Task<bool> MayEnrollAsync(string username, Guid caId)
        {
            Asked.Add((username, caId));
            return Task.FromResult(verdict);
        }
    }

    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required X509Certificate2 CaCert { get; init; }
        public required CertificateAuthorityEntity Ca { get; init; }
        public required SigningProfileEntity Signing { get; init; }
        public required CertProfileEntity DeviceProfile { get; init; }
        public required RecordingAuthorizer Authorizer { get; init; }
        public required XcepPolicyService Service { get; init; }

        public CertificateTemplateEntity AddTemplate(string name, CertProfileEntity profile, string? oid,
            bool enabled = true, bool machine = true, int minor = 0, Guid? caId = null)
        {
            var t = new CertificateTemplateEntity
            {
                Id = Guid.NewGuid(), Name = name, CaId = caId ?? Ca.Id, CertProfileId = profile.Id,
                SigningProfileId = Signing.Id, IsEnabled = enabled, MsaeTemplateOid = oid,
                MsaeMachineType = machine, MsaeMinorVersion = minor,
            };
            Db.CertificateTemplates.Add(t);
            Db.SaveChanges();
            return t;
        }
    }

    private static Harness Build(bool msaeEnabled = true, bool member = true)
    {
        var db = InMemoryDbContextFactory.Create();
        var caCert = TestCertificates.CreateCa("CN=Lab Issuing CA, O=ModularCA");
        var caCertEntity = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = caCert.SerialNumber, Pem = caCert.ExportCertificatePem(),
            SubjectDN = caCert.Subject, Issuer = caCert.Issuer, IsCA = true, NotBefore = caCert.NotBefore, NotAfter = caCert.NotAfter,
        };
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = "Lab CA", Label = "lab", IsDefault = true, IsEnabled = true,
            CertificateId = caCertEntity.CertificateId, TenantId = Guid.NewGuid(),
        };
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "lab-signing", IssuerId = caCertEntity.CertificateId };
        var device = new CertProfileEntity
        {
            Id = Guid.NewGuid(), Name = "Device", ValidityPeriodMax = "P365D",
            KeyUsages = """["digitalSignature","keyEncipherment"]""",
            ExtendedKeyUsages = """["clientAuth","serverAuth"]""",
            AllowedKeyAlgorithms = """["RSA"]""",
            AllowedKeySizes = """["3072","2048","4096"]""",
        };
        db.Certificates.Add(caCertEntity);
        db.CertificateAuthorities.Add(ca);
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(device);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "MSAE", IsEnabled = msaeEnabled,
            SigningProfileId = signing.Id, CertProfileId = device.Id,
        });
        // The usage catalogue the profile names are resolved against, as bootstrap seeds it.
        db.OIDOptions.AddRange(
            new OIDOptionEntity { OID = "1.3.6.1.5.5.7.3.2", FriendlyName = "clientAuth", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = "1.3.6.1.5.5.7.3.1", FriendlyName = "serverAuth", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = "2.5.29.15.0", FriendlyName = "digitalSignature", KeyUsage = "Standard" },
            new OIDOptionEntity { OID = "2.5.29.15.2", FriendlyName = "keyEncipherment", KeyUsage = "Standard" });
        db.SaveChanges();

        var config = new SystemConfig();
        config.Https.PublicDomain = "ca.example.test";
        config.Https.Port = 443;

        var authorizer = new RecordingAuthorizer(member);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var service = new XcepPolicyService(db, new CaResolverService(db), authorizer, profiles,
            new IssuanceValidationService(db, NullLogger<IssuanceValidationService>.Instance), config,
            NullLogger<XcepPolicyService>.Instance);

        return new Harness { Db = db, CaCert = caCert, Ca = ca, Signing = signing, DeviceProfile = device, Authorizer = authorizer, Service = service };
    }

    private static byte[] Value(XcepMessages.PolicyTemplate t, string oid) => t.Extensions.Single(e => e.Oid == oid).Value;

    [Fact]
    public async Task Only_enabled_templates_offered_to_windows_on_this_ca_are_advertised()
    {
        var h = Build();
        h.AddTemplate("Zulu", h.DeviceProfile, "2.25.30");
        h.AddTemplate("Alpha", h.DeviceProfile, "2.25.10");
        h.AddTemplate("NotOffered", h.DeviceProfile, oid: null);
        h.AddTemplate("Disabled", h.DeviceProfile, "2.25.40", enabled: false);
        var otherCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "other", Label = "other", IsEnabled = true, TenantId = h.Ca.TenantId };
        h.Db.CertificateAuthorities.Add(otherCa);
        h.Db.SaveChanges();
        h.AddTemplate("Elsewhere", h.DeviceProfile, "2.25.50", caId: otherCa.Id);

        var policy = await h.Service.GetPoliciesAsync("lab", "svc-enroll");

        Assert.Equal(["Alpha", "Zulu"], policy.Templates.Select(t => t.Name));
        Assert.Equal(["2.25.10", "2.25.30"], policy.Templates.Select(t => t.Oid));
    }

    [Fact]
    public async Task A_template_whose_profile_permits_no_rsa_key_is_skipped_not_advertised()
    {
        var h = Build();
        var ecc = new CertProfileEntity { Id = Guid.NewGuid(), Name = "ECC only", AllowedKeyAlgorithms = """["ECDSA"]""" };
        h.Db.CertProfiles.Add(ecc);
        h.Db.SaveChanges();
        h.AddTemplate("EccDevice", ecc, "2.25.60");
        h.AddTemplate("RsaDevice", h.DeviceProfile, "2.25.61");

        var policy = await h.Service.GetPoliciesAsync("lab", "svc-enroll");
        Assert.Equal(["RsaDevice"], policy.Templates.Select(t => t.Name));
    }

    [Fact]
    public async Task Template_attributes_come_from_the_certificate_profile()
    {
        var h = Build();
        h.AddTemplate("LabUser", h.DeviceProfile, "2.25.20", machine: false, minor: 2);

        var t = Assert.Single((await h.Service.GetPoliciesAsync("lab", "svc-enroll")).Templates);

        Assert.Equal(365L * 24 * 3600, t.ValiditySeconds);
        Assert.Equal((long)(365L * 24 * 3600 * 0.2), t.RenewalSeconds);
        Assert.Equal(2048, t.MinimalKeyLength);          // the smallest size the profile permits
        Assert.False(t.MachineType);
        Assert.Equal((100, 2), (t.MajorVersion, t.MinorVersion));
        Assert.Equal("2.16.840.1.101.3.4.2.1", t.HashAlgorithmOid);
        Assert.Equal(("1.2.840.113549.1.1.1", "RSA"), (t.PublicKeyAlgorithmOid, t.PublicKeyAlgorithmName));
        Assert.False(t.AutoEnroll);
        Assert.False(t.ExportableKey);
        Assert.Equal([0], t.CaReferenceIds);
    }

    [Fact]
    public async Task Extensions_decode_back_to_what_the_profile_says()
    {
        var h = Build();
        h.AddTemplate("LabDevice", h.DeviceProfile, "2.25.10", minor: 5);

        var t = Assert.Single((await h.Service.GetPoliciesAsync("lab", "svc-enroll")).Templates);

        // Key usage: the two bits the profile names, and critical, as RFC 5280 recommends.
        var keyUsage = t.Extensions.Single(e => e.Oid == "2.5.29.15");
        Assert.True(keyUsage.Critical);
        var bits = KeyUsage.GetInstance(Asn1Object.FromByteArray(keyUsage.Value)).IntValue;
        Assert.Equal(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment, bits);

        // EKU: the profile's names resolved to OIDs through the catalogue.
        var eku = (Asn1Sequence)Asn1Object.FromByteArray(Value(t, "2.5.29.37"));
        Assert.Equal(["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"], eku.Cast<DerObjectIdentifier>().Select(o => o.Id));

        // Application policies carry the same OIDs in Windows' own extension.
        var appPolicies = (Asn1Sequence)Asn1Object.FromByteArray(Value(t, "1.3.6.1.4.1.311.21.10"));
        Assert.Equal(["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"],
            appPolicies.Cast<Asn1Sequence>().Select(s => ((DerObjectIdentifier)s[0]).Id));

        // Template information is what the client echoes in its CSR: OID plus version.
        var info = (Asn1Sequence)Asn1Object.FromByteArray(Value(t, MsaeCsrTemplate.TemplateInfoOid));
        Assert.Equal("2.25.10", ((DerObjectIdentifier)info[0]).Id);
        Assert.Equal(100, ((DerInteger)info[1]).IntValueExact);
        Assert.Equal(5, ((DerInteger)info[2]).IntValueExact);

        // And the CSR reader on the enrollment side reads that same value back.
        Assert.Equal(4, t.Extensions.Count);
    }

    [Fact]
    public async Task A_profile_with_no_usages_yields_only_the_template_information_extension()
    {
        var h = Build();
        var bare = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Bare", KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        h.Db.CertProfiles.Add(bare);
        h.Db.SaveChanges();
        h.AddTemplate("Bare", bare, "2.25.70");

        var t = Assert.Single((await h.Service.GetPoliciesAsync("lab", "svc-enroll")).Templates);
        Assert.Equal([MsaeCsrTemplate.TemplateInfoOid], t.Extensions.Select(e => e.Oid));
        Assert.Equal(2048, t.MinimalKeyLength);
    }

    [Fact]
    public async Task The_ca_entry_carries_its_certificate_and_the_ces_url_and_reports_permission()
    {
        var h = Build(member: false);
        h.AddTemplate("LabDevice", h.DeviceProfile, "2.25.10");

        var policy = await h.Service.GetPoliciesAsync(null, "svc-enroll");

        var ca = Assert.Single(policy.Cas);
        Assert.Equal("https://ca.example.test/msae/lab/ces", ca.CesUri);
        Assert.Equal(h.CaCert.RawData, ca.CertificateDer);
        Assert.False(ca.EnrollPermission);
        Assert.False(policy.Templates.Single().Enroll);
        Assert.Equal([("svc-enroll", h.Ca.Id)], h.Authorizer.Asked);

        Assert.Equal(h.Ca.Id, policy.PolicyId);
        Assert.Contains("Lab CA", policy.FriendlyName);
        Assert.Equal(XcepPolicyService.NextUpdateHours, policy.NextUpdateHours);
    }

    [Fact]
    public async Task A_member_is_told_they_may_enroll()
    {
        var h = Build(member: true);
        h.AddTemplate("LabDevice", h.DeviceProfile, "2.25.10");
        var policy = await h.Service.GetPoliciesAsync("lab", "svc-enroll");
        Assert.True(policy.Cas.Single().EnrollPermission);
        Assert.True(policy.Templates.Single().Enroll);
    }

    [Fact]
    public async Task A_ca_with_msae_disabled_refuses_policy_too()
    {
        var h = Build(msaeEnabled: false);
        var ex = await Assert.ThrowsAsync<MsaeEnrollmentException>(() => h.Service.GetPoliciesAsync("lab", "svc-enroll"));
        Assert.Contains("MSAE", ex.Message);
    }

    [Theory]
    [InlineData("[]", 2048)]
    [InlineData("""["512","4096"]""", 4096)]
    [InlineData("""["8192","3072"]""", 3072)]
    [InlineData("not json", 2048)]
    public void The_minimal_key_length_is_the_smallest_permitted_size_of_at_least_1024(string sizes, int expected)
    {
        Assert.Equal(expected, XcepPolicyService.MinimalRsaKeyLength(sizes));
    }
}
