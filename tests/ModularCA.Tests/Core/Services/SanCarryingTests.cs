using Microsoft.AspNetCore.DataProtection;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// SANs reach the certificate they were asked for: overrides set at CSR upload (stored as objects
/// that issuance could not read, so silently ignored), and every SAN type on the infrastructure
/// CSR path that auto-renewal and Web TLS renewal take (which dropped all but DNS and IP).
/// </summary>
public sealed class SanCarryingTests
{
    [Fact]
    public void Overrides_are_read_in_the_stored_form_and_in_the_legacy_object_form()
    {
        const string original = "[\"DNS:a.example\"]";
        Assert.Equal("[\"DNS:b.example\",\"IP:10.0.0.1\"]",
            CertificateIssuanceService.ApplySanOverrides(original, "[{\"Type\":\"DNS\",\"Value\":\"b.example\"},{\"type\":\"ip\",\"value\":\"10.0.0.1\"}]"));
        Assert.Equal("[\"DNS:b.example\"]", CertificateIssuanceService.ApplySanOverrides(original, "[\"DNS:b.example\"]"));
        Assert.Equal(original, CertificateIssuanceService.ApplySanOverrides(original, "[{\"Type\":\"DNS\"}]"));
        Assert.Equal(original, CertificateIssuanceService.ApplySanOverrides(original, "{\"Type\":\"DNS\",\"Value\":\"b\"}"));
    }

    [Fact]
    public async Task Upload_stores_overrides_in_the_form_issuance_reads()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (certProfile, signingProfile) = SeedProfiles(db);
        var user = new UserEntity { Id = Guid.NewGuid(), Username = "u", Email = "u@x" };
        db.Users.Add(user);
        db.SaveChanges();
        var service = new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService()));

        await service.UploadCsrAsync(CsrPem("CN=upload"), certProfile.Id, signingProfile.Id, user.Id, null,
            [new SanOverride { Type = "dns", Value = "override.example" }, new SanOverride { Type = "Email", Value = "a@example.test" }]);

        var row = db.CertificateRequests.Single();
        Assert.Equal("[\"DNS:override.example\",\"EMAIL:a@example.test\"]", row.SanOverrides);
        Assert.Equal(row.SanOverrides, CertificateIssuanceService.ApplySanOverrides(row.SubjectAlternativeNames, row.SanOverrides));
    }

    /// <summary>The regression end to end: an override stored by an upload before the fix is in the issued certificate.</summary>
    [Fact]
    public async Task A_legacy_upload_override_reaches_the_issued_certificate()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var ca = await w.CreateRootAsync("Override Root", null, null);
        var issued = await w.IssueLeafAsync(ca, "CN=leaf", ["DNS:original.example"],
            sanOverrides: "[{\"Type\":\"DNS\",\"Value\":\"override.example\"}]");

        var cert = CertificateUtil.ParseFromPem(issued.Pem);
        var names = GeneralNames.GetInstance(cert.GetExtensionParsedValue(X509Extensions.SubjectAlternativeName)).GetNames();
        Assert.Equal(["override.example"], names.Select(n => n.Name.ToString()));
    }

    [Fact]
    public async Task An_infrastructure_csr_carries_every_san_type()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (certProfile, signingProfile) = SeedProfiles(db);
        var service = new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService()));

        var (csrId, _) = await service.GenerateInfrastructureCsrAsync("CN=renewed", "ECDSA", 256, certProfile.Id, signingProfile.Id,
            ["DNS:host.example", "IP:10.0.0.5", "Email:ops@example.test", "rfc822:alt@example.test", "URI:https://host.example/", "UPN:svc@corp.example"],
            isInfrastructure: false);

        var row = db.CertificateRequests.Single(r => r.Id == csrId);
        Assert.Equal(
            ["DNS:host.example", "IP:10.0.0.5", "EMAIL:ops@example.test", "EMAIL:alt@example.test", "URI:https://host.example/", "UPN:svc@corp.example"],
            System.Text.Json.JsonSerializer.Deserialize<List<string>>(row.SubjectAlternativeNames!));

        using var reader = new StringReader(row.CSR);
        var csr = (Pkcs10CertificationRequest)new PemReader(reader).ReadObject();
        var extensions = X509Extensions.GetInstance(((AttributePkcs)AttributePkcs.GetInstance(csr.GetCertificationRequestInfo().Attributes[0])).AttrValues[0]);
        var names = GeneralNames.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.SubjectAlternativeName)).GetNames();
        Assert.Equal(6, names.Length);
        Assert.Equal(GeneralName.OtherName, names[5].TagNo);
    }

    [Theory]
    [InlineData("FOO:bar", "Unsupported SAN type 'FOO'")]
    [InlineData("host.example", "has no TYPE: prefix")]
    [InlineData("IP:not-an-address", "cannot be encoded as IP")]
    public async Task An_infrastructure_csr_refuses_a_san_it_cannot_encode_rather_than_dropping_it(string san, string message)
    {
        using var db = InMemoryDbContextFactory.Create();
        var (certProfile, signingProfile) = SeedProfiles(db);
        var service = new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService()));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => service.GenerateInfrastructureCsrAsync(
            "CN=renewed", "ECDSA", 256, certProfile.Id, signingProfile.Id, ["DNS:host.example", san]));
        Assert.Contains(message, ex.Message);
        Assert.Empty(db.CertificateRequests);
    }

    /// <summary>Auto-renewal reads a certificate's stored SANs with legacy otherName renderings repaired, so a UPN is renewed as a UPN.</summary>
    [Fact]
    public void Auto_renewal_reads_stored_sans_with_legacy_upns_repaired()
    {
        var sans = AutoRenewalJob.ParseSansFromJson(
            "[\"DNS:a.example\",\"Email:x@example.test\",\"Other:[1.3.6.1.4.1.311.20.2.3, [CONTEXT 0]user@corp.example]\"]");
        Assert.Equal(["DNS:a.example", "Email:x@example.test", "UPN:user@corp.example"], sans);
        Assert.Null(AutoRenewalJob.ParseSansFromJson("[]"));
        Assert.Null(AutoRenewalJob.ParseSansFromJson("not json"));
    }

    /// <summary>The Web TLS paths keep their DNS/IP-only rule though the CSR builder now takes every type.</summary>
    [Fact]
    public void Web_tls_sans_stay_dns_or_ip()
    {
        WebTlsProvisioningService.EnsureDnsOrIpSans(["DNS:localhost", "ip:127.0.0.1", " "]);
        Assert.Throws<InvalidOperationException>(() => WebTlsProvisioningService.EnsureDnsOrIpSans(["DNS:a", "EMAIL:x@y.test"]));
        Assert.Throws<InvalidOperationException>(() => WebTlsProvisioningService.EnsureDnsOrIpSans(["localhost"]));
    }

    private static (CertProfileEntity, SigningProfileEntity) SeedProfiles(ModularCADbContext db)
    {
        var certProfile = new CertProfileEntity { Name = "leaf", KeyUsages = "[]", ExtendedKeyUsages = "[]", AllowedKeySizes = "[]", AllowedSignatureAlgorithms = "[]" };
        var signingProfile = new SigningProfileEntity { Name = "sp", AllowedAlgorithms = "[]" };
        db.CertProfiles.Add(certProfile);
        db.SigningProfiles.Add(signingProfile);
        db.SaveChanges();
        return (certProfile, signingProfile);
    }

    private static string CsrPem(string subject)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()),
            new X509Name(subject), keys.Public, null);
        using var sw = new StringWriter();
        new PemWriter(sw).WriteObject(csr);
        return sw.ToString();
    }
}
