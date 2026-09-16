using System.IO.Compression;
using ModularCA.Core.Services.Msae;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// The setup kit carries exactly what a customer's domain administrator needs and nothing secret:
/// the values Windows records for the policy server come from the CA, and the forest binding and
/// CA must belong to the same tenant.
/// </summary>
public class MsaeSetupKitServiceTests
{
    private static (MsaeSetupKitService Service, CertificateAuthorityEntity Ca, KerberosRealmEntity Realm, Guid OtherTenantRealm) Build(bool withRoot = true)
    {
        var db = InMemoryDbContextFactory.Create();
        var tenant = new TenantEntity { Id = Guid.NewGuid(), Name = "Customer A", Slug = "customer-a" };
        db.Tenants.Add(tenant);
        CertificateEntity? root = null;
        if (withRoot)
        {
            root = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "01", Pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", SubjectDN = "CN=Customer A Root", Issuer = "CN=Customer A Root", NotBefore = DateTime.UtcNow, NotAfter = DateTime.UtcNow.AddYears(10) };
            db.Certificates.Add(root);
        }
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Customer A Issuing", Label = "customer-a-issuing", TenantId = tenant.Id, CertificateId = root?.CertificateId, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        var user = new UserEntity { Id = Guid.NewGuid(), Username = "svc-enroll", Email = "x@y", PasswordHash = "x" };
        db.Users.Add(user);
        var realm = new KerberosRealmEntity { Id = Guid.NewGuid(), TenantId = tenant.Id, Realm = "CORP.CUSTOMER-A.LOCAL", DnsDomain = "corp.customer-a.local", ServicePrincipal = "HTTP/ca.msp.example", EnrollmentUserId = user.Id, IsEnabled = true };
        db.KerberosRealms.Add(realm);
        var other = new KerberosRealmEntity { Id = Guid.NewGuid(), TenantId = Guid.NewGuid(), Realm = "CORP.CUSTOMER-B.LOCAL", DnsDomain = "corp.customer-b.local", ServicePrincipal = "HTTP/ca.msp.example", EnrollmentUserId = user.Id, IsEnabled = true };
        db.KerberosRealms.Add(other);
        db.SaveChanges();
        var config = new SystemConfig { Https = { PublicDomain = "ca.msp.example", PublicPort = 443 } };
        return (new MsaeSetupKitService(db, config), ca, realm, other.Id);
    }

    [Fact]
    public async Task The_kit_carries_the_scripts_the_root_and_the_values_windows_records()
    {
        var (service, ca, realm, _) = Build();
        var files = (await service.FilesAsync(ca.Id, realm.Id))!;

        Assert.Equal(["README.md", "1-ad-service-account.ps1", "2-gpo-policy-server.ps1", "3-client-check.ps1", "customer-a-issuing-root.cer"], files.Select(f => f.Name));

        var gpo = files.Single(f => f.Name == "2-gpo-policy-server.ps1").Content;
        Assert.Contains("$CepUrl       = 'https://ca.msp.example/msae/customer-a-issuing/cep'", gpo);
        Assert.Contains($"$PolicyId     = '{{{ca.Id.ToString().ToUpperInvariant()}}}'", gpo);
        Assert.Contains("$FriendlyName = 'Customer A Issuing (ModularCA)'", gpo);
        Assert.Contains("[string]$Domain = 'corp.customer-a.local'", gpo);
        Assert.Contains("-ValueName AuthFlags    -Type DWord  -Value 2", gpo);   // Kerberos

        var ad = files.Single(f => f.Name == "1-ad-service-account.ps1").Content;
        Assert.Contains("CORP.CUSTOMER-A.LOCAL", ad);
        Assert.Contains("HTTP/ca.msp.example", ad);
        Assert.DoesNotContain("AccountPassword (ConvertTo-SecureString '", ad);   // no secret in the kit

        var check = files.Single(f => f.Name == "3-client-check.ps1").Content;
        Assert.Contains("https://ca.msp.example/msae/customer-a-issuing/whoami", check);
        Assert.Contains("klist get \"HTTP/ca.msp.example\"", check);
        Assert.Contains("*Customer A Issuing*", check);

        Assert.Contains("-----BEGIN CERTIFICATE-----", files.Single(f => f.Name == "customer-a-issuing-root.cer").Content);
        var readme = files.Single(f => f.Name == "README.md").Content;
        Assert.Contains("canonical name", readme);
        Assert.Contains("psexec -s", readme);
    }

    [Fact]
    public async Task The_zip_holds_the_same_files_and_a_ca_without_a_stored_root_omits_the_cer()
    {
        var (service, ca, realm, _) = Build();
        using var zip = new ZipArchive(new MemoryStream((await service.BuildAsync(ca.Id, realm.Id))!), ZipArchiveMode.Read);
        Assert.Equal(5, zip.Entries.Count);
        using var reader = new StreamReader(zip.GetEntry("2-gpo-policy-server.ps1")!.Open());
        Assert.Contains("Set-GPRegistryValue", await reader.ReadToEndAsync());

        var (bare, bareCa, bareRealm, _) = Build(withRoot: false);
        var files = (await bare.FilesAsync(bareCa.Id, bareRealm.Id))!;
        Assert.DoesNotContain(files, f => f.Name.EndsWith(".cer"));
    }

    [Fact]
    public async Task A_forest_bound_to_another_tenant_gets_no_kit_for_this_ca()
    {
        var (service, ca, realm, otherRealm) = Build();
        Assert.Null(await service.BuildAsync(ca.Id, otherRealm));
        Assert.Null(await service.BuildAsync(Guid.NewGuid(), realm.Id));
        Assert.Null(await service.BuildAsync(ca.Id, Guid.NewGuid()));
    }
}
