using ModularCA.Bootstrap;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A CA created at runtime issues itself an OCSP responder and a timestamp signer through its own
/// signing profile, from the certificate profiles bootstrap seeds. Each must carry the extended
/// key usage its job needs: a responder without <c>id-kp-OCSPSigning</c> is refused by the OCSP
/// service, and the CA then answers every query "unauthorized".
/// </summary>
public sealed class RuntimeCaInfrastructureCertificateTests
{
    private static readonly DerObjectIdentifier OcspSigning = new("1.3.6.1.5.5.7.3.9");
    private static readonly DerObjectIdentifier TimeStamping = new("1.3.6.1.5.5.7.3.8");

    /// <summary>The world of the name-constraint tests, with the certificate profiles as bootstrap seeds them.</summary>
    private static NameConstraintIssuanceTests.IssuanceWorld WorldWithSeededProfiles()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        w.Db.CertProfiles.RemoveRange(w.Db.CertProfiles.Where(p =>
            p.Name == "TSA Certificate Profile" || p.Name == "OCSP Responder Certificate Profile"));
        w.Db.SaveChanges();
        BootstrapProfileSeeder.LoadOidsToDb(w.Db, YamlOIDLoader.GetDefaultOIDConfig());
        BootstrapProfileSeeder.SeedInfrastructureCertProfiles(w.Db);
        return w;
    }

    private static IList<DerObjectIdentifier> ExtendedKeyUsages(NameConstraintIssuanceTests.IssuanceWorld w, Guid? certificateId)
    {
        Assert.NotNull(certificateId);
        var row = w.Db.Certificates.Single(c => c.CertificateId == certificateId);
        return CertificateUtil.ParseFromPem(row.Pem).GetExtendedKeyUsage() ?? [];
    }

    private static void AssertInfrastructure(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity ca)
    {
        Assert.Contains(OcspSigning, ExtendedKeyUsages(w, ca.OcspResponderCertificateId));
        Assert.Contains(TimeStamping, ExtendedKeyUsages(w, ca.TsaCertificateId));
    }

    [Fact]
    public async Task A_root_created_at_runtime_gets_a_responder_and_a_timestamp_signer_that_can_do_their_jobs()
    {
        var w = WorldWithSeededProfiles();

        var root = await w.CreateRootAsync("Runtime Root", null, null);

        AssertInfrastructure(w, root);
    }

    /// <summary>
    /// Staging's two profiles had been seeded with no usages by an early build. Every CA created
    /// there got a responder that could not answer, and nothing said so.
    /// </summary>
    [Theory]
    [InlineData("OCSP Responder Certificate Profile")]
    [InlineData("TSA Certificate Profile")]
    public async Task A_ca_is_not_created_from_an_infrastructure_profile_that_lists_no_usage(string profileName)
    {
        var w = WorldWithSeededProfiles();
        w.Db.CertProfiles.Single(p => p.Name == profileName).ExtendedKeyUsages = "[]";
        w.Db.SaveChanges();

        var refused = await Assert.ThrowsAsync<ModularCA.Shared.Errors.ConfigurationValidationException>(
            () => w.CreateRootAsync("Never Created", null, null));

        Assert.Contains(profileName, refused.Message);
        Assert.DoesNotContain(w.Db.CertificateAuthorities, c => c.Name == "Never Created");
    }

    [Fact]
    public async Task An_intermediate_created_at_runtime_gets_them_too()
    {
        var w = WorldWithSeededProfiles();
        var root = await w.CreateRootAsync("Runtime Parent", null, null);

        var intermediate = await w.CreateIntermediateAsync(root, "Runtime Sub", null, null);

        AssertInfrastructure(w, intermediate);
    }
}
