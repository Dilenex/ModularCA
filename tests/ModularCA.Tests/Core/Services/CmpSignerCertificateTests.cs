using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;
using ModularCA.Tests.TestUtils;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the post-issuance check on a dedicated CMP signing certificate.
/// </summary>
/// <remarks>
/// The signer exists for exactly one reason: the CA certificate's key usage is
/// <c>keyCertSign, cRLSign</c> and OpenSSL refuses a CMP message signer without
/// <c>digitalSignature</c>. A signer issued without that bit would be revoked into place over a
/// working predecessor and change nothing, which is the failure the OCSP and TSA checks already
/// guard against for their EKUs.
/// </remarks>
public class CmpSignerCertificateTests
{
    private static BcX509Certificate ToBc(X509Certificate2 cert) => new X509CertificateParser().ReadCertificate(cert.RawData);

    private static X509Certificate2 LeafWithKeyUsage(X509Certificate2 ca, X509KeyUsageFlags flags)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=CMP Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(flags, true));
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        using var signed = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
        return X509CertificateLoader.LoadCertificate(signed.Export(X509ContentType.Cert));
    }

    [Fact]
    public void A_signer_with_digitalSignature_passes()
    {
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");
        using var signer = LeafWithKeyUsage(ca, X509KeyUsageFlags.DigitalSignature);

        CaCreationService.EnsureIssuedCertCarriesDigitalSignature(ToBc(signer), "CMP Signer");
    }

    [Fact]
    public void A_signer_with_other_usages_but_not_digitalSignature_is_refused_with_the_profile_named()
    {
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");
        using var signer = LeafWithKeyUsage(ca, X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation);

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => CaCreationService.EnsureIssuedCertCarriesDigitalSignature(ToBc(signer), "CMP Signer"));
        Assert.Contains("digitalSignature", ex.Message);
        Assert.Contains(CaCreationService.CmpSignerProfileName, ex.Message);
    }

    [Fact]
    public void The_CA_certificate_itself_would_be_refused_which_is_the_whole_point()
    {
        // keyCertSign and cRLSign only: what a CA carries, and what OpenSSL rejects as a CMP
        // message signer. If this ever passed, the dedicated signer would be pointless.
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");

        Assert.Throws<ConfigurationValidationException>(
            () => CaCreationService.EnsureIssuedCertCarriesDigitalSignature(ToBc(ca), "CMP Signer"));
    }

    [Fact]
    public void A_certificate_with_no_key_usage_extension_is_refused()
    {
        // Absent KU is "unrestricted" for EKU purposes but not what a client checks for signing;
        // the profile must have put the bit there explicitly.
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");
        using var bare = TestCertificates.IssueLeaf(ca, "CN=CMP Signer");

        Assert.Throws<ConfigurationValidationException>(
            () => CaCreationService.EnsureIssuedCertCarriesDigitalSignature(ToBc(bare), "CMP Signer"));
    }
}
