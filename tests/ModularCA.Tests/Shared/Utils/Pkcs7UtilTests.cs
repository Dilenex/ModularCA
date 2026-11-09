using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the certs-only PKCS#7 shape shared by EST and MSAE: the output is a SignedData that a
/// standard importer reads back as exactly the certificates that went in.
/// </summary>
public class Pkcs7UtilTests
{
    private static BcX509Certificate ToBouncy(X509Certificate2 cert) => new X509CertificateParser().ReadCertificate(cert.RawData);

    /// <summary>The certificates a standard PKCS#7 reader (.NET's SignedCms) finds in the output.</summary>
    private static X509Certificate2Collection Import(byte[] der)
    {
        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(der);
        return cms.Certificates;
    }

    [Fact]
    public void The_output_imports_as_the_same_certificates_in_order()
    {
        using var ca = TestCertificates.CreateCa();
        using var leaf = TestCertificates.IssueLeaf(ca, "CN=device.example.test");

        var der = Pkcs7Util.BuildCertsOnly([ToBouncy(leaf), ToBouncy(ca)]);

        var imported = Import(der);
        Assert.Equal(2, imported.Count);
        Assert.Contains(imported.Cast<X509Certificate2>(), c => c.Thumbprint == leaf.Thumbprint);
        Assert.Contains(imported.Cast<X509Certificate2>(), c => c.Thumbprint == ca.Thumbprint);
    }

    [Fact]
    public void An_empty_set_is_still_a_valid_signed_data()
    {
        Assert.Empty(Import(Pkcs7Util.BuildCertsOnly([])));
    }

    /// <summary>
    /// The exact encoding of an empty certs-only SignedData: ContentInfo { id-signedData, [0] {
    /// version 1, no digest algorithms, id-data content, [0] IMPLICIT empty certificate set, no
    /// signer infos } }. Pinned byte for byte so that moving between BouncyCastle encoders cannot
    /// change what EST and MSAE clients receive.
    /// </summary>
    [Fact]
    public void An_empty_set_encodes_byte_for_byte()
    {
        const string expected =
            "3025" + "06092A864886F70D010702" +
            "A018" + "3016" +
                "020101" +
                "3100" +
                "300B" + "06092A864886F70D010701" +
                "A000" +
                "3100";

        Assert.Equal(expected, Convert.ToHexString(Pkcs7Util.BuildCertsOnly([])));
    }
}
