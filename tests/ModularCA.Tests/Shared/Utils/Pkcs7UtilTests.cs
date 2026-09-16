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

    [Fact]
    public void The_output_imports_as_the_same_certificates_in_order()
    {
        using var ca = TestCertificates.CreateCa();
        using var leaf = TestCertificates.IssueLeaf(ca, "CN=device.example.test");

        var der = Pkcs7Util.BuildCertsOnly([ToBouncy(leaf), ToBouncy(ca)]);

        var imported = new X509Certificate2Collection();
        imported.Import(der);
        Assert.Equal(2, imported.Count);
        Assert.Contains(imported.Cast<X509Certificate2>(), c => c.Thumbprint == leaf.Thumbprint);
        Assert.Contains(imported.Cast<X509Certificate2>(), c => c.Thumbprint == ca.Thumbprint);
    }

    [Fact]
    public void An_empty_set_is_still_a_valid_signed_data()
    {
        var der = Pkcs7Util.BuildCertsOnly([]);
        var imported = new X509Certificate2Collection();
        imported.Import(der);
        Assert.Empty(imported);
    }
}
