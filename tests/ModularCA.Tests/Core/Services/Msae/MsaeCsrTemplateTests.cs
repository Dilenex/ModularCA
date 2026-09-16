using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services.Msae;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins how the template a Windows client asked for is read out of its PKCS#10: the version 1
/// name extension, the version 2 OID extension, both, or neither.
/// </summary>
public class MsaeCsrTemplateTests
{
    private static byte[] Csr(params X509Extension[] extensions)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=device-01.lab.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (var ext in extensions)
            req.CertificateExtensions.Add(ext);
        return req.CreateSigningRequest();
    }

    private static X509Extension NameExtension(string name)
        => new(new Oid(MsaeCsrTemplate.TemplateNameOid), new DerBmpString(name).GetDerEncoded(), false);

    private static X509Extension InfoExtension(string oid, int major = 100, int minor = 2)
        => new(new Oid(MsaeCsrTemplate.TemplateInfoOid),
            new DerSequence(new DerObjectIdentifier(oid), new DerInteger(major), new DerInteger(minor)).GetDerEncoded(),
            false);

    [Fact]
    public void The_v1_name_extension_yields_the_template_name()
    {
        var reference = MsaeCsrTemplate.TryRead(Csr(NameExtension("LabDevice")));
        Assert.NotNull(reference);
        Assert.Equal("LabDevice", reference!.Name);
        Assert.Null(reference.Oid);
    }

    [Fact]
    public void The_v2_info_extension_yields_the_template_oid()
    {
        var reference = MsaeCsrTemplate.TryRead(Csr(InfoExtension("1.3.6.1.4.1.311.21.8.1.2.3")));
        Assert.NotNull(reference);
        Assert.Null(reference!.Name);
        Assert.Equal("1.3.6.1.4.1.311.21.8.1.2.3", reference.Oid);
    }

    [Fact]
    public void Both_extensions_are_read_together()
    {
        var reference = MsaeCsrTemplate.TryRead(Csr(NameExtension("LabDevice"), InfoExtension("1.3.6.1.4.1.311.21.8.9")));
        Assert.Equal("LabDevice", reference!.Name);
        Assert.Equal("1.3.6.1.4.1.311.21.8.9", reference.Oid);
    }

    [Fact]
    public void A_request_naming_no_template_reads_as_null()
    {
        // Other extensions present, so "no extension request at all" is not what makes it null.
        var other = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false);
        Assert.Null(MsaeCsrTemplate.TryRead(Csr(other)));
        Assert.Null(MsaeCsrTemplate.TryRead(Csr()));
    }

    [Fact]
    public void An_empty_name_reads_as_no_template()
    {
        Assert.Null(MsaeCsrTemplate.TryRead(Csr(NameExtension("   "))));
    }

    [Fact]
    public void Unreadable_input_reads_as_null_rather_than_throwing()
    {
        Assert.Null(MsaeCsrTemplate.TryRead([]));
        Assert.Null(MsaeCsrTemplate.TryRead([0x30, 0x03, 0x02, 0x01, 0x00]));
        Assert.Null(MsaeCsrTemplate.TryRead(new byte[] { 1, 2, 3 }));
    }
}
