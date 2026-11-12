using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// <see cref="CertificateUtil.ParseCertificateExtensions(X509Certificate)"/> reads the subject and
/// authority key identifiers as colon-separated upper-case hex, and leaves the authority key
/// identifier empty when the extension names the issuer and serial only.
/// </summary>
public sealed class CertificateKeyIdentifierParsingTests
{
    private static readonly byte[] SubjectKeyId = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    private static readonly byte[] AuthorityKeyId = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F];

    private static X509Certificate Certificate(AuthorityKeyIdentifier? aki)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.One);
        gen.SetIssuerDN(new X509Name("CN=Issuer"));
        gen.SetSubjectDN(new X509Name("CN=Subject"));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        gen.SetPublicKey(keys.Public);
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(SubjectKeyId));
        if (aki != null) gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()));
    }

    [Fact]
    public void Both_key_identifiers_read_as_colon_separated_hex()
    {
        var parsed = CertificateUtil.ParseCertificateExtensions(Certificate(new AuthorityKeyIdentifier(AuthorityKeyId)));

        Assert.Equal("01:23:45:67:89:AB:CD:EF", parsed.SubjectKeyIdentifier);
        Assert.Equal("FE:DC:BA:98:76:54:32:10:0F", parsed.AuthorityKeyIdentifier);
    }

    [Fact]
    public void An_authority_key_identifier_without_a_key_id_leaves_it_empty()
    {
        var issuerOnly = new AuthorityKeyIdentifier(
            new GeneralNames(new GeneralName(new X509Name("CN=Root"))), BigInteger.ValueOf(7));

        var parsed = CertificateUtil.ParseCertificateExtensions(Certificate(issuerOnly));

        Assert.Null(parsed.AuthorityKeyIdentifier);
    }

    [Fact]
    public void No_authority_key_identifier_leaves_it_empty()
    {
        Assert.Null(CertificateUtil.ParseCertificateExtensions(Certificate(null)).AuthorityKeyIdentifier);
    }
}
