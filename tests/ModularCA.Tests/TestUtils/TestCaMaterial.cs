using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// BouncyCastle CA material for tests that have to exercise a real protocol responder rather
/// than a helper in isolation.
/// <para>
/// The OCSP responder resolves its signer from <see cref="IKeystoreCertificates"/>, matches the
/// request's issuer key and name hashes against that signer's certificate, and signs the response
/// with its private key — so nothing about it can be tested without genuine key material. This
/// type produces it, and <see cref="TestKeystore"/> serves it.
/// </para>
/// <para>
/// Keys are deliberately 2048-bit RSA: large enough to be real, small enough that a suite of
/// these does not become the slowest thing in the build.
/// </para>
/// </summary>
internal sealed class TestCaMaterial
{
    public X509Certificate Certificate { get; }
    public AsymmetricCipherKeyPair KeyPair { get; }

    /// <summary>
    /// The subject DN as BouncyCastle renders it, NOT as it was typed. The responder matches its
    /// CertificateAuthorities row with
    /// <c>ca.Certificate.SubjectDN == caCert.SubjectDN.ToString()</c>, and BC normalises spacing
    /// ("CN=x, O=y" becomes "CN=x,O=y"), so seeding the typed form makes CA resolution miss and
    /// every request comes back "unauthorized".
    /// </summary>
    public string SubjectDn => Certificate.SubjectDN.ToString();

    private TestCaMaterial(X509Certificate certificate, AsymmetricCipherKeyPair keyPair)
    {
        Certificate = certificate;
        KeyPair = keyPair;
    }

    private static readonly DateTime NotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime NotAfter = new(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static AsymmetricCipherKeyPair GenerateRsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return gen.GenerateKeyPair();
    }

    /// <summary>Creates a self-signed CA with keyCertSign + cRLSign, as a real root would carry.</summary>
    public static TestCaMaterial CreateCa(string subjectDn = "CN=Test OCSP CA, O=ModularCA")
    {
        var keyPair = GenerateRsa();
        var dn = new X509Name(subjectDn);

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(1));
        gen.SetIssuerDN(dn);
        gen.SetSubjectDN(dn);
        gen.SetNotBefore(NotBefore);
        gen.SetNotAfter(NotAfter);
        gen.SetPublicKey(keyPair.Public);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        gen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));

        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(spki));

        var cert = gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private, new SecureRandom()));
        return new TestCaMaterial(cert, keyPair);
    }

    /// <summary>
    /// Issues a certificate from this CA. <paramref name="isCa"/> produces an intermediate —
    /// the case OCSP status answers used to get wrong.
    /// </summary>
    public X509Certificate Issue(BigInteger serial, string subjectDn, bool isCa = false)
    {
        var subjectKey = GenerateRsa();

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(serial);
        gen.SetIssuerDN(new X509Name(SubjectDn));
        gen.SetSubjectDN(new X509Name(subjectDn));
        gen.SetNotBefore(NotBefore);
        gen.SetNotAfter(NotAfter);
        gen.SetPublicKey(subjectKey.Public);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));

        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private, new SecureRandom()));
    }

    /// <summary>Wraps this CA as the signer the responder will find in the keystore.</summary>
    public CertificateAuthorityIdentity AsSigner() =>
        new(Certificate, new ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle(KeyPair.Private));

    /// <summary>
    /// Builds a DER-encoded OCSPRequest asking this CA about <paramref name="serial"/>.
    /// </summary>
    public byte[] BuildOcspRequest(BigInteger serial)
    {
#pragma warning disable CS0618 // No non-deprecated CertificateID overload exists; the responder uses the same one.
        var certId = new CertificateID(CertificateID.HashSha1, Certificate, serial);
#pragma warning restore CS0618
        var gen = new OcspReqGenerator();
        gen.AddRequest(certId);
        return gen.Generate().GetEncoded();
    }
}
