using ModularCA.Keystore;
using ModularCA.Keystore.Hsm;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Keystore.Hsm;

/// <summary>
/// What <see cref="Pkcs11PrivateKeyHandle"/> returns is what X.509 needs, whatever shape the
/// token signs in. The token here is a fake that signs with a software key and answers in the
/// PKCS#11 shape (raw <c>r || s</c> for ECDSA), so a certificate and a CRL signed through the
/// handle must verify with the CA's public key.
/// </summary>
public sealed class Pkcs11PrivateKeyHandleTests
{
    [Theory]
    [InlineData("P-256", "SHA256withECDSA")]
    [InlineData("P-384", "SHA384withECDSA")]
    [InlineData("P-521", "SHA512withECDSA")]
    public void A_certificate_and_a_crl_signed_with_an_hsm_ec_key_verify(string curve, string algorithm)
    {
        var oid = curve switch { "P-256" => HsmTestKeys.P256, "P-384" => HsmTestKeys.P384, _ => HsmTestKeys.P521 };
        var keys = HsmTestKeys.Ec(oid);
        var token = new FakePkcs11Token();
        var key = token.Add("ec-ca", HsmTestKeys.EcMaterial(keys.Public, oid), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "ec-ca", EcdsaSignatureEncoding.ComponentLength(keys.Public));
        var factory = new HandleSignatureFactory(handle, algorithm);

        var cert = Certificate(keys.Public, factory);
        cert.Verify(keys.Public);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(cert.SubjectDN);
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddDays(1));
        crlGenerator.AddCrlEntry(BigInteger.ValueOf(7), DateTime.UtcNow, CrlReason.KeyCompromise);
        crlGenerator.Generate(factory).Verify(keys.Public);
    }

    [Fact]
    public void An_rsa_signature_is_passed_through_unchanged()
    {
        var keys = HsmTestKeys.Rsa();
        var token = new FakePkcs11Token();
        var key = token.Add("rsa-ca", HsmTestKeys.RsaMaterial(keys.Public), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "rsa-ca");

        Certificate(keys.Public, new HandleSignatureFactory(handle, "SHA256withRSA")).Verify(keys.Public);
    }

    [Theory]
    [InlineData("SHA256withRSAandMGF1")]
    [InlineData("SHA384withRSAandMGF1")]
    [InlineData("SHA512withRSAandMGF1")]
    public void A_certificate_signed_with_an_hsm_rsa_pss_key_verifies_under_the_parameters_it_advertises(string algorithm)
    {
        var keys = HsmTestKeys.Rsa();
        var token = new FakePkcs11Token();
        var key = token.Add("pss-ca", HsmTestKeys.RsaMaterial(keys.Public), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "pss-ca");

        // Verify checks the signature under the RSASSA-PSS-params in the certificate, which the
        // fake token honoured only because the handle passed them.
        Certificate(keys.Public, new HandleSignatureFactory(handle, algorithm)).Verify(keys.Public);
        Assert.NotNull(Assert.Single(token.Mechanisms).Pss);
    }

    [Fact]
    public void A_certificate_signed_with_an_hsm_ed448_key_verifies()
    {
        var keys = HsmTestKeys.Ed448();
        var token = new FakePkcs11Token();
        var key = token.Add("ed448-ca", HsmTestKeys.EdwardsMaterial(keys.Public), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "ed448-ca");

        Certificate(keys.Public, new HandleSignatureFactory(handle, "Ed448")).Verify(keys.Public);
        Assert.False(Assert.Single(token.Mechanisms).Eddsa!.PreHash);
    }

    [Fact]
    public void An_ed25519_signature_is_passed_through_unchanged()
    {
        var keys = HsmTestKeys.Ed25519();
        var token = new FakePkcs11Token();
        var key = token.Add("ed-ca", HsmTestKeys.EdwardsMaterial(keys.Public), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "ed-ca");

        Certificate(keys.Public, new HandleSignatureFactory(handle, "Ed25519")).Verify(keys.Public);
    }

    [Fact]
    public void A_raw_signature_of_the_wrong_length_for_the_curve_is_refused()
    {
        var keys = HsmTestKeys.Ec(HsmTestKeys.P384);
        var token = new FakePkcs11Token();
        // The handle is told P-256 lengths; the token answers with P-384 ones.
        var key = token.Add("ec-ca", HsmTestKeys.EcMaterial(keys.Public, HsmTestKeys.P384), signingKey: keys.Private);
        var handle = new Pkcs11PrivateKeyHandle(token, key, "ec-ca", 32);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => handle.Sign(new byte[] { 1, 2, 3 }, "SHA384withECDSA"));
    }

    private static X509Certificate Certificate(AsymmetricKeyParameter publicKey, ISignatureFactory factory)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(42));
        generator.SetIssuerDN(new X509Name("CN=HSM Handle Test CA"));
        generator.SetSubjectDN(new X509Name("CN=HSM Handle Test CA"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(publicKey);
        return generator.Generate(factory);
    }

    /// <summary>A BouncyCastle signature factory over a key handle, as the signer's own factory is over the signing service.</summary>
    private sealed class HandleSignatureFactory : ISignatureFactory
    {
        private readonly IPrivateKeyHandle _handle;
        private readonly string _algorithm;

        public HandleSignatureFactory(IPrivateKeyHandle handle, string algorithm)
        {
            _handle = handle;
            _algorithm = algorithm;
            AlgorithmDetails = DefaultSignatureAlgorithmFinder.Instance.Find(algorithm);
        }

        public object AlgorithmDetails { get; }

        public IStreamCalculator<IBlockResult> CreateCalculator() => new Calculator(this);

        private sealed class Calculator : IStreamCalculator<IBlockResult>
        {
            private readonly MemoryStream _buffer = new();
            private readonly HandleSignatureFactory _owner;

            public Calculator(HandleSignatureFactory owner) => _owner = owner;

            public Stream Stream => _buffer;

            public IBlockResult GetResult() => new Org.BouncyCastle.Crypto.SimpleBlockResult(_owner._handle.Sign(_buffer.ToArray(), _owner._algorithm));
        }
    }
}
