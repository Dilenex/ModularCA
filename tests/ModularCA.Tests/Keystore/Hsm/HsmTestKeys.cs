using ModularCA.Keystore.Hsm;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Keystore.Hsm;

/// <summary>
/// Software keys and self-signed certificates for the HSM tests, and the attribute values a
/// PKCS#11 token would report for those keys.
/// </summary>
internal static class HsmTestKeys
{
    private static readonly SecureRandom Random = new();

    /// <summary>A 2048-bit RSA key pair.</summary>
    public static AsymmetricCipherKeyPair Rsa()
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), Random, 2048, 80));
        return generator.GenerateKeyPair();
    }

    /// <summary>An EC key pair on the named curve <paramref name="curve"/>.</summary>
    public static AsymmetricCipherKeyPair Ec(DerObjectIdentifier curve)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(curve, Random));
        return generator.GenerateKeyPair();
    }

    /// <summary>An Ed25519 key pair.</summary>
    public static AsymmetricCipherKeyPair Ed25519()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(Random));
        return generator.GenerateKeyPair();
    }

    /// <summary>An Ed448 key pair.</summary>
    public static AsymmetricCipherKeyPair Ed448()
    {
        var generator = new Ed448KeyPairGenerator();
        generator.Init(new Ed448KeyGenerationParameters(Random));
        return generator.GenerateKeyPair();
    }

    /// <summary>A self-signed CA certificate over <paramref name="keys"/>.</summary>
    public static X509Certificate SelfSigned(AsymmetricCipherKeyPair keys, string algorithm)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Random.NextInt() & int.MaxValue).Add(BigInteger.One));
        generator.SetIssuerDN(new X509Name("CN=HSM Test CA"));
        generator.SetSubjectDN(new X509Name("CN=HSM Test CA"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(keys.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        return generator.Generate(new Asn1SignatureFactory(algorithm, keys.Private, Random));
    }

    /// <summary>What a token reports for an RSA public key.</summary>
    public static Pkcs11PublicKeyMaterial RsaMaterial(AsymmetricKeyParameter publicKey)
    {
        var rsa = (RsaKeyParameters)publicKey;
        return Pkcs11PublicKeyMaterial.Rsa(rsa.Modulus.ToByteArrayUnsigned(), rsa.Exponent.ToByteArrayUnsigned(), "the private key object");
    }

    /// <summary>
    /// What a token reports for an EC public key on <paramref name="curve"/>: the curve OID as
    /// <c>CKA_EC_PARAMS</c> and the uncompressed point, DER OCTET STRING wrapped as the standard
    /// says when <paramref name="wrapped"/>, raw otherwise.
    /// </summary>
    public static Pkcs11PublicKeyMaterial EcMaterial(AsymmetricKeyParameter publicKey, DerObjectIdentifier curve, bool wrapped = true)
    {
        var point = ((ECPublicKeyParameters)publicKey).Q.GetEncoded(false);
        return Pkcs11PublicKeyMaterial.Ec(Pkcs11PublicKeyMaterial.CkkEc, curve.GetEncoded(),
            wrapped ? new DerOctetString(point).GetEncoded() : point, "the public key object");
    }

    /// <summary>What a token reports for an Ed25519 or Ed448 public key, with the curve named by OID or by printable string.</summary>
    public static Pkcs11PublicKeyMaterial EdwardsMaterial(AsymmetricKeyParameter publicKey, bool curveByName = false, bool wrapped = true)
    {
        var (raw, oid, name) = publicKey switch
        {
            Ed25519PublicKeyParameters ed => (ed.GetEncoded(), EdECObjectIdentifiers.id_Ed25519, "edwards25519"),
            Ed448PublicKeyParameters ed => (ed.GetEncoded(), EdECObjectIdentifiers.id_Ed448, "edwards448"),
            _ => throw new ArgumentException("Not an Edwards key.", nameof(publicKey)),
        };
        var ecParams = curveByName ? new DerPrintableString(name).GetEncoded() : oid.GetEncoded();
        return Pkcs11PublicKeyMaterial.Ec(Pkcs11PublicKeyMaterial.CkkEcEdwards, ecParams,
            wrapped ? new DerOctetString(raw).GetEncoded() : raw, "the public key object");
    }

    /// <summary>The P-256, P-384 and P-521 curve OIDs.</summary>
    public static readonly DerObjectIdentifier P256 = SecObjectIdentifiers.SecP256r1;

    /// <inheritdoc cref="P256"/>
    public static readonly DerObjectIdentifier P384 = SecObjectIdentifiers.SecP384r1;

    /// <inheritdoc cref="P256"/>
    public static readonly DerObjectIdentifier P521 = SecObjectIdentifiers.SecP521r1;
}

/// <summary>A PKCS#11 object handle in a test: just an id.</summary>
internal sealed class FakeObjectHandle : IObjectHandle
{
    private static ulong _next = 1;

    /// <summary>A handle with a fresh id.</summary>
    public FakeObjectHandle() => ObjectId = Interlocked.Increment(ref _next);

    /// <inheritdoc />
    public ulong ObjectId { get; }
}

/// <summary>
/// A token in a test: private key objects under labels, each with the containment verdict and
/// the public key the real token would report, or the error reading it would raise.
/// </summary>
internal sealed class FakePkcs11Token : IPkcs11Token
{
    private sealed record Entry(string Label, FakeObjectHandle Handle, bool Contained, Pkcs11PublicKeyMaterial? Material, Exception? ReadError, AsymmetricKeyParameter? SigningKey);

    private readonly List<Entry> _entries = new();

    /// <summary>The mechanisms <see cref="Sign"/> was asked for, in order.</summary>
    public List<Pkcs11SignMechanism> Mechanisms { get; } = new();

    /// <summary>
    /// Adds a private key object and returns its handle. <paramref name="signingKey"/> is the
    /// software key <see cref="Sign"/> signs with on its behalf.
    /// </summary>
    public FakeObjectHandle Add(string label, Pkcs11PublicKeyMaterial? material, bool contained = true, Exception? readError = null, AsymmetricKeyParameter? signingKey = null)
    {
        var handle = new FakeObjectHandle();
        _entries.Add(new Entry(label, handle, contained, material, readError, signingKey));
        return handle;
    }

    /// <summary>
    /// Signs as a token would: with the entry's software key, and in the PKCS#11 shape, so an
    /// ECDSA mechanism returns raw fixed-width <c>r || s</c>. Like a token, it refuses an RSA-PSS
    /// mechanism without <c>CK_RSA_PKCS_PSS_PARAMS</c> and an Ed448 key without
    /// <c>CK_EDDSA_PARAMS</c> (<c>CKR_MECHANISM_PARAM_INVALID</c>), and signs PSS with exactly
    /// the hash, MGF1 hash and salt length it is given.
    /// </summary>
    public byte[] Sign(IObjectHandle key, byte[] data, Pkcs11SignMechanism mechanism)
    {
        Mechanisms.Add(mechanism);
        var signingKey = _entries.Single(e => e.Handle == key).SigningKey
            ?? throw new InvalidOperationException("The fake key has no software key to sign with.");
        if (mechanism.Mechanism is CKM.CKM_SHA256_RSA_PKCS_PSS or CKM.CKM_SHA384_RSA_PKCS_PSS or CKM.CKM_SHA512_RSA_PKCS_PSS)
        {
            var pss = mechanism.Pss ?? throw new InvalidOperationException("CKR_MECHANISM_PARAM_INVALID: RSA-PSS needs CK_RSA_PKCS_PSS_PARAMS.");
            var pssSigner = new PssSigner(new RsaBlindedEngine(), Digest(pss.HashAlgorithm), Digest(pss.Mgf), (int)pss.SaltLength);
            pssSigner.Init(true, new ParametersWithRandom(signingKey, new SecureRandom()));
            pssSigner.BlockUpdate(data, 0, data.Length);
            return pssSigner.GenerateSignature();
        }
        if (signingKey is Ed448PrivateKeyParameters && mechanism.Eddsa is null)
            throw new InvalidOperationException("CKR_MECHANISM_PARAM_INVALID: Ed448 needs CK_EDDSA_PARAMS.");
        var algorithm = mechanism.Mechanism switch
        {
            CKM.CKM_SHA256_RSA_PKCS => "SHA256withRSA",
            CKM.CKM_SHA384_RSA_PKCS => "SHA384withRSA",
            CKM.CKM_SHA512_RSA_PKCS => "SHA512withRSA",
            CKM.CKM_SHA256_RSA_PKCS_PSS => "SHA256withRSAandMGF1",
            CKM.CKM_SHA384_RSA_PKCS_PSS => "SHA384withRSAandMGF1",
            CKM.CKM_SHA512_RSA_PKCS_PSS => "SHA512withRSAandMGF1",
            CKM.CKM_ECDSA_SHA256 => "SHA256withECDSA",
            CKM.CKM_ECDSA_SHA384 => "SHA384withECDSA",
            CKM.CKM_ECDSA_SHA512 => "SHA512withECDSA",
            (CKM)0x00001057 => signingKey is Ed448PrivateKeyParameters ? "Ed448" : "Ed25519",
            _ => throw new NotSupportedException($"The fake token does not sign with {mechanism.Mechanism}."),
        };
        if (algorithm.EndsWith("ECDSA", StringComparison.Ordinal))
            return FakeEcdsaToken.SignRaw((ECPrivateKeyParameters)signingKey, algorithm, data);

        var signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, signingKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>The digest a PSS hash mechanism or MGF1 function names.</summary>
    private static IDigest Digest(Enum hashOrMgf) => hashOrMgf switch
    {
        CKM.CKM_SHA256 or CKG.CKG_MGF1_SHA256 => new Sha256Digest(),
        CKM.CKM_SHA384 or CKG.CKG_MGF1_SHA384 => new Sha384Digest(),
        CKM.CKM_SHA512 or CKG.CKG_MGF1_SHA512 => new Sha512Digest(),
        _ => throw new NotSupportedException($"The fake token does not hash with {hashOrMgf}."),
    };

    /// <inheritdoc />
    public IReadOnlyList<IObjectHandle> FindPrivateKeysByLabel(string label)
        => _entries.Where(e => e.Label == label).Select(e => (IObjectHandle)e.Handle).ToList();

    /// <inheritdoc />
    public bool IsHsmContained(IObjectHandle privateKey, string lookupDescription)
        => _entries.Single(e => e.Handle == privateKey).Contained;

    /// <inheritdoc />
    public Pkcs11PublicKeyMaterial ReadPublicKey(IObjectHandle privateKey, string label)
    {
        var entry = _entries.Single(e => e.Handle == privateKey);
        if (entry.ReadError != null)
            throw entry.ReadError;
        return entry.Material ?? throw new InvalidOperationException("No public key.");
    }
}
