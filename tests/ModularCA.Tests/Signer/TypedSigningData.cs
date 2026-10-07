using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace ModularCA.Tests.Signer;

/// <summary>
/// Builds the structures the signer signs, as the node's generators produce them, so a test can
/// ask for a well-formed signature under each purpose and then break one thing at a time.
/// </summary>
internal static class TypedSigningData
{
    private static readonly DateTime NotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime NotAfter = new(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static long _serial = 1000;

    /// <summary>Bytes that are no structure at all.</summary>
    public static readonly byte[] Junk = System.Text.Encoding.ASCII.GetBytes("to-be-signed bytes for the signer contract");

    /// <summary>
    /// A generator signature factory that signs nothing: it records the bytes the generator
    /// streams in, which are exactly the bytes the signer would be asked to sign, and returns a
    /// placeholder signature.
    /// </summary>
    private sealed class Capture : ISignatureFactory
    {
        private readonly MemoryStream _buffer = new();
        public Capture(SignatureAlgorithm algorithm) => AlgorithmDetails = DefaultSignatureAlgorithmFinder.Instance.Find(algorithm.Name);
        public object AlgorithmDetails { get; }
        public byte[] Bytes => _buffer.ToArray();
        public IStreamCalculator<IBlockResult> CreateCalculator() => new Calculator(_buffer);

        private sealed class Calculator(MemoryStream buffer) : IStreamCalculator<IBlockResult>
        {
            public Stream Stream => buffer;
            public IBlockResult GetResult() => new SimpleBlockResult(new byte[] { 0 });
        }
    }

    /// <summary>
    /// A v3 TBSCertificate issued by <paramref name="issuer"/> for <paramref name="subjectKey"/>,
    /// with the algorithm the request will name; <paramref name="extend"/> adds the extensions
    /// under test. A leaf (cA=FALSE) unless it adds basic constraints itself.
    /// </summary>
    public static byte[] Certificate(X509Name issuer, AsymmetricKeyParameter subjectKey, SignatureAlgorithm algorithm,
        Action<X509V3CertificateGenerator>? extend = null, X509Name? subject = null, bool leafConstraints = true)
    {
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Interlocked.Increment(ref _serial)));
        gen.SetIssuerDN(issuer);
        gen.SetSubjectDN(subject ?? new X509Name("CN=typed.signer.test"));
        gen.SetNotBefore(NotBefore);
        gen.SetNotAfter(NotAfter);
        gen.SetPublicKey(subjectKey);
        if (extend != null)
            extend(gen);
        else if (leafConstraints)
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var capture = new Capture(algorithm);
        gen.Generate(capture);
        return capture.Bytes;
    }

    /// <summary>A cA=TRUE TBSCertificate, with a path length when given.</summary>
    public static byte[] CaCertificate(X509Name issuer, AsymmetricKeyParameter subjectKey, SignatureAlgorithm algorithm, X509Name subject, int? pathLength = null)
        => Certificate(issuer, subjectKey, algorithm, gen =>
        {
            gen.AddExtension(X509Extensions.BasicConstraints, true, pathLength is int p ? new BasicConstraints(p) : new BasicConstraints(true));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));
        }, subject);

    /// <summary>A leaf TBSCertificate carrying the OCSP-signing EKU, as a delegated responder certificate does.</summary>
    public static byte[] OcspSigningCertificate(X509Name issuer, AsymmetricKeyParameter subjectKey, SignatureAlgorithm algorithm)
        => Certificate(issuer, subjectKey, algorithm, gen =>
        {
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
        });

    /// <summary>A v1 TBSCertificate, which the signer never signs.</summary>
    public static byte[] V1Certificate(X509Name issuer, AsymmetricKeyParameter subjectKey, SignatureAlgorithm algorithm)
    {
        var gen = new X509V1CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Interlocked.Increment(ref _serial)));
        gen.SetIssuerDN(issuer);
        gen.SetSubjectDN(new X509Name("CN=v1.signer.test"));
        gen.SetNotBefore(NotBefore);
        gen.SetNotAfter(NotAfter);
        gen.SetPublicKey(subjectKey);
        var capture = new Capture(algorithm);
        gen.Generate(capture);
        return capture.Bytes;
    }

    /// <summary>A TBSCertList naming <paramref name="issuer"/>, with one revoked serial.</summary>
    public static byte[] Crl(X509Name issuer, SignatureAlgorithm algorithm)
    {
        var gen = new X509V2CrlGenerator();
        gen.SetIssuerDN(issuer);
        gen.SetThisUpdate(NotBefore);
        gen.SetNextUpdate(NotAfter);
        gen.AddCrlEntry(BigInteger.ValueOf(42), NotBefore, CrlReason.KeyCompromise);
        gen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));
        var capture = new Capture(algorithm);
        gen.Generate(capture);
        return capture.Bytes;
    }

    /// <summary>
    /// An OCSP ResponseData whose responder id is <paramref name="responderKey"/>'s key hash, as
    /// the responder builds it, answering "good" for one serial of <paramref name="issuer"/>.
    /// </summary>
    public static byte[] OcspResponse(AsymmetricKeyParameter responderKey, X509Certificate issuer, SignatureAlgorithm algorithm)
    {
        var gen = new BasicOcspRespGenerator(responderKey);
        var id = new CertificateID(CertificateID.DigestSha1, issuer, BigInteger.ValueOf(42));
        gen.AddResponse(id, CertificateStatus.Good);
        var capture = new Capture(algorithm);
        gen.Generate(capture, null, NotBefore);
        return capture.Bytes;
    }

    /// <summary>CMS signed attributes with the given content type, a message digest, and any extra attributes.</summary>
    public static byte[] SignedAttributes(DerObjectIdentifier contentType, params CmsAttribute[] extra)
    {
        var attributes = new Asn1EncodableVector
        {
            new CmsAttribute(new DerObjectIdentifier("1.2.840.113549.1.9.3"), new DerSet(contentType)),
            new CmsAttribute(new DerObjectIdentifier("1.2.840.113549.1.9.4"), new DerSet(new DerOctetString(new byte[32]))),
        };
        foreach (var attribute in extra)
            attributes.Add(attribute);
        return new DerSet(attributes).GetEncoded(Asn1Encodable.Der);
    }

    /// <summary>The signed attributes of a SCEP CertRep, as the SCEP service builds them.</summary>
    public static byte[] ScepAttributes()
        => SignedAttributes(new DerObjectIdentifier("1.2.840.113549.1.7.1"),
            new CmsAttribute(new DerObjectIdentifier("2.16.840.1.113733.1.9.2"), new DerSet(new DerPrintableString("3"))));

    /// <summary>The signed attributes of a timestamp token, as the TSA's generator builds them.</summary>
    public static byte[] TimestampAttributes()
        => SignedAttributes(new DerObjectIdentifier("1.2.840.113549.1.9.16.1.4"));

    /// <summary>A CMP ProtectedPart (header and a pkiconf body) whose header names <paramref name="algorithm"/>.</summary>
    public static byte[] CmpProtectedPart(SignatureAlgorithm algorithm)
    {
        var header = new PkiHeaderBuilder(PkiHeader.CMP_2000,
                new GeneralName(new X509Name("CN=typed CMP sender")), new GeneralName(new X509Name("CN=typed CMP recipient")))
            .SetProtectionAlg(DefaultSignatureAlgorithmFinder.Instance.Find(algorithm.Name))
            .Build();
        return new ProtectedPart(header, new PkiBody(PkiBody.TYPE_CONFIRM, DerNull.Instance)).GetEncoded(Asn1Encodable.Der);
    }

    /// <summary>A PKCS#10 CertificationRequestInfo for <paramref name="publicKey"/>, the part of a CSR its key signs.</summary>
    public static byte[] CertificationRequest(AsymmetricKeyParameter publicKey)
        => new CertificationRequestInfo(new X509Name("CN=typed request"), SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey), new DerSet())
            .GetEncoded(Asn1Encodable.Der);

    /// <summary>
    /// A certificate over <paramref name="publicKey"/> signed outside the signer by a throwaway
    /// issuer, for tests that only need a certificate row carrying a generated key.
    /// </summary>
    public static X509Certificate OutsideCertificate(AsymmetricKeyParameter publicKey, X509Name subject, bool isCa)
    {
        var issuerKey = ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks + Interlocked.Increment(ref _serial)));
        gen.SetIssuerDN(new X509Name("CN=Outside Test Issuer"));
        gen.SetSubjectDN(subject);
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(publicKey);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
        return gen.Generate(new Asn1SignatureFactory("SHA256withECDSA", issuerKey.Private, new SecureRandom()));
    }
}
