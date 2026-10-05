using System.Security.Cryptography;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The structures the signer signs, one parser per structure. Each takes the exact bytes a
/// caller asks to have signed and returns the parsed structure only when those bytes are one
/// DER-encoded object of that type with nothing after it, so what the signer judges is what a
/// verifier will read. Anything else is null, and the signer refuses it as
/// <see cref="SigningRefusalReason.UntypedData"/>.
/// </summary>
internal static class SignedDataTypes
{
    /// <summary>id-data, the content type of a SCEP pkiMessage's signed attributes.</summary>
    public static readonly DerObjectIdentifier IdData = new("1.2.840.113549.1.7.1");

    /// <summary>id-ct-TSTInfo, the content type of a timestamp token's signed attributes.</summary>
    public static readonly DerObjectIdentifier IdCtTstInfo = new("1.2.840.113549.1.9.16.1.4");

    /// <summary>The SCEP messageType attribute, which every SCEP response the CA signs carries.</summary>
    public static readonly DerObjectIdentifier ScepMessageType = new("2.16.840.1.113733.1.9.2");

    private static readonly DerObjectIdentifier ContentTypeAttribute = new("1.2.840.113549.1.9.3");
    private static readonly DerObjectIdentifier MessageDigestAttribute = new("1.2.840.113549.1.9.4");

    /// <summary>The bytes as one DER object with no trailing data, or null.</summary>
    private static Asn1Object? Der(byte[] data)
    {
        if (data.Length == 0)
            return null;
        try
        {
            var obj = Asn1Object.FromByteArray(data);
            return obj != null && obj.GetEncoded(Asn1Encodable.Der).AsSpan().SequenceEqual(data) ? obj : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Applies <paramref name="parse"/> to the bytes as a DER SEQUENCE, or null when they are not one or it throws.</summary>
    private static T? Sequence<T>(byte[] data, Func<Asn1Sequence, T> parse) where T : class
    {
        if (Der(data) is not Asn1Sequence sequence)
            return null;
        try
        {
            return parse(sequence);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>A TBSCertificate, any version; the caller holds it to v3.</summary>
    public static TbsCertificateStructure? TbsCertificate(byte[] data) => Sequence(data, TbsCertificateStructure.GetInstance);

    /// <summary>A TBSCertList, full or delta.</summary>
    public static TbsCertificateList? TbsCertList(byte[] data) => Sequence(data, TbsCertificateList.GetInstance);

    /// <summary>An OCSP <c>tbsResponseData</c>.</summary>
    public static ResponseData? OcspResponseData(byte[] data) => Sequence(data, ResponseData.GetInstance);

    /// <summary>A PKCS#10 CertificationRequestInfo, the part of a CSR its key signs.</summary>
    public static CertificationRequestInfo? CertificationRequestInfo(byte[] data) => Sequence(data, Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo.GetInstance);

    /// <summary>A CMP ProtectedPart: the header and body a signature-protected PKIMessage signs.</summary>
    public static ProtectedPart? CmpProtectedPart(byte[] data) => Sequence(data, s => s.Count == 2 ? ProtectedPart.GetInstance(s) : null!);

    /// <summary>
    /// CMS signed attributes as a SignerInfo signs them: a DER SET OF Attribute carrying a
    /// content-type attribute of <paramref name="contentType"/>, a message digest, and, when
    /// named, a <paramref name="required"/> attribute.
    /// </summary>
    public static Asn1Set? SignedAttributes(byte[] data, DerObjectIdentifier contentType, DerObjectIdentifier? required)
    {
        if (Der(data) is not Asn1Set set)
            return null;
        try
        {
            bool sawContentType = false, sawDigest = false, sawRequired = required == null;
            foreach (var element in set)
            {
                var attribute = CmsAttribute.GetInstance(element);
                if (attribute.AttrType.Equals(ContentTypeAttribute))
                {
                    if (attribute.AttrValues.Count != 1 || !contentType.Equals(attribute.AttrValues[0]))
                        return null;
                    sawContentType = true;
                }
                else if (attribute.AttrType.Equals(MessageDigestAttribute))
                {
                    if (attribute.AttrValues.Count != 1 || attribute.AttrValues[0] is not Asn1OctetString)
                        return null;
                    sawDigest = true;
                }
                else if (required != null && attribute.AttrType.Equals(required))
                {
                    sawRequired = true;
                }
            }
            return sawContentType && sawDigest && sawRequired ? set : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <paramref name="named"/>, the algorithm a structure says it is signed with, is the
    /// algorithm <paramref name="requested"/> signs with: the same OID, and the same parameters,
    /// an absent and a NULL parameter counting as the same.
    /// </summary>
    public static bool SameAlgorithm(AlgorithmIdentifier? named, SignatureAlgorithm requested)
    {
        if (named == null)
            return false;
        AlgorithmIdentifier expected;
        try
        {
            expected = DefaultSignatureAlgorithmFinder.Instance.Find(requested.Name);
        }
        catch (Exception)
        {
            return false;
        }
        if (!expected.Algorithm.Equals(named.Algorithm))
            return false;
        var a = expected.Parameters;
        var b = named.Parameters;
        var aEmpty = a == null || a is Asn1Null;
        var bEmpty = b == null || b is Asn1Null;
        if (aEmpty || bEmpty)
            return aEmpty && bEmpty;
        return a!.ToAsn1Object().Equals(b!.ToAsn1Object());
    }

    /// <summary>The DER SubjectPublicKeyInfo a structure names, for comparison with a key's.</summary>
    public static byte[] Spki(SubjectPublicKeyInfo info) => info.GetEncoded(Asn1Encodable.Der);

    /// <summary>
    /// The OCSP responder key hash of a public key: SHA-1 over the subjectPublicKey BIT STRING's
    /// contents (RFC 6960 section 4.2.1), as BouncyCastle's responder id computes it.
    /// </summary>
    public static byte[] ResponderKeyHash(SubjectPublicKeyInfo info) => SHA1.HashData(info.PublicKey.GetBytes());

    /// <summary>
    /// What a v3 TBSCertificate asserts that the signer's rules look at: the basic constraints,
    /// the key usages that only a CA may hold, name constraints, and the OCSP-signing EKU.
    /// </summary>
    public sealed record CertificateShape(bool IsCa, BigInteger? PathLength, bool CaKeyUsages, bool NameConstraints, bool OcspSigning, byte[] SubjectPublicKeyInfo);

    /// <summary>
    /// Reads the shape of a TBSCertificate's extensions. Throws when an extension the rules read
    /// does not parse, which the caller treats as untyped data.
    /// </summary>
    public static CertificateShape Shape(TbsCertificateStructure tbs)
    {
        var extensions = tbs.Extensions;
        BasicConstraints? basic = null;
        KeyUsage? usage = null;
        ExtendedKeyUsage? extended = null;
        var nameConstraints = false;
        if (extensions != null)
        {
            if (extensions.GetExtension(X509Extensions.BasicConstraints) is { } bc)
                basic = BasicConstraints.GetInstance(Asn1Object.FromByteArray(bc.Value.GetOctets()));
            if (extensions.GetExtension(X509Extensions.KeyUsage) is { } ku)
                usage = KeyUsage.GetInstance(Asn1Object.FromByteArray(ku.Value.GetOctets()));
            if (extensions.GetExtension(X509Extensions.ExtendedKeyUsage) is { } eku)
                extended = ExtendedKeyUsage.GetInstance(Asn1Object.FromByteArray(eku.Value.GetOctets()));
            nameConstraints = extensions.GetExtension(X509Extensions.NameConstraints) != null;
        }

        var caUsages = usage != null && (usage.IntValue & (KeyUsage.KeyCertSign | KeyUsage.CrlSign)) != 0;
        return new CertificateShape(
            basic?.IsCA() == true,
            basic?.PathLenConstraint,
            caUsages,
            nameConstraints,
            extended?.HasKeyPurposeId(KeyPurposeID.id_kp_OCSPSigning) == true,
            Spki(tbs.SubjectPublicKeyInfo));
    }
}
