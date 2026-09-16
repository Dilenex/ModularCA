using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Builds the degenerate "certs-only" PKCS#7 <c>SignedData</c> that enrollment protocols use to
/// hand a client its certificate and chain in one blob.
/// </summary>
/// <remarks>
/// EST (RFC 7030), MS-WSTEP and SCEP all return issued certificates this way: a
/// <c>SignedData</c> with no signers and no content, carrying only the <c>certificates</c> set
/// (RFC 5652 section 5.2, "degenerate case"). One implementation serves every protocol so the
/// DER shape cannot drift between them.
/// </remarks>
public static class Pkcs7Util
{
    private const string IdData = "1.2.840.113549.1.7.1";
    private const string IdSignedData = "1.2.840.113549.1.7.2";

    /// <summary>
    /// Encodes <paramref name="certificates"/> as a certs-only PKCS#7 <c>ContentInfo</c> (DER).
    /// </summary>
    public static byte[] BuildCertsOnly(IEnumerable<X509Certificate> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        // SignedData ::= SEQUENCE {
        //   version          INTEGER (1),
        //   digestAlgorithms SET OF (empty),
        //   contentInfo      ContentInfo { id-data, absent },
        //   certificates [0] IMPLICIT SET OF Certificate,
        //   signerInfos      SET OF (empty)
        // }
        var certSet = new Asn1EncodableVector();
        foreach (var cert in certificates)
            certSet.Add(Asn1Object.FromByteArray(cert.GetEncoded()));

        var signedData = new DerSequence(
            new DerInteger(1),
            new DerSet(),
            new DerSequence(new DerObjectIdentifier(IdData)),
            new DerTaggedObject(false, 0, new DerSet(certSet)),
            new DerSet());

        var contentInfo = new DerSequence(
            new DerObjectIdentifier(IdSignedData),
            new DerTaggedObject(true, 0, signedData));

        return contentInfo.GetDerEncoded();
    }
}
