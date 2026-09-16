using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Builds the CMC full PKI response (RFC 5272) MS-WSTEP requires in every response collection,
/// used here for the one case the certificate itself cannot express: a request taken under
/// submission.
/// </summary>
/// <remarks>
/// The response is a CMS <c>SignedData</c> whose content is a <c>PKIResponse</c> carrying one
/// <c>CMCStatusInfoV2</c> control with status <c>pending</c> and a <c>PendInfo</c> whose token is
/// the request id the client must quote when it asks again. It carries no signer: the exchange is
/// already authenticated and protected by TLS, and the status is advisory to a client that also
/// receives the disposition and the request id in the SOAP body.
/// </remarks>
public static class CmcResponses
{
    /// <summary>id-cct-PKIResponse: the CMS content type of a CMC response.</summary>
    public const string PkiResponseOid = "1.3.6.1.5.5.7.12.3";

    /// <summary>id-cmc-statusInfoV2.</summary>
    public const string StatusInfoV2Oid = "1.3.6.1.5.5.7.7.25";

    /// <summary>CMCStatus pending.</summary>
    public const int StatusPending = 3;

    /// <summary>The body part id Windows gives the single certification request in its PKIData.</summary>
    public const int RequestBodyPartId = 1;

    /// <summary>
    /// A pending response for the request identified by <paramref name="requestId"/>, DER.
    /// </summary>
    public static byte[] BuildPending(string requestId, DateTime pendTimeUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        // PendInfo ::= SEQUENCE { pendToken OCTET STRING, pendTime GeneralizedTime }
        var pendInfo = new DerSequence(
            new DerOctetString(Encoding.UTF8.GetBytes(requestId)),
            new DerGeneralizedTime(pendTimeUtc.ToUniversalTime()));

        // CMCStatusInfoV2 ::= SEQUENCE { cMCStatus, bodyList SEQUENCE OF BodyPartID,
        //   statusString UTF8String OPTIONAL, otherInfo CHOICE { failInfo, pendInfo, ... } OPTIONAL }
        var statusInfo = new DerSequence(
            new DerInteger(StatusPending),
            new DerSequence(new DerInteger(RequestBodyPartId)),
            new DerUtf8String("Taken Under Submission"),
            pendInfo);

        // TaggedAttribute ::= SEQUENCE { bodyPartID, attrType OID, attrValues SET OF ANY }
        var control = new DerSequence(
            new DerInteger(RequestBodyPartId + 1),
            new DerObjectIdentifier(StatusInfoV2Oid),
            new DerSet((Asn1Encodable)statusInfo));

        // PKIResponse ::= SEQUENCE { controlSequence, cmsSequence, otherMsgSequence }
        var response = new DerSequence(new DerSequence((Asn1Encodable)control), new DerSequence(), new DerSequence());

        var generator = new CmsSignedDataGenerator();
        return generator.Generate(PkiResponseOid, new CmsProcessableByteArray(response.GetDerEncoded()), true).GetEncoded();
    }
}
