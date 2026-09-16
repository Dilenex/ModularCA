using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkcs;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Unwraps the CMC request a Windows enrollment client sends: a CMS <c>SignedData</c> whose
/// content is a <c>PKIData</c> (RFC 5272) carrying the PKCS#10 the client wants signed.
/// </summary>
/// <remarks>
/// <para>
/// <c>certreq -submit</c> against an enrollment URL sends a bare PKCS#10. The autoenrollment
/// engine, <c>Get-Certificate</c> and the Certificates snap-in do not: they wrap the PKCS#10 in
/// a CMC <c>PKIData</c>, sign the whole thing with the new private key as proof of possession,
/// and send that as a <c>#PKCS7</c> token. Windows identifies the signer by subject key
/// identifier and includes no certificate, so the signature is checked against the public key
/// inside the PKCS#10 itself: the key that signed the wrapper must be the key being certified.
/// </para>
/// <para>
/// Only the first tagged certification request is taken. CMC allows several requests, CRMF
/// requests and control attributes in one message; Windows enrollment sends one PKCS#10, and a
/// message that does not fit that shape is refused rather than partially honoured. Renewal
/// requests, which a client signs with its existing certificate, are handled separately once
/// they are supported; today they are refused at this layer because the wrapper signer is not
/// the enrolled key.
/// </para>
/// </remarks>
public static class CmcRequests
{
    /// <summary>id-cct-PKIData: the CMS content type of a CMC request.</summary>
    public const string PkiDataOid = "1.3.6.1.5.5.7.12.2";

    /// <summary>
    /// Returns the DER PKCS#10 inside <paramref name="cmsDer"/>. Throws
    /// <see cref="WstepMessages.WstepParseException"/> when the bytes are not a CMC request, carry
    /// no certification request, or the proof-of-possession signature does not verify.
    /// </summary>
    public static byte[] UnwrapPkcs10(byte[] cmsDer)
    {
        ArgumentNullException.ThrowIfNull(cmsDer);

        CmsSignedData signed;
        try
        {
            signed = new CmsSignedData(cmsDer);
        }
        catch (Exception ex) when (ex is CmsException or IOException or ArgumentException or InvalidCastException)
        {
            throw new WstepMessages.WstepParseException($"The PKCS#7 token is not a CMS SignedData: {ex.Message}");
        }

        if (signed.SignedContentType?.Id != PkiDataOid)
            throw new WstepMessages.WstepParseException(
                $"The PKCS#7 token carries content type {signed.SignedContentType?.Id ?? "(none)"}, not a CMC PKIData ({PkiDataOid}).");

        byte[] pkiDataDer;
        try
        {
            using var buffer = new MemoryStream();
            signed.SignedContent!.Write(buffer);
            pkiDataDer = buffer.ToArray();
        }
        catch (Exception ex) when (ex is CmsException or IOException or NullReferenceException)
        {
            throw new WstepMessages.WstepParseException("The CMC request has no encapsulated content.");
        }

        var pkcs10Der = ExtractFirstCertificationRequest(pkiDataDer);
        VerifyProofOfPossession(signed, pkcs10Der);
        return pkcs10Der;
    }

    // PKIData ::= SEQUENCE {
    //   controlSequence  SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
    //   reqSequence      SEQUENCE SIZE(0..MAX) OF TaggedRequest,
    //   cmsSequence      SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
    //   otherMsgSequence SEQUENCE SIZE(0..MAX) OF OtherMsg }
    // TaggedRequest ::= CHOICE { tcr [0] TaggedCertificationRequest, crm [1] ..., orm [2] ... }
    // TaggedCertificationRequest ::= SEQUENCE { bodyPartID INTEGER, certificationRequest CertificationRequest }
    private static byte[] ExtractFirstCertificationRequest(byte[] pkiDataDer)
    {
        Asn1Sequence pkiData;
        try
        {
            pkiData = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(pkiDataDer));
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            throw new WstepMessages.WstepParseException($"The CMC PKIData is not well-formed: {ex.Message}");
        }
        if (pkiData.Count < 2)
            throw new WstepMessages.WstepParseException("The CMC PKIData has no request sequence.");

        try
        {
            var requests = Asn1Sequence.GetInstance(pkiData[1]);
            foreach (var entry in requests)
            {
                if (entry is not Asn1TaggedObject tagged || tagged.TagNo != 0)
                    continue;   // a CRMF or other request type; not what Windows enrollment sends
                var tcr = Asn1Sequence.GetInstance(tagged, false);
                if (tcr.Count < 2)
                    throw new WstepMessages.WstepParseException("The CMC tagged certification request is incomplete.");
                return tcr[1].ToAsn1Object().GetDerEncoded();
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidCastException or IOException)
        {
            throw new WstepMessages.WstepParseException($"The CMC request sequence is not well-formed: {ex.Message}");
        }
        throw new WstepMessages.WstepParseException("The CMC request carries no PKCS#10 certification request.");
    }

    /// <summary>
    /// The CMC wrapper must be signed by the key inside the PKCS#10. A signer certificate, when
    /// one is present, is not consulted: the proof that matters is possession of the key being
    /// certified, and a wrapper signed by anything else is either a renewal (not supported here)
    /// or tampering.
    /// </summary>
    private static void VerifyProofOfPossession(CmsSignedData signed, byte[] pkcs10Der)
    {
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter publicKey;
        try
        {
            publicKey = new Pkcs10CertificationRequest(pkcs10Der).GetPublicKey();
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            throw new WstepMessages.WstepParseException($"The PKCS#10 inside the CMC request is not readable: {ex.Message}");
        }

        var signers = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().ToList();
        if (signers.Count == 0)
            throw new WstepMessages.WstepParseException("The CMC request is not signed.");

        foreach (var signer in signers)
        {
            try
            {
                if (signer.Verify(publicKey)) return;
            }
            catch (CmsException)
            {
                // Fall through: this signer does not verify with the request key.
            }
        }
        throw new WstepMessages.WstepParseException(
            "The CMC request is not signed by the key it asks to certify (proof of possession failed).");
    }
}
