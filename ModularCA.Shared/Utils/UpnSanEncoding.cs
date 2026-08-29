using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The single place that encodes and decodes a User Principal Name carried as an X.509
/// <c>otherName</c> subject alternative name.
/// </summary>
/// <remarks>
/// <para>
/// Windows maps a certificate to an Active Directory account through a UPN in an
/// <c>otherName</c> SAN under Microsoft's OID <c>1.3.6.1.4.1.311.20.2.3</c>. Without one, a
/// smart-card logon certificate identifies nobody, whatever EKUs it carries.
/// </para>
/// <para>
/// Encode and decode live together here for the same reason
/// <see cref="UsageCatalogResolver"/> exists: the SAN decode logic was hand-rolled at four
/// separate sites in <c>CertificateUtil</c>, each with its own type-name switch, and every one of
/// them mapped an unrecognised tag to the literal string <c>"Other"</c> while calling
/// <c>gn.Name.ToString()</c> on it — which for an <c>otherName</c> yields a DER dump, not a UPN.
/// A round trip through parse → store → re-encode therefore could not preserve one. Splitting
/// this across the encoder and four decoders is what guarantees they drift.
/// </para>
/// <para>
/// ASN.1, per RFC 5280 §4.2.1.6:
/// <code>
/// GeneralName ::= CHOICE { otherName [0] OtherName, ... }
/// OtherName   ::= SEQUENCE { type-id OBJECT IDENTIFIER,
///                            value   [0] EXPLICIT ANY DEFINED BY type-id }
/// </code>
/// The <c>otherName</c> tag is IMPLICIT; the inner value tag is EXPLICIT. Microsoft encodes the
/// UPN as a <c>UTF8String</c>. Getting the explicit/implicit pairing wrong produces a structure
/// Windows silently declines to map, so both directions are covered by tests.
/// </para>
/// </remarks>
public static class UpnSanEncoding
{
    /// <summary>
    /// Microsoft's UPN <c>otherName</c> OID (<c>szOID_NT_PRINCIPAL_NAME</c>).
    /// </summary>
    public const string UpnOid = "1.3.6.1.4.1.311.20.2.3";

    /// <summary>
    /// The <c>TYPE:</c> prefix this codebase uses for a UPN SAN in its string form.
    /// </summary>
    public const string UpnPrefix = "UPN";

    /// <summary>
    /// Builds the <c>otherName</c> GeneralName for a UPN.
    /// </summary>
    /// <param name="upn">The user principal name, e.g. <c>alice@example.test</c>.</param>
    public static GeneralName BuildUpnGeneralName(string upn)
    {
        // [0] EXPLICIT on the value, per OtherName. The outer otherName tag is applied implicitly
        // by GeneralName itself when it encodes.
        var otherName = new DerSequence(
            new DerObjectIdentifier(UpnOid),
            new DerTaggedObject(true, 0, new DerUtf8String(upn)));

        return new GeneralName(GeneralName.OtherName, otherName);
    }

    /// <summary>
    /// Extracts the UPN from a GeneralName, or returns null when it is not a UPN
    /// <c>otherName</c>.
    /// </summary>
    /// <remarks>
    /// Tolerant on input shape because the same value arrives having been decoded by different
    /// paths — straight from a certificate extension, from a CSR attribute, or re-read after a
    /// database round trip — and the inner value is not always unwrapped to the same depth.
    /// </remarks>
    public static string? TryGetUpn(GeneralName generalName)
    {
        if (generalName.TagNo != GeneralName.OtherName)
            return null;

        var inner = generalName.Name;

        // Some decode paths hand back the otherName still wrapped in its context tag.
        if (inner is Asn1TaggedObject tagged)
            inner = tagged.GetBaseObject();

        if (inner is not Asn1Sequence seq || seq.Count < 2)
            return null;

        if (seq[0] is not DerObjectIdentifier oid || oid.Id != UpnOid)
            return null;

        var value = seq[1];
        if (value is Asn1TaggedObject valueTag)
            value = valueTag.GetBaseObject();

        return value switch
        {
            DerUtf8String utf8 => utf8.GetString(),
            // Not what Microsoft writes, but readable and harmless to accept when a third-party
            // enrollment client chose a different string type.
            DerPrintableString printable => printable.GetString(),
            DerIA5String ia5 => ia5.GetString(),
            _ => null,
        };
    }

    /// <summary>
    /// Renders a GeneralName as the <c>TYPE:value</c> string this codebase stores SANs in.
    /// </summary>
    /// <remarks>
    /// Every SAN decode path routes through here so the four copies of this switch cannot
    /// disagree again. IP addresses are DER octet strings and are converted to their textual form;
    /// a UPN <c>otherName</c> becomes <c>UPN:alice@example.test</c>; anything else falls back to
    /// the previous behaviour rather than throwing, because these paths run when displaying
    /// certificates the CA did not issue and must not fail on an exotic-but-valid SAN.
    /// </remarks>
    public static string Describe(GeneralName generalName)
    {
        var upn = TryGetUpn(generalName);
        if (upn != null)
            return $"{UpnPrefix}:{upn}";

        var value = generalName.TagNo == GeneralName.IPAddress && generalName.Name is DerOctetString octets
            ? new System.Net.IPAddress(octets.GetOctets()).ToString()
            : generalName.Name.ToString() ?? string.Empty;

        return $"{TypeName(generalName.TagNo)}:{value}";
    }

    /// <summary>Maps a GeneralName tag to the type prefix used in stored SAN strings.</summary>
    public static string TypeName(int tag) => tag switch
    {
        GeneralName.DnsName => "DNS",
        GeneralName.IPAddress => "IP",
        GeneralName.Rfc822Name => "Email",
        GeneralName.UniformResourceIdentifier => "URI",
        _ => "Other",
    };
}
