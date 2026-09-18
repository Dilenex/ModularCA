using System.Buffers.Binary;
using System.Numerics;
using System.Text.RegularExpressions;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Object identifiers for certificate templates offered to Windows clients.
/// </summary>
/// <remarks>
/// <para>
/// Windows identifies a template by OID: the policy service advertises it, the client puts it in
/// its CSR, and the issuing side matches on it. Active Directory mints template OIDs under a
/// per-forest arc below Microsoft's. ModularCA mints its own from the template id.
/// </para>
/// <para>
/// Windows parses an OID arc into a signed 64-bit integer and rejects anything larger (verified
/// against CertEnroll on Windows 11: every arc up to 2^63-1 is accepted, 2^63 and above are
/// refused, whatever the surrounding arcs). A template with such an OID silently disappears from
/// the client's template list. The generated form therefore spreads the 128-bit template id over
/// four arcs of 31 bits each, which every OID parser in the field handles, and validation refuses
/// any operator-supplied OID with an arc Windows cannot read.
/// </para>
/// <para>
/// The base arc is the operator's: a Private Enterprise Number arc such as
/// <c>1.3.6.1.4.1.66874.1.1</c>, configured as <c>Msae:TemplateOidArc</c>. Until one is configured,
/// generated OIDs sit under <c>2.25</c>, the UUID arc: a first sub-arc below 2^31 is an integer no
/// RFC 4122 UUID can take (their variant bits put every real UUID above 2^63), so the space is
/// unclaimed, though it is not the letter of X.667. An operator may also supply an OID outright,
/// typically to keep the one an existing AD CS template carried so clients that already hold
/// certificates from it see a continuation rather than a new template.
/// </para>
/// </remarks>
public static partial class MsaeTemplateOids
{
    /// <summary>Longest OID accepted; matches the column width.</summary>
    public const int MaxLength = 128;

    /// <summary>
    /// The arc generated OIDs live under when no <c>Msae:TemplateOidArc</c> is configured: this
    /// product's own arc, under Dilenex LLC's Private Enterprise Number 66874. A template minted
    /// by any installation therefore says "a ModularCA template" and is correct with no
    /// configuration at all, which is how Active Directory Certificate Services also mints
    /// template identifiers for its customers, under its vendor's arc. An operator holding their
    /// own enterprise number overrides it; see <c>docs/oid-allocation.md</c>.
    /// </summary>
    public const string DefaultArc = "1.3.6.1.4.1.66874.1.1";

    /// <summary>
    /// Arcs this product generated under before <see cref="DefaultArc"/>, recognised so an
    /// identifier minted by an older build is still known to be generated rather than mistaken
    /// for one an operator typed. <c>2.25</c> is the arc for identifiers derived from a
    /// universally unique identifier, which is legitimate but says nothing about who minted it.
    /// </summary>
    public static readonly IReadOnlyList<string> HistoricalArcs = ["2.25"];

    /// <summary>
    /// Whether <paramref name="oid"/> is one this product generated for <paramref name="templateId"/>:
    /// the pre-2026-09-15 single-arc form, or the four-arc form under the current arc,
    /// <paramref name="effectiveArc"/> if an operator configured one, or any historical arc.
    /// Anything else is an operator's own and is never rewritten.
    /// </summary>
    public static bool IsGenerated(Guid templateId, string? oid, string? effectiveArc = null)
    {
        if (string.IsNullOrWhiteSpace(oid)) return false;
        if (oid == LegacyFromTemplateId(templateId)) return true;
        if (oid == FromTemplateId(templateId, DefaultArc)) return true;
        if (!string.IsNullOrWhiteSpace(effectiveArc) && IsValidBaseArc(effectiveArc.Trim())
            && oid == FromTemplateId(templateId, effectiveArc.Trim())) return true;
        foreach (var arc in HistoricalArcs)
            if (oid == FromTemplateId(templateId, arc)) return true;
        return false;
    }

    /// <summary>Largest arc value Windows parses: a signed 64-bit integer.</summary>
    public static readonly BigInteger MaxArc = long.MaxValue;

    [GeneratedRegex(@"^[0-2](\.(0|[1-9][0-9]*))+$")]
    private static partial Regex OidShape();

    /// <summary>
    /// Derives the OID for a template id under <paramref name="baseArc"/> (or <see cref="DefaultArc"/>
    /// when blank): the id's sixteen bytes as four big-endian 32-bit words, each with the top bit
    /// cleared so every arc fits a signed 32-bit integer.
    /// </summary>
    public static string FromTemplateId(Guid templateId, string? baseArc = null)
    {
        var arc = string.IsNullOrWhiteSpace(baseArc) ? DefaultArc : baseArc.Trim();
        if (!IsValidBaseArc(arc))
            throw new ArgumentException($"'{arc}' is not a usable base arc for template OIDs.", nameof(baseArc));
        Span<byte> bytes = stackalloc byte[16];
        templateId.TryWriteBytes(bytes, bigEndian: true, out _);
        var words = new uint[4];
        for (var i = 0; i < 4; i++)
            words[i] = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(i * 4, 4)) & 0x7FFF_FFFF;
        return $"{arc}.{words[0]}.{words[1]}.{words[2]}.{words[3]}";
    }

    /// <summary>
    /// The form generated before 2026-09-15: <c>2.25.</c> followed by the whole id as one unsigned
    /// integer. Windows cannot parse it for roughly half of all ids. Kept so stored OIDs of that
    /// shape can be recognised as generated, and rewritten, rather than mistaken for an operator's.
    /// </summary>
    public static string LegacyFromTemplateId(Guid templateId)
    {
        var value = new BigInteger(templateId.ToByteArray(bigEndian: true), isUnsigned: true, isBigEndian: true);
        return $"2.25.{value}";
    }

    /// <summary>
    /// True when <paramref name="oid"/> is a dotted-decimal OID: a root arc of 0, 1 or 2 followed
    /// by at least one more arc, no leading zeros, within the stored length, and no arc above
    /// <see cref="MaxArc"/>, since Windows would refuse the template.
    /// </summary>
    public static bool IsValid(string? oid)
        => !string.IsNullOrWhiteSpace(oid) && oid.Length <= MaxLength && OidShape().IsMatch(oid) && ArcsFitWindows(oid);

    /// <summary>
    /// True when <paramref name="arc"/> can prefix generated OIDs: a valid OID by <see cref="IsValid"/>
    /// that still leaves room for the four generated arcs within <see cref="MaxLength"/>.
    /// </summary>
    public static bool IsValidBaseArc(string? arc)
        => IsValid(arc) && arc!.Length + ".2147483647".Length * 4 <= MaxLength;

    private static bool ArcsFitWindows(string oid)
    {
        foreach (var arc in oid.Split('.'))
        {
            if (!BigInteger.TryParse(arc, out var value) || value > MaxArc) return false;
        }
        return true;
    }
}
