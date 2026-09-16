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
/// per-forest arc below Microsoft's. ModularCA has no registered arc of its own, so a generated
/// OID lives under the UUID arc, <c>2.25.{uuid}</c> (ITU-T X.667), which needs no registration
/// and cannot collide with anything issued elsewhere: the integer is the template's own id.
/// </para>
/// <para>
/// An operator may supply an OID instead, typically to keep the one an existing AD CS template
/// carried so clients that already hold certificates from it see a continuation rather than a new
/// template.
/// </para>
/// </remarks>
public static partial class MsaeTemplateOids
{
    /// <summary>Longest OID accepted; matches the column width.</summary>
    public const int MaxLength = 64;

    [GeneratedRegex(@"^[0-2](\.(0|[1-9][0-9]*))+$")]
    private static partial Regex OidShape();

    /// <summary>Derives the UUID-arc OID for a template id: <c>2.25.</c> followed by the id as an unsigned integer.</summary>
    public static string FromTemplateId(Guid templateId)
    {
        var value = new BigInteger(templateId.ToByteArray(bigEndian: true), isUnsigned: true, isBigEndian: true);
        return $"2.25.{value}";
    }

    /// <summary>
    /// True when <paramref name="oid"/> is a dotted-decimal OID: a root arc of 0, 1 or 2 followed
    /// by at least one more arc, no leading zeros, and within the stored length.
    /// </summary>
    public static bool IsValid(string? oid)
        => !string.IsNullOrWhiteSpace(oid) && oid.Length <= MaxLength && OidShape().IsMatch(oid);
}
