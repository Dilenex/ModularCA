using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Builds a BouncyCastle <see cref="GeneralName"/> from the <c>TYPE</c> / <c>value</c> pair this
/// codebase represents a subject alternative name with.
/// </summary>
/// <remarks>
/// <para>
/// The counterpart to <see cref="UpnSanEncoding.Describe"/> on the decode side. Three separate
/// places construct SANs — the runtime certificate builder, the bootstrap self-signed builder, and
/// the admin generate-key path that assembles a PKCS#10 on the caller's behalf — and two of them
/// mapped any unrecognised type to <c>DnsName</c> rather than failing.
/// </para>
/// <para>
/// That default is worse than it looks. It does not drop the entry: it puts the caller's text into
/// the certificate as a DNS name, signed. A <c>UPN:alice@example.test</c> became a DNS SAN
/// containing a UPN, and a mistyped <c>DSN:host</c> became a DNS SAN with nothing reported. Both
/// are wrong identities in a signed certificate, which is the one thing a CA must not produce
/// quietly, so an unknown type is an error here.
/// </para>
/// </remarks>
public static class SanGeneralNames
{
    /// <summary>The SAN types this CA can encode, for error messages and UI.</summary>
    public const string SupportedTypes = "DNS, IP, URI, EMAIL, UPN";

    /// <summary>
    /// Constructs the GeneralName for a SAN type and value.
    /// </summary>
    /// <remarks>
    /// Shape and policy validation is the caller's job and happens before this — wildcard rules
    /// need the resolved cert profile, and IP values may need normalising out of their DER hex
    /// form first. This method is only the encoding step.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The SAN type is not one this CA can encode.</exception>
    public static GeneralName Build(string type, string value)
        => type?.Trim().ToUpperInvariant() switch
        {
            "DNS" => new GeneralName(GeneralName.DnsName, value),
            "IP" => new GeneralName(GeneralName.IPAddress, value),
            "URI" => new GeneralName(GeneralName.UniformResourceIdentifier, value),
            "EMAIL" or "RFC822" => new GeneralName(GeneralName.Rfc822Name, value),
            "UPN" => UpnSanEncoding.BuildUpnGeneralName(value),
            _ => throw new InvalidOperationException(
                $"Unsupported SAN type '{type}'. Supported types: {SupportedTypes}."),
        };

    /// <summary>
    /// Parses one SAN entry as this codebase stores it, <c>TYPE:value</c>, into the GeneralName
    /// <see cref="Build"/> encodes, with the canonical type (DNS, IP, EMAIL, URI, UPN; RFC822 reads
    /// as EMAIL) and the trimmed value. An IP value in BouncyCastle's <c>#hex</c> form is read as
    /// the address it encodes.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The entry has no <c>TYPE:</c> prefix, names a type this CA cannot encode, or carries a value
    /// that cannot be encoded as that type.
    /// </exception>
    public static GeneralName Parse(string? entry, out string type, out string value)
    {
        var colon = entry?.IndexOf(':') ?? -1;
        if (entry == null || colon < 1)
            throw new InvalidOperationException(
                $"SAN entry '{entry}' has no TYPE: prefix; expected one of {SupportedTypes}, as in DNS:host.example.com.");
        var rawType = entry[..colon].Trim().ToUpperInvariant();
        type = rawType == "RFC822" ? "EMAIL" : rawType;
        value = entry[(colon + 1)..].Trim();
        try
        {
            if (type == "IP" && value.StartsWith('#') && value.Length is 9 or 33)
                value = new System.Net.IPAddress(Convert.FromHexString(value[1..])).ToString();
            return Build(type, value);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            throw new InvalidOperationException($"SAN entry '{entry}' cannot be encoded as {type}: {ex.Message}", ex);
        }
    }
}
