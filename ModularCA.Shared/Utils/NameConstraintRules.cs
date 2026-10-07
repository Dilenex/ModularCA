using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Parses name-constraint subtree entries (RFC 5280 §4.2.1.10) written as <c>TYPE:value</c>, the
/// form signing profiles store as a JSON array and CA creation takes as a list. TYPE is DNS, IP,
/// EMAIL, URI or DN, in any case.
/// </summary>
/// <remarks>
/// <para>
/// One parser serves both the certificate builder and the save-time checks, so an entry accepted
/// when a profile or CA request is saved is exactly one the builder can encode. The builder used to
/// drop entries it could not read (no colon, unknown type) and pass the rest to BouncyCastle
/// unchecked, which accepted a bare IP address as a 4-byte constraint relying parties reject and
/// stored <c>@example.com</c>, which is not an RFC 5280 form. When every entry dropped,
/// BouncyCastle refused the resulting empty subtree list, so the CA certificate failed to build
/// with an unrelated-looking error, on the ceremony path only after the approvals were in.
/// </para>
/// <para>
/// The console mirrors these rules in <c>shared/common/src/generalNames.ts</c>; the cases both
/// test suites run are in <c>tests/modularca.web.tests/src/common/name-constraint-cases.json</c>.
/// </para>
/// </remarks>
public static class NameConstraintRules
{
    /// <summary>The TYPE prefixes accepted, for messages.</summary>
    public const string SupportedTypes = "DNS, IP, EMAIL, URI, DN";

    private static readonly Regex DnsLabel = new("^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$", RegexOptions.CultureInvariant);
    private static readonly Regex DottedQuad = new(@"^\d+(\.\d+){3}$", RegexOptions.CultureInvariant);
    private static readonly Regex StrictIpv4 = new(@"^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$", RegexOptions.CultureInvariant);
    private static readonly Regex PrefixLength = new(@"^(0|[1-9]\d{0,2})$", RegexOptions.CultureInvariant);
    private static readonly Regex MailboxLocal = new(@"^[^\s@<>()\[\],;:""\\]+$", RegexOptions.CultureInvariant);

    /// <summary>Why <paramref name="entry"/> is not a valid subtree, or null when it is.</summary>
    public static string? EntryError(string? entry)
    {
        TryParse(entry, out _, out var error);
        return error;
    }

    /// <summary>
    /// Parses one <c>TYPE:value</c> entry into a subtree. False, with the reason, for an entry the
    /// builder must not encode.
    /// </summary>
    public static bool TryParse(string? entry, out GeneralSubtree? subtree, out string? error)
    {
        subtree = null;
        if (string.IsNullOrWhiteSpace(entry))
        {
            error = "An entry is empty.";
            return false;
        }
        var colon = entry.IndexOf(':');
        if (colon < 1)
        {
            error = $"'{entry}' has no TYPE: prefix; expected one of {SupportedTypes}, as in DNS:example.com.";
            return false;
        }
        var type = entry[..colon].Trim().ToUpperInvariant();
        var value = entry[(colon + 1)..].Trim();
        if (value.Length == 0)
        {
            error = $"'{entry}' has no value after the type.";
            return false;
        }
        if (DnComponentSanitizer.HasControlCharacter(value))
        {
            error = $"'{type}' entry contains a control character.";
            return false;
        }

        GeneralName? name = null;
        switch (type)
        {
            case "DNS":
                error = DomainError(value, "DNS name", allowLeadingDot: true);
                if (error == null) name = new GeneralName(GeneralName.DnsName, value);
                break;
            case "IP":
                var octets = ParseIpRange(value, out error);
                if (octets != null) name = new GeneralName(GeneralName.IPAddress, new DerOctetString(octets));
                break;
            case "EMAIL":
                error = EmailError(value);
                if (error == null) name = new GeneralName(GeneralName.Rfc822Name, value);
                break;
            case "URI":
                error = value.IndexOfAny(['/', ':', '?', '#', '@', '[', ']']) >= 0
                    ? $"URI constraint '{value}' must be a host (example.com) or a domain (.example.com), not a URL; RFC 5280 constrains the host of a URI."
                    : DomainError(value, "host name", allowLeadingDot: true);
                if (error == null) name = new GeneralName(GeneralName.UniformResourceIdentifier, value);
                break;
            case "DN":
                // The DN sanitizer runs before the ASN.1 parser so a profile cannot smuggle control
                // characters or BIDI overrides into a subtree; both refuse by throwing.
                try
                {
                    name = new GeneralName(GeneralName.DirectoryName,
                        new X509Name(DnComponentSanitizer.SanitizeDistinguishedName(value)));
                    error = null;
                }
                catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
                {
                    error = $"DN constraint '{value}' is not a valid distinguished name: {ex.Message}";
                }
                break;
            default:
                error = $"'{type}' in '{entry}' is not a name-constraint type; expected one of {SupportedTypes}.";
                break;
        }

        if (name == null)
            return false;
        subtree = new GeneralSubtree(name);
        return true;
    }

    /// <summary>
    /// The first invalid entry in <paramref name="entries"/>, as a message naming
    /// <paramref name="fieldName"/>, or null when all are valid (or there are none).
    /// </summary>
    public static string? ListError(IEnumerable<string?>? entries, string fieldName)
    {
        if (entries == null) return null;
        foreach (var entry in entries)
        {
            if (EntryError(entry) is string error)
                return $"{fieldName}: {error}";
        }
        return null;
    }

    /// <summary>
    /// Why a stored JSON field is not a valid subtree list, or null when it is valid, blank, or an
    /// empty array. The field must be a JSON array of strings.
    /// </summary>
    public static string? JsonError(string? json, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        List<string?>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<string?>>(json, SafeJsonOptions.Default);
        }
        catch (JsonException)
        {
            return $"{fieldName} must be a JSON array of \"TYPE:value\" strings, such as [\"DNS:example.com\"].";
        }
        return ListError(entries, fieldName);
    }

    /// <summary>
    /// Parses a stored JSON array into subtrees for the NameConstraints extension. Null when the
    /// field is blank or an empty array, so the caller omits that half of the extension (RFC 5280
    /// forbids an empty subtree list). Throws <see cref="InvalidOperationException"/> on any
    /// invalid entry: dropping one would issue a CA certificate constrained differently from what
    /// the operator configured, and dropping a permitted entry can leave no constraint at all.
    /// </summary>
    public static GeneralSubtree[]? ParseJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        List<string?>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<string?>>(json, SafeJsonOptions.Default);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("A name-constraint list is not a JSON array of \"TYPE:value\" strings.", ex);
        }
        if (entries == null || entries.Count == 0) return null;

        var subtrees = new GeneralSubtree[entries.Count];
        for (var i = 0; i < entries.Count; i++)
        {
            if (!TryParse(entries[i], out var subtree, out var error))
                throw new InvalidOperationException($"Invalid name constraint: {error}");
            subtrees[i] = subtree!;
        }
        return subtrees;
    }

    /// <summary>
    /// A host name or, with <paramref name="allowLeadingDot"/>, a <c>.domain</c>: LDH labels of 1
    /// to 63 characters, 253 in all, no trailing dot, no wildcard, not an IPv4 literal.
    /// </summary>
    private static string? DomainError(string value, string kind, bool allowLeadingDot)
    {
        var host = value;
        if (host.StartsWith('.'))
        {
            if (!allowLeadingDot) return $"'{value}' cannot start with a dot here.";
            host = host[1..];
        }
        if (host.Length == 0) return $"'{value}' names no domain.";
        if (host.Contains('*')) return $"'{value}': wildcards are not used in name constraints; write .example.com to cover every subdomain of example.com.";
        if (host.EndsWith('.')) return $"'{value}' has a trailing dot.";
        if (host.Length > 253) return $"'{value}' is longer than 253 characters.";
        if (DottedQuad.IsMatch(host)) return $"'{value}' is an address, not a {kind}; use an IP entry with a prefix, such as IP:10.0.0.0/8.";
        foreach (var label in host.Split('.'))
        {
            if (label.Length == 0) return $"'{value}' has an empty label.";
            if (label.Length > 63) return $"'{value}' has a label longer than 63 characters.";
            if (!DnsLabel.IsMatch(label))
                return $"'{value}': '{label}' is not a valid DNS label (letters, digits and hyphens, not starting or ending with a hyphen).";
        }
        return null;
    }

    /// <summary>
    /// An rfc822Name constraint in one of the three RFC 5280 forms: a mailbox, a host, or a
    /// <c>.domain</c>. <c>@example.com</c> is none of them.
    /// </summary>
    private static string? EmailError(string value)
    {
        var at = value.IndexOf('@');
        if (at < 0) return DomainError(value, "mail domain", allowLeadingDot: true);
        if (at == 0)
            return $"'{value}' is not an RFC 5280 email constraint; write {value[1..]} for every mailbox at that host, or .{value[1..]} for its subdomains.";
        if (value.IndexOf('@', at + 1) >= 0) return $"'{value}' has more than one '@'.";
        if (!MailboxLocal.IsMatch(value[..at])) return $"'{value}' is not a bare mailbox such as admin@example.com.";
        return DomainError(value[(at + 1)..], "mail domain", allowLeadingDot: false);
    }

    /// <summary>
    /// The octets of an IP constraint: address then mask (8 bytes for IPv4, 32 for IPv6). The
    /// range is written <c>address/prefix</c> or <c>address/netmask</c>; the mask must be
    /// contiguous and the address must be the network address.
    /// </summary>
    private static byte[]? ParseIpRange(string value, out string? error)
    {
        var parts = value.Split('/');
        if (parts.Length == 1)
        {
            error = $"'{value}' is a single address; IP constraints are ranges, so add a prefix length such as /{(value.Contains(':') ? 128 : 32)}.";
            return null;
        }
        if (parts.Length > 2)
        {
            error = $"'{value}' has more than one '/'.";
            return null;
        }
        var address = ParseAddress(parts[0]);
        if (address == null)
        {
            error = $"'{parts[0]}' is not an IPv4 or IPv6 address.";
            return null;
        }

        int prefix;
        var maxPrefix = address.Length * 8;
        if (PrefixLength.IsMatch(parts[1]))
        {
            prefix = int.Parse(parts[1]);
            if (prefix > maxPrefix)
            {
                error = $"The prefix length in '{value}' must be 0 to {maxPrefix}.";
                return null;
            }
        }
        else
        {
            var mask = ParseAddress(parts[1]);
            if (mask == null || mask.Length != address.Length)
            {
                error = $"After '/' in '{value}' give a prefix length or a netmask of the same address family.";
                return null;
            }
            var contiguous = PrefixOfMask(mask);
            if (contiguous == null)
            {
                error = $"'{parts[1]}' is not a contiguous netmask.";
                return null;
            }
            prefix = contiguous.Value;
        }

        var maskBytes = MaskBytes(address.Length, prefix);
        var network = address.Select((b, i) => (byte)(b & maskBytes[i])).ToArray();
        if (!network.SequenceEqual(address))
        {
            error = $"'{value}' has bits set after the /{prefix} prefix; use {new IPAddress(network)}/{prefix}.";
            return null;
        }

        error = null;
        return [.. address, .. maskBytes];
    }

    /// <summary>
    /// Bytes of a strictly written address: a dotted quad without leading zeros, or an IPv6
    /// address without a zone or brackets. Null otherwise.
    /// </summary>
    private static byte[]? ParseAddress(string text)
    {
        if (text.Contains(':'))
        {
            if (text.IndexOfAny(['%', '[', ']']) >= 0) return null;
            return IPAddress.TryParse(text, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6
                ? v6.GetAddressBytes() : null;
        }
        if (!StrictIpv4.IsMatch(text)) return null;
        var octets = text.Split('.').Select(int.Parse).ToArray();
        return octets.All(o => o <= 255) ? octets.Select(o => (byte)o).ToArray() : null;
    }

    private static byte[] MaskBytes(int length, int prefix)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
        {
            var bits = Math.Clamp(prefix - i * 8, 0, 8);
            bytes[i] = bits == 0 ? (byte)0 : (byte)(0xFF << (8 - bits));
        }
        return bytes;
    }

    private static int? PrefixOfMask(byte[] mask)
    {
        var prefix = 0;
        var ended = false;
        foreach (var b in mask)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var set = ((b >> bit) & 1) == 1;
                if (set && ended) return null;
                if (set) prefix++;
                else ended = true;
            }
        }
        return prefix;
    }
}
