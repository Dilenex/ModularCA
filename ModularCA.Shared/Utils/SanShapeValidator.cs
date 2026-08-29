using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Catches the shape-mismatch class of SAN bugs at validation time instead of letting them
/// surface as <see cref="System.ArgumentException"/> from BouncyCastle's
/// <c>GeneralName(GeneralName.IPAddress, "...")</c> constructor deep in the issuance pipeline.
/// Two checks supported:
///   "IP"  → must parse as IPv4 or IPv6 via <see cref="IPAddress.TryParse(string, out IPAddress?)"/>.
///   "DNS" → must be a syntactically valid FQDN (label rules per RFC 1035 with underscores
///           tolerated for service-prefix names, optional leading <c>*.</c> wildcard).
/// All other SAN types (RFC822, URI, etc.) are returned as <see langword="null"/> from
/// <see cref="ValidateShape"/> so this stays additive — profile-author regex still applies.
/// </summary>
public static class SanShapeValidator
{
    // RFC 1035 label, plus underscore tolerated for _acme-challenge / _dmarc / etc.
    // Each label: 1–63 chars, starts/ends alphanumeric (or underscore), interior may be
    // alphanumeric/underscore/hyphen.
    private static readonly Regex LabelRe = new(
        @"^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// True if <paramref name="value"/> parses as an IPv4 or IPv6 address. Stricter than
    /// <see cref="IPAddress.TryParse(string, out IPAddress?)"/> for IPv4: that .NET API
    /// accepts shortened forms (<c>"1.2.3"</c> → 1.2.0.3), but BouncyCastle's
    /// <c>GeneralName.IPAddress</c> ctor rejects them with an <see cref="System.ArgumentException"/>.
    /// We require strict dotted-quad for v4 to match the issuance pipeline's expectations.
    /// </summary>
    public static bool IsValidIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var v = value!.Trim();
        if (IsStrictIpv4(v)) return true;
        if (!IPAddress.TryParse(v, out var addr)) return false;
        return addr.AddressFamily == AddressFamily.InterNetworkV6;
    }

    private static bool IsStrictIpv4(string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 3) return false;
            if (part.Length > 1 && part[0] == '0') return false; // no leading zeros
            foreach (var c in part) if (c < '0' || c > '9') return false;
            if (!int.TryParse(part, out var n) || n < 0 || n > 255) return false;
        }
        return true;
    }

    /// <summary>
    /// True if <paramref name="value"/> is a syntactically valid FQDN (or wildcard FQDN).
    /// Total length ≤ 253; each label 1–63 chars matching <see cref="LabelRe"/>.
    /// A leading <c>*.</c> is tolerated; bare <c>*</c> alone is rejected. A value that
    /// parses as a literal IP address is rejected (caller used the wrong SAN type).
    /// </summary>
    public static bool IsValidFqdn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        // Reject IP-shaped strings outright — those belong in IP SANs, not DNS.
        if (IsValidIp(value)) return false;
        var v = value!;
        // Strip trailing dot if present (common in DNS notation).
        if (v.EndsWith('.')) v = v[..^1];
        if (v.Length == 0 || v.Length > 253) return false;
        var labels = v.Split('.');
        var start = 0;
        if (labels[0] == "*")
        {
            if (labels.Length < 2) return false; // bare "*" not a hostname
            start = 1;
        }
        for (var i = start; i < labels.Length; i++)
        {
            if (!LabelRe.IsMatch(labels[i])) return false;
        }
        return true;
    }

    /// <summary>
    /// Returns <see langword="null"/> if the value's shape matches the SAN type, otherwise an
    /// error message suitable for surfacing to the user. Unknown types pass through (return
    /// null) so the profile-author regex remains the only gate for those.
    /// </summary>
    public static string? ValidateShape(string type, string value)
    {
        if (string.IsNullOrWhiteSpace(type)) return null;
        switch (type.Trim().ToUpperInvariant())
        {
            case "IP":
                return IsValidIp(value)
                    ? null
                    : $"'{value}' is not a valid IPv4 or IPv6 address.";
            case "DNS":
                return IsValidFqdn(value)
                    ? null
                    : $"'{value}' is not a valid DNS hostname (FQDN).";
            case "UPN":
                // Same rule the issuance pipeline enforces, surfaced here so a malformed principal
                // name is reported while the operator is still looking at the form rather than
                // failing at signing time.
                try
                {
                    DnComponentSanitizer.ValidateUpn(value);
                    return null;
                }
                catch (InvalidOperationException ex)
                {
                    return ex.Message;
                }
            default:
                return null;
        }
    }
}
