using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Save-time checks for the SSH profile fields stored as JSON-array strings. The signing endpoints
/// (AdminSshController, UserSshController) parse these at issuance; a malformed value there either
/// throws for every request or, for a source address, yields certificates sshd rejects at login.
/// Each method returns null when the value is acceptable, otherwise a message for a 400 response.
/// </summary>
public static class SshProfileFieldRules
{
    /// <summary>
    /// Validates <c>SourceAddressRestrictions</c>: a JSON array of IPv4/IPv6 addresses or CIDR
    /// networks, written into the certificate's <c>source-address</c> critical option. A range with
    /// bits set after the prefix (<c>10.0.0.1/8</c>) is refused because OpenSSH refuses it.
    /// Null means "not supplied" (create applies the default, update leaves the value alone).
    /// </summary>
    /// <param name="json">The field as sent in the request body.</param>
    public static string? ValidateSourceAddressRestrictions(string? json)
    {
        if (json == null) return null;
        if (ParseStringArray(json, "SourceAddressRestrictions", "[\"10.0.0.0/8\"]", out var entries) is { } shapeError)
            return shapeError;

        foreach (var entry in entries)
        {
            if (SourceAddressError(entry) is { } error)
                return $"SourceAddressRestrictions: {error}";
        }
        return null;
    }

    /// <summary>
    /// Validates <c>AllowedPrincipalPatterns</c>: a JSON array of .NET regular expressions, each of
    /// which must compile as <see cref="ProfileRegex"/> will construct it. An uncompilable pattern
    /// never matches, so it would silently refuse every principal it was meant to allow.
    /// Null means "not supplied".
    /// </summary>
    /// <param name="json">The field as sent in the request body.</param>
    public static string? ValidateAllowedPrincipalPatterns(string? json)
    {
        if (json == null) return null;
        if (ParseStringArray(json, "AllowedPrincipalPatterns", "[\"^[a-z_][a-z0-9_-]*$\"]", out var entries) is { } shapeError)
            return shapeError;

        foreach (var pattern in entries)
        {
            if (ProfileRegex.CompileError(pattern) is { } error)
                return $"AllowedPrincipalPatterns: {error}";
        }
        return null;
    }

    /// <summary>
    /// Checks one <c>source-address</c> entry: a strict dotted-quad IPv4 or an IPv6 address, with
    /// an optional prefix length whose host bits are zero. Returns null when valid.
    /// </summary>
    /// <param name="entry">One element of the array.</param>
    public static string? SourceAddressError(string? entry)
    {
        var value = entry?.Trim() ?? string.Empty;
        if (value.Length == 0)
            return "entries must not be empty.";

        var slash = value.IndexOf('/');
        var addressPart = slash < 0 ? value : value[..slash];
        if (!TryParseStrictAddress(addressPart, out var address))
            return $"\"{value}\" is not an IPv4 or IPv6 address or CIDR network.";
        if (slash < 0)
            return null;

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefixPart = value[(slash + 1)..];
        if (prefixPart.Length == 0 || prefixPart.Length > 3 || !prefixPart.All(char.IsAsciiDigit)
            || int.Parse(prefixPart) > maxPrefix)
            return $"\"{value}\" needs a prefix length from 0 to {maxPrefix}.";

        var prefix = int.Parse(prefixPart);
        var bytes = address.GetAddressBytes();
        for (var bit = prefix; bit < bytes.Length * 8; bit++)
        {
            if ((bytes[bit / 8] & (0x80 >> (bit % 8))) != 0)
                return $"\"{value}\" has bits set after the /{prefix} prefix; OpenSSH rejects it. Use the network address.";
        }
        return null;
    }

    /// <summary>
    /// Parses an address without the legacy shorthands <see cref="IPAddress.TryParse(string, out IPAddress)"/>
    /// accepts for IPv4 (<c>10.1</c>, <c>167772161</c>), which OpenSSH does not, and without IPv6 zone ids.
    /// </summary>
    private static bool TryParseStrictAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.Contains('%')) return false;
        if (!text.Contains(':'))
        {
            var parts = text.Split('.');
            if (parts.Length != 4 || parts.Any(p => p.Length is 0 or > 3 || !p.All(char.IsAsciiDigit) || (p.Length > 1 && p[0] == '0')))
                return false;
        }
        if (!IPAddress.TryParse(text, out var parsed) || parsed == null) return false;
        address = parsed;
        return true;
    }

    /// <summary>Deserializes a JSON array of non-null strings, or returns a shape error.</summary>
    private static string? ParseStringArray(string json, string field, string example, out List<string> entries)
    {
        entries = new List<string>();
        List<string?>? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<List<string?>>(json);
        }
        catch (JsonException)
        {
            return $"{field} must be a JSON array of strings, e.g. {example}.";
        }
        if (parsed == null || parsed.Any(e => e == null))
            return $"{field} must be a JSON array of strings, e.g. {example}.";
        entries = parsed!.Select(e => e!).ToList();
        return null;
    }
}
