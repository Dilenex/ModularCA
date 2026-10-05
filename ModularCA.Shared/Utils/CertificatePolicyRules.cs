using System.Text.Json;
using Org.BouncyCastle.Asn1;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Save-time checks for a signing profile's CertificatePolicies fields: <c>PolicyOids</c>, a JSON
/// array of dotted OIDs, and <c>PolicyQualifiersJson</c>, a JSON object
/// <c>{ "&lt;oid&gt;": { "cpsUri": "...", "userNotice": "...", "critical": true } }</c>.
/// Each method returns null when the value is acceptable, otherwise a message for a 400 response.
/// </summary>
/// <remarks>
/// The certificate builder parses both for every certificate issued under the profile. One OID
/// <see cref="DerObjectIdentifier"/> refuses made every issuance throw; a misspelled qualifier key,
/// or a qualifier for an OID not listed, was silently ignored (yet its <c>critical</c> flag still
/// made the whole extension critical). The console mirrors the per-value checks in
/// <c>modularca.adminui/src/pages/profiles/certificatePolicies.ts</c>; the cases both suites run are
/// in <c>tests/modularca.web.tests/src/common/certificate-policy-cases.json</c>.
/// </remarks>
public static class CertificatePolicyRules
{
    /// <summary>RFC 5280 §4.2.1.4: explicitText is at most 200 characters (BouncyCastle truncates longer text).</summary>
    public const int MaxUserNoticeLength = 200;

    /// <summary>The qualifier keys the certificate builder reads, in the case it reads them.</summary>
    public static readonly IReadOnlyList<string> QualifierKeys = new[] { "cpsUri", "userNotice", "critical" };

    /// <summary>Why <paramref name="oid"/> is not an OID the certificate builder can encode, or null.</summary>
    public static string? OidError(string? oid)
    {
        if (string.IsNullOrWhiteSpace(oid)) return "A policy OID is empty.";
        try
        {
            _ = new DerObjectIdentifier(oid);
            return null;
        }
        catch (Exception)
        {
            return $"'{oid}' is not a dotted OID such as 2.23.140.1.2.1.";
        }
    }

    /// <summary>
    /// Why <paramref name="uri"/> is not a usable CPS pointer, or null: an absolute http or https URL
    /// in printable ASCII, since the builder writes it as an IA5String.
    /// </summary>
    public static string? CpsUriError(string? uri)
    {
        if (string.IsNullOrEmpty(uri)) return null;
        if (uri.Any(c => c < 0x21 || c > 0x7E))
            return $"CPS URI '{uri}' must be printable ASCII with no spaces (it is encoded as an IA5String).";
        if (!uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || !Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)
            || string.IsNullOrEmpty(parsed.Host))
            return $"CPS URI '{uri}' must be an absolute http:// or https:// URL.";
        return null;
    }

    /// <summary>Why <paramref name="text"/> is not a usable user notice, or null: at most <see cref="MaxUserNoticeLength"/> characters, no control characters.</summary>
    public static string? UserNoticeError(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        if (text.Length > MaxUserNoticeLength)
            return $"A user notice is at most {MaxUserNoticeLength} characters (RFC 5280 explicitText); this one has {text.Length}.";
        if (text.Any(char.IsControl))
            return "A user notice cannot contain control characters or line breaks.";
        return null;
    }

    /// <summary>
    /// Parses <c>PolicyOids</c>: true with no OIDs for a blank field; false, with the reason, when
    /// it is not a JSON array of valid, distinct OIDs.
    /// </summary>
    public static bool TryParseOids(string? json, out List<string> oids, out string? error)
    {
        oids = new List<string>();
        error = null;
        if (string.IsNullOrWhiteSpace(json)) return true;
        List<string?>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<string?>>(json, SafeJsonOptions.Default);
        }
        catch (JsonException)
        {
            error = "PolicyOids must be a JSON array of dotted OIDs, such as [\"2.23.140.1.2.1\"].";
            return false;
        }
        foreach (var entry in entries ?? new List<string?>())
        {
            if (OidError(entry) is { } oidError)
            {
                error = $"PolicyOids: {oidError}";
                return false;
            }
            if (oids.Contains(entry!, StringComparer.Ordinal))
            {
                error = $"PolicyOids lists '{entry}' more than once; RFC 5280 allows each policy once.";
                return false;
            }
            oids.Add(entry!);
        }
        return true;
    }

    /// <summary>Why <c>PolicyOids</c> would not build, or null (see <see cref="TryParseOids"/>).</summary>
    public static string? PolicyOidsError(string? json) => TryParseOids(json, out _, out var error) ? null : error;

    /// <summary>
    /// Why <c>PolicyQualifiersJson</c> is not of the shape the builder reads, or null. Blank is
    /// fine. Otherwise it must be a JSON object whose keys are OIDs listed in
    /// <paramref name="policyOidsJson"/>, each mapping to null or an object with only
    /// <see cref="QualifierKeys"/>: <c>cpsUri</c> (<see cref="CpsUriError"/>), <c>userNotice</c>
    /// (<see cref="UserNoticeError"/>), each a string or null, and <c>critical</c>, a boolean.
    /// </summary>
    public static string? PolicyQualifiersError(string? json, string? policyOidsJson)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        TryParseOids(policyOidsJson, out var listed, out _);

        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException) { return "PolicyQualifiersJson must be a JSON object mapping policy OIDs to qualifiers."; }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return "PolicyQualifiersJson must be a JSON object mapping policy OIDs to qualifiers.";
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (OidError(prop.Name) is { } oidError)
                    return $"PolicyQualifiersJson: {oidError}";
                if (!listed.Contains(prop.Name, StringComparer.Ordinal))
                    return $"PolicyQualifiersJson has qualifiers for '{prop.Name}', which PolicyOids does not list.";
                var value = prop.Value;
                if (value.ValueKind == JsonValueKind.Null) continue;
                if (value.ValueKind != JsonValueKind.Object)
                    return $"PolicyQualifiersJson: the qualifiers for '{prop.Name}' must be an object with cpsUri, userNotice or critical.";
                foreach (var field in value.EnumerateObject())
                {
                    switch (field.Name)
                    {
                        case "cpsUri":
                        case "userNotice":
                            if (field.Value.ValueKind == JsonValueKind.Null) break;
                            if (field.Value.ValueKind != JsonValueKind.String)
                                return $"PolicyQualifiersJson: {field.Name} for '{prop.Name}' must be a string.";
                            var text = field.Value.GetString();
                            if ((field.Name == "cpsUri" ? CpsUriError(text) : UserNoticeError(text)) is { } fieldError)
                                return $"PolicyQualifiersJson ('{prop.Name}'): {fieldError}";
                            break;
                        case "critical":
                            if (field.Value.ValueKind != JsonValueKind.True && field.Value.ValueKind != JsonValueKind.False)
                                return $"PolicyQualifiersJson: critical for '{prop.Name}' must be true or false.";
                            break;
                        default:
                            return $"PolicyQualifiersJson: '{field.Name}' for '{prop.Name}' is not a recognised key; expected {string.Join(", ", QualifierKeys)} (case-sensitive).";
                    }
                }
            }
        }
        return null;
    }

    /// <summary>The first problem with the pair of fields, or null when both would build.</summary>
    public static string? Error(string? policyOidsJson, string? policyQualifiersJson) =>
        PolicyOidsError(policyOidsJson) ?? PolicyQualifiersError(policyQualifiersJson, policyOidsJson);
}
