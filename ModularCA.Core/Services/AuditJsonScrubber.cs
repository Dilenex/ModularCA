using System.Text.Json;
using System.Text.Json.Nodes;

namespace ModularCA.Core.Services;

/// <summary>
/// Defence-in-depth scrubber applied by <see cref="AuditService.LogAsync"/>
/// to every serialized <c>DetailsJson</c> blob before it reaches the audit database. Walks the
/// parsed <see cref="JsonNode"/> tree and replaces the value of any property whose name matches
/// a sensitive pattern (case-insensitive substring match against <see cref="SensitiveNameTokens"/>)
/// with the literal string <c>"***"</c>.
///
/// This is unconditionally applied regardless of caller diligence — the controller-level
/// allowlist projection (used by <c>AdminConfigController.UpdateEmail</c> / <c>UpdateLdapAuth</c>)
/// is the first line of defence, but any future call site that forgets to project a safe
/// subset still lands a redacted row. Latent risk of plaintext secret exposure is bounded
/// even if a new field is added mid-refactor.
/// </summary>
public static class AuditJsonScrubber
{
    /// <summary>
    /// Case-insensitive substrings that mark a property name as carrying sensitive material.
    /// Matches are substring-based (so <c>bindPassword</c>, <c>oauth2ClientSecret</c>, and
    /// <c>PrivateKeyDer</c> all hit). The set is intentionally conservative: false positives
    /// just lose diagnostic value in an audit row, false negatives leak secrets.
    /// </summary>
    private static readonly string[] SensitiveNameTokens = new[]
    {
        "password",
        "keytab",
        "secret",
        "token",
        "key",
        "hmac",
        "otp",
        "seed",
        "pin",
        "passphrase",
        "credential",
    };

    /// <summary>
    /// Serializes <paramref name="details"/> to JSON and scrubs any sensitive fields in the
    /// result. Returns <c>null</c> if <paramref name="details"/> is null. Never throws —
    /// malformed or cyclic values fall back to the plain <see cref="JsonSerializer.Serialize(object?, JsonSerializerOptions?)"/>
    /// string so the audit row is still written, just without redaction.
    /// </summary>
    public static string? SerializeAndScrub(object? details)
    {
        if (details == null) return null;
        string raw;
        try
        {
            raw = JsonSerializer.Serialize(details);
        }
        catch
        {
            return null;
        }

        return ScrubJsonString(raw);
    }

    /// <summary>
    /// Parses <paramref name="json"/> and scrubs sensitive properties in place. Returns the
    /// scrubbed JSON string on success, or the original string unchanged if parsing fails
    /// (e.g. the caller serialized a raw non-JSON value). Never throws.
    /// </summary>
    public static string ScrubJsonString(string json)
    {
        if (string.IsNullOrEmpty(json)) return json;
        try
        {
            var node = JsonNode.Parse(json);
            if (node == null) return json;
            ScrubNode(node);
            return node.ToJsonString();
        }
        catch
        {
            return json;
        }
    }

    /// <summary>
    /// Recursively walks a JSON node tree and replaces any sensitive-named property values
    /// with the literal <c>"***"</c>. Arrays are traversed element-by-element; primitive leaves
    /// are left alone when their parent property name is not sensitive.
    /// </summary>
    private static void ScrubNode(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                {
                    // Collect keys first — we're going to mutate obj during iteration.
                    var keys = obj.Select(kv => kv.Key).ToList();
                    foreach (var key in keys)
                    {
                        if (IsSensitiveName(key))
                        {
                            var existing = obj[key];
                            // Preserve null as null (a null secret is still "nothing to leak").
                            obj[key] = existing == null ? null : JsonValue.Create("***");
                        }
                        else
                        {
                            var child = obj[key];
                            if (child != null)
                                ScrubNode(child);
                        }
                    }
                    break;
                }
            case JsonArray arr:
                {
                    foreach (var child in arr)
                    {
                        if (child != null)
                            ScrubNode(child);
                    }
                    break;
                }
            // JsonValue leaf: nothing to do at this level — redaction is decided by the parent
            // property name, not the value shape.
            default:
                break;
        }
    }

    /// <summary>
    /// Returns true if <paramref name="name"/> contains any of the sensitive tokens using an
    /// ordinal case-insensitive substring match. Keeps the rule simple: a property named
    /// <c>bindPassword</c>, <c>BindPassword</c>, <c>OAuth2ClientSecret</c>, or <c>privateKey</c>
    /// all match.
    /// </summary>
    private static bool IsSensitiveName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        foreach (var token in SensitiveNameTokens)
        {
            if (name.Contains(token, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
