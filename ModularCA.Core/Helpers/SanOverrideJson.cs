using System.Text.Json;
using ModularCA.Shared.Models.Csr;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The stored form of a request's SAN overrides (<c>CertRequestEntity.SanOverrides</c>): a JSON
/// array of <c>TYPE:value</c> strings, the same form as <c>SubjectAlternativeNames</c>, which the
/// certificate builder reads. CSR upload writes it from the request's <see cref="SanOverride"/>
/// objects and reissue writes it from its SAN list; issuance reads it.
/// </summary>
/// <remarks>
/// Upload used to store the objects themselves (<c>[{"Type":"DNS","Value":"a.example"}]</c>), which
/// issuance, reading a list of strings, could not parse and so ignored: overrides set at upload
/// never reached the certificate. <see cref="Read"/> still accepts that form so rows stored before
/// the fix take effect.
/// </remarks>
public static class SanOverrideJson
{
    /// <summary>One override as a stored entry: the type upper-cased, both parts trimmed.</summary>
    public static string Format(string type, string value) => $"{type.Trim().ToUpperInvariant()}:{value.Trim()}";

    /// <summary>The stored form of <paramref name="overrides"/>.</summary>
    public static string Serialize(IEnumerable<SanOverride> overrides)
        => JsonSerializer.Serialize(overrides.Select(o => Format(o.Type ?? string.Empty, o.Value ?? string.Empty)).ToList());

    /// <summary>
    /// The overrides in <paramref name="json"/> as <c>TYPE:value</c> entries, from the stored form
    /// or the legacy array of <c>{Type, Value}</c> objects (property names in any case). Null when
    /// <paramref name="json"/> is blank, not a JSON array, or holds anything else, so the caller
    /// keeps the request's own SANs.
    /// </summary>
    public static List<string>? Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                return null;
            var entries = new List<string>();
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.String)
                    entries.Add(element.GetString()!);
                else if (element.ValueKind == JsonValueKind.Object
                    && Property(element, "Type") is string type && Property(element, "Value") is string value)
                    entries.Add(Format(type, value));
                else
                    return null;
            }
            return entries;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Property(JsonElement element, string name)
    {
        foreach (var property in element.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                return property.Value.GetString();
        return null;
    }
}
