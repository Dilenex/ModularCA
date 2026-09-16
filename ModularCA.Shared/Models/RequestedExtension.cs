using System.Text.Json;

namespace ModularCA.Shared.Models;

/// <summary>
/// An X.509 extension a certificate request asks to have stamped on the issued certificate,
/// beyond what the certificate and signing profiles produce.
/// </summary>
/// <remarks>
/// Persisted as JSON on <see cref="Entities.CertRequestEntity.AdditionalExtensions"/> so that a
/// request issued later, after approval, still carries it. The builder refuses any OID the
/// profiles govern (key usage, EKU, SAN, basic constraints, and so on); this is for identifiers
/// an enrollment protocol must echo, such as the Windows Certificate Template Information
/// extension that lets a client match a certificate to the template it came from.
/// </remarks>
/// <param name="Oid">Dotted-decimal extension OID.</param>
/// <param name="Critical">Whether the extension is marked critical.</param>
/// <param name="ValueBase64">The DER-encoded extnValue content (the bytes inside the OCTET STRING), base64.</param>
public sealed record RequestedExtension(string Oid, bool Critical, string ValueBase64)
{
    /// <summary>Serialises a list for the request row; null for an empty list.</summary>
    public static string? ToJson(IReadOnlyCollection<RequestedExtension>? extensions)
        => extensions == null || extensions.Count == 0 ? null : JsonSerializer.Serialize(extensions);

    /// <summary>Reads a request row's list; empty for null or blank.</summary>
    public static IReadOnlyList<RequestedExtension> FromJson(string? json)
        => string.IsNullOrWhiteSpace(json)
            ? []
            : JsonSerializer.Deserialize<List<RequestedExtension>>(json) ?? [];

    /// <summary>The DER extnValue bytes.</summary>
    public byte[] Value => Convert.FromBase64String(ValueBase64);
}
