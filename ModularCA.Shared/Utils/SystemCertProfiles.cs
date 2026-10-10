namespace ModularCA.Shared.Utils;

/// <summary>
/// The certificate profiles the application finds by name. Each is seeded at bootstrap and
/// looked up again whenever the thing it serves is issued, so its name, its kind and its
/// instance-wide scope are fixed: <c>CertProfileService</c> refuses to rename, delete, rebind
/// or turn one into a profile of the other kind.
/// </summary>
public static class SystemCertProfiles
{
    /// <summary>Default profile of a CA's timestamp signer.</summary>
    public const string Tsa = "TSA Certificate Profile";

    /// <summary>Default profile of a CA's delegated OCSP responder.</summary>
    public const string OcspResponder = "OCSP Responder Certificate Profile";

    /// <summary>Default profile of a CA's CMP message signer.</summary>
    public const string CmpSigner = "CMP Signer Certificate Profile";

    /// <summary>Profile of the console's own TLS certificate, issued and renewed by the instance.</summary>
    public const string WebTls = "Web TLS Certificate Profile";

    /// <summary>Profile a new CA certificate is issued under when the request names none.</summary>
    public const string MainCa = "Main CA Certificate Profile";

    private static readonly Dictionary<string, string> Purposes = new(StringComparer.Ordinal)
    {
        [Tsa] = "every CA issues its timestamp signer from it unless the CA names another profile",
        [OcspResponder] = "every CA issues its OCSP responder from it unless the CA names another profile",
        [CmpSigner] = "every CA issues its CMP signer from it unless the CA names another profile",
        [WebTls] = "the console's own TLS certificate is issued and renewed from it",
        [MainCa] = "a new CA certificate is issued from it when no CA profile is chosen",
    };

    /// <summary>Whether <paramref name="name"/> is one of the profiles found by name.</summary>
    public static bool IsNameBound(string? name) => name != null && Purposes.ContainsKey(name);

    /// <summary>What the application uses the profile named <paramref name="name"/> for, or null when it is not found by name.</summary>
    public static string? PurposeOf(string? name) => name != null && Purposes.TryGetValue(name, out var purpose) ? purpose : null;
}
