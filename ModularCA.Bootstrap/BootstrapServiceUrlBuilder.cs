namespace ModularCA.Bootstrap;

/// <summary>
/// Builds the public base URL that AIA, CDP and OCSP URLs are hung off during bootstrap.
/// </summary>
/// <remarks>
/// <para>
/// The CLI and the setup wizard each derived this independently and each got it wrong, in
/// different ways, so every certificate either install produced carried a revocation URL that
/// nothing answered:
/// </para>
/// <list type="bullet">
/// <item><description>
/// The CLI used <c>"http://localhost:" + HttpsApi.Port</c> — plaintext HTTP aimed at the
/// <em>TLS</em> port — while writing <c>httpPort: 8080</c> into config.yaml six lines later and
/// never referring to it again.
/// </description></item>
/// <item><description>
/// Both dropped the port entirely on the DNS-SAN branch, yielding port 80 against a listener on
/// 8080.
/// </description></item>
/// <item><description>
/// The wizard offers "set to 0 to disable" for the HTTP port and Kestrel honours it, but the URL
/// was still built as <c>http://{domain}:{port}</c> — producing a literal <c>:0</c>.
/// </description></item>
/// </list>
/// <para>
/// A certificate's CDP and AIA are fixed at signing and cannot be corrected afterwards, so this
/// is one of the few bootstrap decisions with no second chance. Both callers now share this
/// method: the scheme, the port and the disabled case are decided once.
/// </para>
/// <para>
/// The scheme is always plain HTTP. Serving a CRL or OCSP response over HTTPS makes revocation
/// checking depend on a certificate whose own revocation status is what the client is trying to
/// establish; RFC 5280 §4.2.1.13 and the CA/Browser Forum baseline requirements both assume an
/// HTTP distribution point for exactly that reason.
/// </para>
/// </remarks>
public static class BootstrapServiceUrlBuilder
{
    /// <summary>
    /// Resolves the base URL for revocation and issuer-certificate distribution.
    /// </summary>
    /// <param name="publicDomain">
    /// Operator-supplied public domain. Takes precedence over <paramref name="dnsSans"/> when set.
    /// </param>
    /// <param name="dnsSans">
    /// The web TLS certificate's SAN entries, typed as <c>"DNS:host"</c>. The first non-localhost
    /// DNS entry is used when no public domain was given.
    /// </param>
    /// <param name="httpPort">
    /// The public-facing plain-HTTP port. Zero or negative means HTTP is disabled.
    /// </param>
    /// <returns>
    /// The base URL, or <see langword="null"/> when plain HTTP is disabled — in which case no
    /// CDP/AIA/OCSP URL can be published and the caller must seed none. A certificate carrying no
    /// CDP is honest about having no reachable revocation endpoint; one carrying an unreachable
    /// CDP fails revocation checks at every relying party instead.
    /// </returns>
    public static string? Build(string? publicDomain, IEnumerable<string>? dnsSans, int httpPort)
    {
        if (httpPort <= 0)
            return null;

        var host = !string.IsNullOrWhiteSpace(publicDomain)
            ? publicDomain!.Trim()
            : FirstRoutableDnsSan(dnsSans) ?? "localhost";

        // Port 80 is the scheme default and is omitted, which keeps the URL short and matches what
        // operators expect to see in a certificate. Every other port must be present or the client
        // silently tries 80.
        return httpPort == 80 ? $"http://{host}" : $"http://{host}:{httpPort}";
    }

    /// <summary>
    /// Returns the first <c>DNS:</c> SAN that is not <c>localhost</c>, or null when there is none.
    /// </summary>
    private static string? FirstRoutableDnsSan(IEnumerable<string>? sans)
        => sans?
            .Where(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Substring(4).Trim())
            .FirstOrDefault(s => !string.IsNullOrEmpty(s)
                && !s.Equals("localhost", StringComparison.OrdinalIgnoreCase));
}
