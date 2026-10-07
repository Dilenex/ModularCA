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

        var host = ResolvePublicDomain(publicDomain, dnsSans);

        // Port 80 is the scheme default and is omitted, which keeps the URL short and matches what
        // operators expect to see in a certificate. Every other port must be present or the client
        // silently tries 80.
        return httpPort == 80 ? $"http://{host}" : $"http://{host}:{httpPort}";
    }

    /// <summary>
    /// The name clients reach this instance by: <paramref name="publicDomain"/> when given,
    /// otherwise the first <c>DNS:</c> SAN that is not <c>localhost</c>, otherwise
    /// <c>localhost</c>. The unattended bootstrap writes it to <c>Https.PublicDomain</c>, which
    /// the node refuses to start without, and builds the revocation URLs from it, so the two agree.
    /// </summary>
    public static string ResolvePublicDomain(string? publicDomain, IEnumerable<string>? dnsSans)
        => !string.IsNullOrWhiteSpace(publicDomain)
            ? publicDomain!.Trim()
            : FirstRoutableDnsSan(dnsSans) ?? "localhost";

    /// <summary>
    /// Refuses a public domain the node would refuse at startup: anything but a bare hostname or
    /// IP address, with no scheme, port or path.
    /// </summary>
    public static void EnsurePublicDomainUsable(string? publicDomain)
    {
        if (string.IsNullOrWhiteSpace(publicDomain))
            return;
        var domain = publicDomain.Trim();
        var kind = domain.Contains("://") || domain.Contains('/') ? UriHostNameType.Unknown : Uri.CheckHostName(domain);
        if (kind is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
            throw new ModularCA.Shared.Errors.InvalidRequestException(
                $"HttpsApi.PublicDomain '{domain}' must be a bare hostname or IP address, with no scheme, port or path. Example: ca.example.com",
                ModularCA.Shared.Errors.ErrorCodes.RequestInvalid);
    }

    /// <summary>
    /// The Web TLS SANs with <paramref name="publicDomain"/> added in front when no entry covers
    /// it, so the certificate is valid for the name clients are told to use. <c>localhost</c> is
    /// never added.
    /// </summary>
    public static List<string> SansCovering(string publicDomain, IEnumerable<string>? sans)
    {
        var result = (sans ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
        var domain = publicDomain.Trim();
        if (domain.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return result;
        var isIp = System.Net.IPAddress.TryParse(domain, out var address);
        var covered = result.Any(s =>
        {
            var colon = s.IndexOf(':');
            if (colon <= 0) return false;
            var type = s[..colon].Trim();
            var value = s[(colon + 1)..].Trim();
            if (isIp)
                return type.Equals("IP", StringComparison.OrdinalIgnoreCase)
                    && System.Net.IPAddress.TryParse(value, out var other) && other.Equals(address);
            return type.Equals("DNS", StringComparison.OrdinalIgnoreCase)
                && value.Equals(domain, StringComparison.OrdinalIgnoreCase);
        });
        if (!covered)
            result.Insert(0, (isIp ? "IP:" : "DNS:") + domain);
        return result;
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
