namespace ModularCA.Shared.Utils;

/// <summary>
/// Resolves a configured subdomain setting to the fully-qualified hostname the TLS layer compares
/// against.
/// </summary>
/// <remarks>
/// Subdomain settings accept two forms because operators write both: a short prefix
/// (<c>"mtls"</c>, <c>"est"</c>) that is completed from <c>Https.PublicDomain</c>, and a complete
/// FQDN (<c>"mtls.ca.example.com"</c>) for deployments whose enrollment hostname does not sit under
/// the portal's domain.
///
/// This existed as four near-identical inline copies — two in <c>MtlsController</c>, one in the
/// Kestrel SNI setup, and the EST gate would have been a fifth. They already differed in whether
/// they trimmed <c>PublicDomain</c>. A drift between the copy that decides which hostname gets a
/// CertificateRequest and the copy that tells the user which hostname to visit produces a page that
/// sends clients to a name the handshake does not gate, and nothing reports it.
/// </remarks>
public static class SubdomainUtil
{
    /// <summary>
    /// Resolves a subdomain setting to an FQDN.
    /// </summary>
    /// <param name="configured">The configured value: a short prefix or a complete FQDN.</param>
    /// <param name="publicDomain">The portal's public domain, used to complete a short prefix.</param>
    /// <returns>
    /// The resolved FQDN, or null when nothing is configured. A short prefix with no public domain
    /// to complete it resolves to the bare prefix — which is what the previous inline copies did,
    /// and is meaningful for a single-label internal hostname.
    /// </returns>
    public static string? ResolveFqdn(string? configured, string? publicDomain)
    {
        if (string.IsNullOrWhiteSpace(configured))
            return null;

        var raw = configured.Trim();
        if (raw.Contains('.'))
            return raw;

        return string.IsNullOrWhiteSpace(publicDomain)
            ? raw
            : $"{raw}.{publicDomain.Trim()}";
    }

    /// <summary>
    /// Determines whether a TLS ClientHello server name matches a resolved subdomain FQDN.
    /// </summary>
    /// <remarks>
    /// Hostname comparison is case-insensitive (RFC 4343), and a client that sends no SNI at all —
    /// an IP-address connection, or an old client — matches nothing. Both matter at the handshake:
    /// a case-sensitive compare silently withholds the CertificateRequest from a client that
    /// capitalised the hostname, and the failure surfaces as an authentication error rather than a
    /// hostname one.
    /// </remarks>
    public static bool MatchesSni(string? serverName, string? resolvedFqdn) =>
        !string.IsNullOrEmpty(resolvedFqdn)
        && !string.IsNullOrEmpty(serverName)
        && string.Equals(serverName, resolvedFqdn, StringComparison.OrdinalIgnoreCase);
}
