using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// Decides which name to advertise in URLs that point back at this service. The instance is
/// known by its configured public domain (<c>Https.PublicDomain</c>); a request's Host header or
/// a service principal's host is used only when it is that name, and anything else falls back
/// to the public domain, so an arbitrary Host header can never steer a client somewhere else.
/// </summary>
public interface IPublicNameResolver
{
    /// <summary>
    /// The known name <paramref name="host"/> is, lower-case without trailing dot, or null when
    /// it is not the instance's public domain.
    /// </summary>
    string? Resolve(string? host);

    /// <summary>
    /// The HTTPS base URL (no trailing slash) to advertise to a client whose request arrived on
    /// <paramref name="requestHost"/>: that host when it is known, else the public one.
    /// </summary>
    string BaseUrlForRequest(string? requestHost);

    /// <summary>
    /// The HTTPS base URL derived from a realm binding's service principal (<c>HTTP/host</c>): the
    /// principal's host when it is known, else the public one. For callers that have no request,
    /// such as readiness and the setup kit.
    /// </summary>
    string BaseUrlForServicePrincipal(string? servicePrincipal);

    /// <summary>The HTTPS base URL for a known name, with the public port rule; the public base URL when null.</summary>
    string BaseUrl(string? knownHost);
}

/// <summary>Resolves names against <c>Https.PublicDomain</c>.</summary>
public sealed class PublicNameResolver(SystemConfig config) : IPublicNameResolver
{
    /// <summary>
    /// The host part of a Kerberos service principal such as <c>HTTP/ca.example.test</c> or
    /// <c>HTTP/ca.example.test@REALM</c>, lower-case without trailing dot; null when there is none.
    /// </summary>
    public static string? HostFromServicePrincipal(string? servicePrincipal)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipal)) return null;
        var spn = servicePrincipal.Trim();
        var slash = spn.IndexOf('/');
        var host = slash >= 0 ? spn[(slash + 1)..] : spn;
        var at = host.IndexOf('@');
        if (at >= 0) host = host[..at];
        // A port suffix (HTTP/host:8443) is legal in an SPN; the name is what matters here.
        var colon = host.IndexOf(':');
        if (colon >= 0) host = host[..colon];
        return Normalize(host);
    }

    /// <summary>Lower-cases and strips the trailing dot; null for blank input.</summary>
    public static string? Normalize(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        return h.Length == 0 ? null : h;
    }

    /// <inheritdoc />
    public string? Resolve(string? host)
    {
        var h = Normalize(host);
        if (h == null) return null;
        var publicDomain = Normalize(config.Https.PublicDomain);
        return publicDomain != null && string.Equals(h, publicDomain, StringComparison.Ordinal) ? publicDomain : null;
    }

    /// <inheritdoc />
    public string BaseUrlForRequest(string? requestHost) => BaseUrl(Resolve(requestHost));

    /// <inheritdoc />
    public string BaseUrlForServicePrincipal(string? servicePrincipal)
        => BaseUrl(Resolve(HostFromServicePrincipal(servicePrincipal)));

    /// <inheritdoc />
    public string BaseUrl(string? knownHost)
        => string.IsNullOrWhiteSpace(knownHost) ? config.Https.GetPublicHttpsBaseUrl() : config.Https.GetHttpsBaseUrlFor(knownHost);
}
