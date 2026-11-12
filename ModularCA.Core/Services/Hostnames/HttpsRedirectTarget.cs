using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// Where a plain-HTTP request is sent: HTTPS on the instance's public domain, never on a name
/// the request merely claimed. Kept free of ASP.NET types so it is testable without the API
/// project.
/// </summary>
public static class HttpsRedirectTarget
{
    /// <summary>
    /// The absolute HTTPS URL for <paramref name="pathAndQuery"/> on the configured public domain,
    /// or, when the public domain is unset, on <paramref name="requestHost"/>. The port is the
    /// public HTTPS port in both cases (<see cref="HttpsConfig.GetPublicHttpsPort"/>:
    /// <c>PublicPort</c>, else the listener port), the same rule as
    /// <see cref="HttpsConfig.GetPublicHttpsBaseUrl"/>, so a redirect lands on the origin every
    /// other link of this instance names.
    /// </summary>
    /// <param name="requestHost">The host the request named, used only when no public domain is configured.</param>
    /// <param name="pathAndQuery">The path and query string to keep, or empty for the origin alone.</param>
    /// <param name="config">The system configuration.</param>
    public static string Build(string? requestHost, string pathAndQuery, SystemConfig config)
    {
        var publicDomain = config.Https.PublicDomain?.Trim();
        var host = !string.IsNullOrWhiteSpace(publicDomain) ? publicDomain : requestHost ?? string.Empty;
        return $"https://{config.Https.GetHttpsAuthorityFor(host)}{pathAndQuery}";
    }
}
