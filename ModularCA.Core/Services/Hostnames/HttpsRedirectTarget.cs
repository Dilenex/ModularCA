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
    /// The absolute HTTPS URL for <paramref name="pathAndQuery"/> on the configured public domain
    /// with the public port rule, or, when the public domain is unset, on
    /// <paramref name="requestHost"/> with the HTTPS listener port.
    /// </summary>
    public static string Build(string? requestHost, string pathAndQuery, SystemConfig config)
    {
        var publicDomain = config.Https.PublicDomain?.Trim();
        if (!string.IsNullOrWhiteSpace(publicDomain))
        {
            var port = config.Https.PublicPort ?? 443;
            var authority = port == 443 ? publicDomain : $"{publicDomain}:{port}";
            return $"https://{authority}{pathAndQuery}";
        }
        var httpsPort = config.Https.Port > 0 ? config.Https.Port : 8443;
        var hostHeader = httpsPort == 443 ? requestHost : $"{requestHost}:{httpsPort}";
        return $"https://{hostHeader}{pathAndQuery}";
    }
}
