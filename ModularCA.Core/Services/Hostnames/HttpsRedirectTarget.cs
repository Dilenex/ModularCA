using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// Where a plain-HTTP request is sent: HTTPS on a name this service is known by, never on a
/// name the request merely claimed.
/// </summary>
/// <remarks>
/// The public domain was the only trusted name until tenants got names of their own. A request
/// that arrived on a tenant's name is sent to HTTPS on that same name, because the service holds
/// a certificate for it; any other host still goes to the public domain, so the Host header
/// cannot steer a redirect anywhere the service is not. Kept free of ASP.NET types so it is
/// testable without the API project.
/// </remarks>
public static class HttpsRedirectTarget
{
    /// <summary>
    /// The absolute HTTPS URL for <paramref name="pathAndQuery"/>, on <paramref name="requestHost"/>
    /// when it is a tenant name known to <paramref name="tenantHostnames"/>, else on the configured
    /// public domain, else (public domain unset) on the request host with the HTTPS listener port.
    /// </summary>
    public static string Build(string? requestHost, string pathAndQuery, SystemConfig config, TenantHostnameCertificateCache? tenantHostnames)
    {
        var publicDomain = config.Https.PublicDomain?.Trim();
        var knownTenantName = !string.IsNullOrWhiteSpace(requestHost) && tenantHostnames?.Find(requestHost) != null ? requestHost : null;
        if (knownTenantName != null || !string.IsNullOrWhiteSpace(publicDomain))
        {
            var name = knownTenantName ?? publicDomain!;
            var port = config.Https.PublicPort ?? 443;
            var authority = port == 443 ? name : $"{name}:{port}";
            return $"https://{authority}{pathAndQuery}";
        }
        var httpsPort = config.Https.Port > 0 ? config.Https.Port : 8443;
        var hostHeader = httpsPort == 443 ? requestHost : $"{requestHost}:{httpsPort}";
        return $"https://{hostHeader}{pathAndQuery}";
    }
}
