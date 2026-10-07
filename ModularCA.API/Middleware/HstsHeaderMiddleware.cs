using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Middleware;

/// <summary>
/// Sets <c>Strict-Transport-Security</c> on HTTPS requests where ASP.NET Core's <c>UseHsts</c>
/// did, which it replaces: at the top of the pipeline, so a request the ingress proxies carries
/// it too, and never for a loopback host name. <c>UseHsts</c> fixed the value at start; this
/// reads <see cref="HstsConfig"/> on every request, so a saved change applies to the next one.
/// </summary>
public class HstsHeaderMiddleware
{
    private static readonly string[] ExcludedHosts = { "localhost", "127.0.0.1", "[::1]" };

    private readonly RequestDelegate _next;
    private readonly SystemConfig _config;

    /// <summary>
    /// Initializes a new <see cref="HstsHeaderMiddleware"/>.
    /// </summary>
    /// <param name="next">The next delegate in the pipeline.</param>
    /// <param name="config">System configuration holding the HSTS settings.</param>
    public HstsHeaderMiddleware(RequestDelegate next, SystemConfig config)
    {
        _next = next;
        _config = config;
    }

    /// <summary>
    /// Sets the header from the HSTS settings as they stand now, then invokes the next delegate.
    /// </summary>
    public Task InvokeAsync(HttpContext context)
    {
        if (context.Request.IsHttps && !IsExcluded(context.Request.Host.Host))
            context.Response.Headers.StrictTransportSecurity = (_config.Http.Hsts ?? new HstsConfig()).HeaderValue();
        return _next(context);
    }

    private static bool IsExcluded(string host)
    {
        foreach (var excluded in ExcludedHosts)
        {
            if (string.Equals(host, excluded, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
