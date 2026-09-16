using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Middleware;

/// <summary>
/// Adds security headers to every HTTP response to protect against common web
/// attacks (XSS, clickjacking, MIME sniffing, referer leakage, powerful-feature
/// abuse) and, on HTTPS responses, enforces Strict-Transport-Security.
/// <para>
/// CSP is hardened with <c>frame-ancestors 'none'</c>,
/// <c>base-uri 'self'</c>, <c>form-action 'self'</c>, <c>object-src 'none'</c>,
/// and a <c>report-uri</c> pointing at the public CSP-report endpoint.
/// <c>style-src 'unsafe-inline'</c> is retained because the admin SPA currently
/// emits inline <c>style=</c> attributes in several pages — the nonce/hash
/// migration is a frontend-only refactor tracked separately.
/// </para>
/// <para>
/// HSTS is now emitted only on HTTPS responses (RFC 6797
/// §7.2 requires UAs to ignore HSTS over plain HTTP, so advertising it on the
/// plain-HTTP PKI listener is pure noise). <c>max-age</c>,
/// <c>includeSubDomains</c>, and <c>preload</c> are configurable via
/// <see cref="HstsConfig"/>.
/// </para>
/// <para>
/// Sensitive auth/admin/user/setup paths get
/// <c>Cache-Control: no-store, no-cache, must-revalidate</c> plus legacy
/// <c>Pragma: no-cache</c>. Static hashed assets under <c>/admin/assets/</c>
/// and <c>/user/assets/</c> retain their default cacheability.
/// </para>
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SystemConfig _config;

    private static readonly string[] NoStorePrefixes = new[]
    {
        "/api/v1/auth/",
        "/admin/",
        "/user/",
        "/login",
        "/banner",
        "/mfa-",
        "/setup/",
        "/api/v1/admin/",
        "/api/v1/user/",
        "/api/v1/setup/",
    };

    private static readonly string[] CacheableAssetPrefixes = new[]
    {
        "/admin/assets/",
        "/user/assets/",
        "/setup/assets/",
    };

    /// <summary>
    /// Initializes a new <see cref="SecurityHeadersMiddleware"/>.
    /// </summary>
    /// <param name="next">The next delegate in the pipeline.</param>
    /// <param name="config">System configuration used for HSTS tuning.</param>
    public SecurityHeadersMiddleware(RequestDelegate next, SystemConfig config)
    {
        _next = next;
        _config = config;
    }

    /// <summary>
    /// Writes the security headers on response start and then invokes the next
    /// delegate. Header evaluation is deferred until <c>OnStarting</c> so a
    /// downstream controller cannot clobber them.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers.TryAdd("X-Content-Type-Options", "nosniff");
            headers.TryAdd("X-Frame-Options", "DENY");
            headers.TryAdd("X-XSS-Protection", "0"); // Modern best practice: disable, rely on CSP
            headers.TryAdd("Referrer-Policy", "strict-origin-when-cross-origin");

            // CSP with frame-ancestors/base-uri/form-action/object-src
            // and a report-uri pointing at the public CSP-report stub
            // (/api/v1/public/csp-report, added in PublicController). style-src
            // keeps 'unsafe-inline' until the admin SPA migrates to nonce/hash.
            headers.TryAdd(
                "Content-Security-Policy",
                "default-src 'self'; " +
                "script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data:; " +
                "connect-src 'self'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self'; " +
                "form-action 'self'; " +
                "object-src 'none'; " +
                "report-uri /api/v1/public/csp-report");

            // HSTS only on HTTPS. RFC 6797 §7.2 says UAs MUST
            // ignore HSTS over plain HTTP, so emitting it on the CRL/OCSP listener
            // is wasted work and muddies the listener posture audit.
            if (context.Request.IsHttps)
            {
                var hsts = _config.Http.Hsts ?? new HstsConfig();
                if (hsts.MaxAgeSeconds > 0)
                {
                    var value = $"max-age={hsts.MaxAgeSeconds}";
                    if (hsts.IncludeSubDomains) value += "; includeSubDomains";
                    if (hsts.Preload) value += "; preload";
                    headers.TryAdd("Strict-Transport-Security", value);
                }
            }

            headers.TryAdd("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

            // Auth/admin/user/setup paths must not be cached by
            // browsers or intermediaries. Static hashed assets under
            // /admin/assets/ etc. are exempted so SPA bundles still cache.
            // Short-URL normalization: /auth/* is a route alias for /api/v1/auth/*
            // exposed by the auth controllers, so it must hit the same no-store
            // rule as the canonical path.
            var path = NormalizeAuthPath(context.Request.Path.Value ?? string.Empty);
            if (IsSensitivePath(path) && !IsCacheableAsset(path))
            {
                headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
                headers["Pragma"] = "no-cache";
                headers["Expires"] = "0";
            }

            // Remove Server header to avoid technology disclosure
            headers.Remove("Server");
            return Task.CompletedTask;
        });
        await _next(context);
    }

    private static bool IsSensitivePath(string path)
    {
        foreach (var prefix in NoStorePrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool IsCacheableAsset(string path)
    {
        foreach (var prefix in CacheableAssetPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Maps the short-URL <c>/auth/*</c> alias to the canonical
    /// <c>/api/v1/auth/*</c> path so cache-control classification matches
    /// regardless of which route shape the client used.
    /// </summary>
    private static string NormalizeAuthPath(string path)
    {
        if (path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase))
            return "/api/v1" + path;
        return path;
    }
}
