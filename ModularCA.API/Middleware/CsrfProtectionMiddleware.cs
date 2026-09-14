using System.Security.Cryptography;

namespace ModularCA.API.Middleware;

/// <summary>
/// Double-submit cookie CSRF protection for unauthenticated endpoints (setup wizard, public forms).
/// JWT-authenticated endpoints are inherently CSRF-safe because the Authorization header
/// isn't auto-sent by browsers. This middleware protects endpoints that don't use JWT.
///
/// Flow:
/// 1. On any GET request, sets a CSRF-TOKEN cookie with a random value (if not already set)
/// 2. On POST/PUT/DELETE to protected paths, validates that X-CSRF-Token header matches the cookie
/// 3. SPAs read the cookie via JavaScript and include the header on mutations
/// </summary>
public class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private const string CookieName = "CSRF-TOKEN";
    private const string HeaderName = "X-CSRF-Token";

    /// <summary>
    /// Paths that require CSRF validation on POST/PUT/DELETE.
    /// JWT-authenticated paths don't need this — the Bearer token provides CSRF protection.
    /// /api/v1/setup/ is included — setup initialize has CSRF protection.
    /// </summary>
    /// <summary>
    /// State-changing paths that require the double-submit token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything here is reachable with ambient browser authority — a session cookie, or in the
    /// setup wizard's case a first-run surface a browser can be walked into. That is what CSRF
    /// defends against, and it is the test for belonging on this list.
    /// </para>
    /// <para>
    /// <c>/api/v1/public/enroll</c> used to be here and is not, deliberately. It carries no ambient
    /// authority of any kind: the request is anonymous, and the only thing authorising it is a
    /// high-entropy enrollment token in the URL path. An attacker who could forge a cross-site POST
    /// to it would need that token, and anyone holding the token can simply enroll directly — so
    /// the protection defended nothing, while making the endpoint unusable by exactly the clients
    /// it exists for. A device following a QR code, or a scripted enrollment, had to GET the page
    /// first purely to collect a cookie, and got a 403 reading "CSRF validation failed" if it did
    /// not — which reads as an authentication problem and is not one.
    /// </para>
    /// <para>
    /// The token remains single-use or use-limited, expiring, and bound to a CA and profile. That
    /// is the control on this endpoint; CSRF never was.
    /// </para>
    /// </remarks>
    private static readonly string[] ProtectedPaths =
    {
        "/api/v1/setup/",
        "/api/v1/auth/login",
        "/api/v1/auth/cert-login",
        "/api/v1/auth/change-password",
    };

    public CsrfProtectionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        var method = context.Request.Method;

        // Short-URL normalization: AuthController/TotpController/WebAuthnController/
        // MtlsController are all registered at both [Route("api/v1/auth")] and
        // [Route("auth")]. Treat /auth/* as /api/v1/auth/* for the allow-list lookup
        // so CSRF validation can't be bypassed via the short-URL twin.
        var normalizedPath = NormalizeAuthPath(path);

        // Issue CSRF token cookie on any request if not already set
        if (!context.Request.Cookies.ContainsKey(CookieName))
        {
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            context.Response.Cookies.Append(CookieName, token, new CookieOptions
            {
                HttpOnly = false, // JS must read this to send in header
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = TimeSpan.FromHours(4),
            });
        }

        // Validate CSRF on state-changing requests to protected paths
        if (method is "POST" or "PUT" or "DELETE")
        {
            var isProtected = ProtectedPaths.Any(p =>
                normalizedPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

            if (isProtected)
            {
                var cookieToken = context.Request.Cookies[CookieName];
                var headerToken = context.Request.Headers[HeaderName].FirstOrDefault();

                if (string.IsNullOrEmpty(cookieToken) ||
                    string.IsNullOrEmpty(headerToken) ||
                    !string.Equals(cookieToken, headerToken, StringComparison.Ordinal))
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        "{\"error\":\"CSRF validation failed. Include the X-CSRF-Token header matching the CSRF-TOKEN cookie.\"}");
                    return;
                }
            }
        }

        await _next(context);
    }

    /// <summary>
    /// Maps the short-URL <c>/auth/*</c> alias to the canonical <c>/api/v1/auth/*</c>
    /// path so CSRF allow-list lookups match regardless of which route shape the
    /// client used. The auth controllers carry both <c>[Route("api/v1/auth")]</c>
    /// and <c>[Route("auth")]</c>, and without this normalization an attacker could
    /// call <c>/auth/login</c> to sidestep the double-submit-cookie check.
    /// </summary>
    private static string NormalizeAuthPath(string path)
    {
        if (path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase))
            return "/api/v1" + path;
        return path;
    }
}
