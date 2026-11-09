using System.Security.Cryptography;

namespace ModularCA.API.Middleware;

/// <summary>
/// Double-submit cookie CSRF protection for unauthenticated endpoints (setup wizard, public forms).
/// JWT-authenticated endpoints are inherently CSRF-safe because the Authorization header
/// isn't auto-sent by browsers. This middleware protects endpoints that don't use JWT.
///
/// Flow:
/// 1. On any request, sets the token cookie with a random value (if not already set)
/// 2. On POST/PUT/DELETE to protected paths, validates that X-CSRF-Token header matches the cookie
/// 3. SPAs read the cookie via JavaScript and include the header on mutations
///
/// Over HTTPS the cookie is <c>__Host-CSRF-TOKEN</c>: the prefix makes the browser refuse it unless
/// it is Secure, host-only and on <c>/</c>, so a sibling subdomain cannot plant a token of its own
/// (cookie tossing). Plain HTTP (development) keeps <c>CSRF-TOKEN</c>, since a browser drops a
/// <c>__Host-</c> cookie that is not Secure. On HTTPS a leftover <c>CSRF-TOKEN</c> from an older
/// release is deleted and never accepted.
/// </summary>
public class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>The token cookie on HTTPS.</summary>
    internal const string SecureCookieName = "__Host-CSRF-TOKEN";

    /// <summary>The token cookie on plain HTTP, and the name used before 0.4.3.</summary>
    internal const string PlainCookieName = "CSRF-TOKEN";

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

    /// <summary>
    /// Issues the token cookie for the request's scheme when it is missing, drops a legacy
    /// unprefixed cookie on HTTPS, and refuses a state-changing request to a protected path with 403
    /// unless its <c>X-CSRF-Token</c> header equals that cookie.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        var method = context.Request.Method;

        // Short-URL normalization: AuthController/TotpController/WebAuthnController/
        // MtlsController are all registered at both [Route("api/v1/auth")] and
        // [Route("auth")]. Treat /auth/* as /api/v1/auth/* for the allow-list lookup
        // so CSRF validation can't be bypassed via the short-URL twin.
        var normalizedPath = NormalizeAuthPath(path);

        var cookieName = CookieNameFor(context.Request.IsHttps);

        // Issue CSRF token cookie on any request if not already set
        if (!context.Request.Cookies.ContainsKey(cookieName))
        {
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            context.Response.Cookies.Append(cookieName, token, new CookieOptions
            {
                HttpOnly = false, // JS must read this to send in header
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = TimeSpan.FromHours(4),
            });
        }

        // An older release's unprefixed cookie would shadow the new one in clients that read the
        // first match; it is never accepted on HTTPS, so drop it.
        if (context.Request.IsHttps && context.Request.Cookies.ContainsKey(PlainCookieName))
            context.Response.Cookies.Delete(PlainCookieName, new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Strict });

        // Validate CSRF on state-changing requests to protected paths
        if (method is "POST" or "PUT" or "DELETE")
        {
            var isProtected = ProtectedPaths.Any(p =>
                normalizedPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

            if (isProtected)
            {
                var cookieToken = context.Request.Cookies[cookieName];
                var headerToken = context.Request.Headers[HeaderName].FirstOrDefault();

                if (string.IsNullOrEmpty(cookieToken) ||
                    string.IsNullOrEmpty(headerToken) ||
                    !string.Equals(cookieToken, headerToken, StringComparison.Ordinal))
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        $"{{\"error\":\"CSRF validation failed. Include the X-CSRF-Token header matching the {cookieName} cookie.\"}}");
                    return;
                }
            }
        }

        await _next(context);
    }

    /// <summary>
    /// The token cookie's name for a request: <see cref="SecureCookieName"/> over HTTPS,
    /// <see cref="PlainCookieName"/> over plain HTTP.
    /// </summary>
    internal static string CookieNameFor(bool isHttps) => isHttps ? SecureCookieName : PlainCookieName;

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
