namespace ModularCA.API.Middleware;

/// <summary>
/// Blocks all API access for users who haven't completed MFA enrollment.
/// Only allows MFA setup endpoints (TOTP, WebAuthn, mTLS enrollment), step-up verification,
/// logout, and token refresh. When the JWT contains an <c>mfa_setup_required</c> claim, all
/// other API endpoints return 403. Both the legacy <c>/api/v1/auth/*</c> and the short-URL
/// <c>/auth/*</c> variants are allowed so the frontend's migrated call sites don't deadlock
/// users in setup mode.
/// </summary>
public class MfaEnrollmentMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Paths that are allowed even when the <c>mfa_setup_required</c> claim is present.
    /// These cover MFA enrollment (TOTP, WebAuthn, mTLS), step-up verification, logout,
    /// and token refresh so the user can complete setup.
    /// </summary>
    private static readonly string[] AllowedPaths =
    {
        "/api/v1/auth/totp/",
        "/api/v1/auth/webauthn/",
        "/api/v1/auth/mtls/",
        "/api/v1/auth/mfa/",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        "/auth/totp/",
        "/auth/webauthn/",
        "/auth/mtls/",
        "/auth/mfa/",
        "/auth/logout",
        "/auth/refresh",
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="MfaEnrollmentMiddleware"/> class.
    /// </summary>
    public MfaEnrollmentMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// SPA prefixes that are always permitted for partially-authenticated users.
    /// These are SPA / static-asset prefixes only. A path that
    /// matches one of these but ALSO begins with <c>/api/</c> or <c>/auth/</c> is
    /// treated as an API call and must come through the explicit <see cref="AllowedPaths"/>
    /// list — this closes the gap where a future re-root like <c>/admin/api/...</c>
    /// would silently bypass the MFA-setup gate.
    /// </summary>
    private static readonly string[] NonApiAllowedPrefixes =
    {
        "/admin/", "/user/", "/public/", "/setup/", "/docs/",
        "/login", "/banner", "/mfa-setup", "/mfa-verify", "/mfa-callback",
        "/css/", "/js/", "/assets/", "/favicon",
    };

    /// <summary>
    /// Inspects the authenticated user's JWT for the <c>mfa_setup_required</c> claim.
    /// If present, only MFA setup endpoints, explicitly whitelisted non-API paths
    /// (UI routes, static assets, health, metrics), and the root path are permitted;
    /// all other endpoints are blocked with a 403 response until MFA enrollment is completed.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var user = context.User;
        if (user?.Identity?.IsAuthenticated == true)
        {
            var mfaRequired = user.FindFirst("mfa_setup_required")?.Value == "true";
            if (mfaRequired)
            {
                var path = context.Request.Path.Value ?? "";

                // Treat /api/ and /auth/ as API-rooted no matter
                // what — any static-prefix match that also begins with one of these
                // must go through the explicit AllowedPaths list. This defends against
                // future re-roots like /admin/api/...
                var isApiRooted = path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase);

                bool isAllowed;
                if (isApiRooted)
                {
                    isAllowed = AllowedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    // /health and /metrics are matched as exact
                    // paths (no prefix) so paths like /metrics-sensitive don't silently
                    // slip through the previous StartsWith gate.
                    var isExactHealthOrMetrics = path.Equals("/health", StringComparison.OrdinalIgnoreCase)
                        || path.Equals("/metrics", StringComparison.OrdinalIgnoreCase);

                    isAllowed = isExactHealthOrMetrics
                        || NonApiAllowedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                        || path == "/";
                }

                if (!isAllowed)
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        "{\"error\":\"MFA enrollment required. Please set up TOTP or a security key before accessing admin functions.\",\"mfaSetupRequired\":true}");
                    return;
                }
            }
        }

        await _next(context);
    }
}
