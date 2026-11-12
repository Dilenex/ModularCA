namespace ModularCA.API.Middleware;

/// <summary>
/// Protects the /docs/ SPA by requiring authentication.
/// Runs after UseAuthentication so that context.User is populated from any Bearer token.
/// If a Bearer token is present but invalid/missing, redirects browser requests to the admin login
/// page and returns 401 for API/XHR requests.
/// For browser page loads (which lack a Bearer header), the request passes through and the docs
/// SPA handles the client-side auth check, redirecting to /login if no token is in localStorage.
/// </summary>
public class DocsAuthMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>Creates the middleware.</summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    public DocsAuthMiddleware(RequestDelegate next) { _next = next; }

    /// <summary>
    /// For a <c>/docs</c> path carrying a Bearer token that did not authenticate, answers 401 JSON when
    /// the client accepts <c>application/json</c> and otherwise redirects to <c>/login</c> with the path
    /// as <c>returnUrl</c>. Every other request passes through.
    /// </summary>
    /// <param name="context">The current request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";

        if (path.StartsWith("/docs", StringComparison.OrdinalIgnoreCase))
        {
            // If an Authorization header was provided, require it to be valid
            var authHeader = context.Request.Headers.Authorization.ToString();
            var hasBearerHeader = !string.IsNullOrEmpty(authHeader) &&
                                  authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);

            if (hasBearerHeader && context.User?.Identity?.IsAuthenticated != true)
            {
                // Bearer token was provided but is invalid/expired
                var accept = context.Request.Headers.Accept.ToString();
                if (accept.Contains("application/json", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Authentication required to access documentation.\"}");
                    return;
                }

                var returnUrl = Uri.EscapeDataString(path);
                context.Response.Redirect($"/login?returnUrl={returnUrl}");
                return;
            }
        }

        await _next(context);
    }
}
