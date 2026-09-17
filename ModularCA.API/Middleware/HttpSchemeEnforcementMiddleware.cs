using Microsoft.AspNetCore.Http;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Middleware
{
    /// <summary>
    /// Enforces HTTPS for all non-PKI routes. Hardens
    /// this middleware beyond the previous listener-port-based check:
    /// <list type="bullet">
    ///   <item>The plain-HTTP allow-list uses <c>PathString.StartsWithSegments</c>
    ///   (segment-aware) so a future controller whose route happens to start
    ///   with "health", "ocsp", or "tsa" is not silently exposed over plain HTTP.
    ///   <c>/health</c> is additionally matched as an exact path.</item>
    ///   <item>After <c>UseForwardedHeaders</c>, <c>Request.Scheme</c> reflects
    ///   the <b>original</b> client scheme even when a TLS-terminating reverse
    ///   proxy bridged plain HTTP onto the HTTPS listener. Any request with
    ///   <c>Request.Scheme == "http"</c> for a non-PKI path is rejected.</item>
    ///   <item>The redirect target is built from <c>Https.PublicDomain</c> when
    ///   configured, NOT the attacker-controllable <c>Host</c> header.</item>
    /// </list>
    /// Plain-HTTP PKI surface (CRL distribution points, OCSP, CA cert downloads,
    /// TSA, ACME http-01 challenges), plus the <c>/health</c> probe, is preserved.
    /// </summary>
    public class HttpSchemeEnforcementMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly SystemConfig _config;

        /// <summary>
        /// Path prefixes that are allowed to be served over plain HTTP because
        /// they are part of the public PKI surface that RFC 5280 mandates be
        /// reachable without TLS (CRLs, OCSP, CA cert downloads, TSA), ACME
        /// http-01 challenge endpoints. These are matched with
        /// <c>PathString.StartsWithSegments</c> so only full segment
        /// prefixes match — e.g. <c>/ocspxray</c> no longer matches
        /// <c>/ocsp</c>.
        /// </summary>
        private static readonly PathString[] PlainHttpAllowedPrefixes = new[]
        {
            new PathString("/crl"),
            new PathString("/api/v1/public/crl"),
            new PathString("/api/v1/public/ocsp"),
            new PathString("/ocsp"),
            new PathString("/api/v1/public/ca"),
            new PathString("/ca"),
            new PathString("/api/v1/public/tsa"),
            new PathString("/tsa"),
            new PathString("/acme"),
            new PathString("/api/v1/acme"),
            new PathString("/.well-known/acme-challenge"),
            // Public portal SPA + its read-only info endpoint are reachable over plain
            // HTTP as well as HTTPS, consistent with the PKI distribution surface above
            // (relying parties may not have TLS trust established yet). The portal's other
            // calls (/api/v1/public/ca, /crl, /ocsp, /acme) are already allow-listed.
            // NOTE: /api/v1/public/enroll is deliberately NOT listed — enrollment tokens
            // travel in the URL and must stay on HTTPS.
            new PathString("/public"),
            new PathString("/api/v1/public/info"),
        };

        /// <summary>
        /// Initializes a new instance of <see cref="HttpSchemeEnforcementMiddleware"/>.
        /// </summary>
        /// <param name="next">The next delegate in the request pipeline.</param>
        /// <param name="config">The system configuration supplying the HTTP and HTTPS listener ports.</param>
        private readonly ModularCA.Core.Services.Hostnames.TenantHostnameCertificateCache? _tenantHostnames;

        /// <param name="tenantHostnames">
        /// The names this service presents a tenant certificate for. A request that arrived on one
        /// of them is sent to HTTPS on that same name; every other host is sent to the public
        /// domain, so the header still cannot steer the redirect anywhere the service is not.
        /// </param>
        public HttpSchemeEnforcementMiddleware(RequestDelegate next, SystemConfig config,
            ModularCA.Core.Services.Hostnames.TenantHostnameCertificateCache? tenantHostnames = null)
        {
            _next = next;
            _config = config;
            _tenantHostnames = tenantHostnames;
        }

        /// <summary>
        /// Inspects the incoming request. Allows PKI / health paths through
        /// unconditionally, otherwise upgrades plain-HTTP requests (listener or
        /// forwarded-scheme) to HTTPS via a 308 redirect built from
        /// <c>Https.PublicDomain</c>.
        /// </summary>
        public async Task InvokeAsync(HttpContext context)
        {
            var reqPath = context.Request.Path;

            // Allow the /health probe as an exact match plus the segment form
            // /health/... so probe-path drift stays safe.
            if (IsHealthPath(reqPath) || IsPkiAllowlisted(reqPath))
            {
                await _next(context);
                return;
            }

            // Non-PKI path. Two independent triggers can send us to HTTPS:
            //  1. The request arrived on the Kestrel plain-HTTP listener (LocalPort==Http.Port).
            //  2. The request's effective scheme (after UseForwardedHeaders) is "http".
            // Either one alone is sufficient to force a redirect.
            var arrivedOnPlainHttpListener =
                _config.Http.Port > 0 &&
                context.Connection.LocalPort == _config.Http.Port;

            var schemeIsHttp = string.Equals(
                context.Request.Scheme, "http", StringComparison.OrdinalIgnoreCase);

            if (!arrivedOnPlainHttpListener && !schemeIsHttp)
            {
                await _next(context);
                return;
            }

            // Build the HTTPS redirect. Prefer the configured PublicDomain so
            // an attacker-controllable Host header cannot influence the
            // Location. Fall back to request host only if PublicDomain is
            // unset (operators are warned at startup).
            var target = ModularCA.Core.Services.Hostnames.HttpsRedirectTarget.Build(
                context.Request.Host.Host, $"{context.Request.Path}{context.Request.QueryString}", _config, _tenantHostnames);

            context.Response.StatusCode = 308;
            context.Response.Headers.Location = target;
        }

        /// <summary>
        /// Returns <c>true</c> if the request targets <c>/health</c> exactly or
        /// a <c>/health/...</c> sub-segment — not <c>/healthxray</c>.
        /// </summary>
        private static bool IsHealthPath(PathString path)
        {
            if (path.Equals(new PathString("/health"), StringComparison.OrdinalIgnoreCase))
                return true;
            return path.StartsWithSegments(new PathString("/health"), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Returns <c>true</c> if the request path starts with any PKI-allowed
        /// segment prefix.
        /// </summary>
        private static bool IsPkiAllowlisted(PathString path)
        {
            foreach (var prefix in PlainHttpAllowedPrefixes)
            {
                if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
