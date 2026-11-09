using System.Text.Json;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Middleware;

/// <summary>
/// Middleware that checks protocol-level feature flags and returns 503 when a
/// protocol is disabled by the administrator. This allows operators to disable
/// CRL, OCSP, ACME, EST, SCEP, or CMP endpoints at runtime without a restart.
/// </summary>
public class ProtocolFeatureGateMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Maps request path prefixes to the feature flag that gates them. Each prefix is matched by
    /// whole segments (<see cref="PathString.StartsWithSegments(PathString, StringComparison)"/>),
    /// so <c>/ocsp</c> gates both <c>/ocsp</c> and <c>/ocsp/...</c> and not <c>/ocspfoo</c>.
    /// </summary>
    /// <remarks>
    /// These were matched as raw string prefixes ending in a slash, so the exact paths a client
    /// posts to — <c>POST /ocsp</c> above all — were never gated, and the ones without a slash
    /// (<c>/api/v1/acme</c>) also matched unrelated paths that merely began with the same letters.
    /// </remarks>
    private static readonly (PathString PathPrefix, string FlagName)[] Gates = new (PathString, string)[]
    {
        // CRL — public distribution endpoints
        ("/api/v1/public/crl", "CRL.Enabled"),
        ("/crl",               "CRL.Enabled"),

        // OCSP — public responder endpoints
        ("/api/v1/public/ocsp", "OCSP.Enabled"),
        ("/ocsp",               "OCSP.Enabled"),

        // ACME — RFC 8555 endpoints
        ("/api/v1/acme",                  "ACME.Enabled"),
        ("/acme",                         "ACME.Enabled"),
        ("/.well-known/acme-challenge",   "ACME.Enabled"),

        // EST — RFC 7030 endpoints
        ("/api/v1/est",            "EST.Enabled"),
        ("/est",                   "EST.Enabled"),
        ("/.well-known/est",       "EST.Enabled"),

        // SCEP — Simple Certificate Enrollment Protocol endpoints
        ("/api/v1/scep", "SCEP.Enabled"),
        ("/scep",        "SCEP.Enabled"),

        // CMP — Certificate Management Protocol endpoints
        ("/api/v1/cmp", "CMP.Enabled"),
        ("/cmp",        "CMP.Enabled"),

        // Windows autoenrollment (MS-WSTEP)
        ("/api/v1/msae", "MSAE.Enabled"),
        ("/msae",        "MSAE.Enabled"),
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public ProtocolFeatureGateMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Checks whether the request targets a protocol endpoint that is disabled and short-circuits with 503 if so.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, IFeatureFlagService featureFlagService)
    {
        var path = context.Request.Path;
        if (path.HasValue)
        {
            foreach (var (prefix, flagName) in Gates)
            {
                if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (!featureFlagService.IsEnabled(flagName))
                    {
                        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                        context.Response.ContentType = "application/json";
                        var body = JsonSerializer.Serialize(
                            new { error = "This protocol is currently disabled by the system administrator." },
                            JsonOptions);
                        await context.Response.WriteAsync(body);
                        return;
                    }
                    // Flag is enabled — no need to check further prefixes for this request.
                    break;
                }
            }
        }

        await _next(context);
    }
}
