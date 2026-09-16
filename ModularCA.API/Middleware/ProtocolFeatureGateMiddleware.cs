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
    /// Maps request path prefixes to the feature flag that gates them.
    /// Order matters: more-specific prefixes must appear before shorter ones
    /// so that e.g. "/api/v1/admin/crl" (not listed) is not blocked.
    /// </summary>
    private static readonly (string PathPrefix, string FlagName)[] Gates = new[]
    {
        // CRL — public distribution endpoints
        ("/api/v1/public/crl", "CRL.Enabled"),
        ("/crl/",              "CRL.Enabled"),

        // OCSP — public responder endpoints
        ("/api/v1/public/ocsp", "OCSP.Enabled"),
        ("/ocsp/",              "OCSP.Enabled"),

        // ACME — RFC 8555 endpoints
        ("/api/v1/acme",                  "ACME.Enabled"),
        ("/acme/",                        "ACME.Enabled"),
        ("/.well-known/acme-challenge/",  "ACME.Enabled"),

        // EST — RFC 7030 endpoints
        ("/api/v1/est",            "EST.Enabled"),
        ("/est/",                  "EST.Enabled"),
        ("/.well-known/est/",      "EST.Enabled"),

        // SCEP — Simple Certificate Enrollment Protocol endpoints
        ("/api/v1/scep", "SCEP.Enabled"),
        ("/scep/",       "SCEP.Enabled"),

        // CMP — Certificate Management Protocol endpoints
        ("/api/v1/cmp", "CMP.Enabled"),
        ("/cmp/",       "CMP.Enabled"),

        // Windows autoenrollment (MS-WSTEP)
        ("/api/v1/msae", "MSAE.Enabled"),
        ("/msae/",       "MSAE.Enabled"),
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
        var path = context.Request.Path.Value;
        if (path != null)
        {
            foreach (var (prefix, flagName) in Gates)
            {
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
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
