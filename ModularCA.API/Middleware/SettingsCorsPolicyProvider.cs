using Microsoft.AspNetCore.Cors.Infrastructure;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Middleware;

/// <summary>
/// The restricted CORS policy, taken from <c>Http.EnableCors</c> and <c>Http.CorsOrigins</c> as
/// they stand when a request arrives, so a saved change applies to the next one. There is no
/// policy while CORS is off or no origin is allowed. The policy is rebuilt only when the origin
/// list changes.
/// </summary>
public sealed class SettingsCorsPolicyProvider : ICorsPolicyProvider
{
    private sealed record Built(string? Origins, CorsPolicy? Policy);

    private readonly SystemConfig _config;
    private volatile Built _built = new(null, null);

    /// <summary>
    /// Initializes a new <see cref="SettingsCorsPolicyProvider"/>.
    /// </summary>
    /// <param name="config">System configuration holding the CORS settings.</param>
    public SettingsCorsPolicyProvider(SystemConfig config)
    {
        _config = config;
    }

    /// <summary>Whether a CORS policy is in force now: CORS is on and at least one origin is allowed.</summary>
    public bool Active => Current() != null;

    /// <summary>
    /// The policy in force now, whatever <paramref name="policyName"/> asks for, or null when
    /// there is none.
    /// </summary>
    public Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName) => Task.FromResult(Current());

    private CorsPolicy? Current()
    {
        var http = _config.Http;
        if (!http.EnableCors)
            return null;

        var origins = http.CorsOrigins ?? string.Empty;
        var built = _built;
        if (built.Origins != origins)
        {
            built = new Built(origins, Build(origins));
            _built = built;
        }
        return built.Policy;
    }

    private static CorsPolicy? Build(string csv)
    {
        var origins = ConfigInputRules.CorsOriginsAllowed(csv);
        if (origins.Length == 0)
            return null;

        // DO NOT add AllowCredentials — the SPA uses Bearer tokens, not cookies,
        // for API calls. Adding credentials would require narrowing the origin
        // allow-list further and opens the door to CSRF on credentialed endpoints.
        return new CorsPolicyBuilder()
            .WithOrigins(origins)
            .WithMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
            .WithHeaders(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-MFA-Token",
                "X-CSRF-Token",
                "X-Correlation-Id",
                "DPoP")
            .Build();
    }
}
