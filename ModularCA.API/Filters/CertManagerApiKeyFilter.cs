using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Filters;

/// <summary>
/// Action filter that authenticates requests to cert-manager integration endpoints
/// by validating the <c>X-API-Key</c> header against the configured API key in
/// <see cref="CertManagerConfig"/>. Returns 401 if the key is missing or invalid,
/// and 503 if the cert-manager integration is disabled.
/// </summary>
public class CertManagerApiKeyFilter : IAsyncActionFilter
{
    private readonly SystemConfig _config;

    /// <summary>
    /// Initializes a new instance of <see cref="CertManagerApiKeyFilter"/>.
    /// </summary>
    /// <param name="config">The system configuration containing cert-manager settings.</param>
    public CertManagerApiKeyFilter(SystemConfig config)
    {
        _config = config;
    }

    /// <summary>
    /// Admits the request by its <c>X-API-Key</c> header: one of the integration's named keys, or
    /// the single key in the configuration. See <see cref="IntegrationKeyGate"/>.
    /// </summary>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var refusal = await IntegrationKeyGate.AdmitAsync(context.HttpContext, ModularCA.Core.Services.ApiKeyIntegrations.CertManager,
            _config.CertManager.Enabled, _config.CertManager.ApiKey, _config.CertManager.SpaceScope(),
            disabledError: "cert-manager integration is disabled", unconfiguredError: "cert-manager API key is not configured");
        if (refusal != null)
        {
            context.Result = refusal;
            return;
        }
        await next();
    }
}
