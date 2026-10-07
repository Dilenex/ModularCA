using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Filters;

/// <summary>
/// Action filter attribute that validates API key authentication via the X-API-Key header.
/// Used by integration endpoints for infrastructure-as-code tools (Terraform, Ansible).
/// Rejects requests when the integration API is disabled or the key does not match.
/// Implements IFilterFactory to resolve SystemConfig from DI at runtime.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class ApiKeyAuthAttribute : Attribute, IFilterFactory
{
    /// <inheritdoc />
    public bool IsReusable => true;

    /// <summary>
    /// Creates the inner action filter, resolving the SystemConfig from DI.
    /// </summary>
    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        var config = serviceProvider.GetRequiredService<SystemConfig>();
        return new ApiKeyAuthFilter(config);
    }
}

/// <summary>
/// Inner filter: 503 when the integration API is disabled or has no key, 401 when the key is
/// missing or wrong, 403 when a named key is scoped outside the integration's own scope.
/// See <see cref="IntegrationKeyGate"/>.
/// </summary>
internal class ApiKeyAuthFilter(SystemConfig config) : IAsyncActionFilter
{
    /// <summary>
    /// Admits the request by its X-API-Key header: one of the integration's named keys, or the
    /// single key in the configuration.
    /// </summary>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var refusal = await IntegrationKeyGate.AdmitAsync(context.HttpContext, ModularCA.Core.Services.ApiKeyIntegrations.Infrastructure,
            config.IntegrationApi.Enabled, config.IntegrationApi.ApiKey, config.IntegrationApi.SpaceScope(),
            disabledError: "Integration API is disabled.", unconfiguredError: "Integration API key is not configured.");
        if (refusal != null)
        {
            context.Result = refusal;
            return;
        }
        await next();
    }
}
