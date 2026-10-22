using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Filters;

/// <summary>
/// Admits a request to an integration by its <c>X-API-Key</c> header, and remembers who it was
/// admitted as. Both integrations' filters call it; the decision is
/// <see cref="IApiKeyService.AdmitAsync"/>.
/// </summary>
internal static class IntegrationKeyGate
{
    private const string HeaderName = "X-API-Key";
    private static readonly object CallerItem = new();

    /// <summary>
    /// Null when the request is admitted, with its <see cref="IntegrationCaller"/> attached to
    /// it; otherwise the answer to give: 503 when the integration is off or has no key at all,
    /// 401 when no key or a wrong one is presented, 403 when the key is scoped outside what the
    /// integration itself is allowed.
    /// </summary>
    public static async Task<IActionResult?> AdmitAsync(HttpContext http, string integration, bool enabled,
        string? configuredKey, IntegrationSpaceScope integrationScope, string disabledError, string unconfiguredError)
    {
        var presented = http.Request.Headers.TryGetValue(HeaderName, out var header) ? header.ToString() : null;
        var admission = await http.RequestServices.GetRequiredService<IApiKeyService>()
            .AdmitAsync(integration, enabled, configuredKey, integrationScope, presented, http.RequestAborted);

        switch (admission.Status)
        {
            case IntegrationAdmissionStatus.Admitted:
                http.Items[CallerItem] = admission.Caller;
                return null;
            case IntegrationAdmissionStatus.Disabled:
                return new ObjectResult(new { error = disabledError }) { StatusCode = 503 };
            case IntegrationAdmissionStatus.Unconfigured:
                return new ObjectResult(new { error = unconfiguredError }) { StatusCode = 503 };
            case IntegrationAdmissionStatus.MissingKey:
                return new UnauthorizedObjectResult(new { error = "Missing X-API-Key header." });
            case IntegrationAdmissionStatus.OutOfScope:
                return new ObjectResult(new { error = admission.Detail }) { StatusCode = 403 };
            default:
                return new UnauthorizedObjectResult(new { error = "Invalid API key." });
        }
    }

    /// <summary>
    /// The caller the key filter admitted this request as. When no filter ran, which is a
    /// controller called directly, the integration's configured scope and no key.
    /// </summary>
    public static IntegrationCaller CallerOf(HttpContext? http, IntegrationSpaceScope integrationScope) =>
        http != null && http.Items.TryGetValue(CallerItem, out var caller) && caller is IntegrationCaller admitted
            ? admitted
            : new IntegrationCaller(null, null, integrationScope);
}
