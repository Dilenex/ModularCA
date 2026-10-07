using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;

namespace ModularCA.API.Filters;

/// <summary>
/// Declarative replacement for the manual
/// <c>X-MFA-Token</c> + <c>MfaStepUpController.ValidateStepUpTokenAsync</c>
/// block that every mutating endpoint copy-pasted. Attach
/// <c>[RequireStepUp(StepUpOps.DeleteUser, "id")]</c> to an action method and
/// the filter will:
/// <list type="number">
///   <item><description>Read <c>X-MFA-Token</c> from the request headers.</description></item>
///   <item><description>Resolve the distributed cache and the caller's <see cref="System.Security.Claims.ClaimsPrincipal"/>.</description></item>
///   <item><description>Optionally pick up a target id from a named route parameter.</description></item>
///   <item><description>Call <see cref="MfaStepUpController.ValidateStepUpTokenAsync(IDistributedCache, System.Security.Claims.ClaimsPrincipal, string?, string, string?)"/>.</description></item>
///   <item><description>Return <c>403 { requiresStepUp = true, operation }</c> on failure,
///     or invoke the next filter on success.</description></item>
/// </list>
/// </summary>
/// <remarks>
/// This is a standard <see cref="ActionFilterAttribute"/> (not an
/// <see cref="IFilterFactory"/>) — services are resolved from
/// <c>context.HttpContext.RequestServices</c> inside
/// <see cref="OnActionExecutionAsync"/>. That keeps the attribute trivially
/// applicable without needing DI for the attribute itself.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireStepUpAttribute : ActionFilterAttribute
{
    private readonly string _operation;
    private readonly string? _targetRouteParam;

    /// <summary>
    /// Creates an attribute that enforces step-up MFA for the given operation
    /// without a target id.
    /// </summary>
    /// <param name="operation">A <c>StepUpOps</c> constant identifying the protected operation.</param>
    public RequireStepUpAttribute(string operation)
    {
        _operation = operation;
        _targetRouteParam = null;
    }

    /// <summary>
    /// Creates an attribute that enforces step-up MFA for the given operation,
    /// pulling the target id from a named route value (e.g.
    /// <c>[RequireStepUp(StepUpOps.DeleteUser, "id")]</c> on an action with
    /// route template <c>users/{id}</c>).
    /// </summary>
    /// <param name="operation">A <c>StepUpOps</c> constant identifying the protected operation.</param>
    /// <param name="targetRouteParam">The route-parameter name whose value is the target entity id, or
    /// <c>argument.Property</c> when the id arrives in the request body.</param>
    public RequireStepUpAttribute(string operation, string targetRouteParam)
    {
        _operation = operation;
        _targetRouteParam = targetRouteParam;
    }

    /// <inheritdoc />
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var http = context.HttpContext;
        var cache = http.RequestServices.GetRequiredService<IDistributedCache>();

        var mfaToken = http.Request.Headers.TryGetValue("X-MFA-Token", out var headerValue)
            ? headerValue.ToString()
            : null;

        var target = ResolveTarget(_targetRouteParam, context.RouteData.Values, context.ActionArguments);

        var ok = await MfaStepUpController.ValidateStepUpTokenAsync(
            cache,
            http.User,
            mfaToken,
            _operation,
            target);

        if (!ok)
        {
            context.Result = new ObjectResult(new
            {
                error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true,
                operation = _operation,
            })
            {
                StatusCode = 403,
            };
            return;
        }

        await next();
    }

    /// <summary>
    /// The id the step-up token must have been issued for. A plain name is a route value
    /// (<c>"id"</c>); a dotted name is a property of a bound argument (<c>"request.CertId"</c>),
    /// for an action whose target arrives in the body. Null when the name resolves to nothing,
    /// which no token issued for a target matches.
    /// </summary>
    internal static string? ResolveTarget(string? name, IDictionary<string, object?> routeValues, IDictionary<string, object?> arguments)
    {
        if (string.IsNullOrEmpty(name))
            return null;

        var dot = name.IndexOf('.');
        if (dot < 0)
            return routeValues.TryGetValue(name, out var routeValue) ? routeValue?.ToString() : null;

        if (!arguments.TryGetValue(name[..dot], out var argument) || argument == null)
            return null;
        return argument.GetType().GetProperty(name[(dot + 1)..])?.GetValue(argument)?.ToString();
    }
}
