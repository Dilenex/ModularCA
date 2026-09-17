using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Signing;

namespace ModularCA.API.Filters;

/// <summary>
/// Refuses an enrollment or protocol request while the signer reports itself locked. A locked
/// signer holds no usable key, so a request that reached the handler would fail somewhere
/// inside it with a message about a missing key; this answers first, with 503 and a sentence
/// that names the cause, so a client retries later and an operator knows where to look. The
/// signer's health is its own account, asked per request; it costs a count of the registry.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireUnlockedSignerAttribute : ActionFilterAttribute
{
    /// <summary>The sentence a refused client receives.</summary>
    public const string Message = "The signer has not unlocked its keystore; enrollment is unavailable until it does.";

    /// <inheritdoc />
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var signer = context.HttpContext.RequestServices.GetRequiredService<ISigningService>();
        var health = await signer.HealthAsync(context.HttpContext.RequestAborted);
        if (!health.Unlocked)
        {
            context.HttpContext.Response.Headers.RetryAfter = "30";
            context.Result = new ObjectResult(new { error = Message, signer = new { unlocked = false } })
            {
                StatusCode = StatusCodes.Status503ServiceUnavailable,
            };
            return;
        }
        await next();
    }
}
