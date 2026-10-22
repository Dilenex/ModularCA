using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Signing;

namespace ModularCA.API.Filters;

/// <summary>
/// Refuses an enrollment or protocol request while the signer reports itself locked or, when
/// it is another process, unreachable. A locked signer holds no usable key and an unreachable
/// one cannot be asked, so a request that reached the handler would fail somewhere inside it
/// with a message about a missing key; this answers first, with 503 and a sentence that names
/// the cause, so a client retries later and an operator knows where to look. The signer's
/// health is its own account, asked per request; in process it costs a count of the registry,
/// over the wire one round trip.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireUnlockedSignerAttribute : ActionFilterAttribute
{
    /// <summary>The sentence a refused client receives while the signer is locked.</summary>
    public const string Message = "The signer has not unlocked its keystore; enrollment is unavailable until it does.";

    /// <summary>The sentence a refused client receives while a remote signer cannot be reached.</summary>
    public const string UnreachableMessage = "The signer is unreachable; enrollment is unavailable until the node reconnects to it.";

    /// <summary>The sentence for a health report: <see cref="UnreachableMessage"/> for an unreachable signer, <see cref="Message"/> otherwise.</summary>
    public static string MessageFor(SignerHealth health)
        => health.Backend == SignerHealth.UnreachableBackend ? UnreachableMessage : Message;

    /// <inheritdoc />
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var signer = context.HttpContext.RequestServices.GetRequiredService<ISigningService>();
        var health = await signer.HealthAsync(context.HttpContext.RequestAborted);
        if (!health.Unlocked)
        {
            context.Result = Unavailable(context.HttpContext, new { error = MessageFor(health), signer = new { unlocked = false, backend = health.Backend } }, retry: true);
            return;
        }
        await next();
    }

    /// <summary>
    /// The answer for a key the signer cannot serve now, which an action learns only once it
    /// has asked: an SSH CA key the signer refused as locked or unsupported, or one still
    /// awaiting its import into the signer. It is the 503 this filter gives, with
    /// <paramref name="reason"/> as the error, so a client treats both the same way.
    /// </summary>
    /// <param name="http">The request being answered.</param>
    /// <param name="reason">Why the key cannot be used, as the caller is shown it.</param>
    /// <param name="retry">
    /// Whether to tell the client to try again in thirty seconds, as for a locked signer. False
    /// where trying again changes nothing until an operator acts: a key awaiting import, a
    /// signer that has to be upgraded.
    /// </param>
    public static ObjectResult Unavailable(HttpContext http, string reason, bool retry) => Unavailable(http, new { error = reason }, retry);

    /// <summary>A 503 with <paramref name="body"/>, with <c>Retry-After: 30</c> when <paramref name="retry"/> is set.</summary>
    private static ObjectResult Unavailable(HttpContext http, object body, bool retry)
    {
        if (retry)
            http.Response.Headers.RetryAfter = "30";
        return new ObjectResult(body) { StatusCode = StatusCodes.Status503ServiceUnavailable };
    }
}
