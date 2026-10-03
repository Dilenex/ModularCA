using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace ModularCA.API.Filters;

/// <summary>
/// Refuses a request whose query string carries <see cref="Key"/>, a key the action no longer
/// binds, with a 400 problem response that names the key and its <see cref="Replacement"/>.
/// MVC ignores an unbound key, so a stale client would otherwise get the action's answer for no
/// filter at all, which for a chain restart is a different chain. Matched case-insensitively,
/// as query binding is.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
public sealed class RefuseQueryKeyAttribute(string key, string replacement) : ActionFilterAttribute
{
    /// <summary>The query key that is refused.</summary>
    public string Key { get; } = key;

    /// <summary>The query key that replaced <see cref="Key"/>.</summary>
    public string Replacement { get; } = replacement;

    /// <summary>The sentence a refused request receives.</summary>
    public string Message => $"The query parameter '{Key}' is no longer accepted; use '{Replacement}'.";

    /// <inheritdoc />
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.HttpContext.Request.Query.ContainsKey(Key))
            return;
        var problem = new ValidationProblemDetails(new Dictionary<string, string[]> { [Key] = [Message] })
        {
            Status = StatusCodes.Status400BadRequest,
            Detail = Message,
        };
        context.Result = new BadRequestObjectResult(problem);
    }
}
