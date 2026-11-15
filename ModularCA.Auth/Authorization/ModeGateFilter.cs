using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Enforces the instance's mode on every endpoint that declares a <see cref="ModeGateAttribute"/>:
/// when the mode does not allow the endpoint's class, the refusal is written to the audit trail
/// and the request is answered 503 with the mode and what still works. It is registered once,
/// for every controller, and runs after the endpoint's authorization policy and before any other
/// action filter, so an unauthenticated or unauthorised caller is turned away as before and a
/// refused caller is not asked to step up first.
/// </summary>
/// <remarks>
/// An endpoint with no declaration is not refused here: reads declare nothing. A mutating
/// endpoint that declares nothing fails the architecture test instead. An endpoint declared
/// <see cref="ModeGateAttribute.AnsweredByAction"/> is let through and asks the gate itself,
/// through <see cref="RequireAsync"/> or in its own protocol.
/// </remarks>
public sealed class ModeGateFilter : IAsyncActionFilter, IOrderedFilter
{
    /// <summary>The seconds a refused client is told to wait before trying again.</summary>
    public const string RetryAfterSeconds = "60";

    /// <inheritdoc/>
    public int Order => int.MinValue;

    /// <inheritdoc/>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var declared = context.ActionDescriptor.EndpointMetadata.OfType<ModeGateAttribute>().LastOrDefault();
        if (declared is { AnsweredByAction: false })
        {
            var refusal = await RefusalAsync(context.HttpContext, declared.Operation,
                context.ActionDescriptor.DisplayName ?? "This operation");
            if (refusal != null)
            {
                context.Result = refusal;
                return;
            }
        }
        await next();
    }

    /// <summary>
    /// For an action that decides its class from the request: returns null when the instance's
    /// mode allows <paramref name="operation"/>, otherwise audits the refusal and returns the
    /// 503 the action must return.
    /// </summary>
    /// <param name="http">The request.</param>
    /// <param name="operation">The class of what this request does.</param>
    /// <param name="whatIsRefused">The operation as a sentence opener, in the operator's words.</param>
    public static Task<ObjectResult?> RequireAsync(HttpContext? http, ModeOperation operation, string whatIsRefused)
        => RefusalAsync(http, operation, whatIsRefused, friendly: true);

    private static async Task<ObjectResult?> RefusalAsync(HttpContext? http, ModeOperation operation, string what, bool friendly = false)
    {
        // A context with no services (a unit test calling an action directly) has no gate: full.
        var gate = http?.RequestServices?.GetService<IInstanceModeGate>();
        var refusal = InstanceModeGate.Require(gate, operation, friendly ? what : "This operation");
        if (refusal == null || http == null)
            return null;

        // Audit first, answer second. A failure to audit does not turn the refusal into an
        // allowance: the request is refused either way.
        try
        {
            var audit = http.RequestServices?.GetService<IAuditService>();
            if (audit != null)
            {
                Guid? actorId = Guid.TryParse(
                    http.User.FindFirstValue("sub") ?? http.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;
                var actorName = http.User.FindFirstValue("unique_name") ?? http.User.FindFirstValue(ClaimTypes.Name) ?? http.User.Identity?.Name;
                await audit.LogAsync(
                    AuditActionType.InstanceModeRefused, actorId, actorName,
                    targetEntityType: "Endpoint",
                    targetEntityId: $"{http.Request.Method} {http.Request.Path.Value}",
                    details: new
                    {
                        Mode = InstanceModeGate.NameOf(refusal.Mode),
                        Operation = operation.ToString(),
                        Action = friendly ? null : what,
                        What = friendly ? what : null,
                    },
                    sourceIp: http.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: refusal.Code);
            }
        }
        catch (Exception)
        {
            // The refusal stands without its audit record.
        }

        http.Response.Headers.RetryAfter = RetryAfterSeconds;
        return new ObjectResult(new
        {
            type = "about:blank",
            title = refusal.Title,
            status = refusal.Status,
            detail = refusal.Message,
            error = refusal.Message,
            code = refusal.Code,
            mode = InstanceModeGate.NameOf(refusal.Mode),
            operationClass = operation.ToString().ToLowerInvariant(),
            remediation = refusal.Remediation,
        })
        { StatusCode = refusal.Status };
    }
}
