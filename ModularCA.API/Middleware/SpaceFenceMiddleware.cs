using ModularCA.Auth.Authorization;

namespace ModularCA.API.Middleware;

/// <summary>
/// Resolves the authenticated caller's <see cref="SpaceFence"/> through
/// <see cref="ICaGroupAuthorizationService.GetFenceAsync"/> and stores it for the request, with
/// <c>HttpContext.Items["IsSystemAdmin"]</c> for a system admin. An authenticated caller whose
/// subject cannot be read gets <see cref="SpaceFence.None"/>. Anonymous requests get no fence;
/// there is no query filter behind it, so endpoints apply the fence explicitly.
/// </summary>
public class SpaceFenceMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of <see cref="SpaceFenceMiddleware"/>.
    /// </summary>
    public SpaceFenceMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Resolves the caller's fence, stores it in <c>HttpContext.Items</c>, and continues the pipeline.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, ICaGroupAuthorizationService authz)
    {
        var userIdClaim = context.User?.FindFirst("sub")?.Value
            ?? context.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (userIdClaim != null && Guid.TryParse(userIdClaim, out var userId))
            SpaceFence.Store(context, await authz.GetFenceAsync(userId));
        else if (context.User?.Identity?.IsAuthenticated == true)
            SpaceFence.Store(context, SpaceFence.None);

        await _next(context);
    }
}
