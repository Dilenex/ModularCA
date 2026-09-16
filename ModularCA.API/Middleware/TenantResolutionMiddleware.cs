using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Middleware;

/// <summary>
/// Resolves the authenticated user's accessible tenant IDs from their group memberships,
/// stores them in <c>HttpContext.Items["AccessibleTenantIds"]</c> for legacy controller
/// code, and populates the scoped <see cref="ITenantContext"/> that feeds the
/// <c>ModularCADbContext</c> global query filter.
/// <para>
/// System administrators (members of a system-admin group) receive access to all tenants
/// and bypass the query filter via <see cref="ITenantContext.IsSystemAdmin"/>.
/// Non-authenticated requests skip tenant resolution entirely and the query filter
/// evaluates an unresolved context as bypass so anonymous public routes (CRL, OCSP,
/// ACME directory, etc.) continue to read the full dataset.
/// </para>
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of <see cref="TenantResolutionMiddleware"/>.
    /// </summary>
    public TenantResolutionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Resolves tenant access for the current user, stashes the results in HttpContext.Items,
    /// populates the scoped <see cref="ITenantContext"/>, and continues the pipeline.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, ModularCADbContext db, ITenantContext tenantContext, ModularCA.Auth.Authorization.ICaGroupAuthorizationService authz)
    {
        var userIdClaim = context.User?.FindFirst("sub")?.Value
            ?? context.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        HashSet<Guid> accessibleTenantIds = new();
        bool isSystemAdmin = false;
        Guid? resolvedUserId = null;

        if (userIdClaim != null && Guid.TryParse(userIdClaim, out var userId))
        {
            resolvedUserId = userId;

            // system.manage via any of the four grant sources. The resolver answers, rather
            // than a copy of its queries here, so a worn access badge restricts this too.
            isSystemAdmin = await authz.IsSystemAdminAsync(userId);

            if (isSystemAdmin)
            {
                var allTenantIds = await db.Tenants
                    .IgnoreQueryFilters()
                    .Select(t => t.Id)
                    .ToListAsync();
                accessibleTenantIds = new HashSet<Guid>(allTenantIds);
                context.Items["IsSystemAdmin"] = true;
            }
            else
            {
                // Group memberships as the resolver sees them (a worn badge keeps only some).
                var tenantIds = (await authz.GetUserGroupsAsync(userId))
                    .Select(g => g.TenantId)
                    .Distinct()
                    .ToList();
                accessibleTenantIds = new HashSet<Guid>(tenantIds);
            }

            context.Items["AccessibleTenantIds"] = accessibleTenantIds;
        }

        // Ensure AccessibleTenantIds is always set for authenticated users (defense-in-depth:
        // if claim parsing failed or an unexpected path was taken, default to no access)
        if (context.User?.Identity?.IsAuthenticated == true && context.Items["AccessibleTenantIds"] == null)
        {
            context.Items["AccessibleTenantIds"] = accessibleTenantIds;
        }

        // Populate the scoped ITenantContext for the EF global query filter.
        // Anonymous requests leave HasContext = false which the filter treats as bypass so
        // public routes (CRL, OCSP, ACME) continue to see the entire dataset.
        if (resolvedUserId != null || context.User?.Identity?.IsAuthenticated == true)
        {
            tenantContext.Set(resolvedUserId, accessibleTenantIds, isSystemAdmin);
        }

        await _next(context);
    }
}
