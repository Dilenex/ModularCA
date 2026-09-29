using System.Linq.Expressions;
using Microsoft.AspNetCore.Http;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The caller's tenant fence, read from what <c>TenantResolutionMiddleware</c> put in
/// <c>HttpContext.Items</c>: the spaces the caller belongs to, and whether they may see
/// instance rows (a null tenant). Replaces the controllers' <c>tenantIds.Contains(ca.TenantId)</c>
/// checks, which cannot express the instance.
/// </summary>
public sealed class TenantFence
{
    /// <summary>
    /// The fence a non-admin's group memberships give: the tenants of their groups, and instance
    /// scope when a group with no tenant is a system group or an instance CA's group. Membership
    /// of a System-tenant group is what showed the system CAs before 0.4.0, so this preserves it;
    /// a stray null-tenant group that is neither confers nothing.
    /// </summary>
    public static (HashSet<Guid> TenantIds, bool InstanceScope) ScopeOf(IEnumerable<CaGroupEntity> groups)
    {
        var list = groups.ToList();
        return (list.Where(g => g.TenantId != null).Select(g => g.TenantId!.Value).ToHashSet(),
            list.Any(g => g.TenantId == null && (g.IsSystemGroup || g.CertificateAuthorityId != null)));
    }

    private TenantFence(HashSet<Guid> tenantIds, bool instanceScope, bool isSystemAdmin)
    {
        TenantIds = tenantIds;
        InstanceScope = instanceScope || isSystemAdmin;
        IsSystemAdmin = isSystemAdmin;
    }

    /// <summary>The spaces the caller may see.</summary>
    public HashSet<Guid> TenantIds { get; }

    /// <summary>Whether the caller may see instance rows.</summary>
    public bool InstanceScope { get; }

    /// <summary>Whether the caller is a system admin, who sees everything.</summary>
    public bool IsSystemAdmin { get; }

    /// <summary>
    /// The fence for the current request, or null when the middleware resolved none
    /// (an unauthenticated request); each call site keeps its own rule for that case.
    /// </summary>
    public static TenantFence? From(HttpContext context)
    {
        if (context.Items["AccessibleTenantIds"] is not HashSet<Guid> ids)
            return null;
        return new TenantFence(ids, context.Items["HasInstanceScope"] is true, context.Items["IsSystemAdmin"] is true);
    }

    /// <summary>A fence over explicit values, for tests and callers outside a request.</summary>
    public static TenantFence Of(IEnumerable<Guid> tenantIds, bool instanceScope, bool isSystemAdmin = false)
        => new(tenantIds.ToHashSet(), instanceScope, isSystemAdmin);

    /// <summary>Whether a row of <paramref name="tenantId"/> (null for the instance) is inside the fence.</summary>
    public bool Allows(Guid? tenantId)
        => IsSystemAdmin || (tenantId is Guid t ? TenantIds.Contains(t) : InstanceScope);

    /// <summary>
    /// The same rule as <see cref="Allows"/> as a translatable predicate over rows whose tenant
    /// <paramref name="tenantOf"/> selects, for <c>IQueryable.Where</c>.
    /// </summary>
    public Expression<Func<T, bool>> Predicate<T>(Expression<Func<T, Guid?>> tenantOf)
    {
        var ids = TenantIds;
        var all = IsSystemAdmin;
        var instance = InstanceScope;
        Expression<Func<Guid?, bool>> rule = t => all || (t == null && instance) || (t != null && ids.Contains(t.Value));
        var body = new Replace(rule.Parameters[0], tenantOf.Body).Visit(rule.Body)!;
        return Expression.Lambda<Func<T, bool>>(body, tenantOf.Parameters);
    }

    private sealed class Replace(ParameterExpression from, Expression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == from ? to : base.VisitParameter(node);
    }
}
