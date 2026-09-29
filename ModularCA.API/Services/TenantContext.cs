using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Services;

/// <summary>
/// Scoped implementation of <see cref="ITenantContext"/>. Populated by
/// <see cref="Middleware.TenantResolutionMiddleware"/> after the authentication and
/// authorization pipeline has resolved the caller's group memberships. Feeds the
/// global query filter registered in <c>ModularCADbContext.OnModelCreating</c>.
/// </summary>
public class TenantContext : ITenantContext
{
    private static readonly IReadOnlySet<Guid> EmptySet = new HashSet<Guid>();

    /// <inheritdoc />
    public bool HasContext { get; private set; }

    /// <inheritdoc />
    public bool IsSystemAdmin { get; private set; }

    /// <inheritdoc />
    public IReadOnlySet<Guid> AccessibleTenantIds { get; private set; } = EmptySet;

    /// <inheritdoc />
    public bool HasInstanceScope { get; private set; }

    /// <inheritdoc />
    public Guid? UserId { get; private set; }

    /// <inheritdoc />
    public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin, bool hasInstanceScope)
    {
        UserId = userId;
        AccessibleTenantIds = accessibleTenantIds ?? EmptySet;
        IsSystemAdmin = isSystemAdmin;
        HasInstanceScope = isSystemAdmin || hasInstanceScope;
        HasContext = true;
    }
}
