namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Scoped tenant-context accessor resolved once per HTTP request from the authenticated
/// caller's group memberships. Feeds the EF Core global query filter in
/// <c>ModularCADbContext.OnModelCreating</c> so every tenant-scoped read is automatically
/// fenced to <see cref="AccessibleTenantIds"/>.
/// <para>
/// Cross-tenant admin UIs that legitimately need to see every row must call
/// <c>IgnoreQueryFilters()</c> on the query AND gate the call on
/// <see cref="IsSystemAdmin"/>. The filter is a defense-in-depth layer, not the primary
/// authorization check.
/// </para>
/// <para>
/// Background services and startup code with no HTTP context receive an
/// "unresolved" context where <see cref="HasContext"/> is false — the DbContext treats
/// unresolved contexts as bypass (system-level) so migrations, CRL generation, and other
/// infra workloads can read across tenants.
/// </para>
/// </summary>
public interface ITenantContext
{
    /// <summary>
    /// True when the context was populated from an authenticated HTTP request. False for
    /// unauthenticated requests, background jobs, and startup code.
    /// </summary>
    bool HasContext { get; }

    /// <summary>
    /// True when the caller is a member of a system-level admin group. System admins
    /// bypass the tenant filter and see every row across tenants.
    /// </summary>
    bool IsSystemAdmin { get; }

    /// <summary>
    /// The set of tenant IDs the current caller can access. Empty when the caller has
    /// no CA-scoped or tenant-scoped group memberships. When <see cref="IsSystemAdmin"/>
    /// is true this set contains every tenant in the system.
    /// </summary>
    IReadOnlySet<Guid> AccessibleTenantIds { get; }

    /// <summary>
    /// True when the caller may see instance rows (CAs with no tenant): a system admin, or a
    /// member of any group with no tenant (the system groups and the instance CAs' groups).
    /// </summary>
    bool HasInstanceScope { get; }

    /// <summary>
    /// The authenticated user ID, or null when <see cref="HasContext"/> is false.
    /// </summary>
    Guid? UserId { get; }

    /// <summary>
    /// Populates the context after the authorization pipeline has resolved the caller's
    /// tenant memberships. Called once per request from
    /// <c>TenantResolutionMiddleware</c>.
    /// </summary>
    void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin, bool hasInstanceScope);
}

/// <summary>
/// Null-object implementation of <see cref="ITenantContext"/> used by design-time EF tooling,
/// bootstrap, and background jobs that don't have an HTTP scope. Reports
/// <see cref="HasContext"/> = false so the DbContext query filter short-circuits to
/// "allow all rows." Without this null-object the filter expression would NRE during EF's
/// parameter-binding phase because EF captures the field reference at compile time and
/// evaluates it up front, not lazily via the short-circuit in the lambda body.
/// </summary>
public sealed class UnresolvedTenantContext : ITenantContext
{
    /// <summary>Singleton instance — safe because the object has no mutable state.</summary>
    public static readonly UnresolvedTenantContext Instance = new();

    private static readonly IReadOnlySet<Guid> EmptySet = new HashSet<Guid>();

    /// <inheritdoc />
    public bool HasContext => false;

    /// <inheritdoc />
    public bool IsSystemAdmin => false;

    /// <inheritdoc />
    public IReadOnlySet<Guid> AccessibleTenantIds => EmptySet;

    /// <inheritdoc />
    public bool HasInstanceScope => false;

    /// <inheritdoc />
    public Guid? UserId => null;

    /// <inheritdoc />
    public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin, bool hasInstanceScope)
    {
        // No-op. The unresolved context is immutable; callers that want to populate a
        // context should inject the scoped TenantContext DI service instead.
    }
}
