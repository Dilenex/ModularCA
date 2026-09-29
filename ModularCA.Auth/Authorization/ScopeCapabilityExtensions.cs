namespace ModularCA.Auth.Authorization;

/// <summary>
/// Capability checks over a scope that is either a space or the instance.
/// </summary>
public static class ScopeCapabilityExtensions
{
    /// <summary>
    /// Whether the user holds <paramref name="capability"/> across the whole scope: tenant-wide in
    /// <paramref name="tenantId"/>, or, for null (the instance), at system scope. The instance has no
    /// tenant-wide groups, so system scope is what held it across the former system tenant.
    /// A holder of <c>system.manage</c> holds every capability in every scope.
    /// </summary>
    public static async Task<bool> HasScopeCapabilityAsync(this ICaGroupAuthorizationService auth, Guid userId, Guid? tenantId, string capability)
        => tenantId is Guid t
            ? await auth.HasTenantCapabilityAsync(userId, t, capability)
            : await auth.IsSystemAdminAsync(userId) || await auth.HasSystemCapabilityAsync(userId, capability);
}
