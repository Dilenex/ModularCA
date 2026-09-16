namespace ModularCA.Core.Authorization;

/// <summary>
/// Combines the CAs a caller may see with the CA a request asked for, for list endpoints that
/// take an optional <c>caId</c> filter.
/// </summary>
public static class CaScope
{
    /// <summary>
    /// Narrows an accessible-CA set to a requested CA.
    /// </summary>
    /// <param name="accessibleCaIds">
    /// The CAs the caller may see, or <c>null</c> when the caller is unrestricted (a system
    /// administrator).
    /// </param>
    /// <param name="requestedCaId">The <c>caId</c> query parameter, if any.</param>
    /// <returns>
    /// <c>null</c> for "everything"; otherwise the list to filter by. Asking for a CA outside
    /// the accessible set yields an empty list, which callers must treat as "nothing", never as
    /// "no filter": a caller must not widen their view by naming a CA they cannot see.
    /// </returns>
    public static List<Guid>? Narrow(List<Guid>? accessibleCaIds, Guid? requestedCaId)
    {
        if (requestedCaId is not Guid wanted) return accessibleCaIds;
        if (accessibleCaIds == null) return [wanted];
        return accessibleCaIds.Contains(wanted) ? [wanted] : [];
    }

    /// <summary>
    /// Narrows an accessible-CA set to the CAs of one tenant (the console's tenant scope).
    /// </summary>
    /// <param name="accessibleCaIds">The CAs the caller may see, or <c>null</c> when unrestricted.</param>
    /// <param name="tenantCaIds">Every CA in the requested tenant, or <c>null</c> when no tenant was requested.</param>
    /// <returns>
    /// <c>null</c> for "everything"; otherwise the intersection, which is empty when the caller
    /// sees nothing in that tenant. The same rule as <see cref="Narrow"/>: a filter narrows, it
    /// never widens.
    /// </returns>
    public static List<Guid>? NarrowToTenant(List<Guid>? accessibleCaIds, List<Guid>? tenantCaIds)
    {
        if (tenantCaIds == null) return accessibleCaIds;
        if (accessibleCaIds == null) return tenantCaIds.ToList();
        return accessibleCaIds.Where(tenantCaIds.Contains).ToList();
    }
}
