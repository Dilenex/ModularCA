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
}
