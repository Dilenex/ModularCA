namespace ModularCA.Auth.Authorization;

/// <summary>
/// The worn badge as the authorization resolver sees it: the grant sources that still count.
/// </summary>
/// <remarks>
/// Badgeless is represented by the absence of a filter (<c>null</c>), not by an object that
/// allows everything, so there is no "all my rights" badge anywhere in the code. A worn badge
/// that no longer exists, or belongs to someone else, resolves to an empty filter and grants
/// nothing: failing closed is the only safe reading of a claim that names a missing badge.
/// </remarks>
/// <param name="BadgeId">The badge named by the token.</param>
/// <param name="Name">Its name, for audit rows and the console banner.</param>
/// <param name="GroupIds">Groups whose memberships, grants and role assignments count.</param>
/// <param name="RoleAssignmentIds">Direct role assignments on the user that count.</param>
/// <param name="CapabilityGrantIds">Direct capability grants on the user that count.</param>
public sealed record AccessBadgeFilter(
    Guid BadgeId,
    string Name,
    IReadOnlyList<Guid> GroupIds,
    IReadOnlyList<Guid> RoleAssignmentIds,
    IReadOnlyList<Guid> CapabilityGrantIds)
{
    /// <summary>A filter that keeps nothing, for a claim naming a badge that cannot be honoured.</summary>
    public static AccessBadgeFilter Nothing(Guid badgeId) => new(badgeId, string.Empty, [], [], []);
}

/// <summary>
/// The worn badge for the current request, resolved once from the access token's claim.
/// </summary>
public interface IAccessBadgeContext
{
    /// <summary>
    /// The filter for the badge the current request wears, or <c>null</c> when badgeless or
    /// outside an HTTP request (scheduled jobs, protocol clients). Cached per request.
    /// </summary>
    Task<AccessBadgeFilter?> GetWornAsync(Guid userId);
}
