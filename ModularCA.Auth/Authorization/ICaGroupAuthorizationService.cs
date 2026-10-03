using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Central permission resolver for the capability-based authorization model.
/// Determines a user's effective permissions based on their group memberships
/// and the capability grants attached to those groups.
/// </summary>
public interface ICaGroupAuthorizationService
{
    /// <summary>
    /// Checks if the user has the specified capability via any system group.
    /// </summary>
    Task<bool> HasSystemCapabilityAsync(Guid userId, string capability);

    /// <summary>
    /// Checks if the user has the specified capability for a specific CA
    /// (through system, space-wide, or CA-scoped groups).
    /// Users with system.manage implicitly have access to all CAs.
    /// </summary>
    Task<bool> HasCaCapabilityAsync(Guid userId, Guid caId, string capability);

    /// <summary>
    /// Checks if the user has the specified capability for a whole space: held at system
    /// scope, through a space-wide group, or through a space-scoped role or grant on the
    /// user. A grant on one CA of the space does not count. Users with system.manage
    /// implicitly have access to every space.
    /// </summary>
    Task<bool> HasSpaceCapabilityAsync(Guid userId, Guid spaceId, string capability);

    /// <summary>
    /// The spaces for which the user holds the capability space-wide, from the same four
    /// sources as <see cref="HasSpaceCapabilityAsync"/>. System-scoped holders are not
    /// expanded to every space; check <see cref="HasSystemCapabilityAsync"/> for that.
    /// </summary>
    Task<List<Guid>> GetSpaceIdsWithCapabilityAsync(Guid userId, string capability);

    /// <summary>
    /// Canonical "is the caller a system super-admin?" check. Returns true when the user
    /// holds <see cref="ModularCA.Shared.Authorization.Capabilities.SystemManage"/> via
    /// any of the four grant sources (direct group grant, role via group, direct user
    /// grant, role via user).
    /// <para>
    /// <b>This is the One True Way to answer the yes/no super-admin question.</b> Three
    /// equivalent forms are allowed at call-sites:
    /// </para>
    /// <list type="bullet">
    /// <item>In a controller action (sync lookup, no DB hit): use
    /// <c>HttpContext.Items["IsSystemAdmin"] is true</c>. The key is populated once per
    /// request by <c>SpaceFenceMiddleware</c> using the identical four-source check.</item>
    /// <item>Outside an HTTP request or when the Items collection is not available: call
    /// this method.</item>
    /// <item>For scoped auth ("does the user hold capability X on resource Y?") use
    /// <see cref="HasSystemCapabilityAsync"/>, <see cref="HasCaCapabilityAsync"/>, or
    /// <see cref="HasResourceCapabilityAsync"/> with the specific capability constant.</item>
    /// </list>
    /// <para>
    /// <b>Do NOT</b> open-code this check with literal group-name strings
    /// (<c>g.Name == "system-super"</c>, <c>g.Name == "system-admin"</c>) or with
    /// ad-hoc <c>CaGroupMembers.Any(...IsSystemGroup...)</c> queries — those patterns
    /// silently drift from the canonical semantics when bootstrap group names or grant
    /// sources change. Audit-finding #49 tracked the rewrite of the offenders.
    /// </para>
    /// <para>
    /// <b>Tier-check caveat:</b> both the <c>system-super</c> and <c>system-admin</c>
    /// bootstrap groups hold <c>SystemManage</c>, so this method returns true for members
    /// of either. Code that needs to distinguish the two tiers (e.g. "system groups
    /// are writable only by the super tier") reads <c>CaGroupEntity.IsSystemTierSuper</c>
    /// for the super-tier predicate and <c>IsSystemGroup &amp;&amp; !IsSystemTierSuper</c>
    /// for the admin-tier predicate. Do NOT introduce new <c>g.Name == "system-..."</c>
    /// literal-string checks — those are tracked tech debt that produces silent
    /// authz bypass when bootstrap renames the group.
    /// </para>
    /// </summary>
    Task<bool> IsSystemAdminAsync(Guid userId);

    /// <summary>
    /// The user's space fence, from all four grant sources and respecting a worn badge: system
    /// admin; the capabilities held at system scope, each of which makes the fence instance-wide
    /// for that capability (<see cref="SpaceFence.For"/>); the spaces of the user's groups, of
    /// space-scoped grants and roles on the user, and of the CAs the user holds CA-scoped grants
    /// or roles on; and instance scope from an instance CA's group, or a CA-scoped grant or role
    /// on an instance CA. That raw fence is the union over every capability; it also records,
    /// per capability, the spaces and whether the instance in which a group, grant or role confers
    /// it, and <see cref="SpaceFence.For"/> selects from those.
    /// </summary>
    Task<SpaceFence> GetFenceAsync(Guid userId);

    /// <summary>
    /// Gets all groups the user belongs to.
    /// </summary>
    Task<List<CaGroupEntity>> GetUserGroupsAsync(Guid userId);

    /// <summary>
    /// Resolves everything the user may do, across all four grant sources, as the
    /// capabilities held at system scope plus the capabilities that apply on each CA. One
    /// call, a handful of queries; this is what <c>GET /api/v1/me</c> reports so the console
    /// can derive navigation and scope from capabilities rather than role names.
    /// </summary>
    Task<EffectiveCapabilities> GetEffectiveCapabilitiesAsync(Guid userId);

    /// <summary>
    /// Gets all CA IDs the user has the specified capability for.
    /// Users with system.manage get all CA IDs.
    /// </summary>
    Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability);

    /// <summary>
    /// Gets all CA IDs the user has the specified capability for,
    /// filtered to a specific space.
    /// </summary>
    Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability, Guid? spaceId);

    /// <summary>
    /// Checks if the user has a resource-scoped capability grant (e.g. profile.use on a specific CertProfile).
    /// Matches both exact ResourceId grants and wildcard grants (ResourceId == null).
    /// </summary>
    Task<bool> HasResourceCapabilityAsync(Guid userId, string capability, string resourceType, Guid resourceId);

    /// <summary>
    /// Returns all resource IDs the user has any grant for (matching the capability prefix and resource type),
    /// plus a flag indicating whether the user holds a wildcard grant (ResourceId == null) meaning all resources.
    /// Used for batch-filtering listing endpoints.
    /// </summary>
    Task<(List<Guid> ResourceIds, bool HasWildcard)> GetGrantedResourceIdsAsync(
        Guid userId, string capabilityPrefix, string resourceType);
}
