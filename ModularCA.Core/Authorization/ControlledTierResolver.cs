using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Authorization;

/// <summary>A controlled tier held by one user.</summary>
public readonly record struct ControlledHolding(Guid UserId, ControlledTier Tier);

/// <summary>
/// Sources to disregard when resolving holdings, so a caller can evaluate the state that a pending
/// removal would leave behind.
/// </summary>
public sealed record ControlledSourceExclusions
{
    /// <summary>A group whose memberships and grants are ignored (the group is being deleted).</summary>
    public Guid? GroupId { get; init; }

    /// <summary>A role whose controlled capabilities are ignored (the role or some capabilities are being removed).</summary>
    public Guid? RoleId { get; init; }

    /// <summary>With <see cref="RoleId"/>: only these capabilities of the role are ignored; null ignores all of them.</summary>
    public IReadOnlyCollection<string>? RoleCapabilities { get; init; }

    /// <summary>A single role assignment that is ignored (it is being unassigned).</summary>
    public Guid? RoleAssignmentId { get; init; }
}

/// <summary>
/// The grant sources a worn badge keeps, for resolving an actor's tiers under that badge. Mirrors
/// the badge filter the authorization resolver applies: group memberships (with their grants and
/// roles), direct role assignments and direct capability grants not listed here do not count.
/// </summary>
/// <param name="GroupIds">Groups whose memberships, grants and role assignments count.</param>
/// <param name="RoleAssignmentIds">Direct role assignments on the user that count.</param>
/// <param name="CapabilityGrantIds">Direct capability grants on the user that count.</param>
public sealed record ControlledSourceFilter(
    IReadOnlyCollection<Guid> GroupIds,
    IReadOnlyCollection<Guid> RoleAssignmentIds,
    IReadOnlyCollection<Guid> CapabilityGrantIds);

/// <summary>
/// Capability-based resolution of controlled-user tiers, shared by the controlled-user ceremony
/// service (Auth) and LDAP group sync (Core), which cannot reference Auth. A tier is derived from
/// what a user can actually do, from every grant source the authorization resolver honours: direct
/// group grants, roles on groups, direct user grants and roles on the user. It mirrors
/// <c>CaGroupAuthorizationService</c>'s scoping (a group's scope comes from the group, a user grant's
/// from its own space/CA) but ignores worn badges, because a tier describes what the account holds.
/// <list type="bullet">
/// <item>system-super: membership of an <see cref="CaGroupEntity.IsSystemTierSuper"/> group.</item>
/// <item>system-admin: <c>system.manage</c> at system scope.</item>
/// <item>space-admin(T): <c>system.manage</c> space-wide in T.</item>
/// <item>ca-admin(X): <c>system.manage</c> on CA X.</item>
/// <item>space-operator(T): <c>ca.manage</c> space-wide in T, which makes the holder a key-ceremony
/// approver for the space.</item>
/// <item>system-operator: <c>ca.manage</c> at instance scope, which makes the holder a key-ceremony
/// approver for every space and the instance.</item>
/// </list>
/// <c>audit.view</c> alone (auditor) confers no tier.
/// </summary>
public static class ControlledTierResolver
{
    /// <summary>Capabilities that can confer a controlled tier at some scope.</summary>
    public static readonly string[] ControlledCapabilities = { Capabilities.SystemManage, Capabilities.CaManage };

    /// <summary>True when <paramref name="capability"/> can confer a controlled tier at some scope.</summary>
    public static bool IsControlledCapability(string? capability) =>
        capability != null && ControlledCapabilities.Contains(capability, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The tier that <paramref name="capability"/> confers at a scope: system when both
    /// <paramref name="spaceId"/> and <paramref name="caId"/> are null, a CA when
    /// <paramref name="caId"/> is set (which wins over the space), otherwise space-wide.
    /// <paramref name="caSpaceId"/> is stamped on CA tiers so a space admin can dominate them.
    /// <c>ca.manage</c> on one CA confers none.
    /// </summary>
    public static ControlledTier? TierFor(string capability, Guid? spaceId, Guid? caId, Guid? caSpaceId)
    {
        if (string.Equals(capability, Capabilities.SystemManage, StringComparison.OrdinalIgnoreCase))
        {
            if (caId != null) return new ControlledTier(ControlledTierLevel.CaAdmin, caId) { SpaceId = caSpaceId };
            if (spaceId != null) return new ControlledTier(ControlledTierLevel.SpaceAdmin, null) { SpaceId = spaceId };
            return new ControlledTier(ControlledTierLevel.SystemAdmin, null);
        }
        if (string.Equals(capability, Capabilities.CaManage, StringComparison.OrdinalIgnoreCase) && caId == null)
            return spaceId != null
                ? new ControlledTier(ControlledTierLevel.SpaceOperator, null) { SpaceId = spaceId }
                : new ControlledTier(ControlledTierLevel.SystemOperator, null);
        return null;
    }

    /// <summary>
    /// The tier a capability held through a group confers; the group's own scope applies. Only
    /// a system group confers a system tier: a non-system group with neither space nor CA
    /// confers none, so a null space can never widen a group into system scope.
    /// </summary>
    public static ControlledTier? TierForGroupCapability(string capability, bool isSystemGroup, Guid? groupSpaceId, Guid? groupCaId)
    {
        if (isSystemGroup) return TierFor(capability, null, null, null);
        if (groupCaId == null && groupSpaceId == null) return null;
        return TierFor(capability, groupSpaceId, groupCaId, groupSpaceId);
    }

    /// <summary>
    /// The tier membership in <paramref name="group"/> confers: the covering tier
    /// (<see cref="ControlledTier.Covering"/>) of the structural classification
    /// (<see cref="ControlledGroupClassifier"/>) and the tiers of every controlled capability the
    /// group holds through direct grants or role assignments. A non-system group that was given a
    /// <c>system.manage</c> role therefore classifies as controlled even though its template says
    /// otherwise.
    /// </summary>
    public static async Task<ControlledTier?> ClassifyGroupAsync(ModularCADbContext db, CaGroupEntity group)
    {
        var caps = ControlledCapabilities;
        var granted = await db.CapabilityGrants.AsNoTracking()
            .Where(g => g.GroupId == group.Id && g.ResourceType == null && caps.Contains(g.Capability))
            .Select(g => g.Capability)
            .ToListAsync();
        var groupId = group.Id;
        var viaRoles = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.GroupId == groupId)
            .Join(db.RoleCapabilities.AsNoTracking()
                    .Where(rc => rc.ResourceType == null && caps.Contains(rc.Capability)),
                ra => ra.RoleId, rc => rc.RoleId, (ra, rc) => rc.Capability)
            .ToListAsync();

        var tiers = granted.Concat(viaRoles)
            .Select(c => TierForGroupCapability(c, group.IsSystemGroup, group.SpaceId, group.CertificateAuthorityId))
            .Append(ControlledGroupClassifier.Classify(group));
        return ControlledTier.Covering(tiers);
    }

    /// <summary>
    /// <see cref="ClassifyGroupAsync"/> for many groups in two queries, keyed by group id: the same
    /// grants, role capabilities and structural classification, read for all of them at once (for
    /// a listing that marks each group controlled or not).
    /// </summary>
    public static async Task<Dictionary<Guid, ControlledTier?>> ClassifyGroupsAsync(ModularCADbContext db, IReadOnlyCollection<CaGroupEntity> groups)
    {
        var caps = ControlledCapabilities;
        var ids = groups.Select(g => g.Id).ToList();
        var granted = await db.CapabilityGrants.AsNoTracking()
            .Where(g => ids.Contains(g.GroupId) && g.ResourceType == null && caps.Contains(g.Capability))
            .Select(g => new { g.GroupId, g.Capability })
            .ToListAsync();
        var viaRoles = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.GroupId != null && ids.Contains(ra.GroupId.Value))
            .Join(db.RoleCapabilities.AsNoTracking()
                    .Where(rc => rc.ResourceType == null && caps.Contains(rc.Capability)),
                ra => ra.RoleId, rc => rc.RoleId, (ra, rc) => new { GroupId = ra.GroupId!.Value, rc.Capability })
            .ToListAsync();
        var byGroup = granted.Concat(viaRoles).ToLookup(x => x.GroupId, x => x.Capability);

        var result = new Dictionary<Guid, ControlledTier?>();
        foreach (var group in groups)
        {
            var tiers = byGroup[group.Id]
                .Select(c => TierForGroupCapability(c, group.IsSystemGroup, group.SpaceId, group.CertificateAuthorityId))
                .Append(ControlledGroupClassifier.Classify(group));
            result[group.Id] = ControlledTier.Covering(tiers);
        }
        return result;
    }

    /// <summary>The distinct tiers <paramref name="userId"/> holds, from every grant source.</summary>
    public static async Task<IReadOnlyList<ControlledTier>> GetUserTiersAsync(ModularCADbContext db, Guid userId)
    {
        var holdings = await LoadHoldingsAsync(db, userId, null);
        return holdings.Select(h => h.Tier).Distinct().ToList();
    }

    /// <summary>
    /// The distinct tiers <paramref name="userId"/> can act with: every grant source when
    /// <paramref name="worn"/> is null (badgeless), otherwise only the sources the worn badge keeps.
    /// For the acting user only; a target account's tiers come from <see cref="GetUserTiersAsync"/>.
    /// </summary>
    public static async Task<IReadOnlyList<ControlledTier>> GetActorTiersAsync(ModularCADbContext db, Guid userId, ControlledSourceFilter? worn)
    {
        var holdings = await LoadHoldingsAsync(db, userId, null, worn);
        return holdings.Select(h => h.Tier).Distinct().ToList();
    }

    /// <summary>
    /// Every controlled tier held by every (non-deleted) user, or by <paramref name="userId"/> only,
    /// after disregarding the sources named in <paramref name="exclusions"/>. When
    /// <paramref name="only"/> is set, just the sources it lists count (a worn badge).
    /// </summary>
    public static async Task<List<ControlledHolding>> LoadHoldingsAsync(
        ModularCADbContext db, Guid? userId, ControlledSourceExclusions? exclusions, ControlledSourceFilter? only = null)
    {
        var caps = ControlledCapabilities;
        var ignoreGroup = exclusions?.GroupId;
        var ignoreRole = exclusions?.RoleId;
        var ignoreRoleCaps = exclusions?.RoleCapabilities;
        var ignoreAssignment = exclusions?.RoleAssignmentId;

        var roleCaps = (await db.RoleCapabilities.AsNoTracking()
                .Where(rc => rc.ResourceType == null && caps.Contains(rc.Capability))
                .Select(rc => new { rc.RoleId, rc.Capability })
                .ToListAsync())
            .Where(rc => !(ignoreRole == rc.RoleId
                && (ignoreRoleCaps == null || ignoreRoleCaps.Contains(rc.Capability, StringComparer.OrdinalIgnoreCase))))
            .ToList();
        var capsByRole = roleCaps.GroupBy(r => r.RoleId).ToDictionary(g => g.Key, g => g.Select(x => x.Capability).ToList());
        var roleIds = capsByRole.Keys.ToList();

        var assignments = (await db.RoleAssignments.AsNoTracking()
                .Where(ra => roleIds.Contains(ra.RoleId) && (ra.GroupId != null || userId == null || ra.UserId == userId))
                .Select(ra => new { ra.Id, ra.RoleId, ra.GroupId, ra.UserId, ra.SpaceId, ra.CertificateAuthorityId })
                .ToListAsync())
            .Where(ra => ra.Id != ignoreAssignment
                && (only == null || ra.GroupId != null || only.RoleAssignmentIds.Contains(ra.Id)))
            .ToList();

        // Group-sourced capabilities.
        var groupCaps = new Dictionary<Guid, List<string>>();
        void AddGroupCap(Guid gid, string cap)
        {
            if (!groupCaps.TryGetValue(gid, out var list)) groupCaps[gid] = list = new List<string>();
            list.Add(cap);
        }
        foreach (var g in await db.CapabilityGrants.AsNoTracking()
                     .Where(g => g.ResourceType == null && caps.Contains(g.Capability))
                     .Select(g => new { g.GroupId, g.Capability })
                     .ToListAsync())
            AddGroupCap(g.GroupId, g.Capability);
        foreach (var ra in assignments.Where(a => a.GroupId != null))
            foreach (var cap in capsByRole[ra.RoleId])
                AddGroupCap(ra.GroupId!.Value, cap);

        var capGroupIds = groupCaps.Keys.ToList();
        var groups = await db.CaGroups.AsNoTracking()
            .Where(g => (capGroupIds.Contains(g.Id) || g.IsSystemTierSuper) && (ignoreGroup == null || g.Id != ignoreGroup))
            .Select(g => new { g.Id, g.IsSystemGroup, g.IsSystemTierSuper, g.SpaceId, g.CertificateAuthorityId })
            .ToListAsync();

        var tiersByGroup = new Dictionary<Guid, List<ControlledTier>>();
        foreach (var g in groups)
        {
            var tiers = new List<ControlledTier>();
            if (g.IsSystemTierSuper) tiers.Add(new ControlledTier(ControlledTierLevel.SystemSuper, null));
            if (groupCaps.TryGetValue(g.Id, out var gc))
                foreach (var cap in gc)
                    if (TierForGroupCapability(cap, g.IsSystemGroup, g.SpaceId, g.CertificateAuthorityId) is { } t)
                        tiers.Add(t);
            if (tiers.Count > 0) tiersByGroup[g.Id] = tiers;
        }

        var tierGroupIds = tiersByGroup.Keys.ToList();
        var members = await db.CaGroupMembers.AsNoTracking()
            .Where(m => tierGroupIds.Contains(m.GroupId) && (userId == null || m.UserId == userId))
            .Select(m => new { m.UserId, m.GroupId })
            .ToListAsync();
        if (only != null) members.RemoveAll(m => !only.GroupIds.Contains(m.GroupId));

        var holdings = new HashSet<ControlledHolding>();
        foreach (var m in members)
            foreach (var t in tiersByGroup[m.GroupId])
                holdings.Add(new ControlledHolding(m.UserId, t));

        // User-sourced capabilities.
        var userGrants = await db.UserCapabilityGrants.AsNoTracking()
            .Where(ug => ug.ResourceType == null && caps.Contains(ug.Capability) && (userId == null || ug.UserId == userId))
            .Select(ug => new { ug.Id, ug.UserId, ug.Capability, ug.SpaceId, ug.CertificateAuthorityId })
            .ToListAsync();
        if (only != null) userGrants.RemoveAll(ug => !only.CapabilityGrantIds.Contains(ug.Id));
        var userAssignments = assignments.Where(a => a.GroupId == null && a.UserId != null).ToList();

        var caIds = userGrants.Select(g => g.CertificateAuthorityId)
            .Concat(userAssignments.Select(a => a.CertificateAuthorityId))
            .Where(id => id != null).Select(id => id!.Value).Distinct().ToList();
        var caSpaces = caIds.Count == 0
            ? new Dictionary<Guid, Guid?>()
            : await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(c => caIds.Contains(c.Id))
                .ToDictionaryAsync(c => c.Id, c => c.SpaceId);
        Guid? CaSpace(Guid? caId) => caId is Guid id && caSpaces.TryGetValue(id, out var t) ? t : null;

        foreach (var ug in userGrants)
            if (TierFor(ug.Capability, ug.SpaceId, ug.CertificateAuthorityId, CaSpace(ug.CertificateAuthorityId)) is { } t)
                holdings.Add(new ControlledHolding(ug.UserId, t));
        foreach (var ra in userAssignments)
            foreach (var cap in capsByRole[ra.RoleId])
                if (TierFor(cap, ra.SpaceId, ra.CertificateAuthorityId, CaSpace(ra.CertificateAuthorityId)) is { } t)
                    holdings.Add(new ControlledHolding(ra.UserId!.Value, t));

        if (userId != null) return holdings.ToList();

        // A soft-deleted account holds nothing.
        var holderIds = holdings.Select(h => h.UserId).Distinct().ToList();
        var live = (await db.Users.AsNoTracking().Where(u => holderIds.Contains(u.Id)).Select(u => u.Id).ToListAsync()).ToHashSet();
        return holdings.Where(h => live.Contains(h.UserId)).ToList();
    }

    /// <summary>
    /// Takes a row lock on the role for the rest of the current transaction (PostgreSQL only), so a
    /// capability change on the role and an assignment of the role serialise: whichever runs second
    /// sees the other's committed rows. A no-op on providers without row locks (unit tests).
    /// </summary>
    public static async Task LockRoleAsync(ModularCADbContext db, Guid roleId)
    {
        if (db.Database.IsNpgsql())
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM \"Roles\" WHERE \"Id\" = {roleId} FOR UPDATE");
    }
}
