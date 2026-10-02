using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Default <see cref="IControlledUserCeremonyService"/>. Mirrors
/// <c>TenantPolicyChangeService</c>: opens a <see cref="CeremonyType.ControlledUserChange"/>
/// ceremony via <see cref="IKeyCeremonyService"/> with the deferred change in
/// <c>ParametersJson</c>, and applies it on execute. Tiers come from effective capability across
/// every grant source (<see cref="ControlledTierResolver"/>), not from group structure alone.
/// The acting user's tiers (initiate, approve, super) honour the worn badge from
/// <paramref name="badges"/>; a target account's tiers never do.
/// </summary>
public class ControlledUserCeremonyService(
    ModularCADbContext db,
    IKeyCeremonyService keyCeremonyService,
    IUserManagementService userService,
    ILogger<ControlledUserCeremonyService> logger,
    IAccessBadgeContext? badges = null) : IControlledUserCeremonyService
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    /// <inheritdoc />
    public ControlledTier? ClassifyCapabilityGrant(string capability, Guid? certificateAuthorityId, Guid? tenantId = null)
    {
        if (string.IsNullOrWhiteSpace(capability)) return null;
        // A CA-scoped grant is minted without the CA's tenant, so only system-tier or same-CA
        // holders dominate it (stricter than the tier the grant eventually confers).
        return ControlledTierResolver.TierFor(capability, tenantId, certificateAuthorityId, null);
    }

    /// <inheritdoc />
    public async Task<ControlledTier?> ClassifyRoleAssignmentAsync(Guid roleId, Guid? certificateAuthorityId, Guid? tenantId = null, Guid? groupId = null)
    {
        var caps = ControlledTierResolver.ControlledCapabilities;
        var roleCaps = await db.RoleCapabilities.AsNoTracking()
            .Where(rc => rc.RoleId == roleId && rc.ResourceType == null && caps.Contains(rc.Capability))
            .Select(rc => rc.Capability)
            .ToListAsync();
        if (roleCaps.Count == 0) return null;

        // A role on a group takes the group's scope, exactly as the authorization resolver reads it.
        if (groupId != null)
        {
            var group = await db.CaGroups.AsNoTracking().FirstOrDefaultAsync(g => g.Id == groupId);
            if (group != null)
                return ControlledTierResolver.Strongest(roleCaps.Select(c =>
                    ControlledTierResolver.TierForGroupCapability(c, group.IsSystemGroup, group.TenantId, group.CertificateAuthorityId)));
        }
        return ControlledTierResolver.Strongest(roleCaps.Select(c =>
            ControlledTierResolver.TierFor(c, tenantId, certificateAuthorityId, null)));
    }

    /// <summary>
    /// The tiers that <paramref name="capabilities"/> on role <paramref name="roleId"/> confer through
    /// the role's current assignments and through pending or approved-but-unexecuted
    /// <c>AssignRole</c> ceremonies, so a role awaiting a ceremony-gated assignment counts as assigned.
    /// </summary>
    public async Task<IReadOnlyList<ControlledTier>> TiersConferredByRoleAsync(Guid roleId, IEnumerable<string> capabilities)
    {
        var caps = capabilities.Where(ControlledTierResolver.IsControlledCapability).ToList();
        if (caps.Count == 0) return Array.Empty<ControlledTier>();

        var assignments = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.RoleId == roleId)
            .Select(ra => new ScopedAssignment(ra.TenantId, ra.CertificateAuthorityId, ra.GroupId))
            .ToListAsync();

        var roleIdText = roleId.ToString();
        var open = await db.KeyCeremonies.AsNoTracking()
            .Where(c => c.OperationType == "ControlledUserChange"
                && (c.Status == "Pending" || c.Status == "Approved")
                && c.ParametersJson.Contains(roleIdText))
            .ToListAsync();
        foreach (var c in open)
        {
            var p = Deserialize(c);
            if (p is { ChangeType: "AssignRole" } && p.RoleId == roleId)
                assignments.Add(new ScopedAssignment(p.TenantId, p.CertificateAuthorityId, p.GroupId));
        }

        var groupIds = assignments.Where(a => a.GroupId != null).Select(a => a.GroupId!.Value).Distinct().ToList();
        var groups = await db.CaGroups.AsNoTracking()
            .Where(g => groupIds.Contains(g.Id))
            .ToDictionaryAsync(g => g.Id);

        var tiers = new HashSet<ControlledTier>();
        foreach (var a in assignments)
            foreach (var c in caps)
            {
                ControlledTier? t;
                if (a.GroupId is Guid gid)
                {
                    if (!groups.TryGetValue(gid, out var g)) continue;
                    t = ControlledTierResolver.TierForGroupCapability(c, g.IsSystemGroup, g.TenantId, g.CertificateAuthorityId);
                }
                else
                    t = ControlledTierResolver.TierFor(c, a.TenantId, a.CertificateAuthorityId, null);
                if (t != null) tiers.Add(t.Value);
            }
        return tiers.ToList();
    }

    private sealed record ScopedAssignment(Guid? TenantId, Guid? CertificateAuthorityId, Guid? GroupId);

    /// <inheritdoc />
    public Task<ControlledTier?> ClassifyGroupAsync(CaGroupEntity group) => ControlledTierResolver.ClassifyGroupAsync(db, group);

    /// <summary>
    /// True when <paramref name="userId"/>, the acting user, is system-super under the badge they
    /// wear: a worn badge counts the super group only when it includes that group.
    /// </summary>
    public async Task<bool> IsSuperAsync(Guid userId)
    {
        var worn = await WornSourcesAsync(userId);
        var superGroups = await db.CaGroupMembers
            .Where(m => m.UserId == userId && m.Group.IsSystemTierSuper)
            .Select(m => m.GroupId)
            .ToListAsync();
        return worn == null ? superGroups.Count > 0 : superGroups.Any(worn.GroupIds.Contains);
    }

    /// <summary>True when the account <paramref name="userId"/> is system-super, ignoring any worn badge.</summary>
    private Task<bool> IsSuperAccountAsync(Guid userId)
        => db.CaGroupMembers.AnyAsync(m => m.UserId == userId && m.Group.IsSystemTierSuper);

    /// <inheritdoc />
    public Task<IReadOnlyList<ControlledTier>> GetUserTiersAsync(Guid userId) => ControlledTierResolver.GetUserTiersAsync(db, userId);

    /// <inheritdoc />
    public async Task<IReadOnlyList<ControlledTier>> GetActorTiersAsync(Guid actorUserId)
        => await ControlledTierResolver.GetActorTiersAsync(db, actorUserId, await WornSourcesAsync(actorUserId));

    /// <summary>
    /// The grant sources the acting user's worn badge keeps, or null when badgeless or outside a
    /// request. Must be called for the request's own user: the badge context resolves the token's
    /// badge and fails closed (keeps nothing) for any other user id.
    /// </summary>
    private async Task<ControlledSourceFilter?> WornSourcesAsync(Guid actorUserId)
    {
        var filter = badges == null ? null : await badges.GetWornAsync(actorUserId);
        return filter == null ? null : new ControlledSourceFilter(filter.GroupIds, filter.RoleAssignmentIds, filter.CapabilityGrantIds);
    }

    /// <summary>
    /// The tier an approver must dominate to delete <paramref name="userId"/>: the user's strongest
    /// tier when it dominates every other tier they hold (e.g. org-admin(T) over ca-admin(X in T)),
    /// otherwise system-admin, because the holdings span scopes (two tenants, two CAs, or a CA and
    /// a tenant-wide operator tier) that no single scoped approver covers. Null when the user holds
    /// no controlled tier.
    /// </summary>
    public async Task<ControlledTier?> GetDeletionTierAsync(Guid userId)
    {
        var tiers = await GetUserTiersAsync(userId);
        if (tiers.Count == 0) return null; // not a controlled user — delete is uncontrolled

        if (tiers.Any(t => t.Level == ControlledTierLevel.SystemSuper))
            return new ControlledTier(ControlledTierLevel.SystemSuper, null);
        if (tiers.Any(t => t.Level == ControlledTierLevel.SystemAdmin))
            return new ControlledTier(ControlledTierLevel.SystemAdmin, null);

        var strongest = ControlledTierResolver.Strongest(tiers.Select(t => (ControlledTier?)t))!.Value;
        return tiers.All(strongest.Dominates)
            ? strongest
            : new ControlledTier(ControlledTierLevel.SystemAdmin, null);
    }

    /// <inheritdoc />
    public Task<int> CountDominatingControlledUsersAsync(
        ControlledTier minted, Guid excludeUserId, Guid? ignoreGroupId = null, Guid? actorUserId = null, Guid? ignoreRoleAssignmentId = null)
        => CountDominatorsAsync(minted, excludeUserId, actorUserId,
            new ControlledSourceExclusions { GroupId = ignoreGroupId, RoleAssignmentId = ignoreRoleAssignmentId });

    /// <summary>
    /// Counts users whose remaining tiers (after <paramref name="exclusions"/>) dominate
    /// <paramref name="minted"/>, without <paramref name="excludeUserId"/>. A non-super actor is also
    /// left out: an initiator never counts toward a ceremony's quorum, so a scope whose only
    /// dominating user is that actor could no longer approve anything. A super actor is counted,
    /// because supers act directly and dominate every scope; a super may therefore remove the last
    /// non-super admin of a scope. Only accounts that can act count: active, not hard-locked, not
    /// service identities, and holding the tier through a CA/tenant that is not soft-deleted.
    /// </summary>
    /// <remarks>
    /// <paramref name="actorIsRequestUser"/> is false when the actor is not the caller (the initiator
    /// of a ceremony being executed): their super status is then read without the caller's badge.
    /// </remarks>
    private async Task<int> CountDominatorsAsync(ControlledTier minted, Guid excludeUserId, Guid? actorUserId, ControlledSourceExclusions exclusions, bool actorIsRequestUser = true)
    {
        var holdings = await ControlledTierResolver.LoadHoldingsAsync(db, null, exclusions);
        var candidates = holdings.Where(h => h.Tier.Dominates(minted) && h.UserId != excludeUserId).ToList();
        if (actorUserId is Guid actor && !(actorIsRequestUser ? await IsSuperAsync(actor) : await IsSuperAccountAsync(actor)))
            candidates.RemoveAll(h => h.UserId == actor);
        if (candidates.Count == 0) return 0;

        var userIds = candidates.Select(h => h.UserId).Distinct().ToList();
        var usable = (await db.Users.AsNoTracking()
                .Where(u => userIds.Contains(u.Id) && u.IsActive && !u.IsLocked && !u.IsServiceIdentity)
                .Select(u => u.Id)
                .ToListAsync())
            .ToHashSet();

        var caIds = candidates.Where(h => h.Tier.CaId != null).Select(h => h.Tier.CaId!.Value).Distinct().ToList();
        var liveCas = (await db.CertificateAuthorities.AsNoTracking()
                .Where(c => caIds.Contains(c.Id) && !c.IsDeleted)
                .Select(c => c.Id)
                .ToListAsync())
            .ToHashSet();
        var tenantIds = candidates.Where(h => h.Tier.TenantId != null).Select(h => h.Tier.TenantId!.Value).Distinct().ToList();
        var liveTenants = (await db.Tenants.AsNoTracking()
                .Where(t => tenantIds.Contains(t.Id) && !t.IsDeleted)
                .Select(t => t.Id)
                .ToListAsync())
            .ToHashSet();

        return candidates
            .Where(h => usable.Contains(h.UserId)
                && (h.Tier.CaId is not Guid ca || liveCas.Contains(ca))
                && (h.Tier.TenantId is not Guid t || liveTenants.Contains(t)))
            .Select(h => h.UserId)
            .Distinct()
            .Count();
    }

    /// <inheritdoc />
    public async Task<bool> CanAdministerAccountAsync(Guid actorUserId, Guid targetUserId)
    {
        if (await IsSuperAsync(actorUserId)) return true;

        var targetTiers = await GetUserTiersAsync(targetUserId);
        if (targetTiers.Any(t => t.Level == ControlledTierLevel.SystemSuper)) return false;
        var actorTiers = await GetActorTiersAsync(actorUserId);

        // System-group members without a tier (system operators and auditors) hold system-wide
        // rights, including key-ceremony approval for every tenant; only system-admin administers them.
        if (await db.CaGroupMembers.AnyAsync(m => m.UserId == targetUserId && m.Group.IsSystemGroup)
            && !actorTiers.Any(a => a.Level == ControlledTierLevel.SystemAdmin))
            return false;

        return targetTiers.All(t => actorTiers.Any(a => a.Dominates(t)));
    }

    /// <inheritdoc />
    public async Task<bool> IsLastControlledSourceForRoleAsync(
        Guid roleId, ControlledTier minted, Guid? actorUserId = null, IReadOnlyCollection<string>? removedCapabilities = null)
        => await CountDominatorsAsync(minted, Guid.Empty, actorUserId,
            new ControlledSourceExclusions { RoleId = roleId, RoleCapabilities = removedCapabilities }) == 0;

    /// <inheritdoc />
    public async Task<bool> CanInitiateAsync(Guid userId, ControlledTier minted)
    {
        var tiers = await GetActorTiersAsync(userId);
        return tiers.Any(t => t.Dominates(minted));
    }

    /// <inheritdoc />
    public async Task<bool> CanApproveAsync(Guid approverUserId, KeyCeremonyEntity ceremony)
    {
        var p = Deserialize(ceremony);
        if (p == null) return false;

        // The user being promoted/demoted can't approve their own privilege change.
        if (approverUserId == p.TargetUserId) return false;

        var minted = new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { TenantId = p.MintedTierTenantId };
        var tiers = await GetActorTiersAsync(approverUserId);
        return tiers.Any(t => t.Dominates(minted));
    }

    /// <inheritdoc />
    public (Guid? TargetUserId, ControlledTier? Minted) DescribeCeremony(KeyCeremonyEntity ceremony)
    {
        var p = Deserialize(ceremony);
        if (p == null) return (null, null);
        return (p.TargetUserId == Guid.Empty ? null : p.TargetUserId,
            new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { TenantId = p.MintedTierTenantId });
    }

    /// <inheritdoc />
    public Task<Guid> InitiateCapabilityGrantAsync(
        Guid targetUserId,
        string? targetUsername,
        string capability,
        Guid? tenantId,
        Guid? certificateAuthorityId,
        string? resourceType,
        Guid? resourceId,
        ControlledTier minted,
        Guid initiatorUserId,
        string initiatorUsername)
    {
        var parameters = new ControlledUserChangeParameters
        {
            ChangeType = "GrantCapability",
            TargetUserId = targetUserId,
            TargetUsername = targetUsername,
            Capability = capability,
            TenantId = tenantId,
            CertificateAuthorityId = certificateAuthorityId,
            ResourceType = resourceType,
            ResourceId = resourceId,
        };
        return InitiateChangeAsync(parameters, minted, initiatorUserId, initiatorUsername);
    }

    /// <summary>
    /// Opens a <c>ControlledUserChange</c> ceremony for <paramref name="parameters"/>, recording the
    /// minted tier in the parameters and stamping the ceremony's tenant from the tier's scope (the
    /// tier's tenant, or its CA's tenant) so scoped approvers can reach it. System tiers leave the
    /// tenant null, which keeps the ceremony system-only.
    /// </summary>
    public async Task<Guid> InitiateChangeAsync(
        ControlledUserChangeParameters parameters,
        ControlledTier minted,
        Guid initiatorUserId,
        string initiatorUsername)
    {
        // The minted tier is authoritative for later approver-dominance checks.
        parameters.MintedTierLevel = (int)minted.Level;
        parameters.MintedTierCaId = minted.CaId;
        parameters.MintedTierTenantId = minted.TenantId;

        var quorum = await ResolveUserQuorumAsync(minted);

        var ceremony = await keyCeremonyService.InitiateAsync(
            operationType: "ControlledUserChange",
            description: DescribeChange(parameters, minted),
            targetEntityId: (parameters.TargetUserId != Guid.Empty
                ? parameters.TargetUserId
                : parameters.GroupId)?.ToString() ?? "-",
            initiatorUserId: initiatorUserId,
            initiatorUsername: initiatorUsername,
            parametersJson: JsonSerializer.Serialize(parameters),
            quorumOverride: quorum);

        // The base InitiateAsync doesn't know the ControlledUserChange enum value — stamp it.
        var tracked = await db.KeyCeremonies.FindAsync(ceremony.Id)
            ?? throw new InvalidOperationException($"Newly-created ceremony {ceremony.Id} could not be re-loaded.");
        tracked.CeremonyType = CeremonyType.ControlledUserChange;
        tracked.TenantId = await ScopeTenantAsync(minted);
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Initiated ControlledUserChange ceremony {CeremonyId} ({ChangeType}, tier {Tier}, quorum {Quorum}, initiator {Initiator}).",
            tracked.Id, parameters.ChangeType, minted.Level, quorum, initiatorUserId);

        return tracked.Id;
    }

    private static string DescribeChange(ControlledUserChangeParameters p, ControlledTier minted)
    {
        var who = p.TargetUsername
                  ?? (p.TargetUserId != Guid.Empty ? p.TargetUserId.ToString() : (p.GroupId?.ToString() ?? "?"));
        var scope = minted.CaId != null ? $" on CA {minted.CaId}" : " (system)";
        return p.ChangeType switch
        {
            "GrantCapability" => $"Promote controlled user {who}: grant '{p.Capability}'{scope}",
            "AssignRole" => $"Promote controlled user {who}: assign role {p.RoleId}{scope}",
            "AddGroupMember" => $"Promote controlled user {who}: add to group {p.GroupId}{scope}",
            "RevokeCapability" => $"Demote controlled user {who}: revoke '{p.Capability}'{scope}",
            "UnassignRole" => $"Demote controlled user {who}: unassign role {p.RoleId}{scope}",
            "RemoveGroupMember" => $"Demote controlled user {who}: remove from group {p.GroupId}{scope}",
            "DeleteUser" => $"Delete controlled user {who}{scope}",
            _ => $"Controlled-user change ({p.ChangeType}) for {who}{scope}",
        };
    }

    /// <summary>
    /// Applies an approved controlled-user ceremony. Inside a transaction it locks the ceremony row
    /// and re-reads its status, so of two concurrent executes only one finds it Approved; the other
    /// gets <see cref="CeremonyNotExecutableException"/>. It then takes the role lock where a role is
    /// involved and recomputes the tier the change confers or removes now. When that tier is higher
    /// than the approved one, or the recorded approvals no longer hold enough active approvers
    /// dominating it, the ceremony is marked Expired and a
    /// <see cref="ControlledUserChangeRefusedException"/> is thrown. A demotion or deletion that would
    /// leave its scope without a dominating user is refused the same way but stays Approved.
    /// Otherwise the ceremony is marked Executed in the same transaction as the change.
    /// </summary>
    public async Task<ControlledUserChangeResult> ApplyApprovedAsync(Guid ceremonyId)
    {
        await using var tx = db.Database.CurrentTransaction == null ? await db.Database.BeginTransactionAsync() : null;

        await ModularCA.Core.Services.KeyCeremonyService.LockRowAsync(db, ceremonyId);
        var ceremony = await db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException($"Ceremony {ceremonyId} not found.");
        await db.Entry(ceremony).ReloadAsync();

        if (ceremony.Status != "Approved")
            throw new CeremonyNotExecutableException(ceremonyId, ceremony.Status);

        var p = Deserialize(ceremony)
            ?? throw new InvalidOperationException($"Ceremony {ceremonyId} parameters could not be deserialized.");

        var approved = new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { TenantId = p.MintedTierTenantId };
        var (current, stale) = await RecomputeTierAsync(p);
        if (stale == null && current is { } now && !approved.Dominates(now))
            stale = "it now confers a higher privilege tier than the one approved";
        if (stale == null && !await ApprovalsStillCoverAsync(ceremony, p, approved, current))
            stale = "the recorded approvals no longer include enough active approvers who dominate it";
        if (stale != null)
        {
            ceremony.Status = "Expired";
            await db.SaveChangesAsync();
            if (tx != null) await tx.CommitAsync();
            logger.LogWarning("Refused ControlledUserChange ceremony {CeremonyId} at execute: {Reason}.", ceremonyId, stale);
            throw new ControlledUserChangeRefusedException(
                $"The privilege changed after approval ({stale}); start a new ceremony.", ceremonyExpired: true);
        }

        if (current is { } removed && p.ChangeType is "RevokeCapability" or "UnassignRole" or "RemoveGroupMember" or "DeleteUser"
            && await CountDominatorsAsync(removed, p.TargetUserId, ceremony.InitiatedByUserId,
                new ControlledSourceExclusions { RoleAssignmentId = p.ChangeType == "UnassignRole" ? p.RecordId : null },
                actorIsRequestUser: false) == 0)
        {
            if (tx != null) await tx.RollbackAsync();
            throw new ControlledUserChangeRefusedException(
                "Refusing this change: it would remove the last controlled user of this scope.", ceremonyExpired: false);
        }

        ceremony.Status = "Executed";
        ceremony.ExecutedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        switch (p.ChangeType)
        {
            case "GrantCapability":
                {
                    if (string.IsNullOrWhiteSpace(p.Capability))
                        throw new InvalidOperationException($"Ceremony {ceremonyId} has no capability to grant.");

                    // A CA-scoped grant is effective on its CA whatever tenant it records.
                    var exists = await db.UserCapabilityGrants.AnyAsync(g =>
                        g.UserId == p.TargetUserId
                        && g.Capability == p.Capability
                        && (p.CertificateAuthorityId != null
                            ? g.CertificateAuthorityId == p.CertificateAuthorityId
                            : g.CertificateAuthorityId == null && g.TenantId == p.TenantId)
                        && g.ResourceType == p.ResourceType
                        && g.ResourceId == p.ResourceId);

                    if (!exists)
                    {
                        db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
                        {
                            UserId = p.TargetUserId,
                            Capability = p.Capability,
                            TenantId = p.TenantId,
                            CertificateAuthorityId = p.CertificateAuthorityId,
                            ResourceType = p.ResourceType,
                            ResourceId = p.ResourceId,
                            GrantedByUserId = ceremony.InitiatedByUserId,
                        });
                        await db.SaveChangesAsync();
                    }
                    break;
                }
            case "AssignRole":
                {
                    if (p.RoleId == null)
                        throw new InvalidOperationException($"Ceremony {ceremonyId} has no role to assign.");

                    var userId = p.TargetUserId != Guid.Empty ? (Guid?)p.TargetUserId : null;
                    var exists = await db.RoleAssignments.AnyAsync(ra =>
                        ra.RoleId == p.RoleId
                        && ra.UserId == userId
                        && ra.GroupId == p.GroupId
                        && ra.TenantId == p.TenantId
                        && ra.CertificateAuthorityId == p.CertificateAuthorityId);

                    if (!exists)
                    {
                        db.RoleAssignments.Add(new RoleAssignmentEntity
                        {
                            RoleId = p.RoleId.Value,
                            UserId = userId,
                            GroupId = p.GroupId,
                            TenantId = p.TenantId,
                            CertificateAuthorityId = p.CertificateAuthorityId,
                            AssignedByUserId = ceremony.InitiatedByUserId,
                        });
                        await db.SaveChangesAsync();
                    }
                    break;
                }
            case "AddGroupMember":
                {
                    if (p.GroupId == null || p.TargetUserId == Guid.Empty)
                        throw new InvalidOperationException($"Ceremony {ceremonyId} is missing the group or target user.");

                    var exists = await db.CaGroupMembers.AnyAsync(m =>
                        m.GroupId == p.GroupId && m.UserId == p.TargetUserId);
                    if (!exists)
                    {
                        db.CaGroupMembers.Add(new CaGroupMemberEntity
                        {
                            GroupId = p.GroupId.Value,
                            UserId = p.TargetUserId,
                            AddedByUserId = ceremony.InitiatedByUserId,
                        });
                        await db.SaveChangesAsync();
                    }
                    break;
                }
            case "RevokeCapability":
                {
                    if (p.RecordId != null)
                    {
                        var grant = await db.UserCapabilityGrants.FindAsync(p.RecordId.Value);
                        if (grant != null)
                        {
                            db.UserCapabilityGrants.Remove(grant);
                            await db.SaveChangesAsync();
                        }
                    }
                    break;
                }
            case "UnassignRole":
                {
                    if (p.RecordId != null)
                    {
                        var assignment = await db.RoleAssignments.FindAsync(p.RecordId.Value);
                        if (assignment != null)
                        {
                            db.RoleAssignments.Remove(assignment);
                            await db.SaveChangesAsync();
                        }
                    }
                    break;
                }
            case "RemoveGroupMember":
                {
                    if (p.GroupId != null && p.TargetUserId != Guid.Empty)
                    {
                        var membership = await db.CaGroupMembers
                            .FirstOrDefaultAsync(m => m.GroupId == p.GroupId && m.UserId == p.TargetUserId);
                        if (membership != null)
                        {
                            db.CaGroupMembers.Remove(membership);
                            await db.SaveChangesAsync();
                        }
                    }
                    break;
                }
            case "DeleteUser":
                {
                    if (p.TargetUserId == Guid.Empty)
                        throw new InvalidOperationException($"Ceremony {ceremonyId} has no target user to delete.");
                    // Delegate to the same deletion path the controller uses (handles cascade).
                    await userService.DeleteUser(p.TargetUserId);
                    break;
                }
            default:
                throw new InvalidOperationException($"Unsupported controlled-user change type '{p.ChangeType}'.");
        }

        if (tx != null) await tx.CommitAsync();

        logger.LogInformation(
            "Applied ControlledUserChange ceremony {CeremonyId}: {ChangeType} for user {TargetUserId}.",
            ceremonyId, p.ChangeType, p.TargetUserId);

        return new ControlledUserChangeResult(p.ChangeType, p.TargetUserId, p.Capability, p.TenantId, p.CertificateAuthorityId);
    }

    /// <summary>
    /// The tier the stored change would confer (promotion) or remove (demotion/deletion) against the
    /// current state, taking the row lock on every role involved first. Null when the change no
    /// longer touches a controlled tier (including a demotion whose record is already gone).
    /// <c>Stale</c> is set when a record the promotion needs has disappeared.
    /// </summary>
    private async Task<(ControlledTier? Tier, string? Stale)> RecomputeTierAsync(ControlledUserChangeParameters p)
    {
        switch (p.ChangeType)
        {
            case "GrantCapability":
                return (string.IsNullOrWhiteSpace(p.Capability)
                    ? null
                    : ClassifyCapabilityGrant(p.Capability, p.CertificateAuthorityId, p.TenantId), null);

            case "AssignRole":
                {
                    if (p.RoleId is not Guid roleId)
                        return (null, "the role no longer exists");
                    // Checked under the lock: a delete that committed while we waited is seen here.
                    await ControlledTierResolver.LockRoleAsync(db, roleId);
                    if (!await db.Roles.AnyAsync(r => r.Id == roleId))
                        return (null, "the role no longer exists");
                    if (p.GroupId is Guid gid && !await db.CaGroups.AnyAsync(g => g.Id == gid))
                        return (null, "the group no longer exists");
                    return (await ClassifyRoleAssignmentAsync(roleId, p.CertificateAuthorityId, p.TenantId, p.GroupId), null);
                }

            case "AddGroupMember":
                {
                    var group = p.GroupId is Guid gid
                        ? await db.CaGroups.AsNoTracking().FirstOrDefaultAsync(g => g.Id == gid)
                        : null;
                    if (group == null) return (null, "the group no longer exists");
                    await LockGroupRolesAsync(group.Id);
                    return (await ClassifyGroupAsync(group), null);
                }

            case "RevokeCapability":
                {
                    var grant = p.RecordId is Guid rid
                        ? await db.UserCapabilityGrants.AsNoTracking().FirstOrDefaultAsync(g => g.Id == rid)
                        : null;
                    return (grant == null ? null : ClassifyCapabilityGrant(grant.Capability, grant.CertificateAuthorityId, grant.TenantId), null);
                }

            case "UnassignRole":
                {
                    var assignment = p.RecordId is Guid rid
                        ? await db.RoleAssignments.AsNoTracking().FirstOrDefaultAsync(ra => ra.Id == rid)
                        : null;
                    if (assignment == null) return (null, null);
                    await ControlledTierResolver.LockRoleAsync(db, assignment.RoleId);
                    return (await ClassifyRoleAssignmentAsync(assignment.RoleId, assignment.CertificateAuthorityId, assignment.TenantId, assignment.GroupId), null);
                }

            case "RemoveGroupMember":
                {
                    var group = p.GroupId is Guid gid
                        ? await db.CaGroups.AsNoTracking().FirstOrDefaultAsync(g => g.Id == gid)
                        : null;
                    if (group == null || !await db.CaGroupMembers.AnyAsync(m => m.GroupId == group.Id && m.UserId == p.TargetUserId))
                        return (null, null);
                    await LockGroupRolesAsync(group.Id);
                    return (await ClassifyGroupAsync(group), null);
                }

            case "DeleteUser":
                return (await GetDeletionTierAsync(p.TargetUserId), null);

            default:
                return (null, null);
        }
    }

    /// <summary>Takes the role lock on every role assigned to <paramref name="groupId"/>, in id order.</summary>
    private async Task LockGroupRolesAsync(Guid groupId)
    {
        var roleIds = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.GroupId == groupId)
            .Select(ra => ra.RoleId)
            .Distinct()
            .ToListAsync();
        foreach (var roleId in roleIds.OrderBy(id => id))
            await ControlledTierResolver.LockRoleAsync(db, roleId);
    }

    /// <summary>
    /// True when the ceremony's recorded approvals still include at least
    /// <c>RequiredApprovals</c> distinct approvers, other than the initiator and the target, whose
    /// accounts can act (exist, active, not locked, not service identities) and who hold a tier
    /// dominating both the <paramref name="approved"/> tier and the <paramref name="current"/> one.
    /// </summary>
    private async Task<bool> ApprovalsStillCoverAsync(
        KeyCeremonyEntity ceremony, ControlledUserChangeParameters p, ControlledTier approved, ControlledTier? current)
    {
        List<ModularCA.Core.Services.ApprovalRecord> records;
        try
        {
            records = JsonSerializer.Deserialize<List<ModularCA.Core.Services.ApprovalRecord>>(ceremony.ApprovalsJson, JsonOpts) ?? new();
        }
        catch (JsonException)
        {
            return false;
        }

        var approverIds = records
            .Where(r => r.Decision == "Approved" && r.UserId != ceremony.InitiatedByUserId && r.UserId != p.TargetUserId)
            .Select(r => r.UserId)
            .Distinct()
            .ToList();
        var usable = await db.Users.AsNoTracking()
            .Where(u => approverIds.Contains(u.Id) && u.IsActive && !u.IsLocked && !u.IsServiceIdentity)
            .Select(u => u.Id)
            .ToListAsync();

        var valid = 0;
        foreach (var id in usable)
        {
            var tiers = await GetUserTiersAsync(id);
            if (tiers.Any(t => t.Dominates(approved)) && (current is not { } c || tiers.Any(t => t.Dominates(c))))
                valid++;
        }
        return valid >= Math.Max(1, ceremony.RequiredApprovals);
    }

    /// <summary>The tenant a tier is scoped to: its own tenant, else its CA's tenant; null for system tiers.</summary>
    private async Task<Guid?> ScopeTenantAsync(ControlledTier tier)
    {
        if (tier.TenantId != null) return tier.TenantId;
        if (tier.CaId is not Guid caId) return null;
        return await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => (Guid?)c.TenantId)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// Resolves the user quorum for a change at <paramref name="minted"/>. Scopes are independent —
    /// System does NOT cascade to tenants, and parents are <i>ceilings</i>, not floors:
    /// <list type="bullet">
    /// <item>System-tier change (system admin/super) → <c>SecurityPolicy.UserQuorum</c> (standalone).</item>
    /// <item>CA-scoped change → the CA's override if set, capped at its scope's CA-level quorum (a
    /// CA may require fewer approvals than its tenant, never more); otherwise that quorum. The
    /// scope of an instance CA is the instance, whose CA-level quorum is
    /// <c>SecurityPolicy.UserCeremonyRequiredApprovals</c>, the value the System tenant held.</item>
    /// <item>Org-scoped change (org admin/operator) → the affected tenant's quorum.</item>
    /// </list>
    /// Clamped to a minimum of 1; a null scope quorum means 1.
    /// </summary>
    private async Task<int> ResolveUserQuorumAsync(ControlledTier minted)
    {
        // CA-scoped change: CA override (bounded above by its scope) → else the scope's quorum.
        if (minted.CaId != null)
        {
            var ca = await db.CertificateAuthorities.AsNoTracking()
                .Where(c => c.Id == minted.CaId)
                .Select(c => new { c.UserCeremonyRequiredApprovals, c.TenantId })
                .FirstOrDefaultAsync();

            var tenantQuorum = 1;
            if (ca != null)
            {
                var policy = await new EffectivePolicyResolver(db).ResolveAsync(ca.TenantId);
                tenantQuorum = Math.Max(1, (policy.Found ? policy.UserCeremonyRequiredApprovals : null) ?? 1);

                if (ca.UserCeremonyRequiredApprovals.HasValue)
                    // Tenant is the ceiling: the CA can require fewer approvals, never more.
                    return Math.Max(1, Math.Min(ca.UserCeremonyRequiredApprovals.Value, tenantQuorum));
            }
            return tenantQuorum;
        }

        // Org-scoped change (org admin/operator): the affected tenant's quorum.
        if (minted.TenantId is Guid orgTenantId)
        {
            var policy = await new EffectivePolicyResolver(db).ResolveAsync(orgTenantId);
            return Math.Max(1, (policy.Found ? policy.UserCeremonyRequiredApprovals : null) ?? 1);
        }

        // System-tier change: standalone, independent of any tenant.
        var systemQuorum = (await db.Set<SecurityPolicyEntity>().AsNoTracking().FirstOrDefaultAsync())?.UserQuorum ?? 1;
        return Math.Max(1, systemQuorum);
    }

    private static ControlledUserChangeParameters? Deserialize(KeyCeremonyEntity ceremony)
    {
        try
        {
            return JsonSerializer.Deserialize<ControlledUserChangeParameters>(ceremony.ParametersJson, JsonOpts);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
