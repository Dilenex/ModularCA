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
/// <c>SpacePolicyChangeService</c>: opens a <see cref="CeremonyType.ControlledUserChange"/>
/// ceremony via <see cref="IKeyCeremonyService"/> with the deferred change in
/// <c>ParametersJson</c>, and applies it on execute. Tiers come from effective capability across
/// every grant source (<see cref="ControlledTierResolver"/>), not from group structure alone.
/// The acting user's tiers (initiate, approve, super) honour the worn badge from
/// <paramref name="badges"/>; a target account's tiers never do. A promotion reads recent
/// credential resets from <paramref name="auditDb"/>; when it is null or unreadable the ceremony
/// says so instead. Approval and execute read them again to bar the resetters from approving,
/// falling back to those recorded at initiation. A group membership removed on execute revokes,
/// through <paramref name="sshLoginNames"/>, the SSH certificates that carried a login name the
/// user held through that group; a membership, a role or a capability removed on execute
/// revokes those on an SSH CA the user may then no longer request from. A deletion or a
/// disabling goes through the user service, which revokes for itself.
/// </summary>
public class ControlledUserCeremonyService(
    ModularCADbContext db,
    IKeyCeremonyService keyCeremonyService,
    IUserManagementService userService,
    ILogger<ControlledUserCeremonyService> logger,
    IAccessBadgeContext? badges = null,
    AuditDbContext? auditDb = null,
    ISshLoginNameService? sshLoginNames = null) : IControlledUserCeremonyService
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    /// <summary>How far back a promotion looks for credential resets of the accounts it promotes.</summary>
    public static readonly TimeSpan ResetDisclosureWindow = TimeSpan.FromDays(30);

    /// <summary>The prefix of each description line that warns approvers; the console highlights those lines.</summary>
    public const string WarningPrefix = "WARNING: ";

    /// <summary>The refusal at execute of a promotion or identity change opened before its credential state was recorded.</summary>
    public const string PredatesCredentialCheck = "This ceremony predates the credential check; open it again.";

    /// <inheritdoc />
    public ControlledTier? ClassifyCapabilityGrant(string capability, Guid? certificateAuthorityId, Guid? spaceId = null)
    {
        if (string.IsNullOrWhiteSpace(capability)) return null;
        // A CA-scoped grant is minted without the CA's space, so only system-tier or same-CA
        // holders dominate it (stricter than the tier the grant eventually confers).
        return ControlledTierResolver.TierFor(capability, spaceId, certificateAuthorityId, null);
    }

    /// <inheritdoc />
    public async Task<ControlledTier?> ClassifyRoleAssignmentAsync(Guid roleId, Guid? certificateAuthorityId, Guid? spaceId = null, Guid? groupId = null)
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
                return ControlledTier.Covering(roleCaps.Select(c =>
                    ControlledTierResolver.TierForGroupCapability(c, group.IsSystemGroup, group.SpaceId, group.CertificateAuthorityId)));
        }
        return ControlledTier.Covering(roleCaps.Select(c =>
            ControlledTierResolver.TierFor(c, spaceId, certificateAuthorityId, null)));
    }

    /// <summary>
    /// The tiers that <paramref name="capabilities"/> on role <paramref name="roleId"/> confer through
    /// the role's current assignments and through pending or approved-but-unexecuted
    /// <c>AssignRole</c> ceremonies, so a role awaiting a ceremony-gated assignment counts as assigned.
    /// An open ceremony that names the role but whose parameters cannot be read counts as an
    /// instance-wide assignment (fail closed).
    /// </summary>
    public async Task<IReadOnlyList<ControlledTier>> TiersConferredByRoleAsync(Guid roleId, IEnumerable<string> capabilities)
    {
        var caps = capabilities.Where(ControlledTierResolver.IsControlledCapability).ToList();
        if (caps.Count == 0) return Array.Empty<ControlledTier>();

        var assignments = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.RoleId == roleId)
            .Select(ra => new ScopedAssignment(ra.SpaceId, ra.CertificateAuthorityId, ra.GroupId))
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
            // An unreadable ceremony naming the role may assign it anywhere: read it as an
            // instance-wide assignment, so the change it could promote through stays gated.
            if (p == null)
                assignments.Add(new ScopedAssignment(null, null, null));
            else if (p is { ChangeType: "AssignRole" } && p.RoleId == roleId)
                assignments.Add(new ScopedAssignment(p.SpaceId, p.CertificateAuthorityId, p.GroupId));
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
                    t = ControlledTierResolver.TierForGroupCapability(c, g.IsSystemGroup, g.SpaceId, g.CertificateAuthorityId);
                }
                else
                    t = ControlledTierResolver.TierFor(c, a.SpaceId, a.CertificateAuthorityId, null);
                if (t != null) tiers.Add(t.Value);
            }
        return tiers.ToList();
    }

    private sealed record ScopedAssignment(Guid? SpaceId, Guid? CertificateAuthorityId, Guid? GroupId);

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
    /// The tier an approver must dominate to delete <paramref name="userId"/> or change their account
    /// (password reset, MFA reset, identity update): the covering tier
    /// (<see cref="ControlledTier.Covering"/>) of every tier the user holds, e.g. space-admin(T) over
    /// ca-admin(X in T), or system-admin when the holdings span scopes (two spaces, two CAs, or a
    /// CA and a space-wide operator tier) that no single scoped approver covers. Null when the user
    /// holds no controlled tier, so the change is uncontrolled.
    /// </summary>
    public async Task<ControlledTier?> GetDeletionTierAsync(Guid userId)
        => ControlledTier.Covering((await GetUserTiersAsync(userId)).Select(t => (ControlledTier?)t));

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
    /// service identities, and holding the tier through a CA/space that is not soft-deleted.
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
        var spaceIds = candidates.Where(h => h.Tier.SpaceId != null).Select(h => h.Tier.SpaceId!.Value).Distinct().ToList();
        var liveSpaces = (await db.Spaces.AsNoTracking()
                .Where(t => spaceIds.Contains(t.Id) && !t.IsDeleted)
                .Select(t => t.Id)
                .ToListAsync())
            .ToHashSet();

        return candidates
            .Where(h => usable.Contains(h.UserId)
                && (h.Tier.CaId is not Guid ca || liveCas.Contains(ca))
                && (h.Tier.SpaceId is not Guid t || liveSpaces.Contains(t)))
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

        // System-group members (system operators and auditors) hold system-wide rights, including
        // key-ceremony approval for every space; only system-admin administers them.
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
        => await ApprovalRefusalAsync(approverUserId, ceremony) == null;

    /// <inheritdoc />
    public async Task<bool> HoldsApprovingTierAsync(Guid userId, KeyCeremonyEntity ceremony)
    {
        var p = Deserialize(ceremony);
        if (p == null || userId == p.TargetUserId) return false;
        var minted = new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { SpaceId = p.MintedTierSpaceId };
        return (await GetActorTiersAsync(userId)).Any(t => t.Dominates(minted));
    }

    /// <inheritdoc />
    public async Task<string?> ApprovalRefusalAsync(Guid approverUserId, KeyCeremonyEntity ceremony)
    {
        if (!await HoldsApprovingTierAsync(approverUserId, ceremony))
            return "You are not eligible to approve this controlled-user change: your role doesn't cover the affected privilege tier.";
        var own = (await KnownResetsAsync(ceremony, Deserialize(ceremony)!)).FirstOrDefault(r => r.ActorUserId == approverUserId);
        if (own != null && !await IsSuperAsync(approverUserId))
            return $"You reset {own.Username ?? own.UserId.ToString()}'s credentials on {own.At:yyyy-MM-dd}; another administrator must approve this promotion.";
        return null;
    }

    /// <summary>
    /// The password and MFA resets, by anyone, of the accounts promotion <paramref name="p"/> raises:
    /// those recorded at initiation, and those the audit trail shows now from
    /// <see cref="ResetDisclosureWindow"/> before the ceremony was opened. When the audit trail
    /// cannot be read, the recorded ones alone. Empty for any change that is not a promotion.
    /// </summary>
    private async Task<List<ControlledCredentialReset>> KnownResetsAsync(KeyCeremonyEntity ceremony, ControlledUserChangeParameters p)
    {
        if (!IsPromotion(p.ChangeType)) return [];
        var resets = (p.RecentCredentialResets ?? []).ToList();
        try
        {
            if (auditDb == null) throw new InvalidOperationException("The audit database is not configured.");
            var promoted = p.CredentialSnapshots?.Select(s => s.UserId).ToList() ?? await PromotedUserIdsAsync(p);
            resets.AddRange(await ControlledCredentials.RecentResetsAsync(db, auditDb, promoted, ceremony.CreatedAt - ResetDisclosureWindow));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not read recent credential resets for ControlledUserChange ceremony {CeremonyId}; using those recorded at initiation.", ceremony.Id);
        }
        return resets.Where(r => r.What is ControlledCredentialReset.Password or ControlledCredentialReset.Mfa).ToList();
    }

    /// <inheritdoc />
    public (Guid? TargetUserId, ControlledTier? Minted) DescribeCeremony(KeyCeremonyEntity ceremony)
    {
        var p = Deserialize(ceremony);
        if (p == null) return (null, null);
        return (p.TargetUserId == Guid.Empty ? null : p.TargetUserId,
            new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { SpaceId = p.MintedTierSpaceId });
    }

    /// <inheritdoc />
    public Task<Guid> InitiateCapabilityGrantAsync(
        Guid targetUserId,
        string? targetUsername,
        string capability,
        Guid? spaceId,
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
            SpaceId = spaceId,
            CertificateAuthorityId = certificateAuthorityId,
            ResourceType = resourceType,
            ResourceId = resourceId,
        };
        return InitiateChangeAsync(parameters, minted, initiatorUserId, initiatorUsername);
    }

    /// <summary>
    /// Opens a <c>ControlledUserChange</c> ceremony for <paramref name="parameters"/>, recording the
    /// minted tier in the parameters and stamping the ceremony's space from the tier's scope (the
    /// tier's space, or its CA's space) so scoped approvers can reach it. System tiers leave the
    /// space null, which keeps the ceremony system-only. A promotion also records the credential
    /// state of every account it promotes, and an identity change the account's state, for the
    /// compare-and-set at execute. A promotion records and discloses recent credential resets of
    /// those accounts (<see cref="RecordRecentResetsAsync"/>), which may refuse it, and discloses
    /// those whose password an administrator set and that have not changed it since
    /// (<see cref="ControlledCredentials.PasswordsSetByAdministratorAsync"/>) unless a recorded
    /// password reset already names them.
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
        parameters.MintedTierSpaceId = minted.SpaceId;
        List<string> adminSetPasswords = [];
        if (IsPromotion(parameters.ChangeType))
        {
            var promoted = await PromotedUserIdsAsync(parameters);
            parameters.CredentialSnapshots = await ControlledCredentials.SnapshotAsync(db, promoted);
            await RecordRecentResetsAsync(parameters, promoted, initiatorUserId);
            adminSetPasswords = (await ControlledCredentials.PasswordsSetByAdministratorAsync(db, promoted))
                .Where(u => parameters.RecentCredentialResets?.Any(r => r.UserId == u.Id && r.What == ControlledCredentialReset.Password) != true)
                .Select(u => u.Username)
                .ToList();
        }
        if (parameters is { ChangeType: "UpdateIdentity", Identity: { Before: null } identity })
            identity.Before = await ControlledCredentials.AccountStateAsync(db, parameters.TargetUserId);

        var quorum = await ResolveUserQuorumAsync(minted);

        var ceremony = await keyCeremonyService.InitiateAsync(
            operationType: "ControlledUserChange",
            description: await DescribeChangeAsync(parameters, minted, adminSetPasswords),
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
        tracked.SpaceId = await ScopeSpaceAsync(minted);
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Initiated ControlledUserChange ceremony {CeremonyId} ({ChangeType}, tier {Tier}, quorum {Quorum}, initiator {Initiator}).",
            tracked.Id, parameters.ChangeType, minted.Level, quorum, initiatorUserId);

        return tracked.Id;
    }

    /// <summary>
    /// Records in <paramref name="p"/> the password and MFA resets and creations of
    /// <paramref name="promoted"/> within <see cref="ResetDisclosureWindow"/>, by anyone, or that the
    /// audit trail could not be read, which never fails the request. Throws
    /// <see cref="ControlledUserInitiationRefusedException"/> when <paramref name="initiatorUserId"/>
    /// made one of those resets and is not system-super under the badge they wear.
    /// </summary>
    private async Task RecordRecentResetsAsync(ControlledUserChangeParameters p, IReadOnlyCollection<Guid> promoted, Guid initiatorUserId)
    {
        if (promoted.Count == 0) return;
        try
        {
            if (auditDb == null) throw new InvalidOperationException("The audit database is not configured.");
            p.RecentCredentialResets = await ControlledCredentials.RecentResetsAsync(db, auditDb, promoted, DateTime.UtcNow - ResetDisclosureWindow);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not read recent credential resets for a ControlledUserChange promotion; the ceremony discloses that.");
            p.RecentCredentialResets = null;
            p.RecentResetsUnchecked = true;
            return;
        }

        var own = p.RecentCredentialResets.FirstOrDefault(r => r.ActorUserId == initiatorUserId
            && r.What is ControlledCredentialReset.Password or ControlledCredentialReset.Mfa);
        if (own != null && !await IsSuperAsync(initiatorUserId))
            throw new ControlledUserInitiationRefusedException(
                $"You reset this user's credentials on {own.At:yyyy-MM-dd}; another administrator must open the promotion.");
    }

    /// <summary>
    /// The warning lines a ceremony description leads with: each recent credential reset of an
    /// account it promotes (at most three, then a count), or that they could not be checked; then
    /// each of <paramref name="adminSetPasswords"/>, the promoted accounts whose password an
    /// administrator set and that have not changed it since (at most three, then a count).
    /// </summary>
    private static List<string> ResetWarnings(ControlledUserChangeParameters p, IReadOnlyList<string> adminSetPasswords)
    {
        var lines = new List<string>();
        if (p.RecentResetsUnchecked)
            lines.Add(WarningPrefix + "could not check recent resets");
        var resets = p.RecentCredentialResets ?? [];
        foreach (var r in resets.Take(3))
        {
            var who = r.Username ?? r.UserId.ToString();
            var by = r.ActorUsername ?? r.ActorUserId?.ToString() ?? "an unknown actor";
            lines.Add(WarningPrefix + (r.What == ControlledCredentialReset.Created
                ? $"{who}'s account and first password were created by {by} on {r.At:yyyy-MM-dd}"
                : $"{who}'s {r.What} was reset by {by} on {r.At:yyyy-MM-dd}"));
        }
        if (resets.Count > 3)
            lines.Add(WarningPrefix + $"{resets.Count - 3} more recent credential resets; see the ceremony parameters");
        foreach (var who in adminSetPasswords.Take(3))
            lines.Add(WarningPrefix + $"{who}'s password was set by an administrator and has not been changed since");
        if (adminSetPasswords.Count > 3)
            lines.Add(WarningPrefix + $"{adminSetPasswords.Count - 3} more accounts whose password was set by an administrator and has not been changed since");
        return lines;
    }

    /// <summary>
    /// True for a ceremony opened before its credential state was recorded: a promotion without
    /// <see cref="ControlledUserChangeParameters.CredentialSnapshots"/>, or an identity change
    /// without <see cref="ControlledIdentityChange.Before"/>.
    /// </summary>
    private static bool PredatesCredentialState(ControlledUserChangeParameters p)
        => (IsPromotion(p.ChangeType) && p.CredentialSnapshots == null)
           || (p.ChangeType == "UpdateIdentity" && p.Identity?.Before == null);

    /// <summary>True for the change types that raise an account's privilege.</summary>
    private static bool IsPromotion(string changeType) => changeType is "GrantCapability" or "AssignRole" or "AddGroupMember";

    /// <summary>
    /// The accounts a promotion raises: its target, or for a role assigned to a group, the group's
    /// current members.
    /// </summary>
    private async Task<List<Guid>> PromotedUserIdsAsync(ControlledUserChangeParameters p)
    {
        if (p.TargetUserId != Guid.Empty) return [p.TargetUserId];
        if (p.GroupId is not Guid groupId) return [];
        return await db.CaGroupMembers.AsNoTracking().Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync();
    }

    /// <inheritdoc />
    /// <remarks>
    /// An open ceremony that names the user but whose parameters cannot be read counts as a
    /// promotion (fail closed): it cannot be shown not to be one.
    /// </remarks>
    public async Task<bool> HasOpenPromotionAsync(Guid userId)
    {
        var idText = userId.ToString();
        var now = DateTime.UtcNow;
        var open = await db.KeyCeremonies.AsNoTracking()
            .Where(c => c.OperationType == "ControlledUserChange"
                && ((c.Status == "Pending" && c.ExpiresAt > now) || c.Status == "Approved")
                && c.ParametersJson.Contains(idText))
            .ToListAsync();
        return open.Select(Deserialize).Any(p => p == null || (IsPromotion(p.ChangeType)
            && (p.TargetUserId == userId || p.CredentialSnapshots?.Any(s => s.UserId == userId) == true)));
    }

    /// <summary>
    /// The ceremony description for <paramref name="p"/>, naming the minted tier's scope: on a CA
    /// (by label), in a space (by name), or the instance. Any <see cref="ResetWarnings"/> lead it,
    /// one per line, each starting with <see cref="WarningPrefix"/>. At most 500 characters.
    /// </summary>
    private async Task<string> DescribeChangeAsync(ControlledUserChangeParameters p, ControlledTier minted, IReadOnlyList<string> adminSetPasswords)
    {
        var lines = ResetWarnings(p, adminSetPasswords);
        lines.Add(await DescribeBaseAsync(p, minted));
        var text = string.Join("\n", lines);
        return text.Length <= 500 ? text : text[..500];
    }

    /// <summary>The one-line description of the change itself, naming the minted tier's scope.</summary>
    private async Task<string> DescribeBaseAsync(ControlledUserChangeParameters p, ControlledTier minted)
    {
        var who = p.TargetUsername
                  ?? (p.TargetUserId != Guid.Empty ? p.TargetUserId.ToString() : (p.GroupId?.ToString() ?? "?"));
        var scope = minted.CaId != null || minted.SpaceId != null ? " " + await DescribeScopeAsync(minted) : " (instance)";
        return p.ChangeType switch
        {
            "GrantCapability" => $"Promote controlled user {who}: grant '{p.Capability}'{scope}",
            "AssignRole" => $"Promote controlled user {who}: assign role {p.RoleId}{scope}",
            "AddGroupMember" => $"Promote controlled user {who}: add to group {p.GroupId}{scope}",
            "RevokeCapability" => $"Demote controlled user {who}: revoke '{p.Capability}'{scope}",
            "UnassignRole" => $"Demote controlled user {who}: unassign role {p.RoleId}{scope}",
            "RemoveGroupMember" => $"Demote controlled user {who}: remove from group {p.GroupId}{scope}",
            "DeleteUser" => $"Delete controlled user {who}{scope}",
            "ResetPassword" => $"Reset the password of controlled user {who}{scope}",
            "ResetMfa" => $"Reset the MFA of controlled user {who}{scope}",
            "UpdateIdentity" => $"Change the account of controlled user {who}: {DescribeIdentity(p.Identity)}{scope}",
            _ => $"Controlled-user change ({p.ChangeType}) for {who}{scope}",
        };
    }

    /// <summary>The fields an identity change sets, e.g. "email to a@b, disable".</summary>
    private static string DescribeIdentity(ControlledIdentityChange? c)
    {
        if (c == null) return "nothing";
        var parts = new List<string>();
        if (c.Username != null) parts.Add($"username to {c.Username}");
        if (c.Email != null) parts.Add($"email to {c.Email}");
        if (c.IsActive != null) parts.Add(c.IsActive.Value ? "enable" : "disable");
        if (c.IsLocked != null) parts.Add(c.IsLocked.Value ? "lock" : "unlock");
        if (c.PasswordNeverExpires != null) parts.Add(c.PasswordNeverExpires.Value ? "password never expires" : "password expires");
        if (c.PasswordChangeOnNextLogon != null) parts.Add(c.PasswordChangeOnNextLogon.Value ? "force password change" : "no forced password change");
        if (c.FirstName != null || c.LastName != null || c.DisplayName != null) parts.Add("name");
        return parts.Count == 0 ? "nothing" : string.Join(", ", parts);
    }

    /// <inheritdoc />
    public async Task<string> DescribeScopeAsync(ControlledTier tier)
    {
        if (tier.CaId is Guid caId)
        {
            var label = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(c => c.Id == caId).Select(c => c.Label).FirstOrDefaultAsync();
            return $"on CA {(string.IsNullOrEmpty(label) ? caId.ToString() : label)}";
        }
        if (tier.SpaceId is Guid spaceId)
        {
            var name = await db.Spaces.IgnoreQueryFilters().AsNoTracking()
                .Where(t => t.Id == spaceId).Select(t => t.Name).FirstOrDefaultAsync();
            return $"in space {(string.IsNullOrEmpty(name) ? spaceId.ToString() : name)}";
        }
        return "instance";
    }

    /// <summary>
    /// Applies an approved controlled-user ceremony. Inside a transaction it locks the ceremony row
    /// and re-reads its status, so of two concurrent executes only one finds it Approved; the other
    /// gets <see cref="CeremonyNotExecutableException"/>. It then takes the role lock where a role is
    /// involved and recomputes the tier the change confers or removes now. When a promoted account's
    /// password, MFA or identity changed since initiation, an identity change's account no longer
    /// matches the state it was opened against, a promotion or identity change carries no such
    /// state because it was opened before it was recorded (<see cref="PredatesCredentialCheck"/>),
    /// that tier is higher than the approved one, or the
    /// recorded approvals no longer hold enough active approvers dominating it (for a promotion, who
    /// did not reset the credentials of an account it promotes), the ceremony is marked Expired and a
    /// <see cref="ControlledUserChangeRefusedException"/> is thrown. A demotion, deletion, disable or
    /// lock that would leave its scope without a dominating user is refused the same way but stays
    /// Approved. Otherwise the ceremony is marked Executed in the same transaction as the change.
    /// A password reset generates the temporary password now and returns it only in
    /// <see cref="ControlledUserChangeResult.TemporaryPassword"/>. A group membership removed here
    /// revokes, in the same transaction, the SSH certificates that carried a login name the user
    /// held through that group.
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

        var approved = new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { SpaceId = p.MintedTierSpaceId };
        var predates = PredatesCredentialState(p);
        var (current, stale) = predates ? ((ControlledTier?)null, "it predates the credential check") : await RecomputeTierAsync(p);
        if (stale == null && p.CredentialSnapshots is { } snapshots && await ControlledCredentials.AnyChangedAsync(db, snapshots))
            stale = "the password, MFA or account of a user it promotes changed after it was opened";
        if (stale == null && p.Identity is { Before: { } before } identity
            && await ControlledCredentials.AccountStateAsync(db, p.TargetUserId) is { } state
            && !ControlledCredentials.Unchanged(before, state, identity))
            stale = "the account changed after it was opened";
        if (stale == null && current is { } now && !approved.Dominates(now))
            stale = "it now confers a higher privilege tier than the one approved";
        if (stale == null && !await ApprovalsStillCoverAsync(ceremony, p, approved, current))
            stale = "the recorded approvals no longer include enough active approvers who dominate it and did not reset the credentials of a user it promotes";
        if (stale != null)
        {
            ceremony.Status = "Expired";
            await db.SaveChangesAsync();
            if (tx != null) await tx.CommitAsync();
            logger.LogWarning("Refused ControlledUserChange ceremony {CeremonyId} at execute: {Reason}.", ceremonyId, stale);
            throw new ControlledUserChangeRefusedException(
                predates ? PredatesCredentialCheck : $"The privilege changed after approval ({stale}); start a new ceremony.", ceremonyExpired: true);
        }

        var removesDominator = p.ChangeType is "RevokeCapability" or "UnassignRole" or "RemoveGroupMember" or "DeleteUser"
            || (p.ChangeType == "UpdateIdentity" && p.Identity is { RemovesAccess: true });
        if (current is { } removed && removesDominator
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

        string? temporaryPassword = null;
        switch (p.ChangeType)
        {
            case "GrantCapability":
                {
                    if (string.IsNullOrWhiteSpace(p.Capability))
                        throw new InvalidOperationException($"Ceremony {ceremonyId} has no capability to grant.");

                    // A CA-scoped grant is effective on its CA whatever space it records.
                    var exists = await db.UserCapabilityGrants.AnyAsync(g =>
                        g.UserId == p.TargetUserId
                        && g.Capability == p.Capability
                        && (p.CertificateAuthorityId != null
                            ? g.CertificateAuthorityId == p.CertificateAuthorityId
                            : g.CertificateAuthorityId == null && g.SpaceId == p.SpaceId)
                        && g.ResourceType == p.ResourceType
                        && g.ResourceId == p.ResourceId);

                    if (!exists)
                    {
                        db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
                        {
                            UserId = p.TargetUserId,
                            Capability = p.Capability,
                            SpaceId = p.SpaceId,
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
                        && ra.SpaceId == p.SpaceId
                        && ra.CertificateAuthorityId == p.CertificateAuthorityId);

                    if (!exists)
                    {
                        db.RoleAssignments.Add(new RoleAssignmentEntity
                        {
                            RoleId = p.RoleId.Value,
                            UserId = userId,
                            GroupId = p.GroupId,
                            SpaceId = p.SpaceId,
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
                            if (sshLoginNames != null)
                                await sshLoginNames.ReconcileUsersAsync([grant.UserId], "a capability was taken from the user");
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
                            if (sshLoginNames != null)
                                await sshLoginNames.RoleUnassignedAsync(assignment.UserId, assignment.GroupId);
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
                            if (sshLoginNames != null)
                                await sshLoginNames.ReconcileUsersAsync([p.TargetUserId], "the user left a group");
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
            case "ResetPassword":
                temporaryPassword = await userService.ResetUserPassword(p.TargetUserId);
                break;
            case "ResetMfa":
                await userService.ResetUserMfa(p.TargetUserId);
                break;
            case "UpdateIdentity":
                {
                    var c = p.Identity
                        ?? throw new InvalidOperationException($"Ceremony {ceremonyId} has no account fields to set.");
                    await userService.UpdateUser(p.TargetUserId, new ModularCA.Shared.Models.Management.UpdateUserRequest
                    {
                        Username = c.Username,
                        Email = c.Email,
                        FirstName = c.FirstName,
                        LastName = c.LastName,
                        DisplayName = c.DisplayName,
                        IsActive = c.IsActive,
                        IsLocked = c.IsLocked,
                        PasswordNeverExpires = c.PasswordNeverExpires,
                        PasswordChangeOnNextLogon = c.PasswordChangeOnNextLogon,
                    });
                    break;
                }
            default:
                throw new InvalidOperationException($"Unsupported controlled-user change type '{p.ChangeType}'.");
        }

        if (tx != null) await tx.CommitAsync();

        logger.LogInformation(
            "Applied ControlledUserChange ceremony {CeremonyId}: {ChangeType} for user {TargetUserId}.",
            ceremonyId, p.ChangeType, p.TargetUserId);

        return new ControlledUserChangeResult(p.ChangeType, p.TargetUserId, p.Capability, p.SpaceId, p.CertificateAuthorityId)
        {
            TemporaryPassword = temporaryPassword,
        };
    }

    /// <summary>
    /// The tier the stored change would confer (promotion) or remove (demotion/deletion), or the
    /// target account's covering tier for an account change, against the current state, taking the
    /// row lock on every role involved first. Null when the change no longer touches a controlled
    /// tier (including a demotion whose record is already gone). <c>Stale</c> is set when a record
    /// the change needs has disappeared, or an identity change's username or email was taken.
    /// </summary>
    private async Task<(ControlledTier? Tier, string? Stale)> RecomputeTierAsync(ControlledUserChangeParameters p)
    {
        switch (p.ChangeType)
        {
            case "GrantCapability":
                return (string.IsNullOrWhiteSpace(p.Capability)
                    ? null
                    : ClassifyCapabilityGrant(p.Capability, p.CertificateAuthorityId, p.SpaceId), null);

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
                    return (await ClassifyRoleAssignmentAsync(roleId, p.CertificateAuthorityId, p.SpaceId, p.GroupId), null);
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
                    return (grant == null ? null : ClassifyCapabilityGrant(grant.Capability, grant.CertificateAuthorityId, grant.SpaceId), null);
                }

            case "UnassignRole":
                {
                    var assignment = p.RecordId is Guid rid
                        ? await db.RoleAssignments.AsNoTracking().FirstOrDefaultAsync(ra => ra.Id == rid)
                        : null;
                    if (assignment == null) return (null, null);
                    await ControlledTierResolver.LockRoleAsync(db, assignment.RoleId);
                    return (await ClassifyRoleAssignmentAsync(assignment.RoleId, assignment.CertificateAuthorityId, assignment.SpaceId, assignment.GroupId), null);
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

            case "ResetPassword" or "ResetMfa" or "UpdateIdentity":
                {
                    if (!await db.Users.AnyAsync(u => u.Id == p.TargetUserId))
                        return (null, "the account no longer exists");
                    if (p.ChangeType == "UpdateIdentity" && p.Identity is { } c
                        && ((c.Username != null && await db.Users.AnyAsync(u => u.Id != p.TargetUserId && u.Username == c.Username))
                            || (c.Email != null && await db.Users.AnyAsync(u => u.Id != p.TargetUserId && u.Email == c.Email))))
                        return (null, "the requested username or email now belongs to another account");
                    return (await GetDeletionTierAsync(p.TargetUserId), null);
                }

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
    /// For a promotion, an approver who reset the password or MFA of an account it promotes
    /// (<see cref="KnownResetsAsync"/>, read afresh) does not count unless their account is
    /// system-super.
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
        HashSet<Guid> resetters = usable.Count == 0 ? [] : (await KnownResetsAsync(ceremony, p)).Select(r => r.ActorUserId).OfType<Guid>().ToHashSet();

        var valid = 0;
        foreach (var id in usable)
        {
            if (resetters.Contains(id) && !await IsSuperAccountAsync(id)) continue;
            var tiers = await GetUserTiersAsync(id);
            if (tiers.Any(t => t.Dominates(approved)) && (current is not { } c || tiers.Any(t => t.Dominates(c))))
                valid++;
        }
        return valid >= Math.Max(1, ceremony.RequiredApprovals);
    }

    /// <summary>The space a tier is scoped to: its own space, else its CA's space; null for system tiers.</summary>
    private async Task<Guid?> ScopeSpaceAsync(ControlledTier tier)
    {
        if (tier.SpaceId != null) return tier.SpaceId;
        if (tier.CaId is not Guid caId) return null;
        return await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => (Guid?)c.SpaceId)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// Resolves the user quorum for a change at <paramref name="minted"/>. Scopes are independent —
    /// System does NOT cascade to spaces, and parents are <i>ceilings</i>, not floors:
    /// <list type="bullet">
    /// <item>System-tier change (system admin/operator/super) → <c>SecurityPolicy.UserQuorum</c> (standalone).</item>
    /// <item>CA-scoped change → the CA's override if set, capped at its scope's CA-level quorum (a
    /// CA may require fewer approvals than its space, never more); otherwise that quorum. The
    /// scope of an instance CA is the instance, whose CA-level quorum is
    /// <c>SecurityPolicy.UserCeremonyRequiredApprovals</c>, the value the system tenant held before 0.4.0.</item>
    /// <item>Space-scoped change (space admin/operator) → the affected space's quorum.</item>
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
                .Select(c => new { c.UserCeremonyRequiredApprovals, c.SpaceId })
                .FirstOrDefaultAsync();

            var spaceQuorum = 1;
            if (ca != null)
            {
                var policy = await new EffectivePolicyResolver(db).ResolveAsync(ca.SpaceId);
                spaceQuorum = Math.Max(1, (policy.Found ? policy.UserCeremonyRequiredApprovals : null) ?? 1);

                if (ca.UserCeremonyRequiredApprovals.HasValue)
                    // Space is the ceiling: the CA can require fewer approvals, never more.
                    return Math.Max(1, Math.Min(ca.UserCeremonyRequiredApprovals.Value, spaceQuorum));
            }
            return spaceQuorum;
        }

        // Space-scoped change (space admin/operator): the affected space's quorum.
        if (minted.SpaceId is Guid orgSpaceId)
        {
            var policy = await new EffectivePolicyResolver(db).ResolveAsync(orgSpaceId);
            return Math.Max(1, (policy.Found ? policy.UserCeremonyRequiredApprovals : null) ?? 1);
        }

        // System-tier change: standalone, independent of any space.
        var systemQuorum = (await db.Set<SecurityPolicyEntity>().AsNoTracking().FirstOrDefaultAsync())?.UserQuorum ?? 1;
        return Math.Max(1, systemQuorum);
    }

    private static ControlledUserChangeParameters? Deserialize(KeyCeremonyEntity ceremony)
    {
        try
        {
            return CeremonyParametersJson.Read<ControlledUserChangeParameters>(ceremony.ParametersJson);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
