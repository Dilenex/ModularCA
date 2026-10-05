using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models;

namespace ModularCA.Core.Services;

/// <summary>How many approvals a ceremony needs and how many accounts could still give one.</summary>
/// <param name="RequiredApprovals">Approvals still needed.</param>
/// <param name="EligibleApprovers">Accounts, other than the initiator and anyone who already approved, that could approve.</param>
public sealed record CeremonyReach(int RequiredApprovals, int EligibleApprovers)
{
    /// <summary>True when enough accounts could approve.</summary>
    public bool Reachable => EligibleApprovers >= RequiredApprovals;
}

/// <summary>
/// Decides whether a ceremony could ever reach its quorum, from who may approve each kind.
/// <see cref="KeyCeremonyService.InitiateAsync"/> calls it before creating anything, so every
/// initiation path is covered by the one check.
/// </summary>
public interface ICeremonyQuorumGuard
{
    /// <summary>
    /// The accounts that could approve a ceremony of <paramref name="operationType"/> in
    /// <paramref name="spaceId"/> (null for the instance) with <paramref name="parametersJson"/>,
    /// without <paramref name="initiatorUserId"/>.
    /// </summary>
    Task<IReadOnlySet<Guid>> EligibleApproversAsync(string operationType, Guid? spaceId, string? parametersJson, Guid initiatorUserId);

    /// <summary>
    /// Throws <see cref="CeremonyQuorumUnreachableException"/> when fewer accounts than
    /// <paramref name="requiredApprovals"/> could approve the ceremony.
    /// </summary>
    Task EnsureReachableAsync(string operationType, Guid? spaceId, string? parametersJson, Guid initiatorUserId, int requiredApprovals);

    /// <summary>
    /// For a pending ceremony: the approvals it still needs against the accounts that could still
    /// give one (not its initiator, not those who already approved).
    /// </summary>
    Task<CeremonyReach> AssessPendingAsync(KeyCeremonyEntity ceremony);
}

/// <summary>
/// Default <see cref="ICeremonyQuorumGuard"/>. An approver is an account that can sign in (active,
/// not locked, not a service identity, not deleted), is not the initiator, and passes the rule the
/// approve endpoint applies to that kind of ceremony, read from the account's holdings
/// (<see cref="ControlledTierResolver"/>) without any worn badge:
/// <list type="bullet">
/// <item>Controlled-user change: holds a tier that dominates the affected tier, is not the user it
/// changes, and for a promotion did not reset the credentials of an account it promotes (unless
/// system-super).</item>
/// <item>Instance policy change: <c>system.manage</c> at system scope.</item>
/// <item>Space policy change: <c>system.manage</c> at system scope, or space-wide in the space
/// together with <c>ca.manage</c> for the space.</item>
/// <item>Every other ceremony (CA and SSH CA creation, SSH CA deletion, CA revocation):
/// <c>system.manage</c> or <c>ca.manage</c> at system scope, or <c>ca.manage</c> space-wide in the
/// ceremony's space. An instance ceremony has no space-wide holders.</item>
/// </list>
/// A tier held through a soft-deleted CA or space does not count.
/// </summary>
public sealed class CeremonyQuorumGuard(ModularCADbContext db) : ICeremonyQuorumGuard
{
    private const string ControlledUserChange = "ControlledUserChange";

    /// <summary>True for the ceremonies a scope's <c>RequireKeyCeremony</c> switch opens.</summary>
    public static bool IsGovernedByRequirement(string operationType)
        => operationType is not (ControlledUserChange or nameof(CeremonyType.SpacePolicyChange) or nameof(CeremonyType.InstancePolicyChange));

    /// <summary>Whether <paramref name="tiers"/> let an account approve a ceremony on the CAs of <paramref name="spaceId"/> (null for the instance).</summary>
    public static bool MayApproveInScope(IReadOnlyCollection<ControlledTier> tiers, Guid? spaceId)
        => tiers.Any(t => t.Level is ControlledTierLevel.SystemAdmin or ControlledTierLevel.SystemOperator
            || (spaceId != null && t.Level == ControlledTierLevel.SpaceOperator && t.SpaceId == spaceId));

    /// <summary>Whether <paramref name="tiers"/> let an account approve a policy change of <paramref name="spaceId"/> (null for the instance).</summary>
    public static bool MayApprovePolicyChange(IReadOnlyCollection<ControlledTier> tiers, Guid? spaceId)
        => tiers.Any(t => t.Level == ControlledTierLevel.SystemAdmin)
            || (spaceId != null
                && tiers.Any(t => t.Level == ControlledTierLevel.SpaceAdmin && t.SpaceId == spaceId)
                && MayApproveInScope(tiers, spaceId));

    /// <inheritdoc />
    public async Task<IReadOnlySet<Guid>> EligibleApproversAsync(string operationType, Guid? spaceId, string? parametersJson, Guid initiatorUserId)
    {
        var rule = RuleFor(operationType, spaceId, parametersJson);
        if (rule == null)
            return new HashSet<Guid>();

        var holdings = await LiveHoldingsAsync();
        var candidates = holdings
            .GroupBy(h => h.UserId)
            .Where(g => g.Key != initiatorUserId && rule(g.Key, g.Select(h => h.Tier).ToList()))
            .Select(g => g.Key)
            .ToList();
        if (candidates.Count == 0)
            return new HashSet<Guid>();

        return (await db.Users.AsNoTracking()
                .Where(u => candidates.Contains(u.Id) && u.IsActive && !u.IsLocked && !u.IsServiceIdentity)
                .Select(u => u.Id)
                .ToListAsync())
            .ToHashSet();
    }

    /// <inheritdoc />
    public async Task EnsureReachableAsync(string operationType, Guid? spaceId, string? parametersJson, Guid initiatorUserId, int requiredApprovals)
    {
        var required = Math.Max(1, requiredApprovals);
        var eligible = (await EligibleApproversAsync(operationType, spaceId, parametersJson, initiatorUserId)).Count;
        if (eligible >= required)
            return;

        string? scope = null;
        string? spaceName = null;
        if (IsGovernedByRequirement(operationType))
        {
            scope = spaceId == null ? CeremonyQuorumUnreachableException.InstanceScope : CeremonyQuorumUnreachableException.SpaceScope;
            if (spaceId is Guid id)
                spaceName = await db.Spaces.AsNoTracking().Where(s => s.Id == id).Select(s => s.Name).FirstOrDefaultAsync();
        }
        throw new CeremonyQuorumUnreachableException(operationType, required, eligible, scope,
            scope == CeremonyQuorumUnreachableException.SpaceScope ? spaceId : null, spaceName);
    }

    /// <inheritdoc />
    public async Task<CeremonyReach> AssessPendingAsync(KeyCeremonyEntity ceremony)
    {
        var approved = ApprovedBy(ceremony.ApprovalsJson);
        var eligible = await EligibleApproversAsync(ceremony.OperationType, ceremony.SpaceId, ceremony.ParametersJson, ceremony.InitiatedByUserId);
        return new CeremonyReach(
            Math.Max(0, Math.Max(1, ceremony.RequiredApprovals) - approved.Count),
            eligible.Count(id => !approved.Contains(id)));
    }

    /// <summary>
    /// The approval rule for a ceremony, over an account's id and live tiers. Null when nobody can
    /// approve: a controlled-user ceremony whose parameters cannot be read.
    /// </summary>
    private static Func<Guid, IReadOnlyCollection<ControlledTier>, bool>? RuleFor(string operationType, Guid? spaceId, string? parametersJson)
    {
        switch (operationType)
        {
            case ControlledUserChange:
                {
                    ControlledUserChangeParameters? p;
                    try
                    {
                        p = string.IsNullOrEmpty(parametersJson) ? null : CeremonyParametersJson.Read<ControlledUserChangeParameters>(parametersJson);
                    }
                    catch (JsonException)
                    {
                        p = null;
                    }
                    if (p == null)
                        return null;
                    var minted = new ControlledTier((ControlledTierLevel)p.MintedTierLevel, p.MintedTierCaId) { SpaceId = p.MintedTierSpaceId };
                    var resetters = p.ChangeType is "GrantCapability" or "AssignRole" or "AddGroupMember"
                        ? (p.RecentCredentialResets ?? [])
                            .Where(r => r.What is ControlledCredentialReset.Password or ControlledCredentialReset.Mfa)
                            .Select(r => r.ActorUserId).OfType<Guid>().ToHashSet()
                        : [];
                    return (userId, tiers) => userId != p.TargetUserId
                        && tiers.Any(t => t.Dominates(minted))
                        && (!resetters.Contains(userId) || tiers.Any(t => t.Level == ControlledTierLevel.SystemSuper));
                }
            case nameof(CeremonyType.SpacePolicyChange) or nameof(CeremonyType.InstancePolicyChange):
                return (_, tiers) => MayApprovePolicyChange(tiers, spaceId);
            default:
                return (_, tiers) => MayApproveInScope(tiers, spaceId);
        }
    }

    /// <summary>Every holding of every live account, without those held through a soft-deleted CA or space.</summary>
    private async Task<List<ControlledHolding>> LiveHoldingsAsync()
    {
        var holdings = await ControlledTierResolver.LoadHoldingsAsync(db, null, null);
        var caIds = holdings.Where(h => h.Tier.CaId != null).Select(h => h.Tier.CaId!.Value).Distinct().ToList();
        var liveCas = caIds.Count == 0
            ? []
            : (await db.CertificateAuthorities.AsNoTracking().Where(c => caIds.Contains(c.Id) && !c.IsDeleted).Select(c => c.Id).ToListAsync()).ToHashSet();
        var spaceIds = holdings.Where(h => h.Tier.SpaceId != null).Select(h => h.Tier.SpaceId!.Value).Distinct().ToList();
        var liveSpaces = spaceIds.Count == 0
            ? []
            : (await db.Spaces.AsNoTracking().Where(s => spaceIds.Contains(s.Id) && !s.IsDeleted).Select(s => s.Id).ToListAsync()).ToHashSet();
        return holdings
            .Where(h => (h.Tier.CaId is not Guid ca || liveCas.Contains(ca))
                && (h.Tier.SpaceId is not Guid space || liveSpaces.Contains(space)))
            .ToList();
    }

    private static HashSet<Guid> ApprovedBy(string? approvalsJson)
    {
        try
        {
            return (JsonSerializer.Deserialize<List<ApprovalRecord>>(approvalsJson ?? "[]", ModularCA.Shared.Utils.SafeJsonOptions.Stored) ?? [])
                .Where(a => a.Decision == "Approved")
                .Select(a => a.UserId)
                .ToHashSet();
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
