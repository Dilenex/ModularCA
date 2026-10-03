using ModularCA.Shared.Models;

namespace ModularCA.Core.Services;

/// <summary>
/// Orchestrates ceremony-gated changes to space security policy fields
/// (<see cref="Shared.Entities.SpaceEntity.RequireKeyCeremony"/> and
/// <see cref="Shared.Entities.SpaceEntity.CeremonyRequiredApprovals"/>). A space admin who is
/// not a global system-super must route downgrades through this service, which opens a
/// <see cref="Shared.Enums.CeremonyType.SpacePolicyChange"/> ceremony. Upgrades are never
/// gated — the controller applies them directly.
/// </summary>
public interface ISpacePolicyChangeService
{
    /// <summary>
    /// Returns <c>true</c> when the proposed combination represents a security downgrade
    /// relative to <paramref name="current"/> — either flipping <c>RequireKeyCeremony</c>
    /// from true to false, or decreasing <c>CeremonyRequiredApprovals</c>. Ignores fields
    /// not being changed.
    /// </summary>
    /// <param name="currentRequireKeyCeremony">Current value on the space row.</param>
    /// <param name="currentCeremonyRequiredApprovals">Current value on the space row.</param>
    /// <param name="proposedRequireKeyCeremony">Proposed value, or null if unchanged.</param>
    /// <param name="proposedCeremonyRequiredApprovals">Proposed value, or null if unchanged.</param>
    bool IsDowngrade(
        bool currentRequireKeyCeremony,
        int currentCeremonyRequiredApprovals,
        bool? proposedRequireKeyCeremony,
        int? proposedCeremonyRequiredApprovals);

    /// <summary>
    /// Opens a <see cref="Shared.Enums.CeremonyType.SpacePolicyChange"/> ceremony for the
    /// proposed change, or an <see cref="Shared.Enums.CeremonyType.InstancePolicyChange"/>
    /// ceremony when <paramref name="spaceId"/> is null. The approval threshold snaps to the
    /// scope's <i>current</i> <c>CeremonyRequiredApprovals</c>. Fails with
    /// <see cref="InvalidOperationException"/> if another Pending policy-change ceremony already
    /// exists for the scope.
    /// </summary>
    /// <param name="spaceId">The space whose policy will change on execution, or null for the instance's.</param>
    /// <param name="proposedRequireKeyCeremony">Proposed value, or null if unchanged.</param>
    /// <param name="proposedCeremonyRequiredApprovals">Proposed value, or null if unchanged.</param>
    /// <param name="initiatorUserId">The user initiating the ceremony (for audit/approvals).</param>
    /// <param name="initiatorUsername">The initiator's username (for audit/approvals).</param>
    /// <returns>The created ceremony ID.</returns>
    /// <param name="userQuorumIncluded">When true, the space's controlled-user approval quorum is changed to <paramref name="proposedUserQuorum"/> on execution.</param>
    /// <param name="proposedUserQuorum">Proposed space user-approval quorum (null = inherit System). Only applied when <paramref name="userQuorumIncluded"/> is true.</param>
    /// <param name="caUserQuorums">Per-CA user-approval quorum changes (CaId + ProposedQuorum); current values are snapshotted here for the drift guard.</param>
    Task<Guid> InitiateChangeAsync(
        Guid? spaceId,
        bool? proposedRequireKeyCeremony,
        int? proposedCeremonyRequiredApprovals,
        Guid initiatorUserId,
        string initiatorUsername,
        bool userQuorumIncluded = false,
        int? proposedUserQuorum = null,
        IReadOnlyList<ModularCA.Shared.Models.CaUserQuorumChange>? caUserQuorums = null);

    /// <summary>
    /// Applies an approved policy-change ceremony to the space row, or to the instance's
    /// security policy row for an InstancePolicyChange. Re-validates that
    /// the scope still exists and that the snapshotted <c>Current*</c> values still
    /// match before mutating. Called by the ceremony Execute endpoint after quorum is
    /// reached. On success, marks the ceremony Executed and returns the before/after
    /// values for the calling controller to emit as audit detail.
    /// </summary>
    /// <param name="ceremonyId">The approved ceremony.</param>
    Task<SpacePolicyChangeAppliedResult> ApplyApprovedChangeAsync(Guid ceremonyId);
}

/// <summary>
/// Result of a successful policy-change execution — carries before/after values so the
/// controller can emit them in the audit entry. <c>SpaceId</c> is null for the instance.
/// </summary>
public record SpacePolicyChangeAppliedResult(
    Guid? SpaceId,
    bool BeforeRequireKeyCeremony,
    int BeforeCeremonyRequiredApprovals,
    bool AfterRequireKeyCeremony,
    int AfterCeremonyRequiredApprovals);
