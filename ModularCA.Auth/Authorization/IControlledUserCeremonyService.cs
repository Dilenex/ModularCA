using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Orchestrates ceremony-gated changes to a <i>controlled user</i>'s privileges. A non-super
/// actor who promotes (grants), demotes (revokes), or deletes a user holding an
/// admin/operator/CA-admin tier must route the change through a
/// <see cref="Shared.Enums.CeremonyType.ControlledUserChange"/> ceremony; system-super applies
/// directly. Approvers must hold a tier that <see cref="ControlledTier.Dominates"/> the change.
/// Stage 1 implements the capability-grant (promote) path.
/// </summary>
public interface IControlledUserCeremonyService
{
    /// <summary>
    /// Classifies the tier a direct capability grant would confer at its scope (CA, tenant-wide, or
    /// system when both are null), or <c>null</c> when it confers none (no ceremony required).
    /// </summary>
    ControlledTier? ClassifyCapabilityGrant(string capability, Guid? certificateAuthorityId, Guid? tenantId = null);

    /// <summary>
    /// Classifies the tier a role assignment would confer, or <c>null</c> when the role carries no
    /// controlled capability. An assignment to a group (<paramref name="groupId"/>) takes the group's
    /// scope, as the authorization resolver does; otherwise the assignment's own tenant/CA scope.
    /// </summary>
    Task<ControlledTier?> ClassifyRoleAssignmentAsync(Guid roleId, Guid? certificateAuthorityId, Guid? tenantId = null, Guid? groupId = null);

    /// <summary>
    /// The tiers that <paramref name="capabilities"/> on role <paramref name="roleId"/> confer through
    /// the role's current assignments and pending/approved <c>AssignRole</c> ceremonies (empty when the
    /// role is unassigned or none of them is controlled).
    /// </summary>
    Task<IReadOnlyList<ControlledTier>> TiersConferredByRoleAsync(Guid roleId, IEnumerable<string> capabilities);

    /// <summary>
    /// Classifies the tier that membership in <paramref name="group"/> confers — the strongest of its
    /// structural classification and the capabilities it holds through grants and role assignments —
    /// or <c>null</c> when the group is not privilege-controlled.
    /// </summary>
    Task<ControlledTier?> ClassifyGroupAsync(CaGroupEntity group);

    /// <summary>
    /// Opens a <c>ControlledUserChange</c> ceremony for an arbitrary deferred change described by
    /// <paramref name="parameters"/>. Returns the ceremony id; threshold = resolved user quorum.
    /// </summary>
    Task<Guid> InitiateChangeAsync(
        ControlledUserChangeParameters parameters,
        ControlledTier minted,
        Guid initiatorUserId,
        string initiatorUsername);

    /// <summary>
    /// True when the acting user is system-super (super applies privilege changes directly). A worn
    /// badge counts the super group only when it includes it. Pass the request's own user only.
    /// </summary>
    Task<bool> IsSuperAsync(Guid userId);

    /// <summary>
    /// The privilege tiers the user currently holds, derived from effective capability across group
    /// grants, group roles, direct grants and direct role assignments. Ignores worn badges: this is
    /// the target-side view of an account.
    /// </summary>
    Task<IReadOnlyList<ControlledTier>> GetUserTiersAsync(Guid userId);

    /// <summary>
    /// The tiers the acting user can exercise now: <see cref="GetUserTiersAsync"/> narrowed to the
    /// grant sources their worn badge keeps (all of them when badgeless). Pass the request's own user only.
    /// </summary>
    Task<IReadOnlyList<ControlledTier>> GetActorTiersAsync(Guid actorUserId);

    /// <summary>
    /// The tier an approver must dominate to delete this user, or <c>null</c> if the user holds no
    /// controlled tier (delete is uncontrolled). Collapses multi-CA holders up to system-admin
    /// since only system-tier dominates across CAs.
    /// </summary>
    Task<ControlledTier?> GetDeletionTierAsync(Guid userId);

    /// <summary>
    /// True when the actor holds a tier that dominates <paramref name="minted"/> — i.e. they're
    /// permitted to initiate (propose) a change affecting that tier.
    /// </summary>
    Task<bool> CanInitiateAsync(Guid userId, ControlledTier minted);

    /// <summary>
    /// Approver eligibility for a <c>ControlledUserChange</c> ceremony: the approver must dominate
    /// the ceremony's affected tier and must not be the change's target user.
    /// </summary>
    Task<bool> CanApproveAsync(Guid approverUserId, KeyCeremonyEntity ceremony);

    /// <summary>
    /// The user a <c>ControlledUserChange</c> ceremony changes, and the tier it was approved at; nulls
    /// when its parameters cannot be read.
    /// </summary>
    (Guid? TargetUserId, ControlledTier? Minted) DescribeCeremony(KeyCeremonyEntity ceremony);

    /// <summary>
    /// Opens a <c>ControlledUserChange</c> ceremony for a deferred capability grant. Returns the
    /// ceremony id. The approval threshold is the resolved <i>user quorum</i>.
    /// </summary>
    Task<Guid> InitiateCapabilityGrantAsync(
        Guid targetUserId,
        string? targetUsername,
        string capability,
        Guid? tenantId,
        Guid? certificateAuthorityId,
        string? resourceType,
        Guid? resourceId,
        ControlledTier minted,
        Guid initiatorUserId,
        string initiatorUsername);

    /// <summary>
    /// Counts the users other than <paramref name="excludeUserId"/> who can act (active, not locked,
    /// not service identities, scope not soft-deleted) and hold a tier that dominates
    /// <paramref name="minted"/>. Used by demote/delete to hard-refuse removing the last dominating
    /// controlled user of a scope. A non-super actor is excluded because an initiator never counts
    /// toward quorum; a super actor counts, since supers act directly and dominate every scope.
    /// <paramref name="ignoreGroupId"/> disregards a group being deleted;
    /// <paramref name="ignoreRoleAssignmentId"/> a role assignment being removed.
    /// </summary>
    Task<int> CountDominatingControlledUsersAsync(
        ControlledTier minted, Guid excludeUserId, Guid? ignoreGroupId = null, Guid? actorUserId = null, Guid? ignoreRoleAssignmentId = null);

    /// <summary>
    /// True when <paramref name="actorUserId"/> may perform identity-altering administration
    /// (password reset, MFA reset, activation/lock/username/email changes) on
    /// <paramref name="targetUserId"/>. System-super may administer anyone. Otherwise the target must
    /// not be super, a member of any system group needs a system-admin actor, and every tier the
    /// target holds must be dominated by one of the actor's tiers.
    /// </summary>
    Task<bool> CanAdministerAccountAsync(Guid actorUserId, Guid targetUserId);

    /// <summary>
    /// True when removing <paramref name="removedCapabilities"/> from role <paramref name="roleId"/>
    /// (all of its controlled capabilities when null, i.e. deleting it) would leave no user other than
    /// the actor holding a tier that dominates <paramref name="minted"/>, from any grant source.
    /// </summary>
    Task<bool> IsLastControlledSourceForRoleAsync(
        Guid roleId, ControlledTier minted, Guid? actorUserId = null, IReadOnlyCollection<string>? removedCapabilities = null);

    /// <summary>
    /// Applies an approved controlled-user ceremony on execute, after re-validating it against the
    /// current state, and marks it Executed in the same transaction. Returns a summary for audit.
    /// Throws <see cref="Shared.Interfaces.CeremonyNotExecutableException"/> when the ceremony is no
    /// longer Approved (a concurrent execute ran it), and <see cref="ControlledUserChangeRefusedException"/>
    /// when the privilege grew after approval, the approvals no longer cover it, or a demotion would
    /// leave its scope without a dominating user.
    /// </summary>
    Task<ControlledUserChangeResult> ApplyApprovedAsync(Guid ceremonyId);
}

/// <summary>
/// An approved controlled-user ceremony that may not be executed as it stands.
/// <see cref="CeremonyExpired"/> is true when the ceremony was marked Expired because the approval
/// is stale (a new ceremony is needed); false when it stays Approved and may be retried later.
/// </summary>
public sealed class ControlledUserChangeRefusedException(string message, bool ceremonyExpired)
    : InvalidOperationException(message)
{
    /// <summary>True when the ceremony was marked Expired and can no longer be executed.</summary>
    public bool CeremonyExpired { get; } = ceremonyExpired;
}
