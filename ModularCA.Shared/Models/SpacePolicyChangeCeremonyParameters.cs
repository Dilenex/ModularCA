namespace ModularCA.Shared.Models;

/// <summary>
/// Parameters for a <see cref="Enums.CeremonyType.SpacePolicyChange"/> ceremony.
/// Serialized into <see cref="Entities.KeyCeremonyEntity.ParametersJson"/> at initiation
/// and locked — approvers see exactly which fields will change and from what to what.
/// </summary>
/// <remarks>
/// Only downgrades of <see cref="Entities.SpaceEntity.RequireKeyCeremony"/> (true→false) and
/// decreases of <see cref="Entities.SpaceEntity.CeremonyRequiredApprovals"/> travel through
/// this ceremony. Upgrades and unrelated space field edits apply immediately in the
/// admin controller and never create a ceremony. The <c>Current*</c> snapshot is persisted
/// so the approve/execute path can detect a state change between initiate and execute —
/// if the space has already moved on, we abort and the ceremony expires without mutation.
/// </remarks>
public class SpacePolicyChangeCeremonyParameters
{
    /// <summary>
    /// The space whose policy fields this ceremony will update, or null for the instance's
    /// policy on <see cref="Entities.SecurityPolicyEntity"/> (an InstancePolicyChange ceremony).
    /// <see cref="Guid.Empty"/> reads as null.
    /// </summary>
    public Guid? SpaceId { get => _spaceId; set => _spaceId = value == Guid.Empty ? null : value; }
    private Guid? _spaceId;

    /// <summary>Value of <c>RequireKeyCeremony</c> read from the space at initiation time.</summary>
    public bool CurrentRequireKeyCeremony { get; set; }

    /// <summary>Value of <c>CeremonyRequiredApprovals</c> read from the space at initiation time.</summary>
    public int CurrentCeremonyRequiredApprovals { get; set; }

    /// <summary>Proposed value for <c>RequireKeyCeremony</c>, or <c>null</c> if this ceremony doesn't touch that field.</summary>
    public bool? ProposedRequireKeyCeremony { get; set; }

    /// <summary>Proposed value for <c>CeremonyRequiredApprovals</c>, or <c>null</c> if this ceremony doesn't touch that field.</summary>
    public int? ProposedCeremonyRequiredApprovals { get; set; }

    /// <summary>
    /// Whether this ceremony changes the space's controlled-user approval quorum
    /// (<see cref="Entities.SpaceEntity.UserCeremonyRequiredApprovals"/>). Needed because the proposed
    /// value can legitimately be <c>null</c> (inherit the System quorum), so a bool distinguishes
    /// "set to inherit" from "not touched".
    /// </summary>
    public bool UserQuorumIncluded { get; set; }

    /// <summary>Space user-approval quorum read at initiation (drift guard). Null = inheriting.</summary>
    public int? CurrentUserQuorum { get; set; }

    /// <summary>Proposed space user-approval quorum. Null = inherit the System quorum.</summary>
    public int? ProposedUserQuorum { get; set; }

    /// <summary>Per-CA controlled-user approval quorum changes carried by this ceremony.</summary>
    public List<CaUserQuorumChange> CaUserQuorums { get; set; } = new();
}

/// <summary>A single CA's controlled-user approval quorum change inside a SpacePolicyChange ceremony.</summary>
public class CaUserQuorumChange
{
    /// <summary>The certificate authority whose quorum changes.</summary>
    public Guid CaId { get; set; }

    /// <summary>The CA's quorum read at initiation (drift guard). Null = inheriting the space.</summary>
    public int? CurrentQuorum { get; set; }

    /// <summary>The proposed CA quorum. Null = inherit the space quorum.</summary>
    public int? ProposedQuorum { get; set; }
}
