namespace ModularCA.Shared.Models;

/// <summary>
/// Parameters for a <see cref="Enums.CeremonyType.TenantPolicyChange"/> ceremony.
/// Serialized into <see cref="Entities.KeyCeremonyEntity.ParametersJson"/> at initiation
/// and locked — approvers see exactly which fields will change and from what to what.
/// </summary>
/// <remarks>
/// Only downgrades of <see cref="Entities.TenantEntity.RequireKeyCeremony"/> (true→false) and
/// decreases of <see cref="Entities.TenantEntity.CeremonyRequiredApprovals"/> travel through
/// this ceremony. Upgrades and unrelated tenant field edits apply immediately in the
/// admin controller and never create a ceremony. The <c>Current*</c> snapshot is persisted
/// so the approve/execute path can detect a state change between initiate and execute —
/// if the tenant has already moved on, we abort and the ceremony expires without mutation.
/// </remarks>
public class TenantPolicyChangeCeremonyParameters
{
    /// <summary>
    /// The tenant whose policy fields this ceremony will update, or null for the instance's
    /// policy on <see cref="Entities.SecurityPolicyEntity"/> (an InstancePolicyChange ceremony).
    /// <see cref="Guid.Empty"/> reads as null.
    /// </summary>
    public Guid? TenantId { get => _tenantId; set => _tenantId = value == Guid.Empty ? null : value; }
    private Guid? _tenantId;

    /// <summary>Value of <c>RequireKeyCeremony</c> read from the tenant at initiation time.</summary>
    public bool CurrentRequireKeyCeremony { get; set; }

    /// <summary>Value of <c>CeremonyRequiredApprovals</c> read from the tenant at initiation time.</summary>
    public int CurrentCeremonyRequiredApprovals { get; set; }

    /// <summary>Proposed value for <c>RequireKeyCeremony</c>, or <c>null</c> if this ceremony doesn't touch that field.</summary>
    public bool? ProposedRequireKeyCeremony { get; set; }

    /// <summary>Proposed value for <c>CeremonyRequiredApprovals</c>, or <c>null</c> if this ceremony doesn't touch that field.</summary>
    public int? ProposedCeremonyRequiredApprovals { get; set; }

    /// <summary>
    /// Whether this ceremony changes the tenant's controlled-user approval quorum
    /// (<see cref="Entities.TenantEntity.UserCeremonyRequiredApprovals"/>). Needed because the proposed
    /// value can legitimately be <c>null</c> (inherit the System quorum), so a bool distinguishes
    /// "set to inherit" from "not touched".
    /// </summary>
    public bool UserQuorumIncluded { get; set; }

    /// <summary>Tenant user-approval quorum read at initiation (drift guard). Null = inheriting.</summary>
    public int? CurrentUserQuorum { get; set; }

    /// <summary>Proposed tenant user-approval quorum. Null = inherit the System quorum.</summary>
    public int? ProposedUserQuorum { get; set; }

    /// <summary>Per-CA controlled-user approval quorum changes carried by this ceremony.</summary>
    public List<CaUserQuorumChange> CaUserQuorums { get; set; } = new();
}

/// <summary>A single CA's controlled-user approval quorum change inside a TenantPolicyChange ceremony.</summary>
public class CaUserQuorumChange
{
    /// <summary>The certificate authority whose quorum changes.</summary>
    public Guid CaId { get; set; }

    /// <summary>The CA's quorum read at initiation (drift guard). Null = inheriting the tenant.</summary>
    public int? CurrentQuorum { get; set; }

    /// <summary>The proposed CA quorum. Null = inherit the tenant quorum.</summary>
    public int? ProposedQuorum { get; set; }
}
