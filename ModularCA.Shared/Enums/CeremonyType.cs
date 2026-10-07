namespace ModularCA.Shared.Enums;

/// <summary>
/// Categorizes a <see cref="ModularCA.Shared.Entities.KeyCeremonyEntity"/> by the kind of
/// operation it gates. Added as a nullable column so historical rows — all of which
/// predate the policy-change flow — read as <c>CaCreation</c> after the migration backfill.
/// </summary>
/// <remarks>
/// <para>
/// <b>CaCreation</b> covers the pre-existing ceremony types (CreateRootCA, CreateIntermediateCA,
/// CreateSshCa, DeleteSshCa, RevokeCa, etc.) — anything that mutates CA state.
/// </para>
/// <para>
/// <b>SpacePolicyChange</b> (<c>TenantPolicyChange</c> before 0.4.0; the int is unchanged and
/// the RenameTenantToSpace migration renames stored operation types) gates downgrades of
/// <see cref="Entities.SpaceEntity.RequireKeyCeremony"/>
/// and <see cref="Entities.SpaceEntity.CeremonyRequiredApprovals"/>. The quorum that protects
/// this ceremony is snapshotted from the space's <i>current</i> CeremonyRequiredApprovals so an
/// in-flight downgrade can't ratchet itself down through a second pending ceremony.
/// </para>
/// </remarks>
public enum CeremonyType
{
    /// <summary>Ceremonies that mutate CA state (create/revoke/delete).</summary>
    CaCreation = 0,

    /// <summary>Ceremonies that mutate a space's security policy (ceremony-requirement fields).</summary>
    SpacePolicyChange = 1,

    /// <summary>
    /// Ceremonies that change a <i>controlled user</i>'s privileges — promote (grant),
    /// demote (revoke), or delete a user holding an admin/operator/CA-admin tier. Initiated
    /// by any non-super actor; approved by a quorum that dominates the affected tier. The
    /// approval threshold comes from the <i>user quorum</i> (distinct from the CA/key quorum).
    /// </summary>
    ControlledUserChange = 2,

    /// <summary>
    /// Ceremonies that change the instance's own CA policy on
    /// <see cref="Entities.SecurityPolicyEntity"/> (ceremony requirement, key quorum, instance-CA
    /// user quorum). The instance counterpart of <see cref="SpacePolicyChange"/>; its quorum is
    /// the instance's <c>CeremonyRequiredApprovals</c>, one pending at a time.
    /// </summary>
    InstancePolicyChange = 3,
}
