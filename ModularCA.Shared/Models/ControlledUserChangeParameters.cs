namespace ModularCA.Shared.Models;

/// <summary>
/// Serialized into <c>KeyCeremonyEntity.ParametersJson</c> for a
/// <see cref="Enums.CeremonyType.ControlledUserChange"/> ceremony. Captures the deferred
/// change to a controlled user (promote, demote, delete, or an account change: password reset,
/// MFA reset, identity update) plus the affected tier so approver-dominance can be re-checked at
/// approval time, and the change applied on execute. It never carries a password.
/// </summary>
public class ControlledUserChangeParameters
{
    /// <summary>
    /// The kind of change: <c>GrantCapability</c>, <c>RevokeCapability</c>,
    /// <c>AssignRole</c>/<c>UnassignRole</c>, <c>AddGroupMember</c>/<c>RemoveGroupMember</c>,
    /// <c>DeleteUser</c>, <c>ResetPassword</c>, <c>ResetMfa</c> or <c>UpdateIdentity</c>.
    /// </summary>
    public string ChangeType { get; set; } = "GrantCapability";

    /// <summary>The user whose privileges change.</summary>
    public Guid TargetUserId { get; set; }

    /// <summary>The target user's username, captured for audit/description.</summary>
    public string? TargetUsername { get; set; }

    // ── Deferred capability-grant payload (ChangeType = GrantCapability) ──
    /// <summary>Capability to grant on execute.</summary>
    public string? Capability { get; set; }

    /// <summary>Tenant scope of the grant. Also used by the ceremony layer to stamp the ceremony's tenant.</summary>
    public Guid? TenantId { get; set; }

    /// <summary>CA scope of the grant.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>Optional resource-type scope of the grant.</summary>
    public string? ResourceType { get; set; }

    /// <summary>Optional resource-id scope of the grant.</summary>
    public Guid? ResourceId { get; set; }

    // ── Role assignment / group membership payload ──
    /// <summary>
    /// Id of the record being removed on a demote change (the UserCapabilityGrant for
    /// RevokeCapability, the RoleAssignment for UnassignRole).
    /// </summary>
    public Guid? RecordId { get; set; }

    /// <summary>Role to assign (ChangeType = AssignRole).</summary>
    public Guid? RoleId { get; set; }

    /// <summary>
    /// Group involved: the target group for AddGroupMember, or the group a role is assigned to
    /// (AssignRole to a group rather than a user).
    /// </summary>
    public Guid? GroupId { get; set; }

    /// <summary>The account fields to set (ChangeType = UpdateIdentity); null fields stay unchanged.</summary>
    public ControlledIdentityChange? Identity { get; set; }

    /// <summary>
    /// For a promotion (GrantCapability, AssignRole, AddGroupMember): the credential state, at
    /// initiation, of every account it promotes (the target, or the members of the group a role is
    /// assigned to). Execute expires the ceremony when any of them changed. Null on ceremonies opened
    /// before it was recorded.
    /// </summary>
    public List<ControlledCredentialSnapshot>? CredentialSnapshots { get; set; }

    /// <summary>
    /// For a promotion: the password and MFA resets, and account creations, of the accounts it
    /// promotes in the 30 days before it was opened, by anyone, as the audit trail records them.
    /// The ceremony description discloses them to approvers, and their actors may not approve it,
    /// also at execute when the audit trail cannot be read then.
    /// </summary>
    public List<ControlledCredentialReset>? RecentCredentialResets { get; set; }

    /// <summary>For a promotion: true when the audit trail could not be read at initiation, so recent resets are unknown.</summary>
    public bool RecentResetsUnchecked { get; set; }

    // ── Affected tier (for approver dominance) ──
    /// <summary><see cref="Authorization.ControlledTierLevel"/> of the privilege being changed.</summary>
    public int MintedTierLevel { get; set; }

    /// <summary>CA scope of the affected tier (null for system-scoped tiers).</summary>
    public Guid? MintedTierCaId { get; set; }

    /// <summary>Tenant scope of the affected tier (set for org- and CA-scoped tiers; null for system).</summary>
    public Guid? MintedTierTenantId { get; set; }
}

/// <summary>
/// The account fields an <c>UpdateIdentity</c> controlled-user change sets. Null means unchanged.
/// There is deliberately no password field.
/// </summary>
public class ControlledIdentityChange
{
    /// <summary>New username.</summary>
    public string? Username { get; set; }

    /// <summary>New email address.</summary>
    public string? Email { get; set; }

    /// <summary>New first name.</summary>
    public string? FirstName { get; set; }

    /// <summary>New last name.</summary>
    public string? LastName { get; set; }

    /// <summary>New display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Enable (true) or disable (false) the account.</summary>
    public bool? IsActive { get; set; }

    /// <summary>Lock (true) or unlock (false) the account.</summary>
    public bool? IsLocked { get; set; }

    /// <summary>Exempt the account from password expiry, or not.</summary>
    public bool? PasswordNeverExpires { get; set; }

    /// <summary>Force a password change at next logon, or not.</summary>
    public bool? PasswordChangeOnNextLogon { get; set; }

    /// <summary>
    /// The account state when the ceremony was opened. Execute expires the ceremony when the
    /// account's username, email, enabled or locked state, or a password flag this change sets, no
    /// longer matches it. Null on ceremonies opened before it was recorded.
    /// </summary>
    public ControlledAccountState? Before { get; set; }

    /// <summary>True when the change disables or locks the account, taking it out of any quorum.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool RemovesAccess => IsActive == false || IsLocked == true;
}

/// <summary>An account's identity and access state, compared at execute by an <c>UpdateIdentity</c> ceremony.</summary>
public sealed record ControlledAccountState(
    string Username,
    string Email,
    bool IsActive,
    bool IsLocked,
    bool PasswordNeverExpires,
    bool PasswordChangeOnNextLogon);

/// <summary>
/// An account's credential state: its security stamp, which rotates on every password and identity
/// change, and a digest of its second factors and their enrolment, which self-service enrolment
/// and removal change without rotating the stamp.
/// </summary>
public sealed record ControlledCredentialSnapshot(Guid UserId, string SecurityStamp, string MfaMarker);

/// <summary>
/// A credential change of a promoted account found in the audit trail: whose, which
/// (<see cref="Password"/>, <see cref="Mfa"/> or <see cref="Created"/>), by whom and when (UTC).
/// </summary>
public sealed record ControlledCredentialReset(Guid UserId, string? Username, string What, Guid? ActorUserId, string? ActorUsername, DateTime At)
{
    /// <summary>A password reset by an administrator, directly or by ceremony.</summary>
    public const string Password = "password";

    /// <summary>An MFA reset by an administrator, directly or by ceremony.</summary>
    public const string Mfa = "MFA";

    /// <summary>The account's creation, whose creator chose its first password.</summary>
    public const string Created = "created";
}

/// <summary>Summary returned by applying a controlled-user ceremony, for audit detail.</summary>
public record ControlledUserChangeResult(
    string ChangeType,
    Guid TargetUserId,
    string? Capability,
    Guid? TenantId,
    Guid? CertificateAuthorityId)
{
    /// <summary>
    /// The temporary password a <c>ResetPassword</c> change generated, for the executor's response
    /// only. Never serialized with the result, stored, audited or logged, and left out of
    /// <see cref="ToString"/>.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string? TemporaryPassword { get; init; }

    /// <summary>Prints every member except <see cref="TemporaryPassword"/>.</summary>
    protected virtual bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"ChangeType = {ChangeType}, TargetUserId = {TargetUserId}, Capability = {Capability}, ")
            .Append($"TenantId = {TenantId}, CertificateAuthorityId = {CertificateAuthorityId}");
        return true;
    }
}
