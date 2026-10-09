using System.Text.Json.Serialization;
using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Interfaces;

/// <summary>Where a login name on a certificate comes from: the values of <see cref="SshLoginNameGround.Source"/>.</summary>
public static class SshLoginNameSources
{
    /// <summary>The subject's own username, on a key that allows it.</summary>
    public const string Own = "own";

    /// <summary>A grant to the subject.</summary>
    public const string User = "user";

    /// <summary>A grant to a group the subject is a member of.</summary>
    public const string Group = "group";

    /// <summary>Typed by an administrator for a service identity and checked against the certificate profile only.</summary>
    public const string Typed = "typed";
}

/// <summary>
/// One ground on which a subject holds one login name. Stored with a certificate as the
/// snapshot of why its subject held each name (<see cref="SshCertificateEntity.LoginNameGrounds"/>),
/// so the member names are fixed.
/// </summary>
public sealed record SshLoginNameGround
{
    /// <summary>The login name.</summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>One of <see cref="SshLoginNameSources"/>.</summary>
    [JsonPropertyName("source")]
    public string Source { get; init; } = SshLoginNameSources.Typed;

    /// <summary>The grant, for <c>user</c> and <c>group</c>.</summary>
    [JsonPropertyName("grantId")]
    public Guid? GrantId { get; init; }

    /// <summary>The group the grant was made to, for <c>group</c>.</summary>
    [JsonPropertyName("groupId")]
    public Guid? GroupId { get; init; }

    /// <summary>That group's name.</summary>
    [JsonPropertyName("groupName")]
    public string? GroupName { get; init; }

    /// <summary>Who granted the name, for a grant.</summary>
    [JsonPropertyName("grantedByUserId")]
    public Guid? GrantedByUserId { get; init; }

    /// <summary>The username of whoever granted the name, for a grant.</summary>
    [JsonPropertyName("grantedByUsername")]
    public string? GrantedByUsername { get; init; }

    /// <summary>The grant's own limit in hours; null when it is the SSH CA key's maximum.</summary>
    [JsonPropertyName("maxValidityHours")]
    public int? MaxValidityHours { get; init; }

    /// <summary>When the grant ends, UTC; null when it does not end.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTime? ExpiresAt { get; init; }
}

/// <summary>A login name a user holds on an SSH CA key, with the most generous of its grounds.</summary>
/// <param name="Name">The login name.</param>
/// <param name="Ground">The ground that allows the latest certificate end.</param>
/// <param name="MaxValidityHours">The longest certificate that may carry the name, in hours: that ground's limit, never over the key's maximum.</param>
/// <param name="ExpiresAt">When that ground ends, UTC; null when it does not end.</param>
/// <param name="Grounds">Every ground the user holds the name on now.</param>
public sealed record SshHeldLoginName(string Name, SshLoginNameGround Ground, int MaxValidityHours, DateTime? ExpiresAt,
    IReadOnlyList<SshLoginNameGround> Grounds);

/// <summary>An SSH CA key, as a certificate or a login name refers to it.</summary>
/// <param name="Id">The key.</param>
/// <param name="Name">Its name.</param>
/// <param name="Fingerprint">The SHA-256 fingerprint of its public key, as <c>sshd</c> logs it; null when the key cannot be read.</param>
/// <param name="CertificateAuthorityId">The certificate authority the key belongs to, which rights on the key are held on.</param>
public sealed record SshCaKeyRef(Guid Id, string Name, string? Fingerprint, Guid CertificateAuthorityId);

/// <summary>A user, as a grant or a certificate refers to one.</summary>
/// <param name="Id">The user; null once deleted.</param>
/// <param name="Username">The username; null when it is no longer known.</param>
public sealed record SshUserRef(Guid? Id, string? Username);

/// <summary>A group a login name is granted to.</summary>
/// <param name="Id">The group.</param>
/// <param name="Name">Its name.</param>
/// <param name="DisplayName">Its display name.</param>
/// <param name="MemberCount">How many members it has now.</param>
public sealed record SshGroupRef(Guid Id, string Name, string DisplayName, int MemberCount);

/// <summary>One login name grant, as the admin API answers it.</summary>
/// <param name="Id">The grant.</param>
/// <param name="SshCaKey">The key it is on.</param>
/// <param name="LoginName">The login name.</param>
/// <param name="User">The user it was made to, or null.</param>
/// <param name="Group">The group it was made to, or null.</param>
/// <param name="MaxValidityHours">Its limit in hours; null for the key's maximum.</param>
/// <param name="ExpiresAt">When it ends, UTC; null when it does not end.</param>
/// <param name="Ended">Whether it has ended.</param>
/// <param name="Note">The note left with it.</param>
/// <param name="GrantedBy">Who granted it.</param>
/// <param name="GrantedAt">When it was granted, UTC.</param>
/// <param name="LiveCertificates">The unexpired, unrevoked certificates whose grounds name this grant.</param>
public sealed record SshLoginNameGrantView(Guid Id, SshCaKeyRef SshCaKey, string LoginName, SshUserRef? User, SshGroupRef? Group,
    int? MaxValidityHours, DateTime? ExpiresAt, bool Ended, string? Note, SshUserRef GrantedBy, DateTime GrantedAt, int LiveCertificates);

/// <summary>The login names of one SSH CA key.</summary>
/// <param name="SshCaKey">The key.</param>
/// <param name="MaxValidityHours">The key's maximum validity in hours, which a grant with no limit of its own takes.</param>
/// <param name="AllowOwnUsername">Whether everyone may log in as their own username without a grant.</param>
/// <param name="Grants">The grants, by login name.</param>
public sealed record SshLoginNameGrantList(SshCaKeyRef SshCaKey, int MaxValidityHours, bool AllowOwnUsername, IReadOnlyList<SshLoginNameGrantView> Grants);

/// <summary>What an administrator asks when granting login names.</summary>
/// <param name="LoginNames">The names; one grant is made per name.</param>
/// <param name="UserId">The user to grant them to, or null.</param>
/// <param name="GroupId">The group to grant them to, or null.</param>
/// <param name="MaxValidityHours">The limit in hours; null for the key's maximum.</param>
/// <param name="ExpiresAt">When the grants end, UTC; null when they do not end.</param>
/// <param name="Note">A note, at most 256 characters.</param>
public sealed record SshLoginNameGrantRequest(IReadOnlyList<string> LoginNames, Guid? UserId, Guid? GroupId, int? MaxValidityHours,
    DateTime? ExpiresAt, string? Note);

/// <summary>What a grant is changed to. All three are set: null clears the limit, the end or the note.</summary>
/// <param name="MaxValidityHours">The limit in hours; null for the key's maximum.</param>
/// <param name="ExpiresAt">When the grant ends, UTC; null when it does not end.</param>
/// <param name="Note">A note, at most 256 characters.</param>
public sealed record SshLoginNameGrantChange(int? MaxValidityHours, DateTime? ExpiresAt, string? Note);

/// <summary>A grant after a change, and the certificates the change revoked.</summary>
/// <param name="Grant">The grant as it now is.</param>
/// <param name="RevokedCertificates">How many certificates were revoked because their subject no longer holds a name.</param>
public sealed record SshLoginNameGrantChanged(SshLoginNameGrantView Grant, int RevokedCertificates);

/// <summary>One ground on which a user holds a login name on a key, for the user's page.</summary>
/// <param name="SshCaKey">The key.</param>
/// <param name="LoginName">The login name.</param>
/// <param name="Source">One of <c>own</c>, <c>user</c>, <c>group</c>.</param>
/// <param name="GrantId">The grant, for <c>user</c> and <c>group</c>.</param>
/// <param name="GroupId">The group, for <c>group</c>.</param>
/// <param name="GroupName">That group's name.</param>
/// <param name="MaxValidityHours">The longest certificate under this ground, in hours, never over the key's maximum.</param>
/// <param name="LimitIsKeyMaximum">Whether that limit is the key's maximum, no limit of the grant's own.</param>
/// <param name="ExpiresAt">When the ground ends, UTC; null when it does not end.</param>
/// <param name="Effective">Whether this is the ground that counts for the name: the most generous one.</param>
public sealed record SshUserLoginNameView(SshCaKeyRef SshCaKey, string LoginName, string Source, Guid? GrantId, Guid? GroupId, string? GroupName,
    int MaxValidityHours, bool LimitIsKeyMaximum, DateTime? ExpiresAt, bool Effective);

/// <summary>Who an SSH certificate is for.</summary>
/// <param name="Kind">
/// <c>user</c>, <c>service</c> (a service identity with no account), <c>host</c>, or
/// <c>unknown</c> for a user certificate issued before login names whose subject was not recorded.
/// </param>
/// <param name="UserId">The user, for <c>user</c>; null once deleted.</param>
/// <param name="Username">The username, for <c>user</c>.</param>
/// <param name="ServiceLabel">The label, for <c>service</c>.</param>
public sealed record SshCertificateSubjectView(string Kind, Guid? UserId, string? Username, string? ServiceLabel);

/// <summary>Who asked for an SSH certificate.</summary>
/// <param name="UserId">The user; null when not recorded.</param>
/// <param name="Username">The username; null when the user is gone.</param>
/// <param name="SelfService">Whether the subject asked for it themselves.</param>
/// <param name="SourceIp">The address the request came from; left out of what a user sees of their own certificates.</param>
public sealed record SshCertificateIssuerView(Guid? UserId, string? Username, bool SelfService, string? SourceIp);

/// <summary>
/// An issued SSH certificate with who it is for, who issued it and why its subject held each
/// login name. The first members are the row's own, under the names the API has always used.
/// </summary>
public sealed record SshCertificateView
{
    /// <summary>The certificate row.</summary>
    public Guid Id { get; init; }
    /// <summary>The SSH CA key that signed it.</summary>
    public Guid SshCaKeyId { get; init; }
    /// <summary><c>user</c> or <c>host</c>.</summary>
    public string CertificateType { get; init; } = string.Empty;
    /// <summary>The key id the CA wrote: the name hosts log.</summary>
    public string KeyId { get; init; } = string.Empty;
    /// <summary>The serial number.</summary>
    public long SerialNumber { get; init; }
    /// <summary>The login names (or hostnames), a JSON array in a string, as the row stores it.</summary>
    public string Principals { get; init; } = "[]";
    /// <summary>The start of validity, UTC.</summary>
    public DateTime ValidAfter { get; init; }
    /// <summary>The end of validity, UTC.</summary>
    public DateTime ValidBefore { get; init; }
    /// <summary>The certified public key, an authorized_keys line.</summary>
    public string PublicKey { get; init; } = string.Empty;
    /// <summary>The certificate, as OpenSSH reads it.</summary>
    public string SignedCertificate { get; init; } = string.Empty;
    /// <summary>The options, a JSON array in a string; null when there is none.</summary>
    public string? Extensions { get; init; }
    /// <summary>Whether it is revoked.</summary>
    public bool IsRevoked { get; init; }
    /// <summary>When it was revoked, UTC; null while it is not, and for one revoked before the time was recorded.</summary>
    public DateTime? RevokedAt { get; init; }
    /// <summary>Who asked for it.</summary>
    public Guid? IssuedByUserId { get; init; }
    /// <summary>The address the request came from.</summary>
    public string? SourceIp { get; init; }
    /// <summary>When the row was written, UTC.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary><c>active</c>, <c>expired</c> or <c>revoked</c>.</summary>
    public string Status { get; init; } = string.Empty;
    /// <summary>The SSH CA key that signed it.</summary>
    public SshCaKeyRef? SshCaKey { get; init; }
    /// <summary>The SHA-256 fingerprint of the certified key, as <c>sshd</c> logs it.</summary>
    public string? KeyFingerprint { get; init; }
    /// <summary>The user the certificate is for; null as on the row.</summary>
    public Guid? SubjectUserId { get; init; }
    /// <summary>Who the certificate is for.</summary>
    public SshCertificateSubjectView Subject { get; init; } = new("unknown", null, null, null);
    /// <summary>Who asked for it.</summary>
    public SshCertificateIssuerView IssuedBy { get; init; } = new(null, null, false, null);
    /// <summary>Why the subject held each login name at issuance; null on a host certificate and on a row from before login names.</summary>
    public IReadOnlyList<SshLoginNameGround>? LoginNameGrounds { get; init; }
}

/// <summary>What revoking a user's certificates came to.</summary>
/// <param name="Revoked">How many were revoked.</param>
/// <param name="LeftForRights">How many live ones were left because the caller may not revoke on their key.</param>
public sealed record SshSubjectRevocation(int Revoked, int LeftForRights);

/// <summary>What one periodic sweep of the SSH certificates revoked, per rule.</summary>
/// <param name="UserNotActive">Certificates whose user is not active.</param>
/// <param name="UserDeleted">Certificates issued for a user that has since been deleted.</param>
/// <param name="LoginNameLost">Certificates that carried a login name their subject no longer holds.</param>
/// <param name="UserRenamed">Certificates whose key id is no longer their subject's username.</param>
/// <param name="RequestRightLost">Certificates whose user may no longer request from the SSH CA.</param>
public sealed record SshLoginNameSweep(int UserNotActive, int UserDeleted, int LoginNameLost, int UserRenamed = 0, int RequestRightLost = 0)
{
    /// <summary>Everything the sweep revoked, across the five rules.</summary>
    public int Total => UserNotActive + UserDeleted + LoginNameLost + UserRenamed + RequestRightLost;
}

/// <summary>A login name the caller may ask for on a key, for the request form.</summary>
/// <param name="Name">The login name.</param>
/// <param name="Source">One of <c>own</c>, <c>user</c>, <c>group</c>: the ground that counts.</param>
/// <param name="GrantId">The grant, for <c>user</c> and <c>group</c>.</param>
/// <param name="GroupId">The group, for <c>group</c>.</param>
/// <param name="GroupName">That group's name.</param>
/// <param name="MaxValidityHours">The longest certificate that may carry the name, in hours.</param>
/// <param name="ExpiresAt">When the ground ends, UTC; null when it does not end.</param>
public sealed record SshRequestLoginName(string Name, string Source, Guid? GrantId, Guid? GroupId, string? GroupName, int MaxValidityHours,
    DateTime? ExpiresAt);

/// <summary>One usable combination of profiles on a key.</summary>
/// <param name="RequestProfileId">The request profile, which requires no approval.</param>
/// <param name="RequestProfileName">Its name.</param>
/// <param name="SigningProfileId">The signing profile, which points at the key and allows user certificates.</param>
/// <param name="SigningProfileName">Its name.</param>
/// <param name="CertProfileId">The certificate profile.</param>
/// <param name="CertProfileName">Its name.</param>
/// <param name="MaxValidityHours">The smallest of the three profiles' limits and the key's, in hours.</param>
/// <param name="MaxPrincipals">How many login names one certificate may carry.</param>
/// <param name="UnavailableLoginNames">The caller's login names that the certificate profile's patterns do not allow.</param>
public sealed record SshRequestProfileCombination(Guid RequestProfileId, string RequestProfileName, Guid SigningProfileId, string SigningProfileName,
    Guid CertProfileId, string CertProfileName, int MaxValidityHours, int MaxPrincipals, IReadOnlyList<string> UnavailableLoginNames);

/// <summary>What the caller may ask of one SSH CA key.</summary>
/// <param name="Id">The key.</param>
/// <param name="Name">Its name.</param>
/// <param name="KeyType">Its key type.</param>
/// <param name="Fingerprint">The SHA-256 fingerprint of its public key.</param>
/// <param name="MaxValidityHours">Its maximum validity in hours.</param>
/// <param name="AllowOwnUsername">Whether it lets everyone log in as their own username.</param>
/// <param name="LoginNames">The login names the caller holds on it.</param>
/// <param name="Profiles">The profile combinations the caller can submit with.</param>
public sealed record SshRequestKeyOptions(Guid Id, string Name, string KeyType, string? Fingerprint, int MaxValidityHours, bool AllowOwnUsername,
    IReadOnlyList<SshRequestLoginName> LoginNames, IReadOnlyList<SshRequestProfileCombination> Profiles);

/// <summary>Everything the self-service request form needs.</summary>
/// <param name="KeyId">The key id the CA writes into the caller's certificates; null when the caller's username cannot be one.</param>
/// <param name="CaKeys">The SSH CA keys the caller may request from.</param>
public sealed record SshRequestOptions(string? KeyId, IReadOnlyList<SshRequestKeyOptions> CaKeys);

/// <summary>What issuance may certify for a user subject: the grounds of the names asked, and the latest end they allow.</summary>
/// <param name="Grounds">The ground that counts for each name asked, in the order asked.</param>
/// <param name="MaxValidityHours">The smallest limit among them, in hours.</param>
/// <param name="HoursLimitedBy">The login name with that limit.</param>
/// <param name="NotAfter">The earliest end among them, UTC; null when none ends.</param>
/// <param name="NotAfterLimitedBy">The login name whose ground ends then.</param>
public sealed record SshLoginNameIssuance(IReadOnlyList<SshLoginNameGround> Grounds, int MaxValidityHours, string? HoursLimitedBy,
    DateTime? NotAfter, string? NotAfterLimitedBy);

/// <summary>
/// SSH login names: which accounts a user may get a certificate for from an SSH CA key, the
/// grants that give them, and the revocation of certificates whose subject no longer holds a
/// name or may no longer request from the SSH CA. A user holds their own username where the key
/// allows it, and each name granted on the key to them or to a group they are a member of,
/// while the grant has not ended. The service writes the audit entry of each grant operation
/// and each revocation itself.
/// </summary>
public interface ISshLoginNameService
{
    /// <summary>The login names <paramref name="userId"/> holds on <paramref name="caKeyId"/> now, by name. Empty for an unknown user or key.</summary>
    Task<IReadOnlyList<SshHeldLoginName>> HeldAsync(Guid userId, Guid caKeyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decides a user certificate's login names: every one of <paramref name="principals"/> must
    /// be held by <paramref name="userId"/> on <paramref name="caKeyId"/>.
    /// </summary>
    /// <param name="validAfter">The certificate's start, which the most generous ground of a name is judged from.</param>
    /// <exception cref="ModularCA.Shared.Errors.InvalidRequestException">A principal is not held; the message names it.</exception>
    Task<SshLoginNameIssuance> ForIssuanceAsync(Guid userId, Guid caKeyId, IReadOnlyList<string> principals, DateTime validAfter,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether the SSH CA key's certificate authority may refer to the user: the user exists and
    /// has a membership, a role or a grant in that authority's scope.
    /// </summary>
    Task<bool> MayReferenceUserAsync(Guid caKeyId, Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether the user may request certificates from the SSH CA key's certificate authority:
    /// they hold cert.request on it, from any grant source. A certificate is issued for a user,
    /// whoever asks, only while this holds, and a live one is revoked once it no longer does.
    /// False for an unknown user or key.
    /// </summary>
    Task<bool> MayRequestAsync(Guid userId, Guid caKeyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The scopes a user has a footing in: the space of each group they are a member of and of
    /// each role or grant on them, null standing for the instance.
    /// </summary>
    Task<IReadOnlySet<Guid?>> ScopesOfUserAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>The login names of a key: its own-username switch and its grants. Null for an unknown key.</summary>
    Task<SshLoginNameGrantList?> ListAsync(Guid caKeyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Grants login names on a key to one user or one group, one grant per name, all or none.
    /// </summary>
    /// <exception cref="ModularCA.Shared.Errors.InvalidRequestException">A name, the target, the limit, the end or the note is refused.</exception>
    /// <exception cref="ModularCA.Shared.Errors.ResourceConflictException">The target already has one of the names on this key; the message names it.</exception>
    Task<IReadOnlyList<SshLoginNameGrantView>> GrantAsync(Guid caKeyId, SshLoginNameGrantRequest request, SshCaActor? actor = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Changes a grant's limit, end and note. Moving the end earlier revokes the certificates
    /// whose subject no longer holds a name through their validity; lowering the limit revokes none.
    /// Null when the key has no such grant.
    /// </summary>
    Task<SshLoginNameGrantChanged?> ChangeGrantAsync(Guid caKeyId, Guid grantId, SshLoginNameGrantChange change, SshCaActor? actor = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a grant and revokes the certificates whose subject no longer holds a name. Returns
    /// how many were revoked, or null when the key has no such grant.
    /// </summary>
    Task<int?> RemoveGrantAsync(Guid caKeyId, Guid grantId, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets whether everyone may log in as their own username on a key. Turning it off revokes
    /// the certificates whose subject no longer holds a name. Returns how many were revoked, or
    /// null for an unknown key.
    /// </summary>
    Task<int?> SetOwnUsernameAsync(Guid caKeyId, bool allowed, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>Every ground on which a user holds a login name, on each of <paramref name="caKeyIds"/> that signs user certificates.</summary>
    Task<IReadOnlyList<SshUserLoginNameView>> NamesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> caKeyIds, CancellationToken cancellationToken = default);

    /// <summary>The grants made to a group, on <paramref name="caKeyIds"/>.</summary>
    Task<IReadOnlyList<SshLoginNameGrantView>> GrantsOfGroupAsync(Guid groupId, IReadOnlyCollection<Guid> caKeyIds, CancellationToken cancellationToken = default);

    /// <summary>The certificates issued for a user, on <paramref name="caKeyIds"/>, newest first.</summary>
    /// <param name="liveOnly">Only the unexpired, unrevoked ones.</param>
    Task<IReadOnlyList<SshCertificateView>> CertificatesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> caKeyIds, bool liveOnly,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the live certificates issued for a user on <paramref name="revocableCaKeyIds"/>,
    /// and counts the live ones on any other key as left.
    /// </summary>
    Task<SshSubjectRevocation> RevokeCertificatesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> revocableCaKeyIds, SshCaActor? actor = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The certificates with a serial number, on <paramref name="caKeyIds"/>, narrowed by the SSH
    /// CA key's fingerprint and by the key id when given.
    /// </summary>
    Task<IReadOnlyList<SshCertificateView>> FindCertificatesAsync(long serial, string? caFingerprint, string? keyId, IReadOnlyCollection<Guid> caKeyIds,
        CancellationToken cancellationToken = default);

    /// <summary>Describes certificate rows: who each is for, who issued it, and its grounds.</summary>
    Task<IReadOnlyList<SshCertificateView>> DescribeAsync(IReadOnlyList<SshCertificateEntity> certificates, CancellationToken cancellationToken = default);

    /// <summary>
    /// What the self-service request form needs for a user: per SSH CA key of
    /// <paramref name="requestableCaIds"/> that signs user certificates, the usable profile
    /// combinations and the login names the user holds.
    /// </summary>
    Task<SshRequestOptions> RequestOptionsAsync(Guid userId, IReadOnlyCollection<Guid> requestableCaIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the live certificates of <paramref name="userIds"/> that their subject may no
    /// longer have: every one on an SSH CA the user may no longer request from, those from
    /// before login names included, and every one issued with grounds that carries a login name
    /// its subject no longer holds through its validity. Call it after the change that may have
    /// taken a right or a name away has been saved. Returns how many were revoked.
    /// </summary>
    /// <param name="reason">Why, for the audit entry of each revocation.</param>
    Task<int> ReconcileUsersAsync(IEnumerable<Guid> userIds, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>As <see cref="ReconcileUsersAsync"/>, for every certificate of one SSH CA key.</summary>
    Task<int> ReconcileKeyAsync(Guid caKeyId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// As <see cref="ReconcileUsersAsync"/>, for the members of a group: a role or a capability
    /// was taken from the group, so each member may have lost a right.
    /// </summary>
    Task<int> ReconcileGroupAsync(Guid groupId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// As <see cref="ReconcileUsersAsync"/>, for every user certificate: a role lost a capability
    /// or was deleted, so anyone who held it may have lost a right.
    /// </summary>
    Task<int> ReconcileAllAsync(string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every live certificate issued for a user, those from before login names included:
    /// the user was deactivated or is being deleted. Returns how many were revoked.
    /// </summary>
    Task<int> RevokeAllOfUserAsync(Guid userId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// What deleting a user takes with it, to be called before the user row is removed: every
    /// live certificate issued for the user is revoked and the grants made to the user are removed.
    /// </summary>
    Task<int> UserDeletingAsync(Guid userId, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// What deleting a group takes with it, to be called before the group row is removed: the
    /// grants made to the group are removed, and the certificates of its members that then
    /// carry a login name their subject no longer holds are revoked. Returns how many were revoked.
    /// The rights the group gave are still held at that point: reconcile its former members
    /// (<see cref="ReconcileUsersAsync"/>) once the row is gone.
    /// </summary>
    Task<int> GroupDeletingAsync(Guid groupId, SshCaActor? actor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// The periodic backstop for the hooks above, over every SSH CA key: a hook runs after its
    /// change is saved, so a node that stops between the two leaves a certificate live. Revokes
    /// every live certificate issued for a user that is not active (those from before login names
    /// included), every live user certificate whose grounds name a source other than <c>typed</c>
    /// and whose user has been deleted, every live user certificate issued with grounds whose key
    /// id is no longer its subject's username (a rename), every live certificate issued for a
    /// user who may no longer request from its SSH CA (those from before login names included),
    /// and every live user certificate issued with grounds that carries a login name its subject
    /// no longer holds through its validity. A right can also be lost by a change no hook
    /// follows; the sweep is then what revokes. Host certificates, service identities' and rows
    /// with neither grounds nor a subject are left alone. A sweep that finds nothing writes nothing.
    /// </summary>
    Task<SshLoginNameSweep> SweepAsync(SshCaActor? actor = null, CancellationToken cancellationToken = default);
}

/// <summary>What the places that take a role away call, so each says the same thing in the audit.</summary>
public static class SshLoginNameHooks
{
    /// <summary>
    /// Reconciles after a role assignment has been removed and saved: the user it was on, or
    /// the members of the group it was on.
    /// </summary>
    public static Task<int> RoleUnassignedAsync(this ISshLoginNameService loginNames, Guid? userId, Guid? groupId, SshCaActor? actor = null,
        CancellationToken cancellationToken = default)
    {
        if (groupId is Guid group)
            return loginNames.ReconcileGroupAsync(group, "a role was taken from a group the user is in", actor, cancellationToken);
        return userId is Guid user
            ? loginNames.ReconcileUsersAsync([user], "a role was taken from the user", actor, cancellationToken)
            : Task.FromResult(0);
    }
}
