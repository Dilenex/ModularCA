using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Runtime-tunable security policy stored in the database so admins can change
/// session/lockout, MFA, and OCSP responder posture via
/// <c>PUT /api/v1/admin/security-policy</c> without restarting the app.
/// Single-row entity — same pattern as <see cref="PasswordPolicyEntity"/>.
/// <para>
/// Login-failure lockout is owned exclusively by this entity's
/// <see cref="MaxFailedLoginAttempts"/> / <see cref="LockoutMinutes"/>, applied session-wide
/// across password, LDAP, mTLS, TOTP, and WebAuthn. The previously-duplicated
/// PasswordPolicy lockout columns were dropped.
/// </para>
/// <para>
/// Middleware-wired knobs that need to be read before the DB is available
/// (<c>BindJwtToIp</c>, refresh-token binding, <c>BehindReverseProxy</c>,
/// per-username rate-limits) remain on <c>SystemConfig.Security</c> in YAML.
/// </para>
/// </summary>
[Table("SecurityPolicy")]
public class SecurityPolicyEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    // ── Session / lockout ───────────────────────────────────────────
    /// <summary>Failed login attempts before the account is locked. Default 5.</summary>
    public int MaxFailedLoginAttempts { get; set; } = 5;

    /// <summary>Lockout duration in minutes. Default 15. 0 = permanent lock (admin unlock required).</summary>
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>Minutes of inactivity before a session is considered idle. 0 = no idle timeout. Default 30.</summary>
    public int SessionIdleTimeoutMinutes { get; set; } = 30;

    /// <summary>Maximum active refresh tokens per user. 0 = unlimited. Default 3.</summary>
    public int MaxConcurrentSessions { get; set; } = 3;

    /// <summary>
    /// Absolute session lifetime cap in days. The original token family's creation time
    /// plus this value is the hard horizon. Default 14. Set to 0 to disable.
    /// </summary>
    public int MaxSessionLifetimeDays { get; set; } = 14;

    // ── Login posture ───────────────────────────────────────────────
    /// <summary>
    /// Target response-time budget in ms for the pre-auth login path — the endpoint
    /// waits out the difference so response-time side channels see a constant wall clock.
    /// Default 500. Set to 0 to disable.
    /// </summary>
    public int LoginResponseDelayMs { get; set; } = 500;

    /// <summary>
    /// System-use notification banner displayed on login pages before
    /// authentication. When set, users must acknowledge the banner before logging in.
    /// </summary>
    public string? LoginBanner { get; set; }

    /// <summary>
    /// Heading rendered above <see cref="LoginBanner"/> on the login pages. Defaults
    /// to "System Use Notification" when null/empty so AC-8 wording stays as-is unless
    /// an operator explicitly customizes it (e.g., for non-US compliance frameworks).
    /// </summary>
    [MaxLength(255)]
    public string? LoginBannerTitle { get; set; }

    // ── Approval / mTLS policy ──────────────────────────────────────
    /// <summary>
    /// When true, members of the <c>system-super</c> group are allowed to approve
    /// their own CSRs. Preserves the single-operator bootstrap workflow but weakens
    /// the M-of-N approval invariant. Default false.
    /// </summary>
    public bool AllowSystemSuperSelfApproval { get; set; } = false;

    /// <summary>
    /// When true, enforce OCSP/CRL revocation checks on mTLS client certificates at
    /// the signing CA level. Default false (fail-open). Flip to true in high-assurance.
    /// </summary>
    public bool RequireMtlsOcspCheck { get; set; } = false;

    // ── MFA / step-up (flat on the entity for EF) ───────────────────
    /// <summary>Step-up MFA token lifetime in seconds. Clamped to [30, 300] on write. Default 90.</summary>
    public int StepUpTokenTtlSeconds { get; set; } = 90;

    /// <summary>Login-flow MFA token lifetime (issued after password verification). Clamped to [60, 900]. Default 300.</summary>
    public int MfaSessionTtlSeconds { get; set; } = 300;

    /// <summary>WebAuthn options/challenge cache TTL in seconds. Clamped to [30, 600]. Default 120.</summary>
    public int WebAuthnChallengeTtlSeconds { get; set; } = 120;

    /// <summary>When true, WebAuthn ceremonies require <c>UserVerification=Required</c>. Default true.</summary>
    public bool RequireWebAuthnUserVerification { get; set; } = true;

    /// <summary>Consecutive per-user step-up failures before lockout. Default 5.</summary>
    public int StepUpFailureThreshold { get; set; } = 5;

    /// <summary>Sliding window in seconds for <see cref="StepUpFailureThreshold"/>. Default 300.</summary>
    public int StepUpFailureWindowSeconds { get; set; } = 300;

    // ── OCSP responder policy (flat) ────────────────────────────────
    /// <summary>
    /// When false (default), a CA with no delegated responder certificate returns
    /// <c>Unauthorized</c> instead of signing OCSP responses directly with the CA key.
    /// </summary>
    public bool AllowCaDirectSigning { get; set; } = false;

    /// <summary>
    /// When true, the responder refuses to use a delegated responder certificate that
    /// lacks the <c>id-pkix-ocsp-nocheck</c> extension. Default false (warn-only).
    /// </summary>
    public bool RequireNoCheckExtension { get; set; } = false;

    /// <summary>
    /// When true, all OCSP requests must be signed — unsigned requests are rejected
    /// with <c>SigRequired</c> (5). Default false.
    /// </summary>
    public bool RequireSignedRequests { get; set; } = false;

    /// <summary>Global default for <c>nextUpdate</c> on <c>good</c> responses. Minutes. Default 60.</summary>
    public int DefaultGoodResponseTtlMinutes { get; set; } = 60;

    /// <summary>Global default for <c>nextUpdate</c> on <c>revoked</c> responses. Minutes. Default 15.</summary>
    public int DefaultRevokedResponseTtlMinutes { get; set; } = 15;

    /// <summary>Maximum Request entries allowed in a single OCSPRequest. Default 4.</summary>
    public int MaxSingleRequestsPerRequest { get; set; } = 4;

    // ── Keystore KDF cost ──────────────────────────────────────────────
    /// <summary>
    /// Target scrypt N parameter (iteration cost) used whenever a keystore file is
    /// written. Writes upgrade the cost in-place; reads honor whatever cost is stamped
    /// in the file header. Default 65536 = 2^16, matching the prior pinned constant.
    /// Operators can raise this as hardware improves; existing files re-stamp on the
    /// next append/rewrite. Range clamped 2^14 .. 2^20.
    /// </summary>
    public int KeystoreScryptN { get; set; } = 65536;

    /// <summary>
    /// Target scrypt r parameter (block size). Default 8. Range clamped 1 .. 32.
    /// </summary>
    public int KeystoreScryptR { get; set; } = 8;

    /// <summary>
    /// Target scrypt p parameter (parallelism). Default 1. Range clamped 1 .. 16.
    /// </summary>
    public int KeystoreScryptP { get; set; } = 1;

    // ── Controlled-user ceremonies (user quorum) ────────────────────
    /// <summary>
    /// System-level "user quorum": the number of approvals required for controlled-user
    /// ceremonies (promote/demote/delete of an admin/operator/CA-admin) when the change is
    /// system-scoped. CA- and tenant-scoped changes use their own scope's quorum instead.
    /// Distinct from the CA/key quorum. Default 1 (one other dominating approver; the
    /// initiator is always excluded). Clamped to a minimum of 1 on write.
    /// </summary>
    public int UserQuorum { get; set; } = 1;

    // ── Instance CA policy (the instance's own scope; spaces keep theirs on TenantEntity) ──
    /// <summary>
    /// When true, creating, revoking or deleting an instance CA (one with no tenant) requires a
    /// key ceremony. The instance counterpart of <see cref="TenantEntity.RequireKeyCeremony"/>.
    /// </summary>
    public bool RequireKeyCeremony { get; set; } = true;

    /// <summary>Approvals required for key ceremonies on instance CAs. Default 2.</summary>
    public int CeremonyRequiredApprovals { get; set; } = 2;

    /// <summary>Longest leaf validity, in days, for instance CAs. 0 means unlimited.</summary>
    public int MaxValidityDays { get; set; } = 0;

    /// <summary>What happens when a request to an instance CA exceeds <see cref="MaxValidityDays"/>.</summary>
    public ModularCA.Shared.Enums.ValidityCeilingBehavior ValidityCeilingBehavior { get; set; } = ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten;

    /// <summary>
    /// User quorum for controlled-user changes scoped to an instance CA, and the ceiling for
    /// such a CA's own override. Null means 1. The instance counterpart of
    /// <see cref="TenantEntity.UserCeremonyRequiredApprovals"/>; distinct from
    /// <see cref="UserQuorum"/>, which governs instance-tier changes.
    /// </summary>
    public int? UserCeremonyRequiredApprovals { get; set; }

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
