using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing the runtime-tunable security policy — session
/// lockout, MFA TTLs, OCSP responder posture, and login banner. Mutations require
/// step-up MFA via the <c>X-MFA-Token</c> header. Changes take effect on the
/// next request scope (cache invalidated on PUT). Reading and writing both need a system
/// administrator: these settings govern authentication for every account, and the lockout
/// thresholds would help an operator tune a password-spraying run.
/// </summary>
[ApiController]
[Route("api/v1/admin/security-policy")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminSecurityPolicyController(
    ModularCADbContext db,
    ISecurityPolicyService policyService,
    IAuditService audit,
    ICurrentUserService currentUser,
    IControlledUserCeremonyService controlledUserSvc,
    ICaGroupAuthorizationService groupAuth,
    ModularCA.Core.Services.ISpacePolicyChangeService policyChanges,
    IDistributedCache cache) : ControllerBase
{
    /// <summary>Returns the current security policy row. Needs a system administrator.</summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No security policy configured." });
        return Ok(policy);
    }

    /// <summary>
    /// Whether the instance is still set up for a single administrator while it has more than one:
    /// the number of active system super-administrators, whether self-approval is allowed and
    /// whether key ceremonies are required. <c>outgrown</c> is true when there are several supers
    /// and either setting still says single administrator, so the console can suggest turning
    /// ceremonies on and self-approval off. Needs a system administrator.
    /// </summary>
    [HttpGet("administrators")]
    public async Task<IActionResult> Administrators()
    {
        var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No security policy configured." });
        var supers = await db.CaGroupMembers.AsNoTracking()
            .Where(m => m.Group.IsSystemTierSuper && m.User.IsActive && !m.User.IsDeleted && !m.User.IsServiceIdentity)
            .Select(m => m.UserId)
            .Distinct()
            .CountAsync();
        return Ok(new
        {
            systemSuperCount = supers,
            selfApprovalAllowed = policy.AllowSystemSuperSelfApproval,
            keyCeremonyRequired = policy.RequireKeyCeremony,
            outgrown = supers > 1 && (policy.AllowSystemSuperSelfApproval || !policy.RequireKeyCeremony),
        });
    }

    /// <summary>
    /// Applies a partial update to the security policy. Needs a system administrator; a change to
    /// <c>UserQuorum</c> or <c>AllowSystemSuperSelfApproval</c> needs a system-super (403 otherwise,
    /// nothing saved). Null fields are left untouched.
    /// TTL knobs are clamped to their documented ranges. The keystore scrypt cost
    /// (<c>KeystoreScryptN</c>, <c>KeystoreScryptR</c>, <c>KeystoreScryptP</c>) is not clamped:
    /// when any of the three changes, the resulting triple must pass
    /// <see cref="KeystoreScryptPolicy.CheckNewSetting"/>, or the answer is 400 and nothing is
    /// saved. Values sent back unchanged are not checked. The instance CA policy fields
    /// (<c>RequireKeyCeremony</c>, <c>CeremonyRequiredApprovals</c>, <c>MaxValidityDays</c>,
    /// <c>ValidityCeilingBehavior</c>) need a system admin; a change to the first two by anyone
    /// but a system-super opens an InstancePolicyChange ceremony and returns 202. Every refusal,
    /// and that ceremony, comes before anything is saved: when one is already pending the answer
    /// is 409 and no field changes; otherwise the other fields are saved and the audit record
    /// lists the gated ones as proposed by the ceremony, not applied. The save needs
    /// one step-up token in <c>X-MFA-Token</c>: <see cref="StepUpOps.UpdateConfig"/>, or, when a
    /// system-super turns the instance's ceremony requirement off directly (KC-07),
    /// <see cref="StepUpOps.DisableCeremonyRequirement"/>; that change is audited with a
    /// <c>CeremonyRequirementDisabled</c> marker.
    /// </summary>
    [HttpPut]
    public async Task<IActionResult> Update(
        [FromBody] SecurityPolicyUpdateRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var policy = await db.SecurityPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new SecurityPolicyEntity();
            db.SecurityPolicies.Add(policy);
        }

        await currentUser.EnsureLoadedAsync();
        var disablesCeremonyDirectly = request.RequireKeyCeremony == false && policy.RequireKeyCeremony
            && currentUser.User != null && await controlledUserSvc.IsSuperAsync(currentUser.User.Id);
        var stepUpOp = disablesCeremonyDirectly ? StepUpOps.DisableCeremonyRequirement : StepUpOps.UpdateConfig;
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, stepUpOp))
            return StatusCode(403, new
            {
                error = disablesCeremonyDirectly
                    ? "MFA re-verification required to disable the instance's key ceremony requirement. Call /api/v1/auth/mfa/verify-stepup first."
                    : "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true,
                operation = stepUpOp,
            });
        var ceremonyWasRequired = policy.RequireKeyCeremony;

        if (request.UserQuorum is int requestedQuorum && requestedQuorum >= 1 && requestedQuorum != policy.UserQuorum
            && (currentUser.User == null || !await controlledUserSvc.IsSuperAsync(currentUser.User.Id)))
            return StatusCode(403, new { error = "Only a system super-administrator can change the System controlled-user approval quorum." });
        if (request.AllowSystemSuperSelfApproval is bool selfApproval && selfApproval != policy.AllowSystemSuperSelfApproval
            && (currentUser.User == null || !await controlledUserSvc.IsSuperAsync(currentUser.User.Id)))
            return StatusCode(403, new { error = "Only a system super-administrator can change whether system-supers may approve their own requests." });

        bool? proposedRequire = request.RequireKeyCeremony is bool rkc && rkc != policy.RequireKeyCeremony ? rkc : null;
        int? proposedApprovals = request.CeremonyRequiredApprovals is int cra && Math.Max(1, cra) != policy.CeremonyRequiredApprovals
            ? Math.Max(1, cra) : null;
        var validityChanged = (request.MaxValidityDays is int mvd && mvd != policy.MaxValidityDays)
            || (request.ValidityCeilingBehavior is { } vcb && vcb != policy.ValidityCeilingBehavior);
        var instanceCeremonyGate = false;
        if (proposedRequire.HasValue || proposedApprovals.HasValue || validityChanged)
        {
            if (currentUser.User == null || !await groupAuth.IsSystemAdminAsync(currentUser.User.Id))
                return StatusCode(403, new { error = "Only a system administrator can change the instance's CA policy." });
            if (request.MaxValidityDays is int days && days < 0)
                return BadRequest(new { error = "MaxValidityDays must be 0 (unlimited) or a positive number of days." });
            instanceCeremonyGate = (proposedRequire.HasValue || proposedApprovals.HasValue)
                && !await controlledUserSvc.IsSuperAsync(currentUser.User.Id);
        }

        // The keystore scrypt cost is checked as a whole, and only when one of its values
        // changes: the console sends the stored values back on every save, and a value stored
        // before these checks must not block the fields that did change.
        var scryptN = request.KeystoreScryptN ?? policy.KeystoreScryptN;
        var scryptR = request.KeystoreScryptR ?? policy.KeystoreScryptR;
        var scryptP = request.KeystoreScryptP ?? policy.KeystoreScryptP;
        var scryptChanged = scryptN != policy.KeystoreScryptN || scryptR != policy.KeystoreScryptR || scryptP != policy.KeystoreScryptP;
        if (scryptChanged && KeystoreScryptPolicy.CheckNewSetting(scryptN, scryptR, scryptP) is { } scryptError)
            return BadRequest(new { error = scryptError });

        Guid? ceremonyId = null;
        if (instanceCeremonyGate)
        {
            if (db.Entry(policy).State == EntityState.Added)
                await db.SaveChangesAsync();
            try
            {
                ceremonyId = await policyChanges.InitiateChangeAsync(
                    null, proposedRequire, proposedApprovals,
                    currentUser.User!.Id, currentUser.User.Username);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
            {
                return Conflict(new { error = "An instance policy-change ceremony is already pending. Resolve or cancel it before opening a new one." });
            }
        }

        // Session / lockout
        if (request.MaxFailedLoginAttempts is int mfa && mfa >= 1)
            policy.MaxFailedLoginAttempts = mfa;
        if (request.LockoutMinutes is int lm && lm >= 0)
            policy.LockoutMinutes = lm;
        if (request.SessionIdleTimeoutMinutes is int sit && sit >= 0)
            policy.SessionIdleTimeoutMinutes = sit;
        if (request.MaxConcurrentSessions is int mcs && mcs >= 0)
            policy.MaxConcurrentSessions = mcs;
        if (request.MaxSessionLifetimeDays is int msld && msld >= 0)
            policy.MaxSessionLifetimeDays = msld;

        // Login posture
        if (request.LoginResponseDelayMs is int lrd && lrd >= 0)
            policy.LoginResponseDelayMs = lrd;
        if (request.LoginBanner != null)
            policy.LoginBanner = request.LoginBanner.Length == 0 ? null : request.LoginBanner;
        if (request.LoginBannerTitle != null)
            policy.LoginBannerTitle = request.LoginBannerTitle.Length == 0 ? null : request.LoginBannerTitle;

        // Approval / mTLS policy
        if (request.AllowSystemSuperSelfApproval.HasValue)
            policy.AllowSystemSuperSelfApproval = request.AllowSystemSuperSelfApproval.Value;
        if (request.RequireMtlsOcspCheck.HasValue)
            policy.RequireMtlsOcspCheck = request.RequireMtlsOcspCheck.Value;

        // MFA — clamp on write
        if (request.StepUpTokenTtlSeconds is int stt)
            policy.StepUpTokenTtlSeconds = Math.Clamp(stt, 30, 300);
        if (request.MfaSessionTtlSeconds is int mst)
            policy.MfaSessionTtlSeconds = Math.Clamp(mst, 60, 900);
        if (request.WebAuthnChallengeTtlSeconds is int wct)
            policy.WebAuthnChallengeTtlSeconds = Math.Clamp(wct, 30, 600);
        if (request.RequireWebAuthnUserVerification.HasValue)
            policy.RequireWebAuthnUserVerification = request.RequireWebAuthnUserVerification.Value;
        if (request.StepUpFailureThreshold is int sft && sft >= 1)
            policy.StepUpFailureThreshold = sft;
        if (request.StepUpFailureWindowSeconds is int sfw && sfw >= 30)
            policy.StepUpFailureWindowSeconds = sfw;

        // OCSP
        if (request.AllowCaDirectSigning.HasValue)
            policy.AllowCaDirectSigning = request.AllowCaDirectSigning.Value;
        if (request.RequireNoCheckExtension.HasValue)
            policy.RequireNoCheckExtension = request.RequireNoCheckExtension.Value;
        if (request.RequireSignedRequests.HasValue)
            policy.RequireSignedRequests = request.RequireSignedRequests.Value;
        if (request.DefaultGoodResponseTtlMinutes is int dgt && dgt >= 1)
            policy.DefaultGoodResponseTtlMinutes = dgt;
        if (request.DefaultRevokedResponseTtlMinutes is int drt && drt >= 1)
            policy.DefaultRevokedResponseTtlMinutes = drt;
        if (request.MaxSingleRequestsPerRequest is int mspr && mspr >= 1)
            policy.MaxSingleRequestsPerRequest = mspr;

        if (request.UserQuorum is int uq && uq >= 1)
            policy.UserQuorum = uq;

        if (validityChanged)
        {
            if (request.MaxValidityDays is int newDays)
                policy.MaxValidityDays = newDays;
            if (request.ValidityCeilingBehavior is { } behavior)
                policy.ValidityCeilingBehavior = behavior;
        }
        if (!instanceCeremonyGate)
        {
            if (proposedRequire.HasValue) policy.RequireKeyCeremony = proposedRequire.Value;
            if (proposedApprovals.HasValue) policy.CeremonyRequiredApprovals = proposedApprovals.Value;
        }

        // Keystore scrypt cost: checked with the other refusals above, before anything was saved.
        if (scryptChanged)
        {
            policy.KeystoreScryptN = scryptN;
            policy.KeystoreScryptR = scryptR;
            policy.KeystoreScryptP = scryptP;
        }

        policy.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        policyService.InvalidateCache();

        object details = instanceCeremonyGate
            ? new
            {
                Changes = request.WithoutCeremonyGatedFields(),
                ProposedByCeremony = new { RequireKeyCeremony = proposedRequire, CeremonyRequiredApprovals = proposedApprovals },
                CeremonyId = ceremonyId,
            }
            : ceremonyWasRequired && !policy.RequireKeyCeremony
                ? new { Changes = request, CeremonyRequirementDisabled = true, DisabledBy = currentUser.User?.Username }
                : request;
        await audit.LogAsync(
            AuditActionType.SecurityPolicyUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "SecurityPolicy", policy.Id.ToString(),
            details,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (instanceCeremonyGate)
        {
            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = "Changing the instance's key-ceremony policy requires ceremony approval. Approve via /api/v1/admin/ceremonies/{id}/approve.",
                policy,
            });
        }

        return Ok(policy);
    }
}

/// <summary>
/// Partial-update DTO. Null fields are left untouched on the stored policy row.
/// </summary>
public class SecurityPolicyUpdateRequest
{
    /// <summary>Failed logins, across every login method, before the account is locked; values under 1 are ignored.</summary>
    public int? MaxFailedLoginAttempts { get; set; }
    /// <summary>Lockout duration in minutes; 0 locks until an admin unlocks. Negative values are ignored.</summary>
    public int? LockoutMinutes { get; set; }
    /// <summary>Minutes of inactivity before a session counts as idle; 0 disables the idle timeout. Negative values are ignored.</summary>
    public int? SessionIdleTimeoutMinutes { get; set; }
    /// <summary>Most active refresh tokens one user may hold; 0 means unlimited. Negative values are ignored.</summary>
    public int? MaxConcurrentSessions { get; set; }
    /// <summary>Absolute session lifetime in days from the first token of the family; 0 disables the cap. Negative values are ignored.</summary>
    public int? MaxSessionLifetimeDays { get; set; }
    /// <summary>Constant wall-clock budget in milliseconds for the pre-authentication login path, against timing side channels; 0 disables it. Negative values are ignored.</summary>
    public int? LoginResponseDelayMs { get; set; }
    /// <summary>System-use notice users must acknowledge on the login pages before signing in; empty removes it.</summary>
    public string? LoginBanner { get; set; }
    /// <summary>Heading above <see cref="LoginBanner"/>; empty restores the default "System Use Notification".</summary>
    public string? LoginBannerTitle { get; set; }
    /// <summary>Whether system super-administrators may approve their own requests. Changing it needs a system-super.</summary>
    public bool? AllowSystemSuperSelfApproval { get; set; }
    /// <summary>Whether mTLS client certificates must pass a revocation check; false fails open.</summary>
    public bool? RequireMtlsOcspCheck { get; set; }
    /// <summary>Lifetime of a step-up MFA token in seconds, clamped to 30–300.</summary>
    public int? StepUpTokenTtlSeconds { get; set; }
    /// <summary>Lifetime in seconds of the MFA token issued after password verification during login, clamped to 60–900.</summary>
    public int? MfaSessionTtlSeconds { get; set; }
    /// <summary>How long a WebAuthn challenge stays valid, in seconds, clamped to 30–600.</summary>
    public int? WebAuthnChallengeTtlSeconds { get; set; }
    /// <summary>Whether WebAuthn ceremonies require user verification (PIN or biometric) on the authenticator.</summary>
    public bool? RequireWebAuthnUserVerification { get; set; }
    /// <summary>Step-up failures by one user within the window before step-up is locked; values under 1 are ignored.</summary>
    public int? StepUpFailureThreshold { get; set; }
    /// <summary>Sliding window in seconds for <see cref="StepUpFailureThreshold"/>; values under 30 are ignored.</summary>
    public int? StepUpFailureWindowSeconds { get; set; }
    /// <summary>Whether a CA without a delegated OCSP responder certificate may sign responses with its own key; when false the responder answers <c>unauthorized</c>.</summary>
    public bool? AllowCaDirectSigning { get; set; }
    /// <summary>Whether the OCSP responder refuses a delegated responder certificate lacking <c>id-pkix-ocsp-nocheck</c>; when false it only warns.</summary>
    public bool? RequireNoCheckExtension { get; set; }
    /// <summary>Whether unsigned OCSP requests are refused with <c>sigRequired</c>.</summary>
    public bool? RequireSignedRequests { get; set; }
    /// <summary>Default <c>nextUpdate</c> distance in minutes on <c>good</c> OCSP responses; values under 1 are ignored.</summary>
    public int? DefaultGoodResponseTtlMinutes { get; set; }
    /// <summary>Default <c>nextUpdate</c> distance in minutes on <c>revoked</c> OCSP responses; values under 1 are ignored.</summary>
    public int? DefaultRevokedResponseTtlMinutes { get; set; }
    /// <summary>Most certificate status requests one OCSP request may carry; values under 1 are ignored.</summary>
    public int? MaxSingleRequestsPerRequest { get; set; }
    /// <summary>User quorum for controlled-user ceremonies (promote/demote/delete). Min 1.</summary>
    public int? UserQuorum { get; set; }
    // Keystore KDF cost — raise as hardware improves; existing files re-stamp on append.
    /// <summary>scrypt cost parameter N used when a keystore file is written: a power of two from 2^14 to 2^20, with 128 · N · r at most 1 GiB, or 400.</summary>
    public int? KeystoreScryptN { get; set; }
    /// <summary>scrypt block size r used when a keystore file is written: 1 to 32, with 128 · N · r at most 1 GiB, or 400.</summary>
    public int? KeystoreScryptR { get; set; }
    /// <summary>scrypt parallelism p used when a keystore file is written: 1 to 16, or 400.</summary>
    public int? KeystoreScryptP { get; set; }
    /// <summary>Whether instance CAs need a key ceremony. Ceremony-gated unless the caller is a system-super.</summary>
    public bool? RequireKeyCeremony { get; set; }
    /// <summary>Approvals for key ceremonies on instance CAs (minimum 1). Ceremony-gated unless the caller is a system-super.</summary>
    public int? CeremonyRequiredApprovals { get; set; }
    /// <summary>Longest leaf validity in days for instance CAs; 0 is unlimited.</summary>
    public int? MaxValidityDays { get; set; }
    /// <summary>What happens above <see cref="MaxValidityDays"/> for instance CAs.</summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }

    /// <summary>A copy without the ceremony-gated fields, for auditing what was applied directly.</summary>
    internal SecurityPolicyUpdateRequest WithoutCeremonyGatedFields()
    {
        var copy = (SecurityPolicyUpdateRequest)MemberwiseClone();
        copy.RequireKeyCeremony = null;
        copy.CeremonyRequiredApprovals = null;
        return copy;
    }
}
