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
    /// Applies a partial update to the security policy. Needs a system administrator; a change to
    /// <c>UserQuorum</c> or <c>AllowSystemSuperSelfApproval</c> needs a system-super (403 otherwise,
    /// nothing saved). Null fields are left untouched.
    /// TTL knobs are clamped to their documented ranges. The instance CA policy fields
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

        // Keystore scrypt cost — clamp at write time so the DB never holds an unreasonable value.
        if (request.KeystoreScryptN is int ksn)
            policy.KeystoreScryptN = Math.Clamp(ksn, 1 << 14, 1 << 20);
        if (request.KeystoreScryptR is int ksr)
            policy.KeystoreScryptR = Math.Clamp(ksr, 1, 32);
        if (request.KeystoreScryptP is int ksp)
            policy.KeystoreScryptP = Math.Clamp(ksp, 1, 16);

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
    public int? MaxFailedLoginAttempts { get; set; }
    public int? LockoutMinutes { get; set; }
    public int? SessionIdleTimeoutMinutes { get; set; }
    public int? MaxConcurrentSessions { get; set; }
    public int? MaxSessionLifetimeDays { get; set; }
    public int? LoginResponseDelayMs { get; set; }
    public string? LoginBanner { get; set; }
    public string? LoginBannerTitle { get; set; }
    public bool? AllowSystemSuperSelfApproval { get; set; }
    public bool? RequireMtlsOcspCheck { get; set; }
    public int? StepUpTokenTtlSeconds { get; set; }
    public int? MfaSessionTtlSeconds { get; set; }
    public int? WebAuthnChallengeTtlSeconds { get; set; }
    public bool? RequireWebAuthnUserVerification { get; set; }
    public int? StepUpFailureThreshold { get; set; }
    public int? StepUpFailureWindowSeconds { get; set; }
    public bool? AllowCaDirectSigning { get; set; }
    public bool? RequireNoCheckExtension { get; set; }
    public bool? RequireSignedRequests { get; set; }
    public int? DefaultGoodResponseTtlMinutes { get; set; }
    public int? DefaultRevokedResponseTtlMinutes { get; set; }
    public int? MaxSingleRequestsPerRequest { get; set; }
    /// <summary>User quorum for controlled-user ceremonies (promote/demote/delete). Min 1.</summary>
    public int? UserQuorum { get; set; }
    // Keystore KDF cost — raise as hardware improves; existing files re-stamp on append.
    public int? KeystoreScryptN { get; set; }
    public int? KeystoreScryptR { get; set; }
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
