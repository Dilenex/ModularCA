using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
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
/// next request scope (cache invalidated on PUT).
/// </summary>
[ApiController]
[Route("api/v1/admin/security-policy")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminSecurityPolicyController(
    ModularCADbContext db,
    ISecurityPolicyService policyService,
    IAuditService audit,
    ICurrentUserService currentUser,
    IControlledUserCeremonyService controlledUserSvc) : ControllerBase
{
    /// <summary>Returns the current security policy row.</summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No security policy configured." });
        return Ok(policy);
    }

    /// <summary>
    /// Applies a partial update to the security policy. Null fields are left untouched.
    /// TTL knobs are clamped to their documented ranges.
    /// </summary>
    [HttpPut]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> Update([FromBody] SecurityPolicyUpdateRequest request)
    {
        var policy = await db.SecurityPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new SecurityPolicyEntity();
            db.SecurityPolicies.Add(policy);
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

        // Controlled-user ceremonies (System user quorum) — minimum 1 (initiator always excluded).
        // Super-only: unlike tenant/CA quorums (which a regular admin changes via a ceremony), the
        // System quorum is system-scoped with no tenant-scoped ceremony, so only a system-super may
        // change it. A non-super attempting an actual change is refused.
        if (request.UserQuorum is int uq && uq >= 1 && uq != policy.UserQuorum)
        {
            await currentUser.EnsureLoadedAsync();
            var isSuper = currentUser.User != null && await controlledUserSvc.IsSuperAsync(currentUser.User.Id);
            if (!isSuper)
                return StatusCode(403, new { error = "Only a system super-administrator can change the System controlled-user approval quorum." });
            policy.UserQuorum = uq;
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

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(
            AuditActionType.SecurityPolicyUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "SecurityPolicy", policy.Id.ToString(),
            request,
            HttpContext.Connection.RemoteIpAddress?.ToString());

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
}
