using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using Serilog;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using System.Text.Json;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing certificate signing requests including approval, rejection,
/// multi-person approval workflows, CSR parsing, and profile validation.
/// Approve/reject/cancel resolve the target CA and enforce
/// <c>AccessibleTenantIds</c>. The <c>system-super</c> self-approval bypass is gated on
/// <c>SecurityPolicyEntity.AllowSystemSuperSelfApproval</c> (DB-backed, see <c>/admin/security-policy</c>).
/// </summary>
[ApiController]
[Route("api/v1/admin/requests")]
[Authorize(Policy = "CaAuditor")]
public class AdminCertSignRequestController(
    ICsrService csrService,
    ICertificateStore certService,
    ICurrentUserService currentUser,
    IAuditService auditService,
    ModularCADbContext db,
    SystemConfig systemConfig,
    ICaGroupAuthorizationService authService,
    ISecurityPolicyService securityPolicy
) : ControllerBase
{
    private readonly ICsrService _csrService = csrService;
    private readonly ICertificateStore _certService = certService;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = auditService;
    private readonly ModularCADbContext _db = db;
    private readonly SystemConfig _systemConfig = systemConfig;
    private readonly ICaGroupAuthorizationService _authService = authService;
    private readonly ISecurityPolicyService _securityPolicy = securityPolicy;

    /// <summary>
    /// Retrieves all pending certificate signing requests. CLM-022: the service-layer
    /// <c>accessibleCaIds</c> parameter now filters at the database level so non-system-admin
    /// callers only receive CSRs belonging to CAs they can access. System admins receive all.
    /// </summary>
    /// <param name="caId">Optional: only requests routed to this CA (the console's scope).</param>
    [HttpGet]
    public async Task<IActionResult> RetrievePendingRequests([FromQuery] Guid? caId = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        List<Guid>? accessibleCaIds = null;
        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(
                _currentUser.User.Id, Capabilities.CertView);
        }

        var requests = await _csrService.GetPendingRequests(ModularCA.Core.Authorization.CaScope.Narrow(accessibleCaIds, caId));
        if (requests == null)
            return NotFound();

        return Ok(requests);
    }

    /// <summary>
    /// Generates a new certificate signing request from the provided parameters.
    /// Requires CaOperator (state-changing: persists a CsrSubmitted record) — overrides the
    /// read-only CaAuditor class policy so an auditor cannot seed the issuance pipeline.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Generate([FromBody] CreateCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();
        var pem = await _csrService.GenerateCsrAsync(request, _currentUser.User.Id);
        await _audit.LogAsync(AuditActionType.CsrSubmitted, _currentUser.User.Id, _currentUser.User.Username,
            "CertificateRequest", pem[1], new { request.SubjectName },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return Ok(new { csrId = pem[1], csr = pem[0] });
    }

    /// <summary>
    /// Parses a PEM-encoded CSR and returns structured data including subject DN components,
    /// SANs, key information, requested extensions, and signature validation status.
    /// This is a read-only operation that does not store anything.
    /// </summary>
    [HttpPost("parse-csr")]
    public IActionResult ParseCsr([FromBody] ParseCsrRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Pem))
            return BadRequest(new { error = "PEM CSR string is required." });

        try
        {
            var result = CertificateUtil.ParseCsrDetailed(request.Pem);
            if (result.ValidationErrors.Count > 0 && !result.Valid)
                return BadRequest(new { error = "Failed to parse CSR", details = result.ValidationErrors });
            return Ok(result);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to parse CSR in admin CSR detail endpoint");
            return BadRequest(new { error = "Failed to parse CSR. The submitted data may be malformed." });
        }
    }

    /// <summary>
    /// Validates parsed CSR subject and SAN fields against a request profile's SubjectDnRules
    /// and SanRules. Returns per-field validation results (valid/warning/error) without storing anything.
    /// This is a preview endpoint, but the profile patterns it runs are operator-authored and the
    /// values are caller-supplied, so every match goes through <see cref="ProfileRegex"/> under a
    /// bounded timeout. A pattern that times out or does not compile yields "error" (never "valid")
    /// with a message pointing at the profile, so a broken profile surfaces as broken here instead
    /// of previewing as a pass and then behaving differently at issuance time.
    /// </summary>
    [HttpPost("validate-against-profile")]
    public async Task<IActionResult> ValidateAgainstProfile([FromBody] ValidateAgainstProfileRequest request)
    {
        var profile = await _db.RequestProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == request.RequestProfileId);
        if (profile == null)
            return NotFound(new { error = "Request profile not found." });

        var dnRules = JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(profile.SubjectDnRules) ?? new();
        var sanRules = JsonSerializer.Deserialize<SanRules>(profile.SanRules) ?? new();

        var response = new ValidateAgainstProfileResponse { Valid = true };

        // Validate subject DN fields against rules
        foreach (var rule in dnRules)
        {
            var hasValue = request.Subject.TryGetValue(rule.Field, out var value) && !string.IsNullOrWhiteSpace(value);
            var result = new FieldValidationResult { Field = rule.Field };

            if (rule.Requirement == "Forbidden")
            {
                if (hasValue)
                {
                    result.Status = "error";
                    result.Message = "This field is not allowed by the profile.";
                    response.Valid = false;
                }
                else
                {
                    result.Status = "valid";
                    result.Message = "Forbidden (correctly absent).";
                }
            }
            else if (rule.Requirement == "Required")
            {
                if (!hasValue)
                {
                    result.Status = "error";
                    result.Message = "This field is required.";
                    response.Valid = false;
                }
                else
                {
                    result = ValidateFieldValue(rule, value!);
                    if (result.Status == "error")
                        response.Valid = false;
                }
            }
            else // Optional
            {
                if (!hasValue)
                {
                    result.Status = "warning";
                    result.Message = "Optional field, not provided.";
                }
                else
                {
                    result = ValidateFieldValue(rule, value!);
                    if (result.Status == "error")
                        response.Valid = false;
                }
            }

            response.FieldResults.Add(result);
        }

        // Check for subject fields not covered by any rule (treat as warning)
        foreach (var kvp in request.Subject)
        {
            if (!string.IsNullOrWhiteSpace(kvp.Value) && !dnRules.Any(r => r.Field == kvp.Key))
            {
                response.FieldResults.Add(new FieldValidationResult
                {
                    Field = kvp.Key,
                    Status = "warning",
                    Message = "No rule defined for this field in the profile."
                });
            }
        }

        // Validate SANs
        var sanCountsByType = new Dictionary<string, int>();
        foreach (var san in request.Sans)
        {
            var sanResult = new SanValidationResult { Type = san.Type, Value = san.Value };

            if (!sanRules.AllowedTypes.Contains(san.Type, StringComparer.OrdinalIgnoreCase))
            {
                sanResult.Status = "error";
                sanResult.Message = $"SAN type '{san.Type}' is not allowed by the profile.";
                response.Valid = false;
            }
            else
            {
                // Check regex
                if (sanRules.Rules.TryGetValue(san.Type, out var typeRule))
                {
                    if (!string.IsNullOrWhiteSpace(typeRule.Regex))
                    {
                        // ProfileRegex bounds the match (ReDoS guard) and tells us *why* a pattern
                        // did not pass. A pattern that cannot be evaluated used to be reported as
                        // "valid" so as not to penalise the user — but that made a broken profile
                        // look like a passing one, and the same value would then be rejected (or
                        // silently unchecked) at issuance time. A non-evaluable pattern is now an
                        // error against the profile, with a message that blames the profile.
                        switch (ProfileRegex.Evaluate(san.Value, typeRule.Regex))
                        {
                            case ProfileRegexOutcome.Match:
                                sanResult.Status = "valid";
                                break;
                            case ProfileRegexOutcome.NoMatch:
                                sanResult.Status = "error";
                                sanResult.Message = $"Value does not match required pattern: {typeRule.Regex}";
                                response.Valid = false;
                                break;
                            case ProfileRegexOutcome.Timeout:
                                Log.Warning(
                                    "ValidateAgainstProfile: SAN pattern for type '{SanType}' in profile {ProfileId} timed out after {Timeout}ms; reporting as unevaluable.",
                                    san.Type, request.RequestProfileId, ProfileRegex.MatchTimeout.TotalMilliseconds);
                                sanResult.Status = "error";
                                sanResult.Message = $"The profile's pattern for SAN type '{san.Type}' took too long to evaluate and may be unsafe; this value could not be validated. Ask an administrator to review the profile.";
                                response.Valid = false;
                                break;
                            default:
                                Log.Warning(
                                    "ValidateAgainstProfile: SAN pattern for type '{SanType}' in profile {ProfileId} is not a valid regular expression ('{Pattern}'); reporting as unevaluable.",
                                    san.Type, request.RequestProfileId, typeRule.Regex);
                                sanResult.Status = "error";
                                sanResult.Message = $"The profile's pattern for SAN type '{san.Type}' is not a valid regular expression; this value could not be validated. Ask an administrator to review the profile.";
                                response.Valid = false;
                                break;
                        }
                    }
                    else
                    {
                        sanResult.Status = "valid";
                    }
                }
                else
                {
                    sanResult.Status = "valid";
                }
            }

            // Type-shape gate: catch IP-typed SANs holding non-IP values (and DNS-typed
            // SANs holding malformed FQDNs) here instead of letting BouncyCastle's
            // GeneralName ctor throw ArgumentException deep in issuance. Only runs when
            // we haven't already errored on type-allow / pattern.
            if (sanResult.Status != "error")
            {
                var shapeError = SanShapeValidator.ValidateShape(san.Type, san.Value);
                if (shapeError != null)
                {
                    sanResult.Status = "error";
                    sanResult.Message = shapeError;
                    response.Valid = false;
                }
            }

            // Track counts
            sanCountsByType.TryGetValue(san.Type, out var count);
            sanCountsByType[san.Type] = count + 1;

            response.SanResults.Add(sanResult);
        }

        // Check max counts
        foreach (var kvp in sanCountsByType)
        {
            if (sanRules.Rules.TryGetValue(kvp.Key, out var typeRule) && kvp.Value > typeRule.MaxCount)
            {
                // Mark the last entries as errors
                var overCount = kvp.Value - typeRule.MaxCount;
                var sanResultsOfType = response.SanResults.Where(s => s.Type == kvp.Key).Reverse().Take(overCount);
                foreach (var sr in sanResultsOfType)
                {
                    sr.Status = "error";
                    sr.Message = $"Exceeds maximum count of {typeRule.MaxCount} for type {kvp.Key}.";
                    response.Valid = false;
                }
            }
        }

        // Check if SANs are required but none provided
        if (sanRules.Required && request.Sans.Count == 0)
        {
            response.SanResults.Add(new SanValidationResult
            {
                Type = "",
                Value = "",
                Status = "error",
                Message = "At least one SAN is required by the profile."
            });
            response.Valid = false;
        }

        return Ok(response);
    }

    /// <summary>
    /// Validates a single subject DN field value against its rule's regex and max length constraints.
    /// The pattern comes from the profile (operator-authored) and the value from the requester, so
    /// the match runs through <see cref="ProfileRegex"/> under a bounded timeout — an untimed match
    /// here would let a crafted value plus a backtracking-prone pattern pin a CPU core.
    /// A pattern that cannot be evaluated (uncompilable, or so expensive it times out) is reported
    /// as an error naming the profile as the cause. It previously swallowed the exception and left
    /// the field marked "valid", which presented a broken profile as a passing one.
    /// </summary>
    private static FieldValidationResult ValidateFieldValue(SubjectDnFieldRule rule, string value)
    {
        var result = new FieldValidationResult { Field = rule.Field, Status = "valid" };

        if (rule.MaxLength.HasValue && value.Length > rule.MaxLength.Value)
        {
            result.Status = "error";
            result.Message = $"Value exceeds maximum length of {rule.MaxLength.Value}.";
            return result;
        }

        if (!string.IsNullOrWhiteSpace(rule.Regex))
        {
            switch (ProfileRegex.Evaluate(value, rule.Regex))
            {
                case ProfileRegexOutcome.Match:
                    break;
                case ProfileRegexOutcome.NoMatch:
                    result.Status = "error";
                    result.Message = $"Value does not match required pattern: {rule.Regex}";
                    return result;
                default:
                    Log.Warning(
                        "ValidateFieldValue: profile pattern for field '{Field}' could not be evaluated ('{Pattern}'); reporting the field as unevaluable.",
                        rule.Field, rule.Regex);
                    result.Status = "error";
                    result.Message = $"The profile's pattern for '{rule.Field}' could not be evaluated (invalid or too slow); this value could not be validated. Ask an administrator to review the profile.";
                    return result;
            }
        }

        if (!string.IsNullOrWhiteSpace(rule.FixedValue) && value != rule.FixedValue)
        {
            result.Status = "error";
            result.Message = $"Value must be '{rule.FixedValue}' (fixed by profile).";
            return result;
        }

        return result;
    }

    /// <summary>
    /// Uploads an externally-generated PEM-encoded CSR for processing, with optional
    /// subject and SAN overrides that replace the CSR's original values during issuance.
    /// Requires CaOperator (state-changing: persists a CsrSubmitted record) — overrides the
    /// read-only CaAuditor class policy so an auditor cannot seed the issuance pipeline.
    /// </summary>
    [HttpPost("upload")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> UploadCsrRequest([FromBody] UploadCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();
        var pem = await _csrService.UploadCsrAsync(
            request.Pem, request.CertificateProfileId, request.SigningProfileId,
            _currentUser.User.Id, request.SubjectOverrides, request.SanOverrides,
            request.NotBefore, request.NotAfter);
        if (pem == null)
            return BadRequest(new { error = "Failed to upload CSR" });
        await _audit.LogAsync(AuditActionType.CsrSubmitted, _currentUser.User.Id, _currentUser.User.Username,
            "CertificateRequest", null, new { Source = "Upload", HasOverrides = request.SubjectOverrides != null || request.SanOverrides != null },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return Ok();
    }

    /// <summary>
    /// Records an approval for a pending CSR. When the required approval count is met,
    /// the CSR status transitions to "Approved" and is ready for issuance.
    /// </summary>
    [HttpPost("{id:guid}/approve")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Approve(Guid id, [FromBody] ApproveCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var csr = await _db.CertificateRequests
            .Include(c => c.Approvals)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (csr == null) return NotFound();

        // Tenant fence.
        var fence = await EnforceTenantFenceAsync(csr.SigningProfileId);
        if (fence != null) return fence;

        // Enforce profile.use capability on both profiles referenced by the CSR
        if (csr.CertProfileId.HasValue)
        {
            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "CertProfile", csr.CertProfileId.Value))
                return StatusCode(403, new { error = "You do not have profile.use access on this certificate profile." });
        }
        if (csr.SigningProfileId.HasValue)
        {
            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "SigningProfile", csr.SigningProfileId.Value))
                return StatusCode(403, new { error = "You do not have profile.use access on this signing profile." });
        }

        if (csr.Status != "Pending" && csr.Status != "PendingApproval" && csr.Status != "PartiallyApproved")
            return BadRequest(new { error = $"CSR is already {csr.Status}" });

        // Prevent same user approving twice
        if (csr.Approvals.Any(a => a.ApproverId == _currentUser.User.Id && a.Decision == "Approved"))
            return BadRequest(new { error = "You have already approved this request" });

        // Prevent approving own request. The system-super self-approval
        // escape hatch is now gated by `SecurityPolicyEntity.AllowSystemSuperSelfApproval`
        // (default false) so multi-admin deployments must explicitly opt in.
        if (csr.RequestorUserId == _currentUser.User.Id)
        {
            var secPolicy = await _securityPolicy.GetAsync();
            if (!secPolicy.AllowSystemSuperSelfApproval)
                return BadRequest(new { error = "You cannot approve your own request" });

            // Read the structural super-tier flag so a bootstrap rename of "system-super"
            // doesn't silently bypass the self-approval check.
            var isSuperAdmin = await _db.CaGroupMembers.AnyAsync(gm =>
                gm.UserId == _currentUser.User.Id &&
                gm.Group.IsSystemTierSuper);
            if (!isSuperAdmin)
                return BadRequest(new { error = "You cannot approve your own request" });
        }

        // Record approval
        var approval = new CsrApprovalEntity
        {
            CertRequestId = id,
            ApproverId = _currentUser.User.Id,
            ApproverUsername = _currentUser.User.Username,
            Decision = "Approved",
            Comment = request.Comment,
        };
        _db.CsrApprovals.Add(approval);
        csr.ApprovalCount++;

        // Check if fully approved
        var requiredCount = 1;
        // Trace: CSR -> SigningProfile -> CaProtocolConfig -> RequestProfile -> RequiredApprovalCount
        if (csr.SigningProfileId != null)
        {
            var protocolConfig = await _db.CaProtocolConfigs
                .Include(pc => pc.RequestProfile)
                .FirstOrDefaultAsync(pc => pc.SigningProfileId == csr.SigningProfileId && pc.RequestProfileId != null);
            if (protocolConfig?.RequestProfile != null)
                requiredCount = protocolConfig.RequestProfile.RequiredApprovalCount;
        }

        if (csr.ApprovalCount >= requiredCount)
        {
            csr.Status = "Approved";
        }
        else
        {
            csr.Status = "PartiallyApproved";
        }

        await _db.SaveChangesAsync();

        // Audit
        var caInfoApprove = await ResolveCaFromSigningProfileAsync(csr.SigningProfileId);
        await _audit.LogAsync(AuditActionType.CsrApproved, _currentUser.User.Id, _currentUser.User.Username,
            "CertificateRequest", id.ToString(),
            new { csr.ApprovalCount, RequiredCount = requiredCount, request.Comment },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoApprove?.CaId, tenantId: caInfoApprove?.TenantId);

        return Ok(new
        {
            message = csr.Status == "Approved" ? "CSR fully approved — ready for issuance" : $"Approval recorded ({csr.ApprovalCount}/{requiredCount})",
            status = csr.Status,
            approvalCount = csr.ApprovalCount,
            requiredCount,
        });
    }

    /// <summary>
    /// Returns all approval records for a given certificate signing request.
    /// Requires CaAuditor policy and enforces tenant isolation via the CSR's signing profile.
    /// </summary>
    [HttpGet("{id:guid}/approvals")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetApprovals(Guid id)
    {
        var csr = await _db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == id);
        if (csr == null)
            return NotFound(new { error = "Certificate request not found" });

        // Enforce tenant isolation on the CSR's CA
        var fence = await EnforceTenantFenceAsync(csr.SigningProfileId);
        if (fence != null) return fence;

        var approvals = await _db.CsrApprovals
            .Where(a => a.CertRequestId == id)
            .OrderBy(a => a.Timestamp)
            .Select(a => new
            {
                a.Id,
                a.ApproverId,
                a.ApproverUsername,
                a.Decision,
                a.Comment,
                a.Timestamp,
            })
            .ToListAsync();

        return Ok(approvals);
    }

    /// <summary>
    /// Rejects a pending certificate signing request with a reason.
    /// </summary>
    [HttpPost("{id:guid}/reject")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Reject(Guid id, [FromBody] RejectCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var csr = await _db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == id);
        if (csr == null)
            return NotFound(new { error = "Certificate request not found" });

        // Tenant fence.
        var fenceReject = await EnforceTenantFenceAsync(csr.SigningProfileId);
        if (fenceReject != null) return fenceReject;

        if (csr.Status != "Pending")
            return BadRequest(new { error = $"Request is already {csr.Status}" });

        csr.Status = "Rejected";
        csr.RejectionReason = request.Reason;
        await _db.SaveChangesAsync();

        var caInfoReject = await ResolveCaFromSigningProfileAsync(csr.SigningProfileId);
        await _audit.LogAsync(AuditActionType.CsrRejected, _currentUser.User.Id, _currentUser.User.Username,
            "CertificateRequest", id.ToString(),
            new { request.Reason, csr.Subject },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoReject?.CaId, tenantId: caInfoReject?.TenantId);

        return Ok(new { message = "Request rejected", id, reason = request.Reason });
    }

    /// <summary>
    /// Cancels an approved (but not yet issued) certificate signing request.
    /// Sets the status to "Cancelled" so it no longer appears as actionable.
    /// </summary>
    [HttpPost("{id:guid}/cancel")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Cancel(Guid id, [FromBody] CancelCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var csr = await _db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == id);
        if (csr == null)
            return NotFound(new { error = "Certificate request not found" });

        // Tenant fence.
        var fenceCancel = await EnforceTenantFenceAsync(csr.SigningProfileId);
        if (fenceCancel != null) return fenceCancel;

        if (csr.Status != "Approved" && csr.Status != "Pending")
            return BadRequest(new { error = $"Only Pending or Approved requests can be cancelled. Current status: {csr.Status}" });

        if (csr.IssuedCertificateId != null)
            return BadRequest(new { error = "Cannot cancel a request that has already been issued." });

        csr.Status = "Cancelled";
        csr.RejectionReason = request.Reason;
        await _db.SaveChangesAsync();

        var caInfoCancel = await ResolveCaFromSigningProfileAsync(csr.SigningProfileId);
        await _audit.LogAsync(AuditActionType.CsrRejected, _currentUser.User.Id, _currentUser.User.Username,
            "CertificateRequest", id.ToString(),
            new { request.Reason, csr.Subject, Action = "Cancelled" },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoCancel?.CaId, tenantId: caInfoCancel?.TenantId);

        return Ok(new { message = "Request cancelled", id, reason = request.Reason });
    }

    /// <summary>
    /// Resolves the CA ID and tenant ID from a signing profile via the CaProtocolConfig linkage.
    /// Returns null if the signing profile is not linked to a CA.
    /// </summary>
    private async Task<(Guid CaId, Guid TenantId)?> ResolveCaFromSigningProfileAsync(Guid? signingProfileId)
    {
        if (signingProfileId == null) return null;
        var config = await _db.CaProtocolConfigs
            .Include(pc => pc.Ca)
            .AsNoTracking()
            .FirstOrDefaultAsync(pc => pc.SigningProfileId == signingProfileId);
        if (config?.Ca == null) return null;
        return (config.Ca.Id, config.Ca.TenantId);
    }

    /// <summary>
    /// Returns null when the caller may act on the CSR, or an <see cref="IActionResult"/>
    /// (NotFound on tenant mismatch) when access is denied. System admins always pass.
    /// </summary>
    private async Task<IActionResult?> EnforceTenantFenceAsync(Guid? signingProfileId)
    {
        if (HttpContext.Items["IsSystemAdmin"] is true)
            return null;
        var caInfo = await ResolveCaFromSigningProfileAsync(signingProfileId);
        if (caInfo == null)
            return NotFound();
        var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
        if (tenantIds == null || !tenantIds.Contains(caInfo.Value.TenantId))
            return NotFound();
        return null;
    }
}

/// <summary>
/// Request body for parsing a PEM-encoded CSR without storing it.
/// </summary>
public class ParseCsrRequest
{
    /// <summary>
    /// PEM-encoded CSR string to parse.
    /// </summary>
    public string Pem { get; set; } = string.Empty;
}

/// <summary>
/// Request body for approving a certificate signing request.
/// </summary>
public class ApproveCsrRequest
{
    /// <summary>
    /// Optional comment explaining the approval decision.
    /// </summary>
    public string? Comment { get; set; }
}

/// <summary>
/// Request body for cancelling a certificate signing request.
/// </summary>
public class CancelCsrRequest
{
    /// <summary>
    /// Reason for cancellation.
    /// </summary>
    public string Reason { get; set; } = string.Empty;
}

/// <summary>
/// Request body for rejecting a certificate signing request.
/// </summary>
public class RejectCsrRequest
{
    /// <summary>
    /// Reason for the rejection.
    /// </summary>
    public string Reason { get; set; } = "Unspecified";
}
