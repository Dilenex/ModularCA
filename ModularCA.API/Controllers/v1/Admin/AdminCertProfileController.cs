using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing certificate profiles (extension templates, validity constraints,
/// algorithm restrictions, and CT log configuration).
/// GetAll and Create resolve the profile/CA back to a tenant and enforce
/// AccessibleTenantIds before returning or writing rows.
/// </summary>
[ApiController]
[Route("api/v1/admin/cert-profiles")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminCertProfileController(
    ICertProfileService certProfileService,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    IProfileResolutionService profileResolutionService,
    ModularCADbContext db,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Returns all certificate profiles with resolved EKU friendly names.
    /// Results are filtered to tenant-owned profiles + system-wide profiles (TenantId == null)
    /// for non-system-admin callers. <c>IgnoreQueryFilters()</c> lets system admins see every
    /// profile without triggering the global tenant fence.
    /// </summary>
    /// <param name="caId">Optional certificate authority ID to filter profiles by CA scope.</param>
    /// <param name="isCaProfile">Optional filter: true returns only CA profiles, false returns only leaf profiles, null returns all.</param>
    [HttpGet]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetAll([FromQuery] Guid? caId = null, [FromQuery] bool? isCaProfile = null, [FromQuery] Guid? tenantId = null)
    {
        await currentUser.EnsureLoadedAsync();
        var profiles = await certProfileService.GetAllAsync();

        // The console's tenant scope: the tenant's own profiles plus the system-wide ones.
        if (tenantId.HasValue)
        {
            var inTenant = await db.CertProfiles
                .AsNoTracking()
                .Where(p => p.TenantId == null || p.TenantId == tenantId.Value)
                .Select(p => p.Id)
                .ToListAsync();
            var inTenantSet = new HashSet<Guid>(inTenant);
            profiles = profiles.Where(p => inTenantSet.Contains(p.Id)).ToList();
        }

        // Filter by CA vs leaf profile type when requested
        if (isCaProfile.HasValue)
            profiles = profiles.Where(p => p.IsCaProfile == isCaProfile.Value).ToList();

        // Tenant fence. System admins see everything; other callers see
        // only profiles that are system-wide (TenantId == null) or owned by a tenant in
        // AccessibleTenantIds. The service already honors the global filter for CA-scoped
        // profile lookups, but the GetAll path needs the explicit system-profile allowance.
        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            var accessibleProfileIds = await db.CertProfiles
                .AsNoTracking()
                .Where(p => p.TenantId == null || (tenantIds != null && p.TenantId.HasValue && tenantIds.Contains(p.TenantId.Value)))
                .Select(p => p.Id)
                .ToListAsync();
            var allowedSet = new HashSet<Guid>(accessibleProfileIds);
            profiles = profiles.Where(p => allowedSet.Contains(p.Id)).ToList();

            // Capability-based filtering: restrict to profiles the user has any profile.* grant for
            if (currentUser.User != null)
            {
                var (grantedIds, hasWildcard) = await _authService.GetGrantedResourceIdsAsync(
                    currentUser.User.Id, "profile.", "CertProfile");
                if (!hasWildcard)
                    profiles = profiles.Where(p => grantedIds.Contains(p.Id)).ToList();
            }
        }

        if (caId.HasValue)
            profiles = profiles.Where(p => p.CertificateAuthorityId == caId.Value || p.CertificateAuthorityId == null).ToList();
        return Ok(profiles);
    }

    /// <summary>
    /// Creates a new certificate profile with key usage, EKU, validity, algorithm constraints,
    /// and optional inheritance configuration. Validates that the target
    /// CA (when supplied) belongs to a tenant in the caller's <c>AccessibleTenantIds</c> and
    /// populates <c>CertProfileEntity.TenantId</c> automatically.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    public async Task<IActionResult> Create([FromBody] CreateCertProfileRequest request)
    {
        Guid? resolvedTenantId = null;
        if (request.CertificateAuthorityId.HasValue)
        {
            var ca = await db.CertificateAuthorities
                .AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(c => c.Id == request.CertificateAuthorityId.Value);
            if (ca == null || ca.IsDeleted)
                return NotFound(new { error = "CA not found" });

            if (HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
                if (tenantIds == null || !tenantIds.Contains(ca.TenantId))
                    return NotFound(new { error = "CA not found" });
            }
            resolvedTenantId = ca.TenantId;
        }

        var result = await certProfileService.CreateAsync(request, resolvedTenantId);
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CertProfileCreated, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", null, new { request.Name, TenantId = resolvedTenantId, request.CertificateAuthorityId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: request.CertificateAuthorityId, tenantId: resolvedTenantId);
        return CreatedAtAction(nameof(GetAll), new { }, result);
    }

    /// <summary>
    /// Updates an existing certificate profile by ID with new constraint values
    /// and optional inheritance configuration.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCertProfileRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateCertProfile, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        await certProfileService.UpdateAsync(id, request);
        await audit.LogAsync(AuditActionType.CertProfileUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("CertProfileChanged", AlertSeverity.Warning, $"Certificate profile {id} updated by {currentUser.User?.Username}", new { ProfileId = id });
        return NoContent();
    }

    /// <summary>
    /// Deletes a certificate profile by its integer ID.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Delete(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.DeleteCertProfile, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        await certProfileService.DeleteAsync(id);
        await audit.LogAsync(AuditActionType.CertProfileDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("CertProfileChanged", AlertSeverity.Warning, $"Certificate profile {id} deleted by {currentUser.User?.Username}", new { ProfileId = id, Action = "Deleted" });
        return NoContent();
    }

    /// <summary>
    /// Retrieves a single certificate profile by GUID, including resolved EKU names
    /// and inheritance fields.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await certProfileService.GetByIdAsync(id);
        if (profile == null)
            return NotFound(new { message = "Profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Returns the effective (merged) certificate profile after resolving inheritance
    /// from parent profiles. Useful for previewing the actual constraints that will apply.
    /// </summary>
    /// <param name="id">The GUID of the certificate profile to resolve.</param>
    [HttpGet("{id}/resolved")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetResolved(Guid id)
    {
        var resolved = await profileResolutionService.ResolveCertProfileAsync(id);
        return Ok(resolved);
    }

    /// <summary>
    /// Validates that the certificate profile's inheritance overrides do not violate
    /// the parent profile's constraints. Returns a list of validation errors (empty if valid).
    /// </summary>
    /// <param name="id">The GUID of the child certificate profile to validate.</param>
    [HttpPost("{id}/validate-inheritance")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> ValidateInheritance(Guid id)
    {
        var errors = await profileResolutionService.ValidateCertProfileInheritanceAsync(id);
        return Ok(new { isValid = errors.Count == 0, errors });
    }
}
