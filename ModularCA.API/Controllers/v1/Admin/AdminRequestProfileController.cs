using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.RequestProfiles;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing request profiles that define what requesters
/// can submit in certificate enrollment requests (subject DN rules, SAN rules,
/// approval requirements, and validity constraints).
/// </summary>
[ApiController]
[Route("api/v1/admin/request-profiles")]
[Authorize]
public class AdminRequestProfileController(
    RequestProfileService requestProfileService,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    IProfileResolutionService profileResolutionService,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly IDistributedCache _cache = cache;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Returns all request profiles ordered by name.
    /// Supports optional filtering by CA ID; null returns system-wide profiles.
    /// </summary>
    /// <param name="caId">Optional certificate authority ID to filter profiles by CA scope.</param>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetAll([FromQuery] Guid? caId = null)
    {
        await currentUser.EnsureLoadedAsync();
        var profiles = await requestProfileService.GetAllAsync();

        // Capability-based filtering: non-system-admin callers see only profiles
        // they have a profile.* capability grant for.
        if (HttpContext.Items["IsSystemAdmin"] is not true && currentUser.User != null)
        {
            var (grantedIds, hasWildcard) = await _authService.GetGrantedResourceIdsAsync(
                currentUser.User.Id, "profile.", "RequestProfile");
            if (!hasWildcard)
                profiles = profiles.Where(p => grantedIds.Contains(p.Id)).ToList();
        }

        if (caId.HasValue)
            profiles = profiles.Where(p => p.CertificateAuthorityId == caId.Value || p.CertificateAuthorityId == null).ToList();
        // Without caId filter, return all profiles (system-wide + all CA-scoped)
        return Ok(profiles);
    }

    /// <summary>
    /// Retrieves a single request profile by its GUID, including inheritance fields.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await requestProfileService.GetByIdAsync(id);
        if (profile == null)
            return NotFound(new { message = "Request profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Creates a new request profile with subject DN rules, SAN rules, enrollment constraints,
    /// and optional inheritance configuration.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    public async Task<IActionResult> Create([FromBody] CreateRequestProfileRequest request)
    {
        var result = await requestProfileService.CreateAsync(request);
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync("RequestProfileCreated", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", result.Id.ToString(), new { request.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    /// <summary>
    /// Updates an existing request profile by ID with new rules, constraints,
    /// and optional inheritance configuration.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateRequestProfileRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateRequestProfile, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var result = await requestProfileService.UpdateAsync(id, request);
        await audit.LogAsync("RequestProfileUpdated", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return Ok(result);
    }

    /// <summary>
    /// Deletes a request profile by its GUID.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Delete(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.DeleteRequestProfile, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var deleted = await requestProfileService.DeleteAsync(id);
        if (!deleted)
            return NotFound(new { message = "Request profile not found" });
        await audit.LogAsync("RequestProfileDeleted", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }

    /// <summary>
    /// Returns the effective (merged) request profile after resolving inheritance
    /// from parent profiles. Useful for previewing the actual constraints that will apply.
    /// </summary>
    /// <param name="id">The GUID of the request profile to resolve.</param>
    [HttpGet("{id}/resolved")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetResolved(Guid id)
    {
        var resolved = await profileResolutionService.ResolveRequestProfileAsync(id);
        return Ok(resolved);
    }

    /// <summary>
    /// Validates that the request profile's inheritance overrides do not violate
    /// the parent profile's constraints. Returns a list of validation errors (empty if valid).
    /// </summary>
    /// <param name="id">The GUID of the child request profile to validate.</param>
    [HttpPost("{id}/validate-inheritance")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> ValidateInheritance(Guid id)
    {
        var errors = await profileResolutionService.ValidateRequestProfileInheritanceAsync(id);
        return Ok(new { isValid = errors.Count == 0, errors });
    }
}
