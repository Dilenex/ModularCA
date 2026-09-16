using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing signing profiles (algorithm constraints, name constraints,
/// policy OIDs, and allowed cert profile associations), including inheritance configuration.
/// </summary>
[ApiController]
[Route("api/v1/admin/signing-profiles")]
[Authorize]
public class AdminSigningProfileController(
    ISigningProfileService service,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Returns all signing profiles including their allowed cert profile IDs
    /// and inheritance configuration. Non-system-admin callers see only profiles
    /// they have a profile.* capability grant for.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetAll()
    {
        await currentUser.EnsureLoadedAsync();
        var profiles = await service.GetAllAsync();

        if (HttpContext.Items["IsSystemAdmin"] is not true && currentUser.User != null)
        {
            var (grantedIds, hasWildcard) = await _authService.GetGrantedResourceIdsAsync(
                currentUser.User.Id, "profile.", "SigningProfile");
            if (!hasWildcard)
                profiles = profiles.Where(p => grantedIds.Contains(p.Id)).ToList();
        }

        return Ok(profiles);
    }

    /// <summary>
    /// Creates a new signing profile with optional allowed cert profile links
    /// and inheritance configuration.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CaManage, CaTarget.CaCertificate, "r.IssuerId")]
    public async Task<IActionResult> Create([FromBody] CreateSigningProfileRequest r)
    {
        var result = await service.CreateAsync(r);
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.SigningProfileCreated, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", null, new { r.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return CreatedAtAction(nameof(GetAll), new { }, result);
    }

    /// <summary>
    /// Updates an existing signing profile and replaces its allowed cert profile links
    /// and inheritance configuration.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.UpdateSigningProfile, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateSigningProfileRequest r)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        // UpdateAsync also replaces the allowed-cert-profile links from r.AllowedCertProfileIds, so the
        // detail page's unified Save persists the profile and its links in this one step-up-gated call.
        await service.UpdateAsync(id, r);
        await audit.LogAsync(AuditActionType.SigningProfileUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", id.ToString(), r,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("SigningProfileChanged", AlertSeverity.Warning, $"Signing profile {id} updated by {currentUser.User?.Username}", new { ProfileId = id });
        return NoContent();
    }

    /// <summary>
    /// Deletes a signing profile and its associated cert profile links.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.DeleteSigningProfile, "id")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        await service.DeleteAsync(id);
        await audit.LogAsync(AuditActionType.SigningProfileDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("SigningProfileChanged", AlertSeverity.Warning, $"Signing profile {id} deleted by {currentUser.User?.Username}", new { ProfileId = id, Action = "Deleted" });
        return NoContent();
    }

    /// <summary>
    /// Retrieves a single signing profile by its GUID, including allowed cert profile IDs
    /// and inheritance configuration.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await service.GetByIdAsync(id);
        if (profile == null)
            return NotFound(new { message = "Profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Replaces the set of allowed cert profile IDs for the specified signing profile.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("{id}/allowed-cert-profiles")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.UpdateSigningProfile, "id")]
    public async Task<IActionResult> SetAllowedCertProfiles(Guid id, [FromBody] List<Guid> certProfileIds)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        await service.SetAllowedCertProfilesAsync(id, certProfileIds);
        await audit.LogAsync(AuditActionType.SigningProfileUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", id.ToString(), new { AllowedCertProfileIds = certProfileIds },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }

    /// <summary>
    /// Returns the list of allowed cert profile IDs for the specified signing profile.
    /// </summary>
    [HttpGet("{id}/allowed-cert-profiles")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetAllowedCertProfiles(Guid id)
    {
        var ids = await service.GetAllowedCertProfileIdsAsync(id);
        return Ok(ids);
    }
}
