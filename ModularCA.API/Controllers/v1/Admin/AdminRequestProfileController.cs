using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing request profiles that define what requesters
/// can submit in certificate enrollment requests (subject DN rules, SAN rules,
/// approval requirements, and validity constraints).
/// </summary>
[ApiController]
[Route("api/v1/admin/request-profiles")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminRequestProfileController(
    RequestProfileService requestProfileService,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    IProfileResolutionService profileResolutionService,
    ICaGroupAuthorizationService authService,
    ModularCA.Database.ModularCADbContext db) : ControllerBase
{
    private readonly IDistributedCache _cache = cache;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Whether a request profile bound to <paramref name="caId"/> is inside the caller's
    /// <see cref="SpaceFence"/> for <paramref name="capability"/>: an unbound (system-wide) one
    /// is, as an unbound certificate profile is; a CA-bound one follows its CA's scope, and a
    /// deleted CA's is not.
    /// </summary>
    private async Task<bool> InFenceAsync(Guid? caId, string capability)
    {
        var fence = SpaceFence.From(HttpContext, capability);
        if (caId is not Guid id || fence.InstanceWide)
            return true;
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == id).Select(c => new { c.SpaceId }).FirstOrDefaultAsync();
        return ca != null && fence.Allows(ca.SpaceId);
    }

    /// <summary>
    /// 403 when the profile is unbound (no CA, so instance-wide) and the caller lacks cert.revoke at
    /// system scope, the capability creating one needs; null otherwise.
    /// </summary>
    private async Task<IActionResult?> UnboundRefusalAsync(Guid? caId)
    {
        if (caId != null)
            return null;
        await currentUser.EnsureLoadedAsync();
        return currentUser.User != null && await _authService.HasScopeCapabilityAsync(currentUser.User.Id, null, Capabilities.CertRevoke)
            ? null
            : StatusCode(403, new { error = "An unbound request profile applies instance-wide; changing it needs cert.revoke at system scope." });
    }

    /// <summary>
    /// Returns the request profiles inside the caller's <see cref="SpaceFence"/> (see
    /// <see cref="InFenceAsync"/>), ordered by name; a caller who is not a system admin also
    /// sees only those they hold a <c>profile.*</c> grant for.
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

        var visible = new List<RequestProfileDto>();
        foreach (var p in profiles)
            if (await InFenceAsync(p.CertificateAuthorityId, Capabilities.CertRevoke))
                visible.Add(p);
        profiles = visible;

        if (caId.HasValue)
            profiles = profiles.Where(p => p.CertificateAuthorityId == caId.Value || p.CertificateAuthorityId == null).ToList();
        // Without caId filter, return all profiles (system-wide + all CA-scoped)
        return Ok(profiles);
    }

    /// <summary>
    /// Retrieves a single request profile by its GUID, including inheritance fields. A profile
    /// outside the caller's <see cref="SpaceFence"/> is not found.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await requestProfileService.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(profile.CertificateAuthorityId, Capabilities.CertRevoke))
            return NotFound(new { message = "Request profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Creates a new request profile with subject DN rules, SAN rules, enrollment constraints,
    /// and optional inheritance configuration. A requirement, field or SAN type outside the rule
    /// vocabulary is refused with 400 naming it and the allowed values; the rest are stored in
    /// their canonical spelling (<see cref="RequestProfileRules.Normalize"/>).
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    [RequireStepUp(StepUpOps.CreateRequestProfile)]
    public async Task<IActionResult> Create([FromBody] CreateRequestProfileRequest request)
    {
        if (RequestProfileRules.Normalize(request.SubjectDnRules, request.SanRules) is string rulesError)
            return BadRequest(new { error = rulesError });
        var result = await requestProfileService.CreateAsync(request);
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync("RequestProfileCreated", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", result.Id.ToString(), new { request.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    /// <summary>
    /// Updates an existing request profile by ID with new rules, constraints,
    /// and optional inheritance configuration. A profile outside the caller's fence is not found;
    /// moving it to another CA needs cert.revoke on the new CA and a CA of the profile's current
    /// scope (<see cref="CaBindingAccess"/>). A request profile has no scope of its own beyond its
    /// CA, so unbinding it makes it instance-wide and needs cert.revoke at system scope, as
    /// creating an unbound one does (403 otherwise). Rules are checked and canonicalised as on
    /// create (<see cref="RequestProfileRules.Normalize"/>; 400 when one is outside the vocabulary).
    /// An unbound profile needs cert.revoke at system scope (403, <see cref="UnboundRefusalAsync"/>).
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

        var current = await requestProfileService.GetByIdAsync(id);
        if (current == null || !await InFenceAsync(current.CertificateAuthorityId, Capabilities.CertRevoke))
            return NotFound(new { message = "Request profile not found" });
        if (await UnboundRefusalAsync(current.CertificateAuthorityId) is { } unbound)
            return unbound;
        if (current.CertificateAuthorityId != request.CertificateAuthorityId)
        {
            // Unbound, the profile applies instance-wide, so the scope it lands in is the instance.
            var ownerSpace = current.CertificateAuthorityId is Guid oldCa && request.CertificateAuthorityId != null
                ? await db.CertificateAuthorities.AsNoTracking().Where(c => c.Id == oldCa).Select(c => c.SpaceId).FirstOrDefaultAsync()
                : null;
            if (CaBindingAccess.ToResult(await CaBindingAccess.CheckAsync(_authService, db, SpaceFence.From(HttpContext, Capabilities.CertRevoke),
                    currentUser.User.Id, request.CertificateAuthorityId, ownerSpace, Capabilities.CertRevoke)) is { } refused)
                return refused;
        }

        if (RequestProfileRules.Normalize(request.SubjectDnRules, request.SanRules) is string rulesError)
            return BadRequest(new { error = rulesError });

        var result = await requestProfileService.UpdateAsync(id, request);
        await audit.LogAsync("RequestProfileUpdated", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return Ok(result);
    }

    /// <summary>
    /// Deletes a request profile by its GUID. A profile outside the caller's cert.revoke
    /// <see cref="SpaceFence"/> is not found (404), as on update, and an unbound one needs
    /// cert.revoke at system scope (403, <see cref="UnboundRefusalAsync"/>).
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

        var current = await requestProfileService.GetByIdAsync(id);
        if (current == null || !await InFenceAsync(current.CertificateAuthorityId, Capabilities.CertRevoke))
            return NotFound(new { message = "Request profile not found" });
        if (await UnboundRefusalAsync(current.CertificateAuthorityId) is { } unbound)
            return unbound;

        var deleted = await requestProfileService.DeleteAsync(id);
        if (!deleted)
            return NotFound(new { message = "Request profile not found" });
        await audit.LogAsync("RequestProfileDeleted", currentUser.User?.Id, currentUser.User?.Username,
            "RequestProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }

    /// <summary>
    /// Returns the effective (merged) request profile after resolving inheritance
    /// from parent profiles. Useful for previewing the actual constraints that will apply. A
    /// profile outside the caller's <see cref="SpaceFence"/> is not found.
    /// </summary>
    /// <param name="id">The GUID of the request profile to resolve.</param>
    [HttpGet("{id}/resolved")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetResolved(Guid id)
    {
        var profile = await requestProfileService.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(profile.CertificateAuthorityId, Capabilities.CertView))
            return NotFound(new { message = "Request profile not found" });
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
        var profile = await requestProfileService.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(profile.CertificateAuthorityId, Capabilities.CertView))
            return NotFound(new { message = "Request profile not found" });
        var errors = await profileResolutionService.ValidateRequestProfileInheritanceAsync(id);
        return Ok(new { isValid = errors.Count == 0, errors });
    }
}
