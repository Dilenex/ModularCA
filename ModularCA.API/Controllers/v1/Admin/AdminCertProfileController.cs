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
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing certificate profiles (extension templates, validity constraints,
/// algorithm restrictions, and CT log configuration).
/// Every list, read and write enforces the caller's <see cref="SpaceFence"/>
/// (<see cref="SpaceFence.AllowsProfile"/>): there is no query filter behind it.
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
    /// The caller sees the profiles inside their <see cref="SpaceFence"/>: their spaces'
    /// profiles, the unbound instance-wide ones, and those bound to an instance CA only with
    /// instance scope; a caller who is not a system admin also only those they hold a
    /// <c>profile.*</c> grant for. A <paramref name="spaceId"/> view shows that space's profiles
    /// and the unbound instance-wide ones.
    /// </summary>
    /// <param name="caId">Optional certificate authority ID to filter profiles by CA scope.</param>
    /// <param name="isCaProfile">Optional filter: true returns only CA profiles, false returns only leaf profiles, null returns all.</param>
    /// <param name="spaceId">Optional space view. The pre-0.4.0 <c>tenantId</c> is refused (400).</param>
    [HttpGet]
    [Authorize(Policy = "CaAuditor")]
    [RefuseQueryKey("tenantId", "spaceId")]
    public async Task<IActionResult> GetAll([FromQuery] Guid? caId = null, [FromQuery] bool? isCaProfile = null, [FromQuery] Guid? spaceId = null)
    {
        await currentUser.EnsureLoadedAsync();
        var profiles = await certProfileService.GetAllAsync();

        // The console's space scope: the space's own profiles plus the instance-wide ones not
        // bound to an instance CA.
        if (spaceId.HasValue)
        {
            var inSpace = await db.CertProfiles
                .AsNoTracking()
                .Where(p => (p.SpaceId == null && p.CertificateAuthorityId == null) || p.SpaceId == spaceId.Value)
                .Select(p => p.Id)
                .ToListAsync();
            var inSpaceSet = new HashSet<Guid>(inSpace);
            profiles = profiles.Where(p => inSpaceSet.Contains(p.Id)).ToList();
        }

        // Filter by CA vs leaf profile type when requested
        if (isCaProfile.HasValue)
            profiles = profiles.Where(p => p.IsCaProfile == isCaProfile.Value).ToList();

        if (!ReadFence.IsSystemAdmin)
        {
            var accessibleProfileIds = await db.CertProfiles
                .AsNoTracking()
                .Where(ReadFence.ProfilePredicate<Shared.Entities.CertProfileEntity>(p => p.SpaceId, p => p.CertificateAuthorityId))
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
    /// CA (when supplied) is inside the caller's <see cref="SpaceFence"/> and
    /// populates <c>CertProfileEntity.SpaceId</c> from it (null for an instance CA). An
    /// inheritance parent outside the fence is not found. <c>CtLogIds</c> that are not a JSON array
    /// of existing CT log ids are refused with 400 (<see cref="CtLogIdsErrorAsync"/>).
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    public async Task<IActionResult> Create([FromBody] CreateCertProfileRequest request)
    {
        Guid? resolvedSpaceId = null;
        if (request.CertificateAuthorityId.HasValue)
        {
            var ca = await db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == request.CertificateAuthorityId.Value);
            if (ca == null || !WriteFence.Allows(ca.SpaceId))
                return NotFound(new { error = "CA not found" });
            resolvedSpaceId = ca.SpaceId;
        }

        if (await CtLogIdsErrorAsync(request.CtLogIds) is string ctError)
            return BadRequest(new { error = ctError });

        var result = await certProfileService.CreateAsync(request, resolvedSpaceId, WriteFence.AllowsProfile);
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CertProfileCreated, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", null, new { request.Name, SpaceId = resolvedSpaceId, request.CertificateAuthorityId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: request.CertificateAuthorityId, spaceId: resolvedSpaceId);
        return CreatedAtAction(nameof(GetAll), new { }, result);
    }

    /// <summary>
    /// Updates an existing certificate profile by ID with new constraint values
    /// and optional inheritance configuration. An inheritance parent outside the caller's
    /// <see cref="SpaceFence"/> is not found. Moving the profile to another CA, or unbinding it,
    /// needs cert.revoke on the new CA (or across the profile's scope) and a CA of the profile's
    /// own scope (<see cref="CaBindingAccess"/>). <c>CtLogIds</c> that are not a JSON array of
    /// existing CT log ids are refused with 400 (<see cref="CtLogIdsErrorAsync"/>). An instance-wide
    /// profile needs cert.revoke at system scope (403, <see cref="InstanceWideRefusalAsync"/>).
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

        var current = await db.CertProfiles.AsNoTracking()
            .Where(p => p.Id == id)
            .Select(p => new { p.SpaceId, p.CertificateAuthorityId })
            .FirstOrDefaultAsync();
        if (current == null || !WriteFence.AllowsProfile(current.SpaceId, current.CertificateAuthorityId))
            return NotFound(new { message = "Profile not found" });
        if (await InstanceWideRefusalAsync(current.SpaceId, current.CertificateAuthorityId) is { } instanceWide)
            return instanceWide;
        if (current.CertificateAuthorityId != request.CertificateAuthorityId
            && CaBindingAccess.ToResult(await CaBindingAccess.CheckAsync(_authService, db, WriteFence, currentUser.User!.Id,
                request.CertificateAuthorityId, current.SpaceId, Capabilities.CertRevoke)) is { } refused)
            return refused;

        if (await CtLogIdsErrorAsync(request.CtLogIds) is string ctError)
            return BadRequest(new { error = ctError });

        await certProfileService.UpdateAsync(id, request, WriteFence.AllowsProfile);
        await audit.LogAsync(AuditActionType.CertProfileUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("CertProfileChanged", AlertSeverity.Warning, $"Certificate profile {id} updated by {currentUser.User?.Username}", new { ProfileId = id });
        return NoContent();
    }

    /// <summary>
    /// Deletes a certificate profile by its GUID. A profile outside the caller's cert.revoke
    /// <see cref="SpaceFence"/> is not found (404), as on update, and an instance-wide one needs
    /// cert.revoke at system scope (403, <see cref="InstanceWideRefusalAsync"/>).
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

        var current = await db.CertProfiles.AsNoTracking()
            .Where(p => p.Id == id)
            .Select(p => new { p.SpaceId, p.CertificateAuthorityId })
            .FirstOrDefaultAsync();
        if (current == null || !WriteFence.AllowsProfile(current.SpaceId, current.CertificateAuthorityId))
            return NotFound(new { message = "Profile not found" });
        if (await InstanceWideRefusalAsync(current.SpaceId, current.CertificateAuthorityId) is { } instanceWide)
            return instanceWide;

        await certProfileService.DeleteAsync(id);
        await audit.LogAsync(AuditActionType.CertProfileDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "CertProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("CertProfileChanged", AlertSeverity.Warning, $"Certificate profile {id} deleted by {currentUser.User?.Username}", new { ProfileId = id, Action = "Deleted" });
        return NoContent();
    }

    /// <summary>
    /// Retrieves a single certificate profile by GUID, including resolved EKU names
    /// and inheritance fields. A profile outside the caller's <see cref="SpaceFence"/> is not found:
    /// the policy admits an unbound profile for anyone holding the capability on any CA.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await certProfileService.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(id))
            return NotFound(new { message = "Profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Returns the effective (merged) certificate profile after resolving inheritance
    /// from parent profiles. Useful for previewing the actual constraints that will apply. A
    /// profile outside the caller's <see cref="SpaceFence"/> is not found.
    /// </summary>
    /// <param name="id">The GUID of the certificate profile to resolve.</param>
    [HttpGet("{id}/resolved")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetResolved(Guid id)
    {
        if (!await InFenceAsync(id))
            return NotFound(new { message = "Profile not found" });
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
        if (!await InFenceAsync(id))
            return NotFound(new { message = "Profile not found" });
        var errors = await profileResolutionService.ValidateCertProfileInheritanceAsync(id);
        return Ok(new { isValid = errors.Count == 0, errors });
    }

    /// <summary>
    /// Why <paramref name="ctLogIds"/> cannot be saved, or null: it must be blank or a JSON array of
    /// GUIDs (<see cref="CtLogIdRules"/>), each naming an existing CT log. Issuance reads the field
    /// as such a list, and a value it could not read used to turn off CT submission entirely.
    /// </summary>
    private async Task<string?> CtLogIdsErrorAsync(string? ctLogIds)
    {
        if (!CtLogIdRules.TryParse(ctLogIds, out var ids, out var error))
            return error;
        if (ids.Count == 0) return null;
        var distinct = ids.Distinct().ToList();
        var known = await db.CtLogs.AsNoTracking().Where(l => distinct.Contains(l.Id)).Select(l => l.Id).ToListAsync();
        var unknown = distinct.Except(known).ToList();
        return unknown.Count == 0
            ? null
            : $"CtLogIds names CT logs that do not exist: {string.Join(", ", unknown)}. Remove them, or pick logs from GET /api/v1/admin/ct-logs/options.";
    }

    /// <summary>
    /// 403 when the profile is instance-wide (no space, no CA) and the caller lacks cert.revoke at
    /// system scope, the capability creating one needs; null otherwise. An instance-wide profile
    /// applies to every space's CAs, so a space-scoped caller may read and link it but not change it.
    /// </summary>
    private async Task<IActionResult?> InstanceWideRefusalAsync(Guid? spaceId, Guid? caId)
    {
        if (spaceId != null || caId != null)
            return null;
        await currentUser.EnsureLoadedAsync();
        return currentUser.User != null && await _authService.HasScopeCapabilityAsync(currentUser.User.Id, null, Capabilities.CertRevoke)
            ? null
            : StatusCode(403, new { error = "An instance-wide certificate profile applies to every space; changing it needs cert.revoke at system scope." });
    }

    private SpaceFence ReadFence => SpaceFence.From(HttpContext, Capabilities.CertView);

    private SpaceFence WriteFence => SpaceFence.From(HttpContext, Capabilities.CertRevoke);

    /// <summary>Whether profile <paramref name="id"/> exists and is inside the caller's cert.view fence.</summary>
    private async Task<bool> InFenceAsync(Guid id)
    {
        var scope = await db.CertProfiles.AsNoTracking()
            .Where(p => p.Id == id)
            .Select(p => new { p.SpaceId, p.CertificateAuthorityId })
            .FirstOrDefaultAsync();
        return scope != null && ReadFence.AllowsProfile(scope.SpaceId, scope.CertificateAuthorityId);
    }
}
