using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing signing profiles (algorithm constraints, name constraints,
/// policy OIDs, and allowed cert profile associations), including inheritance configuration.
/// </summary>
[ApiController]
[Route("api/v1/admin/signing-profiles")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminSigningProfileController(
    ISigningProfileService service,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    ICaGroupAuthorizationService authService,
    ModularCA.Database.ModularCADbContext db) : ControllerBase
{
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Whether a signing profile issuing from CA certificate <paramref name="issuerId"/> is inside
    /// the caller's <see cref="SpaceFence"/> for <paramref name="capability"/>: one with no issuer
    /// is unbound and is; otherwise the issuing CA's scope decides, and a profile whose CA is gone
    /// or deleted is not.
    /// </summary>
    private async Task<bool> InFenceAsync(Guid? issuerId, string capability)
    {
        var fence = SpaceFence.From(HttpContext, capability);
        if (issuerId is not Guid id || fence.InstanceWide)
            return true;
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.CertificateId == id).Select(c => new { c.SpaceId }).FirstOrDefaultAsync();
        return ca != null && fence.Allows(ca.SpaceId);
    }

    /// <summary>
    /// 403 when the profile is unbound (no issuer) and the caller lacks ca.manage at system scope,
    /// the capability creating one needs; null otherwise. An unbound profile applies
    /// instance-wide, so a space-scoped caller may read it but not change or delete it.
    /// </summary>
    private async Task<IActionResult?> UnboundRefusalAsync(Guid userId, Guid? issuerId)
        => issuerId != null || await _authService.HasScopeCapabilityAsync(userId, null, Capabilities.CaManage)
            ? null
            : StatusCode(403, new { error = "An unbound signing profile applies instance-wide; changing it needs ca.manage at system scope." });

    /// <summary>
    /// Null when the caller may make CA certificate <paramref name="issuerId"/> a profile's issuer:
    /// its CA is inside the caller's ca.manage fence (else 404) and the caller holds ca.manage on
    /// it (else 403). No issuer makes the profile unbound, which applies instance-wide, so it needs
    /// ca.manage at system scope (else 403), as creating an unbound profile does.
    /// </summary>
    private async Task<IActionResult?> AuthorizeIssuerAsync(Guid userId, Guid? issuerId)
    {
        if (issuerId is not Guid id)
            return await _authService.HasScopeCapabilityAsync(userId, null, Capabilities.CaManage)
                ? null
                : StatusCode(403, new { error = "An unbound signing profile applies instance-wide and needs ca.manage at system scope." });
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.CertificateId == id).Select(c => new { c.Id, c.SpaceId }).FirstOrDefaultAsync();
        if (ca == null || !SpaceFence.From(HttpContext, Capabilities.CaManage).Allows(ca.SpaceId))
            return NotFound(new { error = "Issuing CA not found" });
        return await _authService.HasCaCapabilityAsync(userId, ca.Id, Capabilities.CaManage)
            ? null
            : StatusCode(403, new { error = "You lack ca.manage on the issuing CA." });
    }

    /// <summary>
    /// Null when every certificate profile in <paramref name="certProfileIds"/> may be linked to a
    /// signing profile issuing from CA certificate <paramref name="issuerId"/>; otherwise 400 (404
    /// when the issuer is no registered CA). Each profile must exist and be inside the caller's
    /// cert.view <see cref="SpaceFence"/> (<see cref="SpaceFence.AllowsProfile"/>), except one
    /// already in <paramref name="alreadyLinked"/>, and <see cref="ModularCA.Core.Authorization.CertProfileScope"/> must admit it
    /// for the issuing CA, as issuance will: an instance-wide profile (no space, no CA) fits every
    /// CA, a space profile only that space's CAs, a CA-bound one only its CA. An unbound signing
    /// profile has no CA, so only instance-wide profiles fit it.
    /// </summary>
    private async Task<IActionResult?> CertProfileLinksErrorAsync(Guid? issuerId, IEnumerable<Guid>? certProfileIds,
        IReadOnlyCollection<Guid>? alreadyLinked = null)
    {
        var ids = (certProfileIds ?? []).Distinct().ToList();
        if (ids.Count == 0)
            return null;

        var caId = Guid.Empty;
        Guid? caSpaceId = null;
        if (issuerId is Guid issuer)
        {
            var ca = await db.CertificateAuthorities.AsNoTracking()
                .Where(c => c.CertificateId == issuer).Select(c => new { c.Id, c.SpaceId }).FirstOrDefaultAsync();
            if (ca == null)
                return NotFound(new { error = "Issuing CA not found" });
            (caId, caSpaceId) = (ca.Id, ca.SpaceId);
        }

        var profiles = await db.CertProfiles.AsNoTracking()
            .Where(p => ids.Contains(p.Id))
            .Select(p => new { p.Id, p.SpaceId, p.CertificateAuthorityId })
            .ToDictionaryAsync(p => p.Id);
        var fence = SpaceFence.From(HttpContext, Capabilities.CertView);
        foreach (var id in ids)
        {
            if (!profiles.TryGetValue(id, out var p)
                || (alreadyLinked?.Contains(id) != true && !fence.AllowsProfile(p.SpaceId, p.CertificateAuthorityId)))
                return BadRequest(new { error = $"Certificate profile {id} not found." });
            if (!ModularCA.Core.Authorization.CertProfileScope.Admits(p.SpaceId, p.CertificateAuthorityId, caId, caSpaceId))
                return BadRequest(new
                {
                    error = $"Certificate profile {id} belongs to another scope than the signing profile's issuing CA. Link a profile of "
                        + "the CA's own space, one bound to this CA, or an instance-wide profile.",
                    code = ModularCA.Shared.Errors.ErrorCodes.CertProfileOutOfScope,
                });
        }
        return null;
    }

    /// <summary>
    /// Why the request's name-constraint fields would not build, or null: each must be blank or a
    /// JSON array of entries <see cref="NameConstraintRules"/> accepts, so a profile is never saved
    /// with constraints the certificate builder would refuse when it issues a CA certificate.
    /// </summary>
    private static string? NameConstraintsError(CreateSigningProfileRequest r) =>
        NameConstraintRules.JsonError(r.NameConstraintsPermitted, nameof(r.NameConstraintsPermitted))
        ?? NameConstraintRules.JsonError(r.NameConstraintsExcluded, nameof(r.NameConstraintsExcluded));

    /// <summary>
    /// Why the request's certificate-policy fields would not build, or null: PolicyOids must be
    /// blank or a JSON array of distinct OIDs BouncyCastle accepts, and PolicyQualifiersJson blank
    /// or an object of the shape the certificate builder reads (<see cref="CertificatePolicyRules"/>).
    /// One bad OID used to make every issuance under the profile throw.
    /// </summary>
    private static string? CertificatePoliciesError(CreateSigningProfileRequest r) =>
        CertificatePolicyRules.Error(r.PolicyOids, r.PolicyQualifiersJson);

    /// <summary>
    /// Returns the signing profiles inside the caller's <see cref="SpaceFence"/> (see
    /// <see cref="InFenceAsync"/>), including their allowed cert profile IDs and inheritance
    /// configuration. A caller who is not a system admin also sees only profiles they have a
    /// profile.* capability grant for.
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

        var visible = new List<SigningProfileDto>();
        foreach (var p in profiles)
            if (await InFenceAsync(p.IssuerId, Capabilities.CertView))
                visible.Add(p);
        return Ok(visible);
    }

    /// <summary>
    /// Creates a new signing profile with optional allowed cert profile links
    /// and inheritance configuration. The issuer's CA must be inside the caller's fence and the
    /// caller must hold ca.manage on it (<see cref="AuthorizeIssuerAsync"/>). Invalid name
    /// constraints (<see cref="NameConstraintsError"/>) and certificate policies
    /// (<see cref="CertificatePoliciesError"/>) are refused with 400, as are allowed cert profiles
    /// the caller cannot see or the issuing CA could not issue under (<see cref="CertProfileLinksErrorAsync"/>).
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CaManage, CaTarget.CaCertificate, "r.IssuerId")]
    [RequireStepUp(StepUpOps.CreateSigningProfile)]
    public async Task<IActionResult> Create([FromBody] CreateSigningProfileRequest r)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();
        if (await AuthorizeIssuerAsync(currentUser.User.Id, r.IssuerId) is { } refused)
            return refused;
        if (await CertProfileLinksErrorAsync(r.IssuerId, r.AllowedCertProfileIds) is { } badLinks)
            return badLinks;
        if (NameConstraintsError(r) is string ncError)
            return BadRequest(new { error = ncError });
        if (CertificatePoliciesError(r) is string cpError)
            return BadRequest(new { error = cpError });
        var result = await service.CreateAsync(r);
        await audit.LogAsync(AuditActionType.SigningProfileCreated, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", null, new { r.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return CreatedAtAction(nameof(GetAll), new { }, result);
    }

    /// <summary>
    /// Updates an existing signing profile and replaces its allowed cert profile links
    /// and inheritance configuration. A profile outside the caller's fence is not found, and a new
    /// issuer, or none (unbinding, which needs system scope), is checked by
    /// <see cref="AuthorizeIssuerAsync"/>, since the policy checked only the current one. Invalid
    /// name constraints (<see cref="NameConstraintsError"/>) and certificate policies
    /// (<see cref="CertificatePoliciesError"/>) are refused with 400, as are allowed cert profiles
    /// the resulting issuer could not issue under, or newly linked ones the caller cannot see
    /// (<see cref="CertProfileLinksErrorAsync"/>). An unbound profile needs ca.manage at system scope
    /// (403, <see cref="UnboundRefusalAsync"/>).
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

        var current = await service.GetByIdAsync(id);
        if (current == null || !await InFenceAsync(current.IssuerId, Capabilities.CaManage))
            return NotFound(new { message = "Profile not found" });
        if (await UnboundRefusalAsync(currentUser.User.Id, current.IssuerId) is { } unbound)
            return unbound;
        if (current.IssuerId != r.IssuerId && await AuthorizeIssuerAsync(currentUser.User.Id, r.IssuerId) is { } refused)
            return refused;
        if (await CertProfileLinksErrorAsync(r.IssuerId, r.AllowedCertProfileIds, current.AllowedCertProfileIds) is { } badLinks)
            return badLinks;
        if (NameConstraintsError(r) is string ncError)
            return BadRequest(new { error = ncError });
        if (CertificatePoliciesError(r) is string cpError)
            return BadRequest(new { error = cpError });

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
    /// Deletes a signing profile and its associated cert profile links. A profile outside the
    /// caller's ca.manage <see cref="SpaceFence"/> is not found (404), as on update, and an unbound
    /// one needs ca.manage at system scope (403, <see cref="UnboundRefusalAsync"/>).
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

        var current = await service.GetByIdAsync(id);
        if (current == null || !await InFenceAsync(current.IssuerId, Capabilities.CaManage))
            return NotFound(new { message = "Profile not found" });
        if (await UnboundRefusalAsync(currentUser.User.Id, current.IssuerId) is { } unbound)
            return unbound;

        await service.DeleteAsync(id);
        await audit.LogAsync(AuditActionType.SigningProfileDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = _alertService.RaiseAlertAsync("SigningProfileChanged", AlertSeverity.Warning, $"Signing profile {id} deleted by {currentUser.User?.Username}", new { ProfileId = id, Action = "Deleted" });
        return NoContent();
    }

    /// <summary>
    /// Retrieves a single signing profile by its GUID, including allowed cert profile IDs
    /// and inheritance configuration. A profile outside the caller's <see cref="SpaceFence"/> is
    /// not found.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await service.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(profile.IssuerId, Capabilities.CertView))
            return NotFound(new { message = "Profile not found" });
        return Ok(profile);
    }

    /// <summary>
    /// Replaces the set of allowed cert profile IDs for the specified signing profile. A profile
    /// outside the caller's ca.manage <see cref="SpaceFence"/> is not found, and the links are
    /// checked by <see cref="CertProfileLinksErrorAsync"/> as on create and update. An unbound profile
    /// needs ca.manage at system scope (403, <see cref="UnboundRefusalAsync"/>).
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

        var current = await service.GetByIdAsync(id);
        if (current == null || !await InFenceAsync(current.IssuerId, Capabilities.CaManage))
            return NotFound(new { message = "Profile not found" });
        if (await UnboundRefusalAsync(currentUser.User.Id, current.IssuerId) is { } unbound)
            return unbound;
        certProfileIds ??= [];
        if (await CertProfileLinksErrorAsync(current.IssuerId, certProfileIds, current.AllowedCertProfileIds) is { } badLinks)
            return badLinks;

        await service.SetAllowedCertProfilesAsync(id, certProfileIds.Distinct().ToList());
        await audit.LogAsync(AuditActionType.SigningProfileUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "SigningProfile", id.ToString(), new { AllowedCertProfileIds = certProfileIds },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }

    /// <summary>
    /// Returns the list of allowed cert profile IDs for the specified signing profile. A profile
    /// outside the caller's <see cref="SpaceFence"/> is not found.
    /// </summary>
    [HttpGet("{id}/allowed-cert-profiles")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetAllowedCertProfiles(Guid id)
    {
        var profile = await service.GetByIdAsync(id);
        if (profile == null || !await InFenceAsync(profile.IssuerId, Capabilities.CertView))
            return NotFound(new { message = "Profile not found" });
        var ids = await service.GetAllowedCertProfileIdsAsync(id);
        return Ok(ids);
    }
}
