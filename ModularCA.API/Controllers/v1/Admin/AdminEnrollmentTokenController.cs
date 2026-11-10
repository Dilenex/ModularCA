using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using ModularCA.Shared.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing enrollment tokens used to authenticate protocol enrollment requests.
/// </summary>
[ApiController]
[Route("api/v1/admin/enrollment-tokens")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminEnrollmentTokenController(
    IEnrollmentTokenService tokenService,
    ICurrentUserService currentUser,
    IAuditService audit,
    ModularCADbContext db,
    ICaGroupAuthorizationService auth) : ControllerBase
{
    /// <summary>
    /// Whether the caller may see or revoke <paramref name="token"/>: a token of a space or of an
    /// instance CA follows <see cref="SpaceFence.Allows"/>; a token bound to no CA and no space
    /// is system-wide and needs a fence instance-wide for cert.revoke.
    /// </summary>
    private static bool MayManageToken(SpaceFence fence, EnrollmentTokenEntity token)
        => token.SpaceId == null && token.CertificateAuthorityId == null
            ? fence.InstanceWide
            : fence.Allows(token.SpaceId);

    /// <summary>
    /// Whether <paramref name="token"/> belongs in the console's view of <paramref name="spaceId"/>:
    /// it is scoped to that space, or bound to a CA inside it (by the CA's current space, so a
    /// token whose own space column was never filled still follows its CA). A system-wide token,
    /// one of another space, and one of an instance CA are outside every space view.
    /// </summary>
    /// <param name="token">The token to place.</param>
    /// <param name="spaceId">The space the console is scoped to.</param>
    /// <param name="caSpaces">The space of each CA the listed tokens are bound to (null for an instance CA).</param>
    private static bool InSpaceView(EnrollmentTokenEntity token, Guid spaceId, IReadOnlyDictionary<Guid, Guid?> caSpaces)
        => token.SpaceId == spaceId
            || (token.CertificateAuthorityId is Guid caId && caSpaces.TryGetValue(caId, out var caSpace) && caSpace == spaceId);

    /// <summary>
    /// Resolves the CA + space for a signing profile (or cert/request
    /// profile as a secondary path). Returns null if no CA can be resolved — the caller
    /// should treat null as "system-wide target" and require SystemOperator policy.
    /// A signing profile names its CA by its issuer, the CA <c>RequireCaCapability</c> authorized
    /// against; a protocol configuration that happens to name the profile does not.
    /// </summary>
    private async Task<(Guid CaId, Guid? SpaceId)?> ResolveCaFromProfilesAsync(
        Guid? signingProfileId, Guid? certProfileId, Guid? requestProfileId)
    {
        if (signingProfileId.HasValue)
        {
            var sp = await db.SigningProfiles.AsNoTracking().FirstOrDefaultAsync(s => s.Id == signingProfileId.Value);
            if (sp?.IssuerId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(c => c.CertificateId == sp.IssuerId);
                if (ca != null)
                    return (ca.Id, ca.SpaceId);
            }
        }
        if (certProfileId.HasValue)
        {
            var cp = await db.CertProfiles
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == certProfileId.Value);
            if (cp?.CertificateAuthorityId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.Id == cp.CertificateAuthorityId.Value);
                if (ca != null)
                    return (ca.Id, ca.SpaceId);
            }
        }
        if (requestProfileId.HasValue)
        {
            var rp = await db.RequestProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == requestProfileId.Value);
            if (rp?.CertificateAuthorityId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.Id == rp.CertificateAuthorityId.Value);
                if (ca != null)
                    return (ca.Id, ca.SpaceId);
            }
        }
        return null;
    }

    /// <summary>
    /// Returns the active enrollment tokens the caller's fence admits (<see cref="MayManageToken"/>).
    /// Filters on the token's <c>SpaceId</c> column directly so users who
    /// have moved between spaces don't leak prior-space token visibility.
    /// <para>
    /// The <c>token</c> field is always null: only the hash is stored, so a token is visible
    /// exactly once, in the response to the call that created it.
    /// </para>
    /// <para>
    /// The console's scope narrows what the fence admits, and never widens it: a
    /// <paramref name="caId"/> view keeps the tokens bound to that CA, and a
    /// <paramref name="spaceId"/> view keeps those bound to the space or to a CA inside it
    /// (<see cref="InSpaceView"/>). Without either, every token the fence admits is listed.
    /// </para>
    /// </summary>
    /// <param name="caId">Optional CA view: only the tokens bound to this CA.</param>
    /// <param name="spaceId">Optional space view: the tokens of this space and of its CAs. The pre-0.4.0 <c>tenantId</c> is refused (400).</param>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    [RefuseQueryKey("tenantId", "spaceId")]
    public async Task<IActionResult> GetActiveTokens([FromQuery] Guid? caId = null, [FromQuery] Guid? spaceId = null)
    {
        var tokens = await tokenService.GetActiveTokensAsync();

        var fence = SpaceFence.From(HttpContext, Capabilities.CertRevoke);
        tokens = tokens.Where(t => MayManageToken(fence, t)).ToList();

        if (caId.HasValue)
            tokens = tokens.Where(t => t.CertificateAuthorityId == caId.Value).ToList();
        if (spaceId.HasValue)
        {
            var boundCaIds = tokens.Where(t => t.CertificateAuthorityId != null).Select(t => t.CertificateAuthorityId!.Value).Distinct().ToList();
            var caSpaces = await db.CertificateAuthorities
                .AsNoTracking()
                .IgnoreQueryFilters()
                .Where(c => boundCaIds.Contains(c.Id))
                .Select(c => new { c.Id, c.SpaceId })
                .ToDictionaryAsync(c => c.Id, c => c.SpaceId);
            tokens = tokens.Where(t => InSpaceView(t, spaceId.Value, caSpaces)).ToList();
        }

        // No token value leaves this endpoint, for any row. Bearer tokens used to be echoed
        // back here, which made the list a way to recover a credential long after it was
        // issued; now only their hash is stored, so there is nothing to echo. CMP rows keep
        // the last four characters of their secret, which is how an operator tells two
        // credentials on the same reference value apart, and is the one deliberate exception.
        return Ok(tokens.Select(t => new
        {
            t.Id,
            Token = (string?)null,
            LastFourOfToken = t.UsedForCmp ? t.CmpSecretLastFour : null,
            t.UsedForCmp,
            t.CmpReferenceValue,
            t.CreatedAt,
            t.ExpiresAt,
            t.MaxUses,
            t.UsesRemaining,
            t.SubjectRestriction,
            t.SANRestriction,
            t.Protocol,
            t.IsRevoked,
            t.RequestProfileId,
            t.CertProfileId,
            t.SigningProfileId,
            t.CertificateAuthorityId,
            t.SpaceId
        }));
    }

    /// <summary>
    /// Provision a CMP PBMAC shared-secret credential bound to a
    /// specific <c>senderKID</c> (referenceValue). The plaintext secret is returned
    /// exactly once in the response body — never stored in the clear and never
    /// retrievable via list/GET. Subsequent admin views only show last-4 digits of
    /// the token. Replaces the per-CA <c>CmpSharedSecret</c> single-secret-for-everyone
    /// model.
    /// </summary>
    [HttpPost("cmp-secret")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.SigningProfile, "request.SigningProfileId")]
    [RequireStepUp(StepUpOps.CreateEnrollmentSecret)]
    public async Task<IActionResult> GenerateCmpSharedSecret([FromBody] GenerateCmpSharedSecretRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request.ReferenceValue))
            return BadRequest(new { error = "referenceValue is required" });

        var caInfo = await ResolveCaFromProfilesAsync(request.SigningProfileId, null, null);
        if (caInfo == null)
        {
            if (HttpContext.Items["IsSystemAdmin"] is not true)
                return NotFound(new { error = "CMP target CA not found." });
        }
        else if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            if (!SpaceFence.From(HttpContext, Capabilities.CertRevoke).Allows(caInfo.Value.SpaceId))
                return NotFound(new { error = "CMP target CA not found." });
        }

        var expiresIn = TimeSpan.FromHours(request.ExpiresInHours ?? 24 * 30);
        try
        {
            var (entity, plaintext) = await tokenService.GenerateCmpSharedSecretAsync(
                currentUser.User.Id, request.ReferenceValue, expiresIn, request.MaxUses ?? 0,
                caInfo?.CaId, caInfo?.SpaceId);

            await audit.LogAsync(AuditActionType.EnrollmentTokenGenerated, currentUser.User.Id, currentUser.User.Username,
                "CmpSharedSecret", entity.Id.ToString(),
                new { request.ReferenceValue, ExpiresInHours = expiresIn.TotalHours, TargetCaId = caInfo?.CaId, TargetSpaceId = caInfo?.SpaceId },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfo?.CaId, spaceId: caInfo?.SpaceId);

            return Ok(new
            {
                entity.Id,
                entity.CmpReferenceValue,
                SharedSecret = plaintext,  // returned exactly once
                entity.ExpiresAt,
                entity.MaxUses,
                Warning = "Record this shared secret now — it will not be shown again."
            });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Generates an enrollment token. With <see cref="GenerateEnrollmentTokenRequest.Scope"/> the
    /// token is accepted at the instance's CAs, a space's CAs or one CA, and the caller needs
    /// cert.revoke across that scope; without it the selected profiles decide, as before. A subject
    /// or SAN restriction <see cref="ModularCA.Shared.Utils.EnrollmentNameRestriction.RestrictionError"/>
    /// refuses is a 400.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireStepUp(StepUpOps.CreateEnrollmentSecret)]
    public async Task<IActionResult> GenerateToken([FromBody] GenerateEnrollmentTokenRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var userId = currentUser.User.Id;
        var refused = new ObjectResult(new { error = $"You need {Capabilities.CertRevoke} where this token is accepted." }) { StatusCode = 403 };

        Guid? targetCaId, targetSpaceId;
        if (request.Scope is EnrollmentTokenScope scope)
        {
            var target = await EnrollmentTokenTarget.ResolveAsync(db, scope, request.ScopeId, request.SigningProfileId);
            if (target.NotFound)
                return NotFound(new { error = "Enrollment target not found." });
            if (target.Error != null)
                return BadRequest(new { error = target.Error });
            var allowed = target.CaId is Guid boundCa
                ? await auth.HasCaCapabilityAsync(userId, boundCa, Capabilities.CertRevoke)
                : await auth.HasScopeCapabilityAsync(userId, target.SpaceId, Capabilities.CertRevoke);
            if (!allowed)
                return refused;
            (targetCaId, targetSpaceId) = (target.CaId, target.SpaceId);
        }
        else
        {
            if (!await BodyTargetAuthorization.IsAllowedAsync(auth, new CaTargetResolver(db), userId, Capabilities.CertRevoke, CaTarget.SigningProfile, request.SigningProfileId))
                return refused;
            var caInfo = await ResolveCaFromProfilesAsync(request.SigningProfileId, request.CertProfileId, request.RequestProfileId);
            (targetCaId, targetSpaceId) = (caInfo?.CaId, caInfo?.SpaceId);
        }

        // An instance token needs an instance-wide caller; any other, the caller's SpaceFence.
        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var unbound = targetCaId == null && targetSpaceId == null;
            if (unbound || !SpaceFence.From(HttpContext, Capabilities.CertRevoke).Allows(targetSpaceId))
                return NotFound(new { error = "Enrollment target not found." });
        }

        if ((ModularCA.Shared.Utils.EnrollmentNameRestriction.RestrictionError(request.SubjectRestriction, forSans: false, maxLength: 255)
            ?? ModularCA.Shared.Utils.EnrollmentNameRestriction.RestrictionError(request.SANRestriction, forSans: true, maxLength: 500)) is string restrictionError)
            return BadRequest(new { error = restrictionError });

        var expiresIn = TimeSpan.FromHours(request.ExpiresInHours ?? 24);
        var token = await tokenService.GenerateTokenAsync(
            currentUser.User.Id,
            expiresIn,
            request.MaxUses ?? 1,
            request.SubjectRestriction,
            request.SANRestriction,
            request.Protocol,
            request.RequestProfileId,
            request.CertProfileId,
            request.SigningProfileId,
            targetCaId,
            targetSpaceId);

        await audit.LogAsync(AuditActionType.EnrollmentTokenGenerated, currentUser.User.Id, currentUser.User.Username,
            "EnrollmentToken", null,
            new { request.Protocol, request.MaxUses, ExpiresInHours = expiresIn.TotalHours, request.Scope, TargetCaId = targetCaId, TargetSpaceId = targetSpaceId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: targetCaId, spaceId: targetSpaceId);

        return Ok(new { token, expiresIn = expiresIn.TotalHours });
    }

    /// <summary>
    /// Revokes an enrollment token or CMP shared secret so it is no longer accepted. Requires the
    /// <c>CaOperator</c> policy; a token outside the caller's <see cref="SpaceFence"/>, or a
    /// system-wide token for a caller who is not instance-wide, answers 404 like a missing one.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> RevokeToken(Guid id)
    {
        // Resolve the token's space and enforce access before revoking.
        var existing = await tokenService.GetByIdAsync(id);
        if (existing == null)
            return NotFound(new { error = "Token not found" });

        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            if (!MayManageToken(SpaceFence.From(HttpContext, Capabilities.CertRevoke), existing))
                return NotFound(new { error = "Token not found" });
        }

        if (await tokenService.RevokeTokenAsync(id))
        {
            await currentUser.EnsureLoadedAsync();
            await audit.LogAsync(AuditActionType.EnrollmentTokenRevoked, currentUser.User?.Id, currentUser.User?.Username,
                "EnrollmentToken", id.ToString(),
                new { existing.CertificateAuthorityId, existing.SpaceId },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: existing.CertificateAuthorityId, spaceId: existing.SpaceId);
            return Ok(new { message = "Token revoked" });
        }
        return NotFound(new { error = "Token not found" });
    }
}

/// <summary>
/// Request body for provisioning a CMP PBMAC shared secret.
/// </summary>
public class GenerateCmpSharedSecretRequest
{
    /// <summary>The CMP <c>senderKID</c> / referenceValue the client will present.</summary>
    public string ReferenceValue { get; set; } = string.Empty;
    /// <summary>Lifetime of the secret in hours; null means 30 days.</summary>
    public double? ExpiresInHours { get; set; }
    /// <summary>How many enrolments the secret allows; null or zero means unlimited.</summary>
    public int? MaxUses { get; set; }
    /// <summary>Signing profile used to resolve the target CA for space enforcement.</summary>
    public Guid? SigningProfileId { get; set; }
}

/// <summary>Request body for generating an enrollment token.</summary>
public class GenerateEnrollmentTokenRequest
{
    /// <summary>Lifetime of the token in hours; null means 24.</summary>
    public double? ExpiresInHours { get; set; }
    /// <summary>How many enrolments the token allows; null means one, zero or less means unlimited.</summary>
    public int? MaxUses { get; set; }
    /// <summary>
    /// Patterns the CSR subject must match, at most 255 characters: a DN component such as
    /// <c>O=Acme Corp</c>, or a DNS name that the CN must equal or fall under. Null leaves the subject
    /// unrestricted. See <see cref="ModularCA.Shared.Utils.EnrollmentNameRestriction"/>.
    /// </summary>
    public string? SubjectRestriction { get; set; }
    /// <summary>
    /// DNS-name patterns every SAN in the CSR must equal or fall under, at most 500 characters. Null
    /// leaves the SANs unrestricted. See <see cref="ModularCA.Shared.Utils.EnrollmentNameRestriction"/>.
    /// </summary>
    public string? SANRestriction { get; set; }
    /// <summary>The only enrollment protocol the token is accepted on (e.g. <c>SCEP</c>, or <c>QR</c> for link enrollment); null or empty accepts any.</summary>
    public string? Protocol { get; set; }
    /// <summary>Pre-selected request profile for QR/link enrollment.</summary>
    public Guid? RequestProfileId { get; set; }
    /// <summary>Pre-selected certificate profile for QR/link enrollment.</summary>
    public Guid? CertProfileId { get; set; }
    /// <summary>Pre-selected signing profile for QR/link enrollment.</summary>
    public Guid? SigningProfileId { get; set; }
    /// <summary>Where the token is accepted. Null leaves it to the selected profiles.</summary>
    public EnrollmentTokenScope? Scope { get; set; }
    /// <summary>The space id for <see cref="EnrollmentTokenScope.Space"/>, the CA id for <see cref="EnrollmentTokenScope.Ca"/>.</summary>
    public Guid? ScopeId { get; set; }
}
