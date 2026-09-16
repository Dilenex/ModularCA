using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing enrollment tokens used to authenticate protocol enrollment requests.
/// </summary>
[ApiController]
[Route("api/v1/admin/enrollment-tokens")]
[Authorize]
public class AdminEnrollmentTokenController(
    IEnrollmentTokenService tokenService,
    ICurrentUserService currentUser,
    IAuditService audit,
    ModularCADbContext db) : ControllerBase
{
    /// <summary>
    /// Resolves the CA + tenant for a signing profile (or cert/request
    /// profile as a secondary path). Returns null if no CA can be resolved — the caller
    /// should treat null as "system-wide target" and require SystemOperator policy.
    /// </summary>
    private async Task<(Guid CaId, Guid TenantId)?> ResolveCaFromProfilesAsync(
        Guid? signingProfileId, Guid? certProfileId, Guid? requestProfileId)
    {
        if (signingProfileId.HasValue)
        {
            var config = await db.CaProtocolConfigs
                .Include(p => p.Ca)
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.SigningProfileId == signingProfileId.Value);
            if (config?.Ca != null)
                return (config.Ca.Id, config.Ca.TenantId);

            // Fall back: the signing profile is directly attached to a CA via IssuerId.
            var sp = await db.SigningProfiles.AsNoTracking().FirstOrDefaultAsync(s => s.Id == signingProfileId.Value);
            if (sp?.IssuerId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(c => c.CertificateId == sp.IssuerId);
                if (ca != null)
                    return (ca.Id, ca.TenantId);
            }
        }
        if (certProfileId.HasValue)
        {
            var cp = await db.CertProfiles
                .AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(p => p.Id == certProfileId.Value);
            if (cp?.CertificateAuthorityId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(c => c.Id == cp.CertificateAuthorityId.Value);
                if (ca != null)
                    return (ca.Id, ca.TenantId);
            }
        }
        if (requestProfileId.HasValue)
        {
            var rp = await db.RequestProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == requestProfileId.Value);
            if (rp?.CertificateAuthorityId != null)
            {
                var ca = await db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(c => c.Id == rp.CertificateAuthorityId.Value);
                if (ca != null)
                    return (ca.Id, ca.TenantId);
            }
        }
        return null;
    }

    /// <summary>
    /// Returns all active enrollment tokens, filtered by tenant access for non-system-admins.
    /// Filters on the token's <c>TenantId</c> column directly so users who
    /// have moved between tenants don't leak prior-tenant token visibility.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetActiveTokens()
    {
        var tokens = await tokenService.GetActiveTokensAsync();

        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            tokens = tokens.Where(t =>
                // Tokens without a tenant are system-wide; system-wide tokens should
                // not be visible through the per-tenant list endpoint — system admins
                // have already bypassed this branch above.
                t.TenantId.HasValue && tenantIds != null && tenantIds.Contains(t.TenantId.Value)).ToList();
        }

        // For CMP PBMAC tokens we explicitly OMIT `Token` (the
        // plaintext secret) from the list payload. Only `CmpReferenceValue` and
        // `LastFourOfToken` are returned so operators can identify the credential.
        return Ok(tokens.Select(t => new
        {
            t.Id,
            Token = t.UsedForCmp ? null : t.Token,
            LastFourOfToken = t.UsedForCmp && t.Token.Length >= 4 ? t.Token[^4..] : null,
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
            t.TenantId
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
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null || !tenantIds.Contains(caInfo.Value.TenantId))
                return NotFound(new { error = "CMP target CA not found." });
        }

        var expiresIn = TimeSpan.FromHours(request.ExpiresInHours ?? 24 * 30);
        try
        {
            var (entity, plaintext) = await tokenService.GenerateCmpSharedSecretAsync(
                currentUser.User.Id, request.ReferenceValue, expiresIn, request.MaxUses ?? 0,
                caInfo?.CaId, caInfo?.TenantId);

            await audit.LogAsync(AuditActionType.EnrollmentTokenGenerated, currentUser.User.Id, currentUser.User.Username,
                "CmpSharedSecret", entity.Id.ToString(),
                new { request.ReferenceValue, ExpiresInHours = expiresIn.TotalHours, TargetCaId = caInfo?.CaId, TargetTenantId = caInfo?.TenantId },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfo?.CaId, tenantId: caInfo?.TenantId);

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

    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.SigningProfile, "request.SigningProfileId")]
    public async Task<IActionResult> GenerateToken([FromBody] GenerateEnrollmentTokenRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        // Resolve the target CA/tenant from the selected profiles and
        // enforce AccessibleTenantIds. A SystemOperator can no longer mint tokens against
        // another tenant's CA.
        var caInfo = await ResolveCaFromProfilesAsync(request.SigningProfileId, request.CertProfileId, request.RequestProfileId);
        if (caInfo == null)
        {
            // System-wide token — require SystemOperator / SystemAdmin.
            if (HttpContext.Items["IsSystemAdmin"] is not true)
                return NotFound(new { error = "Enrollment target not found." });
        }
        else if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null || !tenantIds.Contains(caInfo.Value.TenantId))
                return NotFound(new { error = "Enrollment target not found." });
        }

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
            caInfo?.CaId,
            caInfo?.TenantId);

        await audit.LogAsync(AuditActionType.EnrollmentTokenGenerated, currentUser.User.Id, currentUser.User.Username,
            "EnrollmentToken", null,
            new { request.Protocol, request.MaxUses, ExpiresInHours = expiresIn.TotalHours, TargetCaId = caInfo?.CaId, TargetTenantId = caInfo?.TenantId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfo?.CaId, tenantId: caInfo?.TenantId);

        return Ok(new { token, expiresIn = expiresIn.TotalHours });
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> RevokeToken(Guid id)
    {
        // Resolve the token's tenant and enforce access before revoking.
        var existing = await tokenService.GetByIdAsync(id);
        if (existing == null)
            return NotFound(new { error = "Token not found" });

        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (!existing.TenantId.HasValue || tenantIds == null || !tenantIds.Contains(existing.TenantId.Value))
                return NotFound(new { error = "Token not found" });
        }

        if (await tokenService.RevokeTokenAsync(id))
        {
            await currentUser.EnsureLoadedAsync();
            await audit.LogAsync(AuditActionType.EnrollmentTokenRevoked, currentUser.User?.Id, currentUser.User?.Username,
                "EnrollmentToken", id.ToString(),
                new { existing.CertificateAuthorityId, existing.TenantId },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: existing.CertificateAuthorityId, tenantId: existing.TenantId);
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
    public double? ExpiresInHours { get; set; }
    public int? MaxUses { get; set; }
    /// <summary>Signing profile used to resolve the target CA for tenant enforcement.</summary>
    public Guid? SigningProfileId { get; set; }
}

public class GenerateEnrollmentTokenRequest
{
    public double? ExpiresInHours { get; set; }
    public int? MaxUses { get; set; }
    public string? SubjectRestriction { get; set; }
    public string? SANRestriction { get; set; }
    public string? Protocol { get; set; }
    /// <summary>Pre-selected request profile for QR/link enrollment.</summary>
    public Guid? RequestProfileId { get; set; }
    /// <summary>Pre-selected certificate profile for QR/link enrollment.</summary>
    public Guid? CertProfileId { get; set; }
    /// <summary>Pre-selected signing profile for QR/link enrollment.</summary>
    public Guid? SigningProfileId { get; set; }
}
