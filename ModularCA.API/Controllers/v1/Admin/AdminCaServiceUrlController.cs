using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing the per-CA public base URL. CDP, OCSP, and AIA endpoints are
/// always auto-generated from the base URL at cert-build time; no per-field overrides are stored.
/// CreateOrUpdate/Delete/GetByCa resolve the owning CA through the
/// cert → CertificateAuthority map, enforce <c>AccessibleTenantIds</c>, and audit-log the
/// before/after <c>PublicBaseUrl</c> on every change.
/// </summary>
[ApiController]
[Route("api/v1/admin/ca-service-urls")]
[Authorize(Policy = "CaOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminCaServiceUrlController(
    ICaServiceUrlService caServiceUrlService,
    ICertificateStore certStore,
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Resolves the CA owning a given CA-certificate id and verifies that
    /// the caller's <c>AccessibleTenantIds</c> contains the CA's tenant. Returns the CA
    /// entity (for audit-log enrichment) when access is granted, or null on deny.
    /// System admins bypass the tenant check.
    /// </summary>
    private async Task<Shared.Entities.CertificateAuthorityEntity?> ResolveOwningCaAsync(Guid caCertificateId)
    {
        var ca = await db.CertificateAuthorities
            .AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId && !c.IsDeleted);
        if (ca == null)
            return null;

        if (HttpContext.Items["IsSystemAdmin"] is true)
            return ca;

        var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
        if (tenantIds != null && tenantIds.Contains(ca.TenantId))
            return ca;

        return null;
    }

    /// <summary>
    /// Returns all CA service URL configurations, filtered by the caller's accessible tenants.
    /// System administrators see all service URLs.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var all = await caServiceUrlService.GetAllAsync();

        var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
        if (tenantIds != null && HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var accessibleCaCertIds = await db.CertificateAuthorities
                .Where(ca => tenantIds.Contains(ca.TenantId) && ca.CertificateId != null)
                .Select(ca => ca.CertificateId!.Value)
                .ToListAsync();
            var accessibleCaCertIdSet = new HashSet<Guid>(accessibleCaCertIds);
            all = all.Where(s => accessibleCaCertIdSet.Contains(s.CaCertificateId)).ToList();
        }

        return Ok(all.Select(s => new
        {
            s.Id,
            s.CaCertificateId,
            CaSubjectDN = s.CaCertificate?.SubjectDN,
            CaSerial = s.CaCertificate?.SerialNumber,
            s.PublicBaseUrl,
            s.CreatedAt,
            s.UpdatedAt
        }));
    }

    [HttpGet("{caCertificateId:guid}")]
    public async Task<IActionResult> GetByCa(Guid caCertificateId)
    {
        // Tenant fence — 404 on mismatch to avoid existence oracles.
        var owningCa = await ResolveOwningCaAsync(caCertificateId);
        if (owningCa == null)
            return NotFound();

        var entity = await caServiceUrlService.GetByCaCertificateIdAsync(caCertificateId);
        if (entity == null)
            return NotFound();
        return Ok(entity);
    }

    /// <summary>
    /// Creates or updates the per-CA public base URL used to derive CDP, OCSP, and AIA
    /// endpoints embedded in every issued certificate. Step-up MFA is required because
    /// redirecting these URLs is a classic certificate-poisoning vector.
    /// </summary>
    [HttpPut("{caCertificateId:guid}")]
    [RequireStepUp(StepUpOps.UpdateCaServiceUrl, "caCertificateId")]
    public async Task<IActionResult> CreateOrUpdate(Guid caCertificateId, [FromBody] CaServiceUrlRequest request)
    {
        var cert = await certStore.GetCertificateByIdAsync(caCertificateId);
        if (cert == null || !cert.IsCA)
            return NotFound("CA certificate not found.");

        // Resolve the owning CA and enforce tenant access before
        // the write lands. A compromised or over-delegated SystemOperator can no
        // longer redirect another tenant's AIA/CDP/OCSP URLs.
        var owningCa = await ResolveOwningCaAsync(caCertificateId);
        if (owningCa == null)
            return NotFound();

        // Capture before/after state for the audit emission.
        var existing = await caServiceUrlService.GetByCaCertificateIdAsync(caCertificateId);
        var previousBaseUrl = existing?.PublicBaseUrl;

        var entity = await caServiceUrlService.CreateOrUpdateAsync(
            caCertificateId,
            request.PublicBaseUrl);

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CaUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CaServiceUrl", caCertificateId.ToString(),
            new { Before = previousBaseUrl, After = request.PublicBaseUrl, Field = "PublicBaseUrl" },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: owningCa.Id, tenantId: owningCa.TenantId);

        return Ok(entity);
    }

    /// <summary>
    /// Clears the per-CA public base URL configuration. Step-up MFA is required because
    /// removing the configured URL forces fall-back behavior that could be redirected
    /// elsewhere — a certificate-poisoning vector for CDP/AIA/OCSP lookups.
    /// </summary>
    [HttpDelete("{caCertificateId:guid}")]
    [RequireStepUp(StepUpOps.DeleteCaServiceUrl, "caCertificateId")]
    public async Task<IActionResult> Delete(Guid caCertificateId)
    {
        // Tenant fence.
        var owningCa = await ResolveOwningCaAsync(caCertificateId);
        if (owningCa == null)
            return NotFound();

        // Capture the previous URL for audit purposes.
        var existing = await caServiceUrlService.GetByCaCertificateIdAsync(caCertificateId);
        var previousBaseUrl = existing?.PublicBaseUrl;

        var deleted = await caServiceUrlService.DeleteAsync(caCertificateId);
        if (!deleted)
            return NotFound();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CaUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CaServiceUrl", caCertificateId.ToString(),
            new { Before = previousBaseUrl, After = (string?)null, Field = "PublicBaseUrl", Action = "Deleted" },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: owningCa.Id, tenantId: owningCa.TenantId);

        return NoContent();
    }
}

public class CaServiceUrlRequest
{
    /// <summary>
    /// Per-CA public base URL (e.g. <c>http://path2.ca.example.com</c>). The certificate builder
    /// appends the standard short-URL paths at issuance time to produce the CDP, OCSP, and AIA
    /// endpoints embedded in every certificate. Null or empty clears the configuration.
    /// </summary>
    public string? PublicBaseUrl { get; set; }
}
