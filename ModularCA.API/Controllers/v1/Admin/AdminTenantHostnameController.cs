using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// The names a tenant's enrollment and revocation endpoints are reached by, each served under a
/// certificate from one of the tenant's own CAs. The console and sign-in stay on the public
/// domain; these names are for clients.
/// </summary>
/// <remarks>
/// Tenant-scoped like the Kerberos realm bindings: the caller needs <c>ca.manage</c> tenant-wide
/// for the tenant in the route, checked explicitly because the target is a tenant rather than a
/// CA. Every mutation needs step-up under <see cref="StepUpOps.ManageTenantHostname"/>.
/// </remarks>
[ApiController]
[Route("api/v1/admin/tenants/{tenantId:guid}/hostnames")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminTenantHostnameController(
    TenantHostnameService hostnames,
    ICaGroupAuthorizationService groupAuth,
    ICurrentUserService currentUser,
    IAuditService audit,
    SystemConfig config) : ControllerBase
{
    /// <summary>The tenant's hostnames with their issuing CA and certificate state, plus the console's public domain for the UI's wording.</summary>
    [HttpGet]
    public async Task<IActionResult> List(Guid tenantId, CancellationToken cancellation)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        var list = await hostnames.ListAsync(tenantId, cancellation);
        return Ok(new { publicDomain = config.Https.PublicDomain, hostnames = list.Select(Project) });
    }

    /// <summary>Adds a hostname and issues its certificate from the chosen tenant CA.</summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.ManageTenantHostname)]
    public async Task<IActionResult> Create(Guid tenantId, [FromBody] TenantHostnameRequest request, CancellationToken cancellation)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        try
        {
            var created = await hostnames.CreateAsync(tenantId, request.Hostname, request.IssuingCaId, request.Notes, request.NodeUpstream, cancellation);
            await LogAsync(AuditActionType.TenantHostnameCreated, created,
                new { created.Hostname, created.IssuingCaId, IssuingCa = created.IssuingCa?.Label, CertificateSerial = created.Certificate?.SerialNumber, created.Certificate?.NotAfter, created.NodeUpstream });
            return Ok(Project(created));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Issues a new certificate for the hostname now, superseding the current one.</summary>
    [HttpPost("{id:guid}/reissue")]
    [RequireStepUp(StepUpOps.ManageTenantHostname, "id")]
    public async Task<IActionResult> Reissue(Guid tenantId, Guid id, CancellationToken cancellation)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id, cancellation) is not { } existing) return NotFound();
        try
        {
            var previous = existing.Certificate?.SerialNumber;
            var issued = await hostnames.ReissueAsync(id, cancellation);
            await LogAsync(AuditActionType.TenantHostnameCertificateIssued, existing,
                new { existing.Hostname, OldSerial = previous, NewSerial = issued.SerialNumber, issued.NotAfter });
            return Ok(Project((await hostnames.GetAsync(id, cancellation))!));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Sets or clears the node the ingress forwards this name to. Null or blank means the name
    /// is served by the ingress process itself. No console change is needed to use it.
    /// </summary>
    [HttpPut("{id:guid}/upstream")]
    [RequireStepUp(StepUpOps.ManageTenantHostname, "id")]
    public async Task<IActionResult> SetUpstream(Guid tenantId, Guid id, [FromBody] TenantHostnameUpstreamRequest request, CancellationToken cancellation)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id, cancellation) is not { } existing) return NotFound();
        try
        {
            var previous = await hostnames.SetNodeUpstreamAsync(id, request.NodeUpstream, cancellation);
            var updated = (await hostnames.GetAsync(id, cancellation))!;
            await LogAsync(AuditActionType.TenantHostnameUpstreamChanged, existing,
                new { existing.Hostname, OldUpstream = previous, NewUpstream = updated.NodeUpstream });
            return Ok(Project(updated));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Removes the hostname, revokes its certificate and stops serving the name.</summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.ManageTenantHostname, "id")]
    public async Task<IActionResult> Delete(Guid tenantId, Guid id, CancellationToken cancellation)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id, cancellation) is not { } existing) return NotFound();
        await hostnames.DeleteAsync(id, cancellation);
        await LogAsync(AuditActionType.TenantHostnameDeleted, existing, new { existing.Hostname, CertificateSerial = existing.Certificate?.SerialNumber });
        return NoContent();
    }

    // ── Helpers ──

    private async Task<IActionResult?> DenyAsync(Guid tenantId)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        if (!await groupAuth.HasTenantCapabilityAsync(currentUser.User.Id, tenantId, Capabilities.CaManage))
            return StatusCode(403, new { error = "You need ca.manage for this tenant." });
        return null;
    }

    private async Task<TenantHostnameEntity?> OwnedAsync(Guid tenantId, Guid id, CancellationToken cancellation)
    {
        var row = await hostnames.GetAsync(id, cancellation);
        return row != null && row.TenantId == tenantId ? row : null;
    }

    private Task LogAsync(string action, TenantHostnameEntity row, object details)
        => audit.LogAsync(action, currentUser.User?.Id, currentUser.User?.Username, "TenantHostname", row.Id.ToString(), details,
            HttpContext.Connection.RemoteIpAddress?.ToString(), tenantId: row.TenantId);

    /// <summary>The row as the console sees it. The certificate state is derived here so every table agrees on it.</summary>
    private static object Project(TenantHostnameEntity h)
    {
        var now = DateTime.UtcNow;
        var cert = h.Certificate;
        var state = cert == null ? "missing"
            : cert.Revoked ? "revoked"
            : cert.NotAfter.ToUniversalTime() <= now ? "expired"
            : cert.NotAfter.ToUniversalTime() - now <= TimeSpan.FromDays(30) ? "expiring"
            : "active";
        return new
        {
            h.Id,
            h.TenantId,
            h.Hostname,
            h.IssuingCaId,
            IssuingCaLabel = h.IssuingCa?.Label,
            IssuingCaName = h.IssuingCa?.Name,
            h.CertificateId,
            CertificateSerial = cert?.SerialNumber,
            NotBefore = cert?.NotBefore,
            NotAfter = cert?.NotAfter,
            CertificateState = state,
            h.CreatedAt,
            h.Notes,
            h.NodeUpstream,
        };
    }
}

/// <summary>Body for adding a hostname.</summary>
public class TenantHostnameRequest
{
    public string Hostname { get; set; } = string.Empty;
    public Guid IssuingCaId { get; set; }
    public string? Notes { get; set; }

    /// <summary>Optional: the node the ingress forwards this name to, <c>https://host:port</c>; omitted means served locally.</summary>
    public string? NodeUpstream { get; set; }
}

/// <summary>Body for setting or clearing the node a hostname is routed to.</summary>
public class TenantHostnameUpstreamRequest
{
    /// <summary>The node's address, or null to serve the name locally.</summary>
    public string? NodeUpstream { get; set; }
}
