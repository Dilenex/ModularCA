using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Core.Services.Msae.Kerberos;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// A tenant's Kerberos realm bindings for Windows autoenrollment: which forests may present
/// tickets, whose capabilities their principals act with, and the service keys that seal the
/// tickets. Keys go in and are never read back; the only export is the setup script for the
/// forest.
/// </summary>
/// <remarks>
/// Tenant-scoped: the caller needs <c>ca.manage</c> tenant-wide for the tenant in the route,
/// checked explicitly because the target is a tenant rather than a CA. Every mutation needs
/// step-up under <see cref="StepUpOps.ManageKerberosRealm"/>.
/// </remarks>
[ApiController]
[Route("api/v1/admin/tenants/{tenantId:guid}/kerberos-realms")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminKerberosRealmController(
    KerberosRealmService realms,
    ICaGroupAuthorizationService groupAuth,
    ICurrentUserService currentUser,
    IAuditService audit,
    ModularCADbContext db,
    IPublicNameResolver names) : ControllerBase
{
    /// <summary>Lists the tenant's bindings with key versions and encryption types. Never key bytes.</summary>
    [HttpGet]
    public async Task<IActionResult> List(Guid tenantId)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        var list = await realms.ListAsync(tenantId);
        return Ok(list.Select(Project));
    }

    /// <summary>One binding.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid tenantId, Guid id)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        var realm = await realms.GetAsync(id);
        if (realm == null || realm.TenantId != tenantId) return NotFound();
        return Ok(Project(realm));
    }

    /// <summary>Creates a binding. Keys are added separately.</summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.ManageKerberosRealm)]
    public async Task<IActionResult> Create(Guid tenantId, [FromBody] KerberosRealmRequest request)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        try
        {
            var realm = await realms.CreateAsync(tenantId, request.ToSpec());
            await LogAsync(AuditActionType.KerberosRealmCreated, realm, new { realm.Realm, realm.ServicePrincipal, realm.EnrollmentUserId });
            return Ok(Project(realm));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Updates a binding's non-key fields, including enabling and disabling it.</summary>
    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.ManageKerberosRealm, "id")]
    public async Task<IActionResult> Update(Guid tenantId, Guid id, [FromBody] KerberosRealmRequest request)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id) is not { } existing) return NotFound();
        try
        {
            var realm = await realms.UpdateAsync(id, request.ToSpec());
            await LogAsync(existing.IsEnabled && !realm.IsEnabled ? AuditActionType.KerberosRealmDisabled : AuditActionType.KerberosRealmUpdated,
                realm, new { realm.Realm, realm.ServicePrincipal, realm.EnrollmentUserId, realm.IsEnabled });
            return Ok(Project(realm));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Deletes a binding and its keys.</summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.ManageKerberosRealm, "id")]
    public async Task<IActionResult> Delete(Guid tenantId, Guid id)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id) is not { } existing) return NotFound();
        try
        {
            await realms.DeleteAsync(id);
            await LogAsync(AuditActionType.KerberosRealmDeleted, existing, new { existing.Realm });
            return NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Adds key material: a keytab (base64), a password to derive from, or a request to generate
    /// one. Returns what was accepted, and the generated password once.
    /// </summary>
    [HttpPost("{id:guid}/keys")]
    [RequireStepUp(StepUpOps.ManageKerberosRealm, "id")]
    public async Task<IActionResult> AddKey(Guid tenantId, Guid id, [FromBody] KerberosKeyRequest request)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id) is not { } existing) return NotFound();
        try
        {
            KerberosKeyImportResult result;
            string? password = null;
            switch (request.Source)
            {
                case KerberosKeySource.Keytab:
                    if (string.IsNullOrWhiteSpace(request.Keytab)) return BadRequest(new { error = "keytab is required." });
                    result = await realms.ImportKeytabAsync(id, Convert.FromBase64String(request.Keytab));
                    break;
                case KerberosKeySource.Password:
                    if (string.IsNullOrWhiteSpace(request.AccountName) || string.IsNullOrWhiteSpace(request.Password))
                        return BadRequest(new { error = "accountName and password are required." });
                    result = await realms.ImportPasswordAsync(id, request.AccountName, request.AccountKind, request.Password, request.Kvno ?? 1);
                    break;
                case KerberosKeySource.Generated:
                    if (string.IsNullOrWhiteSpace(request.AccountName)) return BadRequest(new { error = "accountName is required." });
                    (result, password) = await realms.GeneratePasswordAsync(id, request.AccountName, request.AccountKind, request.Kvno ?? 1);
                    break;
                default:
                    return BadRequest(new { error = "Unknown key source." });
            }
            await LogAsync(AuditActionType.KerberosRealmKeyAdded, existing, new { existing.Realm, request.Source, result.Kvno, result.EncryptionTypes, result.Retired });
            return Ok(new { result.Kvno, result.EncryptionTypes, result.Dropped, result.Retired, password });
        }
        catch (FormatException)
        {
            return BadRequest(new { error = "keytab must be base64." });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Refuses a key version from now on.</summary>
    [HttpPost("{id:guid}/keys/{kvno:int}/retire")]
    [RequireStepUp(StepUpOps.ManageKerberosRealm, "id")]
    public async Task<IActionResult> RetireKey(Guid tenantId, Guid id, int kvno)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id) is not { } existing) return NotFound();
        try
        {
            await realms.RetireKeyAsync(id, kvno);
            await LogAsync(AuditActionType.KerberosRealmKeyRetired, existing, new { existing.Realm, kvno });
            return NoContent();
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// The PowerShell and Group Policy text for the forest. Contains no secret. The policy URL
    /// names the host in the binding's service principal when that is a name this service is
    /// known by for the tenant, else the public domain, as the setup kit does.
    /// </summary>
    [HttpGet("{id:guid}/setup-script")]
    public async Task<IActionResult> SetupScript(Guid tenantId, Guid id, [FromQuery] string? caLabel = null, [FromQuery] string? accountName = null)
    {
        if (await DenyAsync(tenantId) is { } denied) return denied;
        if (await OwnedAsync(tenantId, id) is not { } realm) return NotFound();
        var tenantName = await db.Tenants.Where(t => t.Id == tenantId).Select(t => t.Name).FirstOrDefaultAsync() ?? tenantId.ToString();
        var host = await names.BaseUrlForServicePrincipalAsync(realm.ServicePrincipal, tenantId);
        var policyUrl = caLabel != null ? $"{host}/msae/{caLabel}/cep" : null;
        return Ok(new { script = KerberosRealmService.SetupScript(realm, tenantName, policyUrl, accountName, null) });
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

    private async Task<KerberosRealmEntity?> OwnedAsync(Guid tenantId, Guid id)
    {
        var realm = await realms.GetAsync(id);
        return realm != null && realm.TenantId == tenantId ? realm : null;
    }

    private Task LogAsync(string action, KerberosRealmEntity realm, object details)
        => audit.LogAsync(action, currentUser.User?.Id, currentUser.User?.Username, "KerberosRealm", realm.Id.ToString(), details,
            HttpContext.Connection.RemoteIpAddress?.ToString(), tenantId: realm.TenantId);

    private static object Project(KerberosRealmEntity r) => new
    {
        r.Id,
        r.TenantId,
        r.Realm,
        r.DnsDomain,
        r.ServicePrincipal,
        r.EnrollmentUserId,
        EnrollmentUsername = r.EnrollmentUser?.Username,
        r.AllowMachines,
        r.AllowUsers,
        r.IsEnabled,
        r.Notes,
        r.CreatedAt,
        r.LastUsedAt,
        Keys = r.Keys.OrderByDescending(k => k.Kvno).ThenBy(k => k.EncryptionType)
            .Select(k => new { k.Kvno, k.EncryptionType, k.Source, k.CreatedAt, k.RetireAfter }),
    };
}

/// <summary>Body for creating or updating a realm binding.</summary>
public class KerberosRealmRequest
{
    public string Realm { get; set; } = string.Empty;
    public string? DnsDomain { get; set; }
    public string ServicePrincipal { get; set; } = string.Empty;
    public Guid EnrollmentUserId { get; set; }
    public bool AllowMachines { get; set; } = true;
    public bool AllowUsers { get; set; } = true;
    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }

    internal KerberosRealmSpec ToSpec() => new(Realm, DnsDomain, ServicePrincipal, EnrollmentUserId, AllowMachines, AllowUsers, IsEnabled, Notes);
}

/// <summary>Body for adding key material. Exactly one path is used, chosen by <see cref="Source"/>.</summary>
public class KerberosKeyRequest
{
    public KerberosKeySource Source { get; set; }
    /// <summary>Base64 keytab file, for <see cref="KerberosKeySource.Keytab"/>.</summary>
    public string? Keytab { get; set; }
    /// <summary>The account holding the SPN, for password and generated keys.</summary>
    public string? AccountName { get; set; }
    public KerberosAccountKind AccountKind { get; set; } = KerberosAccountKind.User;
    /// <summary>The account's password, for <see cref="KerberosKeySource.Password"/>. Used once.</summary>
    public string? Password { get; set; }
    /// <summary>Key version; defaults to 1 for a new account.</summary>
    public int? Kvno { get; set; }
}
