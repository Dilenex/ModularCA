using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing SSH signing profiles, SSH certificate profiles, and SSH
/// request profiles. Cross-space fence: every handler that resolves a
/// profile by GUID first verifies the profile's owning CA is inside the caller's
/// <see cref="SpaceFence"/>; otherwise the call collapses to 404 (no leak that
/// the row exists) and a failure audit row is emitted so SIEM can alert on probing.
/// </summary>
[ApiController]
[Route("api/v1/admin/ssh/profiles")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminSshProfileController(ModularCADbContext db, IAuditService audit, ICurrentUserService currentUser,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IAuditService _audit = audit;
    private readonly ICurrentUserService _currentUser = currentUser;

    /// <summary>
    /// Null when the caller may move a row of scope <paramref name="from"/> (null for a
    /// system-wide row) to the CA of <paramref name="to"/>: 403 without cert.revoke on that CA,
    /// 400 when it belongs to another scope (null equals null).
    /// </summary>
    private async Task<IActionResult?> RefuseRebindAsync((Guid CaId, Guid? SpaceId)? from, (Guid CaId, Guid? SpaceId) to)
    {
        if (_currentUser.User == null || !await authService.HasCaCapabilityAsync(_currentUser.User.Id, to.CaId, Capabilities.CertRevoke))
            return StatusCode(403, new { error = "You lack cert.revoke on the target CA." });
        return from?.SpaceId == to.SpaceId
            ? null
            : BadRequest(new { error = "The target CA belongs to another scope than the profile." });
    }

    // ── Space-fence helpers ───────────────────────────────────────────

    /// <summary>
    /// Resolves the owning CA + space for an <paramref name="sshCaKeyId"/> and verifies
    /// the caller's <see cref="SpaceFence"/> admits that space. Returns the
    /// (CaId, SpaceId) tuple on success, or null when the SSH CA key is missing, the
    /// linked CA is missing/deleted, or the request is outside the fence. The 404-collapse
    /// policy is enforced at the call site to avoid disclosing
    /// existence of cross-space resources.
    /// </summary>
    private async Task<(Guid CaId, Guid? SpaceId)?> ResolveAndFenceBySshCaKeyAsync(Guid sshCaKeyId)
    {
        var key = await _db.SshCaKeys.AsNoTracking()
            .FirstOrDefaultAsync(k => k.Id == sshCaKeyId);
        if (key == null)
            return null;

        return await ResolveAndFenceByCaIdAsync(key.CertificateAuthorityId);
    }

    /// <summary>
    /// Resolves the owning CA + space for a <paramref name="caId"/> and verifies the
    /// caller's <see cref="SpaceFence"/> admits that space. Used by SSH request
    /// profile handlers, which carry a direct (optional) CA reference rather than going
    /// through an SSH CA key.
    /// </summary>
    private async Task<(Guid CaId, Guid? SpaceId)?> ResolveAndFenceByCaIdAsync(Guid caId)
    {
        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == caId);
        if (ca == null || !Fence.Allows(ca.SpaceId))
            return null;
        return (ca.Id, ca.SpaceId);
    }

    /// <summary>True when the caller is a system admin (cross-space access permitted).</summary>
    private bool IsSystemAdmin => HttpContext.Items["IsSystemAdmin"] is true;

    /// <summary>
    /// The cert.revoke fence the current request may act within, the capability every endpoint
    /// here demands; an empty one (nothing) when none was resolved.
    /// </summary>
    private SpaceFence Fence => SpaceFence.From(HttpContext, Capabilities.CertRevoke);

    // ── SSH Signing Profiles ───────────────────────────────────────────

    /// <summary>
    /// Lists the SSH signing profiles whose bound SSH CA key resolves to a CA inside the
    /// caller's <see cref="SpaceFence"/>; an instance-wide caller sees all, unbound ones
    /// included, which are otherwise excluded so another space cannot later claim them.
    /// </summary>
    [HttpGet("signing")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetSigningProfiles()
    {
        await _currentUser.EnsureLoadedAsync();

        if (Fence.InstanceWide)
        {
            var all = await _db.SshSigningProfiles.AsNoTracking()
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description, p.SshCaKeyId,
                    p.MaxValidityHours, p.AllowUserCerts, p.AllowHostCerts,
                    p.ForceCommand, p.SourceAddressRestrictions, p.DefaultExtensions,
                    p.CreatedAt
                })
                .ToListAsync();
            return Ok(all);
        }

        if (Fence.IsEmpty)
            return Ok(Array.Empty<object>());
        var visibleCas = _db.CertificateAuthorities.AsNoTracking()
            .Where(Fence.Predicate<CertificateAuthorityEntity>(ca => ca.SpaceId));

        // SSH CAs are instance CAs, so instance scope is what admits them.
        var profiles = await (
            from p in _db.SshSigningProfiles.AsNoTracking()
            join k in _db.SshCaKeys.AsNoTracking() on p.SshCaKeyId equals k.Id
            join ca in visibleCas on k.CertificateAuthorityId equals ca.Id
            orderby p.Name
            select new
            {
                p.Id, p.Name, p.Description, p.SshCaKeyId,
                p.MaxValidityHours, p.AllowUserCerts, p.AllowHostCerts,
                p.ForceCommand, p.SourceAddressRestrictions, p.DefaultExtensions,
                p.CreatedAt
            }).ToListAsync();
        return Ok(profiles);
    }

    /// <summary>
    /// Retrieves a single SSH signing profile by its identifier. Enforces the
    /// space fence via the profile's bound SSH CA key; cross-space or missing-key
    /// requests collapse to 404 and emit a failure audit row.
    /// </summary>
    [HttpGet("signing/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetSigningProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var profile = await _db.SshSigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id);
        if (profile == null) return NotFound();

        if (profile.SshCaKeyId is not Guid keyId || await ResolveAndFenceBySshCaKeyAsync(keyId) == null)
        {
            await EmitFenceDeniedAsync("SshSigningProfile", id, "GetSigningProfile");
            return NotFound();
        }

        return Ok(new
        {
            profile.Id, profile.Name, profile.Description, profile.SshCaKeyId,
            profile.MaxValidityHours, profile.AllowUserCerts, profile.AllowHostCerts,
            profile.ForceCommand, profile.SourceAddressRestrictions, profile.DefaultExtensions,
            profile.CreatedAt
        });
    }

    /// <summary>
    /// Creates a new SSH signing profile. The target SSH CA key is fenced before
    /// any row is written so a space-A operator cannot bind a new profile to a space-B
    /// CA. Failure paths emit a failure audit row. Step-up MFA is required because creating
    /// a signing profile binds it to an SSH CA key whose material can mint host/user certs.
    /// </summary>
    [HttpPost("signing")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.SshCaKey, "request.SshCaKeyId")]
    [RequireStepUp(StepUpOps.CreateSshProfile)]
    public async Task<IActionResult> CreateSigningProfile([FromBody] CreateSshSigningProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        var fence = await ResolveAndFenceBySshCaKeyAsync(request.SshCaKeyId);
        if (fence == null)
        {
            await EmitFenceDeniedAsync("SshSigningProfile", null, "CreateSigningProfile",
                new { request.Name, request.SshCaKeyId });
            return NotFound();
        }

        var entity = new SshSigningProfileEntity
        {
            Name = request.Name,
            Description = request.Description,
            SshCaKeyId = request.SshCaKeyId,
            MaxValidityHours = request.MaxValidityHours ?? 720,
            AllowUserCerts = request.AllowUserCerts ?? true,
            AllowHostCerts = request.AllowHostCerts ?? false,
            ForceCommand = request.ForceCommand,
            SourceAddressRestrictions = request.SourceAddressRestrictions ?? "[]",
            DefaultExtensions = request.DefaultExtensions ?? "[\"permit-pty\"]",
        };

        _db.SshSigningProfiles.Add(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshSigningProfileCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshSigningProfile", entity.Id.ToString(),
            new { entity.Name, entity.SshCaKeyId, entity.MaxValidityHours, entity.AllowUserCerts, entity.AllowHostCerts },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence.Value.CaId,
            spaceId: fence.Value.SpaceId);

        return Ok(new { entity.Id, entity.Name, entity.CreatedAt });
    }

    /// <summary>
    /// Updates an existing SSH signing profile. Fences both the existing
    /// profile's bound SSH CA key AND any new <c>SshCaKeyId</c> in the request, so a
    /// caller cannot move a profile out of their accessible spaces nor mutate a profile
    /// they cannot read; a new key's CA also needs cert.revoke and the profile's own scope
    /// (<see cref="RefuseRebindAsync"/>). Failure paths emit a failure audit row. Step-up MFA is required
    /// because mutations alter validity, extensions, or CA-key binding for SSH issuance.
    /// </summary>
    [HttpPut("signing/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.UpdateSshProfile, "id")]
    public async Task<IActionResult> UpdateSigningProfile(Guid id, [FromBody] UpdateSshSigningProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshSigningProfiles.FindAsync(id);
        if (entity == null) return NotFound();

        // Fence on the profile's existing CA key binding.
        (Guid CaId, Guid? SpaceId)? fence = entity.SshCaKeyId is Guid existingKeyId
            ? await ResolveAndFenceBySshCaKeyAsync(existingKeyId)
            : null;
        if (fence == null)
        {
            await EmitFenceDeniedAsync("SshSigningProfile", id, "UpdateSigningProfile");
            return NotFound();
        }

        // If the caller is rebinding to a new CA key, fence the new target too.
        if (request.SshCaKeyId.HasValue && request.SshCaKeyId.Value != entity.SshCaKeyId)
        {
            var newFence = await ResolveAndFenceBySshCaKeyAsync(request.SshCaKeyId.Value);
            if (newFence == null)
            {
                await EmitFenceDeniedAsync("SshSigningProfile", id, "UpdateSigningProfile.Rebind",
                    new { TargetSshCaKeyId = request.SshCaKeyId.Value });
                return NotFound();
            }
            if (await RefuseRebindAsync(fence, newFence.Value) is { } refused)
                return refused;
            fence = newFence;
        }

        if (request.Name != null) entity.Name = request.Name;
        if (request.Description != null) entity.Description = request.Description;
        if (request.SshCaKeyId.HasValue) entity.SshCaKeyId = request.SshCaKeyId.Value;
        if (request.MaxValidityHours.HasValue) entity.MaxValidityHours = request.MaxValidityHours.Value;
        if (request.AllowUserCerts.HasValue) entity.AllowUserCerts = request.AllowUserCerts.Value;
        if (request.AllowHostCerts.HasValue) entity.AllowHostCerts = request.AllowHostCerts.Value;
        if (request.ForceCommand != null) entity.ForceCommand = request.ForceCommand;
        if (request.SourceAddressRestrictions != null) entity.SourceAddressRestrictions = request.SourceAddressRestrictions;
        if (request.DefaultExtensions != null) entity.DefaultExtensions = request.DefaultExtensions;

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshSigningProfileUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshSigningProfile", id.ToString(),
            new { entity.Name, entity.SshCaKeyId, entity.MaxValidityHours },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence.Value.CaId,
            spaceId: fence.Value.SpaceId);

        return Ok(new { entity.Id, entity.Name });
    }

    /// <summary>
    /// Deletes an SSH signing profile by its identifier. Fences the profile's
    /// bound SSH CA key so a space-A operator cannot delete space-B's profile.
    /// Failure paths emit a failure audit row. Step-up MFA is required because deletion
    /// permanently removes issuance constraints tied to a live SSH CA key.
    /// </summary>
    [HttpDelete("signing/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.DeleteSshProfile, "id")]
    public async Task<IActionResult> DeleteSigningProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshSigningProfiles.FindAsync(id);
        if (entity == null) return NotFound();

        (Guid CaId, Guid? SpaceId)? fence = entity.SshCaKeyId is Guid keyId
            ? await ResolveAndFenceBySshCaKeyAsync(keyId)
            : null;
        if (fence == null)
        {
            await EmitFenceDeniedAsync("SshSigningProfile", id, "DeleteSigningProfile");
            return NotFound();
        }

        var deletedName = entity.Name;
        _db.SshSigningProfiles.Remove(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshSigningProfileDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshSigningProfile", id.ToString(),
            new { Name = deletedName },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence.Value.CaId,
            spaceId: fence.Value.SpaceId);

        return Ok(new { message = "SSH signing profile deleted" });
    }

    // ── SSH Cert Profiles ──────────────────────────────────────────────

    /// <summary>
    /// Lists all SSH certificate profiles. <see cref="SshCertProfileEntity"/>
    /// has no direct CA/space linkage in the current schema (it is a global catalog of
    /// principal/extension constraints), so list output is identical for all callers; the
    /// create/update/delete handlers are restricted to system admins so a
    /// space operator cannot mutate this shared catalog out from under another space.
    /// </summary>
    [HttpGet("cert")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetCertProfiles()
    {
        await _currentUser.EnsureLoadedAsync();
        var profiles = await _db.SshCertProfiles.AsNoTracking()
            .OrderBy(p => p.Name)
            .Select(p => new
            {
                p.Id, p.Name, p.Description,
                p.AllowedPrincipalPatterns, p.MaxPrincipals,
                p.AllowedExtensions, p.RequiredExtensions,
                p.MaxValidityHours, p.CreatedAt
            })
            .ToListAsync();
        return Ok(profiles);
    }

    /// <summary>
    /// Retrieves a single SSH certificate profile by its identifier. Cert
    /// profiles are a system-wide catalog (no per-space binding in the schema), so reads
    /// are permitted to any authenticated <c>CaOperator</c>; mutations are gated to
    /// system admins on the corresponding write endpoints.
    /// </summary>
    [HttpGet("cert/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetCertProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var profile = await _db.SshCertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id);
        if (profile == null) return NotFound();
        return Ok(new
        {
            profile.Id, profile.Name, profile.Description,
            profile.AllowedPrincipalPatterns, profile.MaxPrincipals,
            profile.AllowedExtensions, profile.RequiredExtensions,
            profile.MaxValidityHours, profile.CreatedAt
        });
    }

    /// <summary>
    /// Creates a new SSH certificate profile. Because
    /// <see cref="SshCertProfileEntity"/> has no per-space FK, creation is restricted to
    /// system admins so a space operator cannot inject globally-visible profiles.
    /// Non-admin callers receive 404 and a failure audit row is emitted. Step-up MFA is
    /// required because cert profiles constrain SSH issuance globally across spaces.
    /// </summary>
    [HttpPost("cert")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
    [RequireStepUp(StepUpOps.CreateSshProfile)]
    public async Task<IActionResult> CreateCertProfile([FromBody] CreateSshCertProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (!IsSystemAdmin)
        {
            await EmitFenceDeniedAsync("SshCertProfile", null, "CreateCertProfile",
                new { request.Name });
            return NotFound();
        }

        var entity = new SshCertProfileEntity
        {
            Name = request.Name,
            Description = request.Description,
            AllowedPrincipalPatterns = request.AllowedPrincipalPatterns ?? "[]",
            MaxPrincipals = request.MaxPrincipals ?? 10,
            AllowedExtensions = request.AllowedExtensions ?? "[\"permit-pty\",\"permit-port-forwarding\",\"permit-agent-forwarding\",\"permit-X11-forwarding\",\"permit-user-rc\"]",
            RequiredExtensions = request.RequiredExtensions ?? "[]",
            MaxValidityHours = request.MaxValidityHours ?? 720,
        };

        _db.SshCertProfiles.Add(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCertProfileCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertProfile", entity.Id.ToString(),
            new { entity.Name, entity.MaxPrincipals, entity.MaxValidityHours },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { entity.Id, entity.Name, entity.CreatedAt });
    }

    /// <summary>
    /// Updates an existing SSH certificate profile. SSH cert profiles are
    /// system-wide (no space FK), so mutation is restricted to system admins. Non-admin
    /// callers receive 404 and a failure audit row is emitted. Step-up MFA is required
    /// because changes affect issuance constraints applied to every space.
    /// </summary>
    [HttpPut("cert/{id:guid}")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
    [RequireStepUp(StepUpOps.UpdateSshProfile, "id")]
    public async Task<IActionResult> UpdateCertProfile(Guid id, [FromBody] UpdateSshCertProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (!IsSystemAdmin)
        {
            await EmitFenceDeniedAsync("SshCertProfile", id, "UpdateCertProfile");
            return NotFound();
        }

        var entity = await _db.SshCertProfiles.FindAsync(id);
        if (entity == null) return NotFound();

        if (request.Name != null) entity.Name = request.Name;
        if (request.Description != null) entity.Description = request.Description;
        if (request.AllowedPrincipalPatterns != null) entity.AllowedPrincipalPatterns = request.AllowedPrincipalPatterns;
        if (request.MaxPrincipals.HasValue) entity.MaxPrincipals = request.MaxPrincipals.Value;
        if (request.AllowedExtensions != null) entity.AllowedExtensions = request.AllowedExtensions;
        if (request.RequiredExtensions != null) entity.RequiredExtensions = request.RequiredExtensions;
        if (request.MaxValidityHours.HasValue) entity.MaxValidityHours = request.MaxValidityHours.Value;

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCertProfileUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertProfile", id.ToString(),
            new { entity.Name, entity.MaxPrincipals, entity.MaxValidityHours },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { entity.Id, entity.Name });
    }

    /// <summary>
    /// Deletes an SSH certificate profile by its identifier. SSH cert profiles
    /// are system-wide (no space FK), so deletion is restricted to system admins.
    /// Non-admin callers receive 404 and a failure audit row is emitted. Step-up MFA is
    /// required because deletion strips SSH issuance constraints spaces may depend on.
    /// </summary>
    [HttpDelete("cert/{id:guid}")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
    [RequireStepUp(StepUpOps.DeleteSshProfile, "id")]
    public async Task<IActionResult> DeleteCertProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();

        if (!IsSystemAdmin)
        {
            await EmitFenceDeniedAsync("SshCertProfile", id, "DeleteCertProfile");
            return NotFound();
        }

        var entity = await _db.SshCertProfiles.FindAsync(id);
        if (entity == null) return NotFound();
        var deletedName = entity.Name;
        _db.SshCertProfiles.Remove(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCertProfileDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertProfile", id.ToString(),
            new { Name = deletedName },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "SSH cert profile deleted" });
    }

    // ── SSH Request Profiles ───────────────────────────────────────────

    /// <summary>
    /// Lists the SSH request profiles whose <c>CertificateAuthorityId</c> resolves to a CA
    /// inside the caller's <see cref="SpaceFence"/>; profiles with a null CA scope are
    /// surfaced only to an instance-wide caller, who sees all.
    /// </summary>
    [HttpGet("request")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetRequestProfiles()
    {
        await _currentUser.EnsureLoadedAsync();

        if (Fence.InstanceWide)
        {
            var all = await _db.SshRequestProfiles.AsNoTracking()
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description,
                    p.AllowedSshSigningProfileIds, p.AllowedSshCertProfileIds,
                    p.RequireApproval, p.MaxValidityHours,
                    p.CertificateAuthorityId, p.CreatedAt
                })
                .ToListAsync();
            return Ok(all);
        }

        if (Fence.IsEmpty)
            return Ok(Array.Empty<object>());
        var visibleCas = _db.CertificateAuthorities.AsNoTracking()
            .Where(Fence.Predicate<CertificateAuthorityEntity>(ca => ca.SpaceId));

        var profiles = await (
            from p in _db.SshRequestProfiles.AsNoTracking()
            join ca in visibleCas on p.CertificateAuthorityId equals ca.Id
            where p.CertificateAuthorityId != null
            orderby p.Name
            select new
            {
                p.Id, p.Name, p.Description,
                p.AllowedSshSigningProfileIds, p.AllowedSshCertProfileIds,
                p.RequireApproval, p.MaxValidityHours,
                p.CertificateAuthorityId, p.CreatedAt
            }).ToListAsync();
        return Ok(profiles);
    }

    /// <summary>
    /// Retrieves a single SSH request profile by its identifier. Enforces the
    /// space fence on the profile's <c>CertificateAuthorityId</c>; profiles with null CA
    /// scope are visible only to system admins. Cross-space or null-scope-non-admin
    /// requests collapse to 404 and emit a failure audit row.
    /// </summary>
    [HttpGet("request/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetRequestProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var profile = await _db.SshRequestProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id);
        if (profile == null) return NotFound();

        if (!await IsRequestProfileAccessibleAsync(profile.CertificateAuthorityId))
        {
            await EmitFenceDeniedAsync("SshRequestProfile", id, "GetRequestProfile");
            return NotFound();
        }

        return Ok(new
        {
            profile.Id, profile.Name, profile.Description,
            profile.AllowedSshSigningProfileIds, profile.AllowedSshCertProfileIds,
            profile.RequireApproval, profile.MaxValidityHours,
            profile.CertificateAuthorityId, profile.CreatedAt
        });
    }

    /// <summary>
    /// Creates a new SSH request profile. The target CA (when supplied) is
    /// fenced before any row is written; null-CA (system-wide) rows may only be created
    /// by system admins. Failure paths emit a failure audit row. Step-up MFA is required
    /// because request profiles gate which signing/cert profiles a space can invoke.
    /// </summary>
    [HttpPost("request")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    [RequireStepUp(StepUpOps.CreateSshProfile)]
    public async Task<IActionResult> CreateRequestProfile([FromBody] CreateSshRequestProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        (Guid CaId, Guid? SpaceId)? fence = null;
        if (request.CertificateAuthorityId.HasValue)
        {
            fence = await ResolveAndFenceByCaIdAsync(request.CertificateAuthorityId.Value);
            if (fence == null)
            {
                await EmitFenceDeniedAsync("SshRequestProfile", null, "CreateRequestProfile",
                    new { request.Name, request.CertificateAuthorityId });
                return NotFound();
            }
        }
        else if (!IsSystemAdmin)
        {
            await EmitFenceDeniedAsync("SshRequestProfile", null, "CreateRequestProfile.NullCa",
                new { request.Name });
            return NotFound();
        }

        var entity = new SshRequestProfileEntity
        {
            Name = request.Name,
            Description = request.Description,
            AllowedSshSigningProfileIds = request.AllowedSshSigningProfileIds ?? "[]",
            AllowedSshCertProfileIds = request.AllowedSshCertProfileIds ?? "[]",
            RequireApproval = request.RequireApproval ?? false,
            MaxValidityHours = request.MaxValidityHours ?? 720,
            CertificateAuthorityId = request.CertificateAuthorityId,
        };

        _db.SshRequestProfiles.Add(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshRequestProfileCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshRequestProfile", entity.Id.ToString(),
            new { entity.Name, entity.RequireApproval, entity.MaxValidityHours, entity.CertificateAuthorityId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence?.CaId,
            spaceId: fence?.SpaceId);

        return Ok(new { entity.Id, entity.Name, entity.CreatedAt });
    }

    /// <summary>
    /// Updates an existing SSH request profile. The existing CA scope is fenced
    /// before any mutation; if the request rebinds to a new CA, the new target is also
    /// fenced, and needs cert.revoke and the profile's own scope (<see cref="RefuseRebindAsync"/>).
    /// Moving a profile to/from null-CA scope requires system admin. Failure paths
    /// emit a failure audit row. Step-up MFA is required because changes alter which SSH
    /// signing/cert bundles a space can invoke during enrollment.
    /// </summary>
    [HttpPut("request/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.UpdateSshProfile, "id")]
    public async Task<IActionResult> UpdateRequestProfile(Guid id, [FromBody] UpdateSshRequestProfileRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshRequestProfiles.FindAsync(id);
        if (entity == null) return NotFound();

        if (!await IsRequestProfileAccessibleAsync(entity.CertificateAuthorityId))
        {
            await EmitFenceDeniedAsync("SshRequestProfile", id, "UpdateRequestProfile");
            return NotFound();
        }

        // Capture an audit anchor for the existing CA (may be null for system-wide rows).
        (Guid CaId, Guid? SpaceId)? fence = entity.CertificateAuthorityId.HasValue
            ? await ResolveAndFenceByCaIdAsync(entity.CertificateAuthorityId.Value)
            : null;

        // If the caller is rebinding the profile, fence the new target as well.
        if (request.CertificateAuthorityId.HasValue && request.CertificateAuthorityId != entity.CertificateAuthorityId)
        {
            var newFence = await ResolveAndFenceByCaIdAsync(request.CertificateAuthorityId.Value);
            if (newFence == null)
            {
                await EmitFenceDeniedAsync("SshRequestProfile", id, "UpdateRequestProfile.Rebind",
                    new { TargetCertificateAuthorityId = request.CertificateAuthorityId.Value });
                return NotFound();
            }
            if (await RefuseRebindAsync(fence, newFence.Value) is { } refused)
                return refused;
            fence = newFence;
        }

        if (request.Name != null) entity.Name = request.Name;
        if (request.Description != null) entity.Description = request.Description;
        if (request.AllowedSshSigningProfileIds != null) entity.AllowedSshSigningProfileIds = request.AllowedSshSigningProfileIds;
        if (request.AllowedSshCertProfileIds != null) entity.AllowedSshCertProfileIds = request.AllowedSshCertProfileIds;
        if (request.RequireApproval.HasValue) entity.RequireApproval = request.RequireApproval.Value;
        if (request.MaxValidityHours.HasValue) entity.MaxValidityHours = request.MaxValidityHours.Value;
        if (request.CertificateAuthorityId.HasValue) entity.CertificateAuthorityId = request.CertificateAuthorityId.Value;

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshRequestProfileUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshRequestProfile", id.ToString(),
            new { entity.Name, entity.RequireApproval, entity.MaxValidityHours, entity.CertificateAuthorityId },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence?.CaId,
            spaceId: fence?.SpaceId);

        return Ok(new { entity.Id, entity.Name });
    }

    /// <summary>
    /// Deletes an SSH request profile by its identifier. Fences the profile's
    /// CA scope; null-scope profiles may only be deleted by system admins. Failure paths
    /// emit a failure audit row. Step-up MFA is required because deletion withdraws the
    /// allow-list of SSH signing/cert bundles available to a space.
    /// </summary>
    [HttpDelete("request/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.DeleteSshProfile, "id")]
    public async Task<IActionResult> DeleteRequestProfile(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshRequestProfiles.FindAsync(id);
        if (entity == null) return NotFound();

        if (!await IsRequestProfileAccessibleAsync(entity.CertificateAuthorityId))
        {
            await EmitFenceDeniedAsync("SshRequestProfile", id, "DeleteRequestProfile");
            return NotFound();
        }

        (Guid CaId, Guid? SpaceId)? fence = entity.CertificateAuthorityId.HasValue
            ? await ResolveAndFenceByCaIdAsync(entity.CertificateAuthorityId.Value)
            : null;

        var deletedName = entity.Name;
        _db.SshRequestProfiles.Remove(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshRequestProfileDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshRequestProfile", id.ToString(),
            new { Name = deletedName },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: fence?.CaId,
            spaceId: fence?.SpaceId);

        return Ok(new { message = "SSH request profile deleted" });
    }

    // ── Internal helpers ───────────────────────────────────────────────

    /// <summary>
    /// Returns true when an SSH request profile with the supplied (optional) CA scope is
    /// accessible to the current caller: an instance-wide fence always passes; null-CA
    /// profiles are system-wide and need it; otherwise the CA's space must be inside the
    /// caller's <see cref="SpaceFence"/>.
    /// </summary>
    private async Task<bool> IsRequestProfileAccessibleAsync(Guid? certificateAuthorityId)
    {
        if (Fence.InstanceWide) return true;
        if (!certificateAuthorityId.HasValue) return false;
        return await ResolveAndFenceByCaIdAsync(certificateAuthorityId.Value) != null;
    }

    /// <summary>
    /// Emits a failure audit row when a space-fence rejection occurs so SIEM can alert
    /// on probing attempts. Uses <see cref="AuditActionType.SystemAdminElevatedAccess"/>
    /// as the action type (the closest existing constant for cross-space probing).
    /// </summary>
    private Task EmitFenceDeniedAsync(string targetEntityType, Guid? targetEntityId, string operation, object? extra = null)
    {
        return _audit.LogAsync(
            AuditActionType.SystemAdminElevatedAccess,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType,
            targetEntityId?.ToString(),
            new { Operation = operation, Reason = "cross-space-or-not-found", Extra = extra },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            success: false,
            errorMessage: "Cross-space access denied");
    }
}

// ── Request DTOs ────────────────────────────────────────────────────────

/// <summary>Request model for creating an SSH signing profile.</summary>
public class CreateSshSigningProfileRequest
{
    /// <summary>Profile name (required, unique).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Optional description.</summary>
    public string? Description { get; set; }
    /// <summary>SSH CA key to bind this profile to.</summary>
    public Guid SshCaKeyId { get; set; }
    /// <summary>Maximum validity hours (default 720).</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>Allow user certificates (default true).</summary>
    public bool? AllowUserCerts { get; set; }
    /// <summary>Allow host certificates (default false).</summary>
    public bool? AllowHostCerts { get; set; }
    /// <summary>Optional forced command.</summary>
    public string? ForceCommand { get; set; }
    /// <summary>JSON array of source address restrictions.</summary>
    public string? SourceAddressRestrictions { get; set; }
    /// <summary>JSON array of default extensions.</summary>
    public string? DefaultExtensions { get; set; }
}

/// <summary>Request model for updating an SSH signing profile (all fields optional).</summary>
public class UpdateSshSigningProfileRequest
{
    /// <summary>New profile name.</summary>
    public string? Name { get; set; }
    /// <summary>New description.</summary>
    public string? Description { get; set; }
    /// <summary>New SSH CA key binding.</summary>
    public Guid? SshCaKeyId { get; set; }
    /// <summary>New maximum validity hours.</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>Whether user certificates are allowed.</summary>
    public bool? AllowUserCerts { get; set; }
    /// <summary>Whether host certificates are allowed.</summary>
    public bool? AllowHostCerts { get; set; }
    /// <summary>New forced command.</summary>
    public string? ForceCommand { get; set; }
    /// <summary>New source address restrictions JSON array.</summary>
    public string? SourceAddressRestrictions { get; set; }
    /// <summary>New default extensions JSON array.</summary>
    public string? DefaultExtensions { get; set; }
}

/// <summary>Request model for creating an SSH certificate profile.</summary>
public class CreateSshCertProfileRequest
{
    /// <summary>Profile name (required, unique).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Optional description.</summary>
    public string? Description { get; set; }
    /// <summary>JSON array of regex patterns for allowed principals.</summary>
    public string? AllowedPrincipalPatterns { get; set; }
    /// <summary>Maximum number of principals per certificate.</summary>
    public int? MaxPrincipals { get; set; }
    /// <summary>JSON array of allowed extensions.</summary>
    public string? AllowedExtensions { get; set; }
    /// <summary>JSON array of required extensions.</summary>
    public string? RequiredExtensions { get; set; }
    /// <summary>Maximum validity hours.</summary>
    public int? MaxValidityHours { get; set; }
}

/// <summary>Request model for updating an SSH certificate profile (all fields optional).</summary>
public class UpdateSshCertProfileRequest
{
    /// <summary>New profile name.</summary>
    public string? Name { get; set; }
    /// <summary>New description.</summary>
    public string? Description { get; set; }
    /// <summary>New allowed principal patterns JSON array.</summary>
    public string? AllowedPrincipalPatterns { get; set; }
    /// <summary>New maximum principals count.</summary>
    public int? MaxPrincipals { get; set; }
    /// <summary>New allowed extensions JSON array.</summary>
    public string? AllowedExtensions { get; set; }
    /// <summary>New required extensions JSON array.</summary>
    public string? RequiredExtensions { get; set; }
    /// <summary>New maximum validity hours.</summary>
    public int? MaxValidityHours { get; set; }
}

/// <summary>Request model for creating an SSH request profile.</summary>
public class CreateSshRequestProfileRequest
{
    /// <summary>Profile name (required, unique).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Optional description.</summary>
    public string? Description { get; set; }
    /// <summary>JSON array of allowed SSH signing profile IDs.</summary>
    public string? AllowedSshSigningProfileIds { get; set; }
    /// <summary>JSON array of allowed SSH cert profile IDs.</summary>
    public string? AllowedSshCertProfileIds { get; set; }
    /// <summary>Whether approval is required.</summary>
    public bool? RequireApproval { get; set; }
    /// <summary>Maximum validity hours.</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>Optional CA ID for access scoping.</summary>
    public Guid? CertificateAuthorityId { get; set; }
}

/// <summary>Request model for updating an SSH request profile (all fields optional).</summary>
public class UpdateSshRequestProfileRequest
{
    /// <summary>New profile name.</summary>
    public string? Name { get; set; }
    /// <summary>New description.</summary>
    public string? Description { get; set; }
    /// <summary>New allowed SSH signing profile IDs JSON array.</summary>
    public string? AllowedSshSigningProfileIds { get; set; }
    /// <summary>New allowed SSH cert profile IDs JSON array.</summary>
    public string? AllowedSshCertProfileIds { get; set; }
    /// <summary>Whether approval is required.</summary>
    public bool? RequireApproval { get; set; }
    /// <summary>New maximum validity hours.</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>New CA ID for access scoping.</summary>
    public Guid? CertificateAuthorityId { get; set; }
}
