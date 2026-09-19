using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing SSH certificate templates that bundle an SSH CA key,
/// signing profile, cert profile, and optional request profile into a named template.
/// </summary>
[ApiController]
[Route("api/v1/admin/ssh/templates")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminSshTemplateController(ModularCADbContext db, IAuditService audit, ICurrentUserService currentUser) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IAuditService _audit = audit;
    private readonly ICurrentUserService _currentUser = currentUser;

    /// <summary>
    /// Lists all SSH certificate templates with resolved profile and CA key names.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetAll()
    {
        var templates = await _db.SshCertificateTemplates
            .AsNoTracking()
            .Include(t => t.SshCaKey)
            .Include(t => t.SshSigningProfile)
            .Include(t => t.SshCertProfile)
            .Include(t => t.SshRequestProfile)
            .OrderBy(t => t.Name)
            .Select(t => new
            {
                t.Id,
                t.Name,
                t.Description,
                t.SshCaKeyId,
                SshCaKeyName = t.SshCaKey.Name,
                t.SshSigningProfileId,
                SshSigningProfileName = t.SshSigningProfile.Name,
                t.SshCertProfileId,
                SshCertProfileName = t.SshCertProfile.Name,
                t.SshRequestProfileId,
                SshRequestProfileName = t.SshRequestProfile != null ? t.SshRequestProfile.Name : null,
                t.IsEnabled,
                t.CreatedAt
            })
            .ToListAsync();
        return Ok(templates);
    }

    /// <summary>
    /// Retrieves a single SSH certificate template by its identifier.
    /// </summary>
    [HttpGet("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var t = await _db.SshCertificateTemplates
            .AsNoTracking()
            .Include(t => t.SshCaKey)
            .Include(t => t.SshSigningProfile)
            .Include(t => t.SshCertProfile)
            .Include(t => t.SshRequestProfile)
            .FirstOrDefaultAsync(t => t.Id == id);
        if (t == null) return NotFound();
        return Ok(new
        {
            t.Id,
            t.Name,
            t.Description,
            t.SshCaKeyId,
            SshCaKeyName = t.SshCaKey.Name,
            t.SshSigningProfileId,
            SshSigningProfileName = t.SshSigningProfile.Name,
            t.SshCertProfileId,
            SshCertProfileName = t.SshCertProfile.Name,
            t.SshRequestProfileId,
            SshRequestProfileName = t.SshRequestProfile?.Name,
            t.IsEnabled,
            t.CreatedAt
        });
    }

    /// <summary>
    /// Creates a new SSH certificate template.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.SshCaKey, "request.SshCaKeyId")]
    public async Task<IActionResult> Create([FromBody] CreateSshTemplateRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = new SshCertificateTemplateEntity
        {
            Name = request.Name,
            Description = request.Description,
            SshCaKeyId = request.SshCaKeyId,
            SshSigningProfileId = request.SshSigningProfileId,
            SshCertProfileId = request.SshCertProfileId,
            SshRequestProfileId = request.SshRequestProfileId,
            IsEnabled = request.IsEnabled ?? true,
        };

        _db.SshCertificateTemplates.Add(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshTemplateCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertificateTemplate", entity.Id.ToString(),
            new { entity.Name, entity.SshCaKeyId, entity.SshSigningProfileId, entity.SshCertProfileId, entity.SshRequestProfileId, entity.IsEnabled },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { entity.Id, entity.Name, entity.CreatedAt });
    }

    /// <summary>
    /// Updates an existing SSH certificate template by its identifier.
    /// </summary>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateSshTemplateRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshCertificateTemplates.FindAsync(id);
        if (entity == null) return NotFound();

        if (request.Name != null) entity.Name = request.Name;
        if (request.Description != null) entity.Description = request.Description;
        if (request.SshCaKeyId.HasValue) entity.SshCaKeyId = request.SshCaKeyId.Value;
        if (request.SshSigningProfileId.HasValue) entity.SshSigningProfileId = request.SshSigningProfileId.Value;
        if (request.SshCertProfileId.HasValue) entity.SshCertProfileId = request.SshCertProfileId.Value;
        if (request.SshRequestProfileId.HasValue) entity.SshRequestProfileId = request.SshRequestProfileId.Value;
        if (request.IsEnabled.HasValue) entity.IsEnabled = request.IsEnabled.Value;

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshTemplateUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertificateTemplate", id.ToString(),
            new { entity.Name, entity.SshCaKeyId, entity.SshSigningProfileId, entity.SshCertProfileId, entity.IsEnabled },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { entity.Id, entity.Name });
    }

    /// <summary>
    /// Deletes an SSH certificate template by its identifier.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        var entity = await _db.SshCertificateTemplates.FindAsync(id);
        if (entity == null) return NotFound();
        var deletedName = entity.Name;
        _db.SshCertificateTemplates.Remove(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshTemplateDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
            "SshCertificateTemplate", id.ToString(),
            new { Name = deletedName },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "SSH certificate template deleted" });
    }
}

/// <summary>Request model for creating an SSH certificate template.</summary>
public class CreateSshTemplateRequest
{
    /// <summary>Template name (required, unique).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Optional description.</summary>
    public string? Description { get; set; }
    /// <summary>SSH CA key to use for signing.</summary>
    public Guid SshCaKeyId { get; set; }
    /// <summary>SSH signing profile to use.</summary>
    public Guid SshSigningProfileId { get; set; }
    /// <summary>SSH cert profile to use.</summary>
    public Guid SshCertProfileId { get; set; }
    /// <summary>Optional SSH request profile for user-facing enrollment.</summary>
    public Guid? SshRequestProfileId { get; set; }
    /// <summary>Whether the template is enabled (default true).</summary>
    public bool? IsEnabled { get; set; }
}

/// <summary>Request model for updating an SSH certificate template (all fields optional).</summary>
public class UpdateSshTemplateRequest
{
    /// <summary>New template name.</summary>
    public string? Name { get; set; }
    /// <summary>New description.</summary>
    public string? Description { get; set; }
    /// <summary>New SSH CA key.</summary>
    public Guid? SshCaKeyId { get; set; }
    /// <summary>New SSH signing profile.</summary>
    public Guid? SshSigningProfileId { get; set; }
    /// <summary>New SSH cert profile.</summary>
    public Guid? SshCertProfileId { get; set; }
    /// <summary>New SSH request profile.</summary>
    public Guid? SshRequestProfileId { get; set; }
    /// <summary>Whether the template is enabled.</summary>
    public bool? IsEnabled { get; set; }
}
