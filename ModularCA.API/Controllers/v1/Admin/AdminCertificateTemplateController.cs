using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.CertificateTemplates;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing certificate templates that bundle a CA, signing profile,
/// cert profile, and optional request profile into a named enrollment template.
/// Restricted to SystemOperator because templates are global artifacts that affect every tenant.
/// </summary>
[ApiController]
[Route("api/v1/admin/templates")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminCertificateTemplateController(
    CertificateTemplateService templateService,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Returns all certificate templates with resolved CA and profile names.
    /// </summary>
    /// <param name="caId">Optional: only templates issued by this CA (the console's scope).</param>
    /// <param name="tenantId">Optional: only templates issued by CAs of this tenant.</param>
    [HttpGet]
    public async Task<IActionResult> GetAll([FromQuery] Guid? caId = null, [FromQuery] Guid? tenantId = null)
    {
        var templates = await templateService.GetAllAsync(caId, tenantId);
        return Ok(templates);
    }

    /// <summary>
    /// Retrieves a single certificate template by its GUID.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var template = await templateService.GetByIdAsync(id);
        if (template == null)
            return NotFound(new { message = "Certificate template not found" });
        return Ok(template);
    }

    /// <summary>
    /// Retrieves a single certificate template by its unique name.
    /// Useful for protocol clients that reference templates by name.
    /// </summary>
    [HttpGet("by-name/{name}")]
    public async Task<IActionResult> GetByName(string name)
    {
        var template = await templateService.GetByNameAsync(name);
        if (template == null)
            return NotFound(new { message = "Certificate template not found" });
        return Ok(template);
    }

    /// <summary>
    /// Creates a new certificate template linking a CA, signing profile, cert profile,
    /// and optional request profile under a unique name.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateCertificateTemplate)]
    public async Task<IActionResult> Create([FromBody] CreateCertificateTemplateRequest request)
    {
        CertificateTemplateDto result;
        try
        {
            result = await templateService.CreateAsync(request);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync("CertificateTemplateCreated", currentUser.User?.Id, currentUser.User?.Username,
            "CertificateTemplate", result.Id.ToString(), new { request.Name },
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    /// <summary>
    /// Updates an existing certificate template by ID with new profile assignments and settings.
    /// </summary>
    [HttpPut("{id}")]
    [RequireStepUp(StepUpOps.UpdateCertificateTemplate, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCertificateTemplateRequest request)
    {
        CertificateTemplateDto result;
        try
        {
            result = await templateService.UpdateAsync(id, request);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync("CertificateTemplateUpdated", currentUser.User?.Id, currentUser.User?.Username,
            "CertificateTemplate", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());
        return Ok(result);
    }

    /// <summary>
    /// Deletes a certificate template by its GUID.
    /// </summary>
    [HttpDelete("{id}")]
    [RequireStepUp(StepUpOps.DeleteCertificateTemplate, "id")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var deleted = await templateService.DeleteAsync(id);
        if (!deleted)
            return NotFound(new { message = "Certificate template not found" });
        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync("CertificateTemplateDeleted", currentUser.User?.Id, currentUser.User?.Username,
            "CertificateTemplate", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        return NoContent();
    }
}
