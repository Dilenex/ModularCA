using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.TrustAnchors;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing trust anchors — imported external CA certificates
/// used for cross-certification and chain validation.
/// </summary>
[ApiController]
[Route("api/v1/admin/trust-anchors")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminTrustAnchorController(
    TrustAnchorService trustAnchorService,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Lists all imported trust anchors.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await trustAnchorService.GetAllAsync();
        return Ok(result);
    }

    /// <summary>
    /// Retrieves a single trust anchor by ID.
    /// </summary>
    /// <param name="id">The trust anchor identifier.</param>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var result = await trustAnchorService.GetByIdAsync(id);
        if (result == null)
            return NotFound(new { error = "Trust anchor not found" });
        return Ok(result);
    }

    /// <summary>
    /// Imports an external CA certificate as a trust anchor. Accepts PEM or base64-encoded DER.
    /// The certificate must have BasicConstraints CA=true.
    /// </summary>
    /// <param name="request">The import request containing the certificate and optional metadata.</param>
    [HttpPost]
    public async Task<IActionResult> Import([FromBody] ImportTrustAnchorRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Certificate))
            return BadRequest(new { error = "Certificate is required" });

        await currentUser.EnsureLoadedAsync();

        try
        {
            var result = await trustAnchorService.ImportAsync(
                request.Certificate,
                request.Label,
                request.Description,
                currentUser.User?.Id,
                currentUser.User?.Username);

            await audit.LogAsync(AuditActionType.TrustAnchorImported, currentUser.User?.Id, currentUser.User?.Username,
                "TrustAnchor", result.Id.ToString(),
                new { result.SubjectDN, result.SerialNumber, result.Label },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (FormatException)
        {
            return BadRequest(new { error = "Invalid certificate format. Provide a valid PEM or base64-encoded DER certificate." });
        }
    }

    /// <summary>
    /// Deletes a trust anchor by ID. The certificate remains in the runtime trusted list
    /// until the application is restarted.
    /// </summary>
    /// <param name="id">The trust anchor identifier.</param>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await currentUser.EnsureLoadedAsync();

        var existing = await trustAnchorService.GetByIdAsync(id);
        if (existing == null)
            return NotFound(new { error = "Trust anchor not found" });

        var deleted = await trustAnchorService.DeleteAsync(id);
        if (!deleted)
            return NotFound(new { error = "Trust anchor not found" });

        await audit.LogAsync(AuditActionType.TrustAnchorDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "TrustAnchor", id.ToString(),
            new { existing.SubjectDN, existing.SerialNumber },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Trust anchor deleted. Will be removed from runtime on restart." });
    }

    /// <summary>
    /// Enables or disables a trust anchor. Disabled trust anchors are not loaded into
    /// the runtime trusted list on application restart.
    /// </summary>
    /// <param name="id">The trust anchor identifier.</param>
    /// <param name="request">The toggle request containing the desired enabled state.</param>
    [HttpPut("{id:guid}/toggle")]
    public async Task<IActionResult> Toggle(Guid id, [FromBody] ToggleTrustAnchorRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        var result = await trustAnchorService.ToggleAsync(id, request.Enabled);
        if (result == null)
            return NotFound(new { error = "Trust anchor not found" });

        await audit.LogAsync(AuditActionType.TrustAnchorToggled, currentUser.User?.Id, currentUser.User?.Username,
            "TrustAnchor", id.ToString(),
            new { result.SubjectDN, result.SerialNumber, result.IsEnabled },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(result);
    }
}

/// <summary>
/// Request body for toggling a trust anchor's enabled state.
/// </summary>
public class ToggleTrustAnchorRequest
{
    /// <summary>
    /// Whether the trust anchor should be enabled or disabled.
    /// </summary>
    public bool Enabled { get; set; }
}
