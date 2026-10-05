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
/// Admin endpoints for managing Certificate Transparency log configurations.
/// CT log URL + public key are system-wide artifacts — corrupting them silently breaks
/// SCT embedding for every space — so mutations require <c>SystemOperator</c>, not the
/// space-scoped <c>CaOperator</c>.
/// </summary>
[ApiController]
[Route("api/v1/admin/ct-logs")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminCtLogController(
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var logs = await db.CtLogs.AsNoTracking().OrderBy(l => l.Name).ToListAsync();
        return Ok(logs);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var log = await db.CtLogs.FindAsync(id);
        if (log == null) return NotFound();
        return Ok(log);
    }

    [HttpPost]
    [RequireStepUp(StepUpOps.CreateCtLog)]
    public async Task<IActionResult> Create([FromBody] CreateCtLogRequest request)
    {
        var entity = new CtLogEntity
        {
            Name = request.Name,
            Url = request.Url,
            PublicKeyBase64 = request.PublicKeyBase64 ?? string.Empty,
            IsEnabled = request.IsEnabled ?? true
        };
        db.CtLogs.Add(entity);
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CtLogCreated, currentUser.User?.Id, currentUser.User?.Username,
            "CtLog", entity.Id.ToString(), new { request.Name, request.Url },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(entity);
    }

    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateCtLog, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCtLogRequest request)
    {
        var log = await db.CtLogs.FindAsync(id);
        if (log == null) return NotFound();

        if (request.Name != null) log.Name = request.Name;
        if (request.Url != null) log.Url = request.Url;
        if (request.PublicKeyBase64 != null) log.PublicKeyBase64 = request.PublicKeyBase64;
        if (request.IsEnabled.HasValue) log.IsEnabled = request.IsEnabled.Value;

        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CtLogUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CtLog", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(log);
    }

    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.DeleteCtLog, "id")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var log = await db.CtLogs.FindAsync(id);
        if (log == null) return NotFound();

        var name = log.Name;
        db.CtLogs.Remove(log);
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CtLogDeleted, currentUser.User?.Id, currentUser.User?.Username,
            "CtLog", id.ToString(), new { Name = name },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }
}

/// <summary>
/// The CT log catalog as profile editors need it to pick a cert profile's logs: id, name, URL
/// and whether the log is enabled, nothing else (no public key). A separate controller because
/// <see cref="AdminCtLogController"/>'s class-level SystemOperator policy would stack on this one.
/// </summary>
[ApiController]
[Route("api/v1/admin/ct-logs")]
[NodeRole(ProcessRole.Control)]
public class AdminCtLogOptionsController(ModularCADbContext db) : ControllerBase
{
    /// <summary>
    /// Lists every CT log as <c>{ id, name, url, enabled }</c>, ordered by name. Open to anyone
    /// who may edit a cert profile (CaOperator: cert.revoke on some CA, the capability profile
    /// create and update demand), so the cert profile form can offer the logs by name.
    /// </summary>
    [HttpGet("options")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetOptions()
    {
        var logs = await db.CtLogs.AsNoTracking()
            .OrderBy(l => l.Name)
            .Select(l => new CtLogOption(l.Id, l.Name, l.Url, l.IsEnabled))
            .ToListAsync();
        return Ok(logs);
    }
}

/// <summary>One CT log as <see cref="AdminCtLogOptionsController.GetOptions"/> returns it.</summary>
public record CtLogOption(Guid Id, string Name, string Url, bool Enabled);

public class CreateCtLogRequest
{
    public string Name { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? PublicKeyBase64 { get; set; }
    public bool? IsEnabled { get; set; }
}

public class UpdateCtLogRequest
{
    public string? Name { get; set; }
    public string? Url { get; set; }
    public string? PublicKeyBase64 { get; set; }
    public bool? IsEnabled { get; set; }
}
