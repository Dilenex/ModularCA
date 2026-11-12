using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing Certificate Transparency log configurations.
/// CT log URL + public key are system-wide artifacts — corrupting them silently breaks
/// SCT verification for every space — so mutations require <c>SystemOperator</c>, not the
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
    /// <summary>Lists every configured CT log, public key included, ordered by name. Requires the <c>SystemOperator</c> policy.</summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var logs = await db.CtLogs.AsNoTracking().OrderBy(l => l.Name).ToListAsync();
        return Ok(logs);
    }

    /// <summary>One CT log, or 404. Requires the <c>SystemOperator</c> policy.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var log = await db.CtLogs.FindAsync(id);
        if (log == null) return NotFound();
        return Ok(log);
    }

    /// <summary>
    /// Why <paramref name="publicKey"/> cannot be stored as a CT log key, or null: blank (no key)
    /// is allowed, anything else must be a key <see cref="CtSctVerifier.PublicKeyError"/> accepts.
    /// </summary>
    private static string? PublicKeyError(string? publicKey) =>
        string.IsNullOrWhiteSpace(publicKey) ? null : CtSctVerifier.PublicKeyError(publicKey);

    /// <summary>
    /// Adds a CT log; it is enabled unless the request says otherwise. A public key that is not an
    /// ECDSA P-256 or RSA (2048 bits or more) SubjectPublicKeyInfo in base64 is refused with 400
    /// (<see cref="PublicKeyError"/>). Without a key, the log's SCTs cannot be verified and are
    /// discarded. Requires the <c>SystemOperator</c> policy and step-up MFA.
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateCtLog)]
    public async Task<IActionResult> Create([FromBody] CreateCtLogRequest request)
    {
        if (PublicKeyError(request.PublicKeyBase64) is { } keyError)
            return BadRequest(new { error = keyError });
        var entity = new CtLogEntity
        {
            Name = request.Name,
            Url = request.Url,
            PublicKeyBase64 = request.PublicKeyBase64?.Trim() ?? string.Empty,
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

    /// <summary>
    /// Changes the fields the request sets on a CT log, or 404. A public key is checked as on
    /// <see cref="Create"/> (400); an empty one removes the key. Requires the <c>SystemOperator</c>
    /// policy and step-up MFA.
    /// </summary>
    [HttpPut("{id:guid}")]
    [RequireStepUp(StepUpOps.UpdateCtLog, "id")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateCtLogRequest request)
    {
        var log = await db.CtLogs.FindAsync(id);
        if (log == null) return NotFound();
        if (PublicKeyError(request.PublicKeyBase64) is { } keyError)
            return BadRequest(new { error = keyError });

        if (request.Name != null) log.Name = request.Name;
        if (request.Url != null) log.Url = request.Url;
        if (request.PublicKeyBase64 != null) log.PublicKeyBase64 = request.PublicKeyBase64.Trim();
        if (request.IsEnabled.HasValue) log.IsEnabled = request.IsEnabled.Value;

        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.CtLogUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "CtLog", id.ToString(), request,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(log);
    }

    /// <summary>Removes a CT log, or 404. Requires the <c>SystemOperator</c> policy and step-up MFA.</summary>
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

/// <summary>Request body for adding a CT log.</summary>
public class CreateCtLogRequest
{
    /// <summary>Display name of the log, at most 200 characters.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Base URL of the log; certificates are posted to <c>{Url}/ct/v1/add-chain</c> (RFC 6962 §4.1). At most 500 characters.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>The log's public key: the base64 of its DER SubjectPublicKeyInfo (ECDSA P-256 or RSA of 2048 bits or more), as the log lists publish it; PEM is accepted. Each SCT is verified against it, and without one the log's SCTs are discarded. Null stores no key.</summary>
    public string? PublicKeyBase64 { get; set; }
    /// <summary>Whether certificates are submitted to this log; null means enabled.</summary>
    public bool? IsEnabled { get; set; }
}

/// <summary>Request body for changing a CT log. Each field left null keeps its current value.</summary>
public class UpdateCtLogRequest
{
    /// <summary>Display name of the log, at most 200 characters.</summary>
    public string? Name { get; set; }
    /// <summary>Base URL of the log; certificates are posted to <c>{Url}/ct/v1/add-chain</c> (RFC 6962 §4.1).</summary>
    public string? Url { get; set; }
    /// <summary>The log's public key, as on create; SCTs are verified against it. Empty removes the key, after which the log's SCTs are discarded.</summary>
    public string? PublicKeyBase64 { get; set; }
    /// <summary>Whether certificates are submitted to this log.</summary>
    public bool? IsEnabled { get; set; }
}
