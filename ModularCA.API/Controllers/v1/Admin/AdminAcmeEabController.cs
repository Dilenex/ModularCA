using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using System.Security.Cryptography;
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
/// Admin endpoints for managing ACME External Account Binding (EAB) keys.
/// EAB keys are pre-shared HMAC keys that ACME clients must present when
/// creating new accounts if the server requires external account binding
/// (RFC 8555 section 7.3.4). An EAB key names no CA or space and is accepted at every CA's
/// ACME endpoint, so it is an instance credential: listing keys needs a <see cref="SpaceFence"/>
/// instance-wide for cert.revoke, and creating or deleting one needs cert.revoke at system scope.
/// </summary>
[ApiController]
[Route("api/v1/admin/acme/eab-keys")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminAcmeEabController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;

    /// <summary>
    /// Lists all EAB keys, including used and expired ones, to a caller whose cert.revoke fence
    /// is instance-wide; anyone else gets an empty list.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> ListEabKeys()
    {
        if (!SpaceFence.From(HttpContext, Capabilities.CertRevoke).InstanceWide)
            return Ok(Array.Empty<object>());
        var keys = await _db.AcmeEabKeys
            .OrderByDescending(k => k.CreatedAt)
            .Select(k => new
            {
                k.Id,
                k.KeyId,
                k.Description,
                k.IsUsed,
                k.UsedAt,
                k.UsedByAccountId,
                k.CreatedAt,
                k.ExpiresAt
            })
            .ToListAsync();

        return Ok(keys);
    }

    /// <summary>
    /// Generates a new EAB key with a random KeyId and HMAC secret.
    /// The response includes the base64url-encoded HMAC key which must
    /// be securely distributed to the ACME client. Refused (403) to a caller without cert.revoke
    /// at system scope.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
    public async Task<IActionResult> CreateEabKey([FromBody] CreateEabKeyRequest? request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        if (!await MayManageAsync(_currentUser.User.Id))
            return StatusCode(403, new { error = "EAB keys are accepted at every CA, so creating one needs cert.revoke at system scope." });

        var keyId = $"eab-{Guid.NewGuid():N}"[..32];
        var hmacKeyBytes = RandomNumberGenerator.GetBytes(32);
        var hmacKeyB64Url = Base64UrlEncode(hmacKeyBytes);

        var entity = new AcmeEabKeyEntity
        {
            KeyId = keyId,
            HmacKey = hmacKeyB64Url,
            Description = request?.Description,
            ExpiresAt = request?.ExpiresAt
        };

        _db.AcmeEabKeys.Add(entity);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.AcmeEabKeyCreated,
            _currentUser.User.Id,
            _currentUser.User.Username,
            "AcmeEabKey",
            entity.Id.ToString(),
            new { entity.KeyId, entity.Description },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            entity.Id,
            entity.KeyId,
            HmacKey = hmacKeyB64Url,
            entity.Description,
            entity.CreatedAt,
            entity.ExpiresAt
        });
    }

    /// <summary>
    /// Deletes an EAB key by its database ID. Used keys can also be deleted. A caller without
    /// cert.revoke at system scope gets 404.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
    [RequireStepUp(StepUpOps.DeleteEabKey, "id")]
    public async Task<IActionResult> DeleteEabKey(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        var key = await MayManageAsync(_currentUser.User.Id) ? await _db.AcmeEabKeys.FindAsync(id) : null;
        if (key == null)
            return NotFound(new { error = "EAB key not found." });

        _db.AcmeEabKeys.Remove(key);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.AcmeEabKeyDeleted,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "AcmeEabKey",
            id.ToString(),
            new { key.KeyId },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "EAB key deleted." });
    }

    /// <summary>Whether the user holds cert.revoke at system scope, or is a system admin.</summary>
    private Task<bool> MayManageAsync(Guid userId) => authService.HasScopeCapabilityAsync(userId, null, Capabilities.CertRevoke);

    /// <summary>
    /// Encodes a byte array as a base64url string (no padding).
    /// </summary>
    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}

/// <summary>
/// Optional request body when creating a new EAB key.
/// </summary>
public class CreateEabKeyRequest
{
    /// <summary>
    /// Optional human-readable description for the EAB key.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Optional expiration date for the EAB key.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}
