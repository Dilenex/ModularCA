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

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing ACME External Account Binding (EAB) keys.
/// EAB keys are pre-shared HMAC keys that ACME clients must present when
/// creating new accounts if the server requires external account binding
/// (RFC 8555 section 7.3.4).
/// </summary>
[ApiController]
[Route("api/v1/admin/acme/eab-keys")]
[Authorize(Policy = "CaOperator")]
public class AdminAcmeEabController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;

    /// <summary>
    /// Lists all EAB keys, including used and expired ones.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ListEabKeys()
    {
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
    /// be securely distributed to the ACME client.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateEabKey([FromBody] CreateEabKeyRequest? request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

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
    /// Deletes an EAB key by its database ID. Used keys can also be deleted.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.DeleteEabKey, "id")]
    public async Task<IActionResult> DeleteEabKey(Guid id)
    {
        var key = await _db.AcmeEabKeys.FindAsync(id);
        if (key == null)
            return NotFound(new { error = "EAB key not found." });

        _db.AcmeEabKeys.Remove(key);
        await _db.SaveChangesAsync();

        await _currentUser.EnsureLoadedAsync();
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
