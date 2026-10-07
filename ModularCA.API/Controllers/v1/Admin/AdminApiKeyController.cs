using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// The named API keys of the two integrations: the infrastructure API and the cert-manager
/// issuer. A key is generated here, returned once and stored only as a hash, so each client can
/// hold its own and lose it alone. System administrators only, as for the integrations' settings.
/// </summary>
[ApiController]
[Route("api/v1/admin/api-keys")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminApiKeyController(IApiKeyService keys, ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Lists the keys, working and not, newest first. No key and no hash is returned: a key is
    /// identified by its name and its last four characters.
    /// </summary>
    /// <param name="integration"><c>integration</c> or <c>cert-manager</c>; every key when omitted.</param>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<IActionResult> List([FromQuery] string? integration = null)
    {
        if (!string.IsNullOrEmpty(integration) && !ApiKeyIntegrations.All.Contains(integration))
            return BadRequest(new { error = $"'{integration}' is not an integration. Use one of: {string.Join(", ", ApiKeyIntegrations.All)}." });

        var now = DateTime.UtcNow;
        return Ok((await keys.ListAsync(integration, HttpContext.RequestAborted)).Select(k => Describe(k, now)));
    }

    /// <summary>
    /// Creates a key. The response carries the key itself in <c>key</c>, and this is the only
    /// time it is shown. Requires step-up MFA (<see cref="StepUpOps.CreateApiKey"/>).
    /// </summary>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateApiKey)]
    [ProducesResponseType(201)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> Create([FromBody] CreateApiKeyRequest request)
    {
        if (request.ExpiresInDays is < 1 or > 3650)
            return BadRequest(new { error = "expiresInDays is between 1 and 3650; leave it out for a key that does not expire." });

        var actor = await ActorAsync();
        if (actor == null) return Unauthorized();
        try
        {
            var (key, plaintext) = await keys.CreateAsync(
                request.Integration ?? string.Empty, request.Name ?? string.Empty, request.SpaceScope,
                request.ExpiresInDays is { } days ? DateTime.UtcNow.AddDays(days) : null,
                actor, HttpContext.RequestAborted);
            return StatusCode(201, new
            {
                key = plaintext,
                message = "Copy the key now. It is not stored and cannot be shown again.",
                apiKey = Describe(key, DateTime.UtcNow),
            });
        }
        catch (ApiKeyRefusedException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Revokes a key. It stops working at once and stays in the list. Requires step-up MFA
    /// (<see cref="StepUpOps.RevokeApiKey"/>).
    /// </summary>
    [HttpDelete("{id:guid}")]
    [RequireStepUp(StepUpOps.RevokeApiKey, "id")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> Revoke(Guid id)
    {
        var actor = await ActorAsync();
        if (actor == null) return Unauthorized();
        return await keys.RevokeAsync(id, actor, HttpContext.RequestAborted)
            ? Ok(new { message = "API key revoked." })
            : NotFound(new { error = "API key not found." });
    }

    private async Task<ApiKeyActor?> ActorAsync()
    {
        await currentUser.EnsureLoadedAsync();
        return currentUser.User == null
            ? null
            : new ApiKeyActor(currentUser.User.Id, currentUser.User.Username, HttpContext.Connection.RemoteIpAddress?.ToString());
    }

    private static object Describe(ApiKeyEntity key, DateTime now) => new
    {
        key.Id,
        key.Integration,
        key.Name,
        key.Hint,
        key.SpaceScope,
        Status = key.RevokedAt != null ? "revoked" : key.ExpiresAt <= now ? "expired" : "active",
        key.CreatedAt,
        CreatedBy = key.CreatedByName,
        key.ExpiresAt,
        key.RevokedAt,
        RevokedBy = key.RevokedByName,
        key.LastUsedAt,
    };
}

/// <summary>What <c>POST /api/v1/admin/api-keys</c> takes.</summary>
public class CreateApiKeyRequest
{
    /// <summary><c>integration</c> for the infrastructure API, <c>cert-manager</c> for the cert-manager issuer.</summary>
    public string? Integration { get; set; }

    /// <summary>What to call the key, usually the client that will hold it. 1 to 100 characters.</summary>
    public string? Name { get; set; }

    /// <summary>A space id or <c>instance</c> to limit the key to those CAs; omitted, the key reaches what the integration is allowed.</summary>
    public string? SpaceScope { get; set; }

    /// <summary>Days until the key stops working, 1 to 3650; omitted, it does not expire.</summary>
    public int? ExpiresInDays { get; set; }
}
