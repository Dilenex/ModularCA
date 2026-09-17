using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Public (unauthenticated) endpoints for downloading SSH CA public keys and KRLs.
/// Accessible via both /api/v1/public/ssh and the shorter /ssh route prefix.
/// </summary>
[ApiController]
[Route("api/v1/public/ssh")]
[Route("ssh")]
[AllowAnonymous]
[NodeRole(ProcessRole.Validation)]
public class PublicSshController(ISshCaService sshCaService, ModularCA.Shared.Models.Config.SystemConfig config) : ControllerBase
{
    /// <summary>
    /// Lists all SSH CA keys with their public metadata, including KRL and public key URLs.
    /// Useful for discovering available CA keys to trust.
    /// </summary>
    [HttpGet("ca-keys")]
    public async Task<IActionResult> ListCaKeys()
    {
        var baseUrl = !string.IsNullOrWhiteSpace(config.Https.PublicDomain)
            ? config.Https.GetPublicHttpsBaseUrl()
            : $"{Request.Scheme}://{Request.Host}";

        var keys = await sshCaService.GetCaKeysAsync();
        return Ok(keys.Select(k => new
        {
            k.Id,
            k.Name,
            k.KeyType,
            k.IsUserCa,
            k.IsHostCa,
            k.PublicKey,
            k.CreatedAt,
            KrlUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}/krl",
            PublicKeyUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}/public-key",
        }));
    }

    /// <summary>
    /// Returns the raw public key text for a specific SSH CA key.
    /// Add this to TrustedUserCAKeys in sshd_config (user CA) or
    /// known_hosts with @cert-authority (host CA).
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/public-key")]
    public async Task<IActionResult> GetCaPublicKey(Guid id)
    {
        try
        {
            var pubKey = await sshCaService.GetPublicKeyAsync(id);
            return Content(pubKey, "text/plain");
        }
        catch
        {
            return NotFound();
        }
    }

    // Keep the legacy route for backward compatibility
    /// <summary>
    /// Legacy route for retrieving an SSH CA public key.
    /// </summary>
    [HttpGet("ca/{id:guid}/public-key")]
    public async Task<IActionResult> GetCaPublicKeyLegacy(Guid id)
    {
        try
        {
            var pubKey = await sshCaService.GetPublicKeyAsync(id);
            return Content(pubKey, "text/plain");
        }
        catch
        {
            return NotFound();
        }
    }

    /// <summary>
    /// Generates and downloads a binary KRL (Key Revocation List) for the specified SSH CA key.
    /// Configure sshd with RevokedKeys pointing to this endpoint or a cached copy.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/krl")]
    public async Task<IActionResult> DownloadKrl(Guid id)
    {
        try
        {
            var krlBytes = await sshCaService.GenerateKrlAsync(id);
            if (krlBytes.Length == 0)
                return NoContent();

            return File(krlBytes, "application/octet-stream", "revoked_keys.krl");
        }
        catch (InvalidOperationException)
        {
            return NotFound();
        }
    }
}
