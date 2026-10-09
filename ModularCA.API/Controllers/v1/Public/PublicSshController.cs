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
    /// Downloads the binary KRL (Key Revocation List) of the specified SSH CA key, built from its
    /// public key and its revoked serials, with no signer and no key. Configure sshd with
    /// RevokedKeys pointing to a copy fetched from this endpoint. With nothing revoked it is a
    /// KRL with no entries; the 204 below is answered only when
    /// <see cref="ModularCA.Core.Services.SshCaService.ServeKrlWithNoEntries"/> is turned off.
    /// The bytes are the same until a certificate of the key is revoked. The answer carries a
    /// strong <c>ETag</c> and <c>Cache-Control: no-cache</c>, and a request whose
    /// <c>If-None-Match</c> names the current ETag is answered 304 without building the list
    /// (<see cref="SshKrlHttp"/>), so a host can poll it often.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/krl")]
    public async Task<IActionResult> DownloadKrl(Guid id)
    {
        try
        {
            return await SshKrlHttp.ServeAsync(this, sshCaService, id, NoContent);
        }
        catch (InvalidOperationException)
        {
            return NotFound();
        }
    }
}

/// <summary>
/// How both KRL routes answer: the list with a strong <c>ETag</c> and
/// <c>Cache-Control: no-cache</c>, or 304 for a request that already has it.
/// </summary>
internal static class SshKrlHttp
{
    /// <summary>The <c>Cache-Control</c> of every KRL answer: it may be kept, and must be checked with the server before each use.</summary>
    public const string CacheControl = "no-cache";

    /// <summary>
    /// Answers a KRL request. When the request carries <c>If-None-Match</c>, the list's state is
    /// read first, without building it, and a match is 304 with the ETag. Otherwise the list is
    /// built and sent with the ETag computed from the rows it was built from.
    /// </summary>
    /// <param name="nothingServed">The answer when no list is served for a key with nothing revoked.</param>
    /// <exception cref="InvalidOperationException">There is no such key, or its public key cannot be read.</exception>
    public static async Task<IActionResult> ServeAsync(ControllerBase controller, ISshCaService service, Guid id, Func<IActionResult> nothingServed)
    {
        var ifNoneMatch = controller.Request.Headers.IfNoneMatch;
        if (ifNoneMatch.Count > 0)
        {
            var state = await service.GetKrlStateAsync(id);
            var served = ModularCA.Core.Services.SshCaService.ServeKrlWithNoEntries || state.RevokedCertificates > 0;
            if (served && Matches(ifNoneMatch, state.ETag))
            {
                SetHeaders(controller.Response, state.ETag);
                return controller.StatusCode(StatusCodes.Status304NotModified);
            }
        }

        var krl = await service.BuildKrlAsync(id);
        if (krl.State == null)
            return nothingServed();

        SetHeaders(controller.Response, krl.State.ETag);
        return controller.File(krl.Bytes, "application/octet-stream", "revoked_keys.krl");
    }

    /// <summary>
    /// Whether an <c>If-None-Match</c> value names <paramref name="etag"/>: <c>*</c>, or a list
    /// with the same opaque tag. The comparison is the weak one RFC 9110 gives this header, so
    /// a proxy that turned the tag into a weak one still gets its 304.
    /// </summary>
    public static bool Matches(Microsoft.Extensions.Primitives.StringValues ifNoneMatch, string etag)
    {
        if (!Microsoft.Net.Http.Headers.EntityTagHeaderValue.TryParse(etag, out var current)
            || !Microsoft.Net.Http.Headers.EntityTagHeaderValue.TryParseList(ifNoneMatch, out var asked))
            return false;
        return asked.Any(tag => tag.Equals(Microsoft.Net.Http.Headers.EntityTagHeaderValue.Any) || tag.Compare(current, useStrongComparison: false));
    }

    /// <summary>Sets the two headers every KRL answer carries, the 304 included.</summary>
    private static void SetHeaders(HttpResponse response, string etag)
    {
        response.Headers.ETag = etag;
        response.Headers.CacheControl = CacheControl;
    }
}
