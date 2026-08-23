using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Controllers.v1.Acme;

[ApiController]
[Route("api/v1/acme")]
[Route("api/v1/acme/{caLabel}")]
[Route("acme/{caLabel}")]
[AllowAnonymous]
public class AcmeDirectoryController(IAcmeNonceService nonceService, SystemConfig config, ModularCADbContext db) : ControllerBase
{
    private readonly IAcmeNonceService _nonceService = nonceService;
    private readonly SystemConfig _config = config;
    private readonly ModularCADbContext _db = db;

    /// <summary>
    /// Reserved CA labels that never serve enrollment protocols. The System Signing
    /// CA is an internal identity used to sign system artifacts (keystore entries,
    /// step-up tokens) and must not be exposed to ACME/EST/SCEP/CMP clients even
    /// when a protocol config row is seeded against it by mistake.
    /// </summary>
    private static readonly HashSet<string> ReservedSystemLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "system-signing-ca",
    };

    /// <summary>
    /// Resolves a CA label into a live, ACME-enabled CA entity. Returns <c>null</c>
    /// when the label is reserved, the CA doesn't exist, is disabled/SSH, or has
    /// no enabled ACME protocol config. Explicit opt-in: a missing
    /// <see cref="CaProtocolConfigEntity"/> row is treated as "not enabled" so CAs
    /// seeded without a protocol config (e.g. the System Signing CA) never leak
    /// an ACME directory.
    /// </summary>
    private async Task<CertificateAuthorityEntity?> ResolveAcmeCaAsync(string label)
    {
        if (ReservedSystemLabels.Contains(label))
            return null;

        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Label == label && c.IsEnabled);
        if (ca == null || ca.IsSshCa)
            return null;

        var protocolConfig = await _db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == "ACME");
        if (protocolConfig == null || !protocolConfig.IsEnabled)
            return null;

        return ca;
    }

    /// <summary>
    /// ACME directory — returns all endpoint URLs per RFC 8555 §7.1.1.
    /// Checks per-CA protocol config before serving the directory.
    /// </summary>
    [HttpGet("directory")]
    public async Task<IActionResult> GetDirectory(string? caLabel = null)
    {
        var label = caLabel ?? "default";

        var ca = await ResolveAcmeCaAsync(label);
        if (ca == null)
            return NotFound(new { type = "urn:ietf:params:acme:error:notFound", detail = $"CA '{label}' not found or disabled." });

        MetricsService.AcmeRequestsTotal.WithLabels("directory", "ok").Inc();
        MetricsService.ProtocolRequestsTotal.WithLabels("ACME", "ok").Inc();
        // Advertise endpoints from the canonical PublicDomain-derived base URL, the
        // same source the JWS filter uses to rebuild the expected `url` for signature
        // verification (AcmeJwsAttribute). Deriving from the proxy-rewritable Host
        // header here let the advertised URL drift from the verified one, producing a
        // spurious "JWS url does not match request URL" 400 on new-order/finalize.
        var baseUrl = _config.Https.GetPublicHttpsBaseUrl();
        var acmeBase = $"{baseUrl}/acme/{label}";

        var directory = new AcmeDirectoryResponse
        {
            NewNonce = $"{acmeBase}/new-nonce",
            NewAccount = $"{acmeBase}/new-account",
            NewOrder = $"{acmeBase}/new-order",
            RevokeCert = $"{acmeBase}/revoke-cert",
            KeyChange = $"{acmeBase}/key-change",
            Meta = AcmeDirectoryMeta.For(_config.Acme)
        };
        return Ok(directory);
    }

    /// <summary>
    /// Returns a fresh replay nonce in the Replay-Nonce header.
    /// Same CA-scope validation as <see cref="GetDirectory"/> so a client
    /// cannot probe the nonce endpoint against a reserved or non-ACME CA.
    /// </summary>
    [HttpHead("new-nonce")]
    [HttpGet("new-nonce")]
    public async Task<IActionResult> NewNonce(string? caLabel = null)
    {
        var label = caLabel ?? "default";
        var ca = await ResolveAcmeCaAsync(label);
        if (ca == null)
            return NotFound(new { type = "urn:ietf:params:acme:error:notFound", detail = $"CA '{label}' not found or disabled." });

        MetricsService.AcmeRequestsTotal.WithLabels("new-nonce", "ok").Inc();
        MetricsService.ProtocolRequestsTotal.WithLabels("ACME", "ok").Inc();
        var nonce = await _nonceService.GenerateAsync();
        Response.Headers["Replay-Nonce"] = nonce;
        Response.Headers["Cache-Control"] = "no-store";

        if (Request.Method == "HEAD")
            return Ok();

        return NoContent();
    }
}
