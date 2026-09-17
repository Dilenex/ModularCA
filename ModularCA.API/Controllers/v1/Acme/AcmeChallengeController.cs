using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ModularCA.API.Filters;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;

namespace ModularCA.API.Controllers.v1.Acme;

/// <summary>
/// ACME challenge and authorization endpoints for domain validation (RFC 8555).
/// </summary>
[ApiController]
[Route("api/v1/acme")]
[Route("api/v1/acme/{caLabel}")]
[Route("acme/{caLabel}")]
[AllowAnonymous]
[AcmeJws]
[RequireUnlockedSigner]
public class AcmeChallengeController(
    IAcmeAuthorizationService authzService,
    IAcmeChallengeService challengeService,
    ILogger<AcmeChallengeController> logger,
    SystemConfig config) : ControllerBase
{
    private readonly IAcmeAuthorizationService _authzService = authzService;
    private readonly IAcmeChallengeService _challengeService = challengeService;
    private readonly ILogger<AcmeChallengeController> _logger = logger;
    private readonly SystemConfig _config = config;

    /// <summary>Canonical base URL from SystemConfig, not the request host header.</summary>
    private string GetBaseUrl() => _config.Https.GetPublicHttpsBaseUrl();

    /// <summary>Keeps the Link header path under the labeled subtree when routed there.</summary>
    private string LabelPrefix()
    {
        var caLabel = HttpContext.Request.RouteValues["caLabel"] as string;
        return !string.IsNullOrWhiteSpace(caLabel) ? $"/acme/{caLabel}" : "/api/v1/acme";
    }

    /// <summary>
    /// Get authorization details (RFC 8555 §7.5 POST-as-GET). Verifies account ownership.
    /// </summary>
    [HttpPost("authz/{id:guid}")]
    public async Task<IActionResult> GetAuthorization(Guid id)
    {
        var jws = HttpContext.Items["AcmeJws"] as AcmeJwsPayload
            ?? throw new InvalidOperationException("JWS not parsed.");
        var authzAccountId = await _authzService.GetAccountIdForAuthorizationAsync(id);
        if (authzAccountId == null)
            return NotFound();
        if (authzAccountId != jws.AccountId)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account does not own this resource.");

        var baseUrl = GetBaseUrl();
        var authz = await _authzService.GetByIdAsync(id, baseUrl);
        if (authz == null)
            return NotFound();
        return Ok(authz);
    }

    /// <summary>
    /// Respond to a challenge (RFC 8555 §7.5.1). Verifies account ownership.
    /// Client POSTs an empty JSON object {} to indicate readiness.
    /// Audit findings #23: maps service-layer <see cref="InvalidOperationException"/>
    /// messages (auth state mismatch, thumbprint mismatch, internal lookups) to a fixed
    /// RFC 7807 detail string so anonymous ACME clients cannot use the response as an
    /// internal-state oracle. Underlying messages are logged at warn level.
    /// </summary>
    [HttpPost("challenge/{id:guid}")]
    public async Task<IActionResult> RespondToChallenge(Guid id)
    {
        var jws = HttpContext.Items["AcmeJws"] as AcmeJwsPayload
            ?? throw new InvalidOperationException("JWS not parsed.");

        var challengeAccountId = await _challengeService.GetAccountIdForChallengeAsync(id);
        if (challengeAccountId == null)
            return NotFound();
        if (challengeAccountId != jws.AccountId)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account does not own this resource.");

        var thumbprint = jws.JwkThumbprint
            ?? throw new InvalidOperationException("Account thumbprint not available.");

        try
        {
            var baseUrl = GetBaseUrl();
            var challenge = await _challengeService.RespondAsync(id, thumbprint, baseUrl);

            var authzId = await _challengeService.GetAuthorizationIdForChallengeAsync(id);
            if (authzId.HasValue)
                Response.Headers["Link"] = $"<{baseUrl}{LabelPrefix()}/authz/{authzId.Value}>;rel=\"up\"";

            return Ok(challenge);
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            // Audit findings #23: do not echo internal exception text to anonymous ACME
            // clients. Keep the original message in operator logs only.
            _logger.LogWarning(ex, "ACME challenge {ChallengeId} rejected: {Reason}", id, ex.Message);
            var error = new AcmeErrorResponse
            {
                Type = "urn:ietf:params:acme:error:malformed",
                Detail = "Challenge cannot be processed in its current state.",
                Status = 400
            };
            return new ObjectResult(error) { StatusCode = 400, ContentTypes = { "application/problem+json" } };
        }
    }

    private ObjectResult AcmeError(int status, string type, string detail)
    {
        var error = new AcmeErrorResponse { Type = type, Detail = detail, Status = status };
        return new ObjectResult(error) { StatusCode = status, ContentTypes = { "application/problem+json" } };
    }
}
