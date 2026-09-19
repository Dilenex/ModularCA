using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.Shared.Interfaces;
using Serilog;
using ModularCA.Shared.Errors;

using ModularCA.API.Filters;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Scep;

/// <summary>
/// SCEP (Simple Certificate Enrollment Protocol) endpoints per RFC 8894.
/// Uses a single URL with operation=value query parameter dispatching.
/// Enforces request size limits and returns protocol-appropriate CMS error responses.
/// </summary>
[ApiController]
[Route("api/v1/scep")]
[Route("api/v1/scep/{caLabel}")]
[Route("scep/{caLabel}")]
[AllowAnonymous]
[RequireUnlockedSigner]
[NodeRole(ProcessRole.Enrollment)]
public class ScepController(IScepService scepService) : ControllerBase
{
    /// <summary>
    /// Maximum allowed size for SCEP PKIOperation request bodies (512 KB).
    /// SCEP messages are CMS-enveloped and larger than raw CSRs.
    /// </summary>
    private const int MaxScepBodySize = 512 * 1024;

    /// <summary>
    /// Maximum allowed size for base64-encoded SCEP GET message parameter (512 KB).
    /// </summary>
    private const int MaxScepGetMessageSize = 512 * 1024;

    /// <summary>
    /// SCEP GET handler — dispatches GetCACert, GetCACaps, and PKIOperation (via GET).
    /// Validates the operation parameter and returns protocol-appropriate errors.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string operation, [FromQuery] string? message, string? caLabel = null)
    {
        if (string.IsNullOrWhiteSpace(operation))
        {
            MetricsService.ScepRequestsTotal.WithLabels("unknown", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            return BadRequest("Missing required 'operation' query parameter.");
        }

        IActionResult result;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            result = operation.ToLowerInvariant() switch
            {
                "getcacert" => await HandleGetCaCert(caLabel),
                "getcacaps" => HandleGetCaCaps(),
                "pkioperation" => await HandlePkiOperationGet(message, caLabel),
                _ => BadRequest($"Unknown SCEP operation: {operation}")
            };
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            Log.Error(ex, "SCEP GET operation failed");
            MetricsService.ScepRequestsTotal.WithLabels(operation, "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("SCEP", "invalid_operation").Inc();
            return BadRequest(new { error = "SCEP operation failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex) when (ex.GetType().Name.Contains("Asn1")
            || ex.GetType().Name.Contains("Cms")
            || ex.GetType().Name.Contains("IOException"))
        {
            Log.Error(ex, "SCEP GET received invalid message");
            MetricsService.ScepRequestsTotal.WithLabels(operation, "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("SCEP", "invalid_message").Inc();
            return BadRequest(new { error = "SCEP operation failed. Contact administrator if the problem persists." });
        }

        stopwatch.Stop();
        // Infer ok/error outcome from the action result's HTTP status. ObjectResult and
        // StatusCodeResult both expose StatusCode.
        int? statusCode = result switch
        {
            ObjectResult obj => obj.StatusCode,
            StatusCodeResult sc => sc.StatusCode,
            _ => null
        };
        var outcomeStatus = statusCode is >= 400 ? "error" : "ok";
        MetricsService.ScepRequestsTotal.WithLabels(operation, outcomeStatus).Inc();
        MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", outcomeStatus).Inc();
        MetricsService.ProtocolRequestDuration.WithLabels("SCEP").Observe(stopwatch.Elapsed.TotalSeconds);
        return result;
    }

    /// <summary>
    /// SCEP POST handler — used for PKIOperation when POSTPKIOperation capability is advertised.
    /// Enforces request size limits and validates content type before processing.
    /// </summary>
    [HttpPost]
    [RequestSizeLimit(MaxScepBodySize)]
    public async Task<IActionResult> Post(string? caLabel = null)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Validate content type — SCEP POST should be application/x-pki-message or binary
        var contentType = Request.ContentType;
        if (!string.IsNullOrEmpty(contentType)
            && !contentType.Contains("application/x-pki-message", StringComparison.OrdinalIgnoreCase)
            && !contentType.Contains("application/octet-stream", StringComparison.OrdinalIgnoreCase))
        {
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            return BadRequest("Invalid content type. Expected application/x-pki-message.");
        }

        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var cmsRequest = ms.ToArray();

        if (cmsRequest.Length == 0)
        {
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            return BadRequest("Empty SCEP PKIOperation request body.");
        }

        if (cmsRequest.Length > MaxScepBodySize)
        {
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            return StatusCode(413, "SCEP request body exceeds maximum allowed size.");
        }

        try
        {
            var cmsResponse = await scepService.PkiOperationAsync(cmsRequest, caLabel, HttpContext.Connection.RemoteIpAddress?.ToString());
            stopwatch.Stop();
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "ok").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels("SCEP").Observe(stopwatch.Elapsed.TotalSeconds);
            return File(cmsResponse, "application/x-pki-message");
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            // SCEP errors should ideally be CMS failure responses, but if we cannot
            // even parse the request we must fall back to HTTP-level errors.
            Log.Error(ex, "SCEP POST operation failed");
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("SCEP", "invalid_operation").Inc();
            return BadRequest(new { error = "SCEP operation failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex) when (ex.GetType().Name.Contains("Asn1")
            || ex.GetType().Name.Contains("Cms")
            || ex.GetType().Name.Contains("IOException"))
        {
            Log.Error(ex, "SCEP POST received invalid CMS message");
            MetricsService.ScepRequestsTotal.WithLabels("PKIOperation", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("SCEP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("SCEP", "invalid_message").Inc();
            return BadRequest(new { error = "SCEP operation failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// Handles GetCACert — returns the CA certificate or certificate chain.
    /// </summary>
    private async Task<IActionResult> HandleGetCaCert(string? caLabel)
    {
        var (data, isPkcs7) = await scepService.GetCaCertAsync(caLabel);
        var contentType = isPkcs7 ? "application/x-x509-ca-ra-cert" : "application/x-x509-ca-cert";
        return File(data, contentType);
    }

    /// <summary>
    /// Handles GetCACaps — returns the server capabilities string.
    /// </summary>
    private IActionResult HandleGetCaCaps()
    {
        var caps = scepService.GetCaCaps();
        return Content(caps, "text/plain");
    }

    /// <summary>
    /// Handles PKIOperation via GET by decoding the base64 message parameter.
    /// Validates message size and encoding before delegating to the service.
    /// </summary>
    private async Task<IActionResult> HandlePkiOperationGet(string? message, string? caLabel)
    {
        if (string.IsNullOrWhiteSpace(message))
            return BadRequest("Missing 'message' parameter for PKIOperation.");

        if (message.Length > MaxScepGetMessageSize)
            return StatusCode(413, "SCEP GET message parameter exceeds maximum allowed size.");

        byte[] cmsRequest;
        try
        {
            cmsRequest = Convert.FromBase64String(message);
        }
        catch (FormatException)
        {
            return BadRequest("Invalid base64 encoding in PKIOperation message parameter.");
        }

        var cmsResponse = await scepService.PkiOperationAsync(cmsRequest, caLabel, HttpContext.Connection.RemoteIpAddress?.ToString());
        return File(cmsResponse, "application/x-pki-message");
    }
}
