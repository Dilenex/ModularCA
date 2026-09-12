using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.Shared.Interfaces;
using Serilog;
using ModularCA.Shared.Errors;

namespace ModularCA.API.Controllers.v1.Cmp;

/// <summary>
/// CMP (Certificate Management Protocol) endpoint per RFC 4210 / RFC 6712.
/// Accepts DER-encoded PKIMessage requests and returns DER-encoded PKIMessage responses.
/// Enforces request size limits and returns CMP PKIMessage error responses on failures.
/// </summary>
[ApiController]
[Route("api/v1/cmp")]
[Route("api/v1/cmp/{caLabel}")]
[Route("cmp/{caLabel}")]
[AllowAnonymous]
public class CmpController(ICmpService cmpService) : ControllerBase
{
    private const string CmpContentType = "application/pkixcmp";

    /// <summary>
    /// Maximum allowed request body size for CMP messages (512 KB).
    /// CMP messages include ASN.1-encoded PKIMessage structures which are typically small.
    /// </summary>
    private const int MaxCmpBodySize = 512 * 1024;

    /// <summary>
    /// CMP HTTP transport endpoint (RFC 6712 §3).
    /// Accepts a DER-encoded PKIMessage and returns a DER-encoded PKIMessage response.
    /// Validates content type and request size before processing.
    /// Returns CMP-formatted error responses wherever possible rather than generic HTTP errors.
    /// </summary>
    [HttpPost]
    [Consumes(CmpContentType)]
    [RequestSizeLimit(MaxCmpBodySize)]
    public async Task<IActionResult> Post(string? caLabel = null)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var derRequest = ms.ToArray();

        if (derRequest.Length == 0)
        {
            MetricsService.CmpRequestsTotal.WithLabels("error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("CMP", "error").Inc();
            return BadRequest("Empty CMP request body.");
        }

        if (derRequest.Length > MaxCmpBodySize)
        {
            MetricsService.CmpRequestsTotal.WithLabels("error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("CMP", "error").Inc();
            return StatusCode(413, "CMP request body exceeds maximum allowed size.");
        }

        try
        {
            var derResponse = await cmpService.ProcessRequestAsync(derRequest, caLabel, HttpContext.Connection.RemoteIpAddress?.ToString());
            stopwatch.Stop();
            MetricsService.CmpRequestsTotal.WithLabels("ok").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("CMP", "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels("CMP").Observe(stopwatch.Elapsed.TotalSeconds);
            return File(derResponse, CmpContentType);
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            // CMP errors are returned as PKIMessage error responses by the service layer.
            // This catch handles cases where the service cannot even construct a valid response
            // (e.g., no CA signer available).
            Log.Error(ex, "CMP processing failed");
            MetricsService.CmpRequestsTotal.WithLabels("error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("CMP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("CMP", "invalid_operation").Inc();
            return BadRequest(new { error = "CMP processing failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex) when (ex.GetType().Name.Contains("Asn1")
            || ex.GetType().Name.Contains("IOException"))
        {
            Log.Error(ex, "CMP received invalid PKIMessage");
            MetricsService.CmpRequestsTotal.WithLabels("error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("CMP", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("CMP", "invalid_message").Inc();
            return BadRequest(new { error = "CMP processing failed. Contact administrator if the problem persists." });
        }
    }
}
