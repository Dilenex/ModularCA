using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// RFC 6960 OCSP responder endpoints. Per-outcome labelling is folded
/// into the metric pipeline via <see cref="OcspProcessingResult"/>,
/// the route-bound <c>caLabel</c> is wired down into the
/// service so per-CA AIA URLs fence against cross-CA answers,
/// <see cref="HttpContext.RequestAborted"/> is threaded through to the
/// signing path, and the response TTL is surfaced as a
/// <c>Cache-Control: max-age</c> header.
/// </summary>
[ApiController]
[Route("api/v1/public/ocsp")]
[Route("api/v1/public/ocsp/ca/{caLabel}")]
[AllowAnonymous]
[NodeRole(ProcessRole.Validation)]
public class OcspController(IOcspService ocspService) : ControllerBase
{
    private const string OcspRequestContentType = "application/ocsp-request";
    private const string OcspResponseContentType = "application/ocsp-response";

    /// <summary>
    /// OCSP POST endpoint (RFC 6960 §A.1).
    /// Accepts a DER-encoded OCSPRequest body.
    /// Body capped at 8 KB — legitimate DER OCSP requests
    /// are under 1 KB, anything larger is an amplification attempt.
    /// </summary>
    [HttpPost]
    [Consumes(OcspRequestContentType)]
    [RequestSizeLimit(8 * 1024)]
    public async Task<IActionResult> Post(string? caLabel = null)
    {
        var ct = HttpContext.RequestAborted;
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        var derRequest = ms.ToArray();

        if (derRequest.Length == 0)
        {
            MetricsService.OcspRequests.WithLabels("malformedRequest", caLabel ?? string.Empty).Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("OCSP", "error").Inc();
            return BadRequest();
        }

        return await HandleAsync(derRequest, caLabel, ct);
    }

    /// <summary>
    /// OCSP GET endpoint (RFC 6960 §A.1).
    /// The path segment is a base64url-encoded DER OCSPRequest.
    /// </summary>
    [HttpGet("{encodedRequest}")]
    [RequestSizeLimit(8 * 1024)]
    public async Task<IActionResult> Get(string encodedRequest, string? caLabel = null)
    {
        var ct = HttpContext.RequestAborted;
        if (!OcspGetDecoder.TryDecode(encodedRequest, out var derRequest) || derRequest == null)
        {
            MetricsService.OcspRequests.WithLabels("malformedRequest", caLabel ?? string.Empty).Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("OCSP", "error").Inc();
            return BadRequest();
        }

        return await HandleAsync(derRequest, caLabel, ct);
    }

    private async Task<IActionResult> HandleAsync(byte[] derRequest, string? caLabel, CancellationToken ct)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = new OcspProcessingResult { CaLabel = caLabel ?? string.Empty };
        try
        {
            var derResponse = await ocspService.ProcessOcspRequestAsync(derRequest, caLabel, result, ct);
            stopwatch.Stop();
            RecordMetrics(result, stopwatch);
            ApplyCacheHeaders(result);
            return File(derResponse, OcspResponseContentType);
        }
        catch
        {
            stopwatch.Stop();
            if (result.Status == "unknown") result.Status = "internalError";
            RecordMetrics(result, stopwatch);
            throw;
        }
    }

    private static void RecordMetrics(OcspProcessingResult result, System.Diagnostics.Stopwatch stopwatch)
    {
        MetricsService.OcspRequests.WithLabels(result.Status, result.CaLabel).Inc();
        MetricsService.ProtocolRequestsTotal
            .WithLabels("OCSP", result.Status == "ok" ? "ok" : "error").Inc();
        MetricsService.ProtocolRequestDuration.WithLabels("OCSP").Observe(stopwatch.Elapsed.TotalSeconds);
    }

    private void ApplyCacheHeaders(OcspProcessingResult result)
    {
        if (result.Status != "ok" || result.CacheMaxAgeSeconds <= 0) return;
        Response.Headers.CacheControl = $"public, max-age={result.CacheMaxAgeSeconds}";
    }
}
