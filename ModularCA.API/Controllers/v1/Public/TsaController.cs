using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// RFC 3161 Time-Stamp Authority endpoint.
/// Accepts DER-encoded TimeStampRequest and returns DER-encoded TimeStampResponse.
/// </summary>
[ApiController]
[Route("api/v1/public/tsa")]
[Route("api/v1/public/tsa/{caLabel}")]
[AllowAnonymous]
[NodeRole(ProcessRole.Enrollment)]
public class TsaController(ITimestampService timestampService) : ControllerBase
{
    /// <summary>
    /// Answers a DER RFC 3161 TimeStampReq (<c>application/timestamp-query</c>, at most 16 KB) with a
    /// DER TimeStampResp signed by the TSA certificate of the CA named by <paramref name="caLabel"/>,
    /// or of the default CA when it is omitted. Open to anonymous callers. An empty body is 400; a
    /// request the TSA cannot serve gets a TimeStampResp with status rejection rather than an HTTP
    /// error.
    /// </summary>
    /// <param name="caLabel">Label of the CA whose TSA signs; null for the default CA.</param>
    [HttpPost]
    [Consumes("application/timestamp-query")]
    [RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> Timestamp(string? caLabel = null)
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var tsqBytes = ms.ToArray();

        if (tsqBytes.Length == 0)
            return BadRequest("Empty timestamp request body.");

        MetricsService.TsaRequests.WithLabels("ok").Inc();
        MetricsService.ProtocolRequestsTotal.WithLabels("TSA", "ok").Inc();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var tsrBytes = await timestampService.ProcessTimestampRequestAsync(tsqBytes, caLabel);
        stopwatch.Stop();
        MetricsService.ProtocolRequestDuration.WithLabels("TSA").Observe(stopwatch.Elapsed.TotalSeconds);
        return File(tsrBytes, "application/timestamp-reply");
    }

    /// <summary>
    /// POST /tsa and /tsa/{caLabel}: the root-level alias, moved here from the distribution
    /// short-URL controller because timestamping is a signing protocol of the enrollment role.
    /// Accepts any content type, as the alias always has. The 16 KB cap protects the
    /// unauthenticated endpoint from memory-pressure DoS via oversized requests.
    /// </summary>
    [HttpPost("/tsa")]
    [HttpPost("/tsa/{caLabel}")]
    [RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> TimestampShortUrl(string? caLabel = null)
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var response = await timestampService.ProcessTimestampRequestAsync(ms.ToArray(), caLabel);
        return File(response, "application/timestamp-reply");
    }
}
