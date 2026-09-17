using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Public CSP-report sink. The hardened
/// <c>Content-Security-Policy</c> header emitted by
/// <see cref="ModularCA.API.Middleware.SecurityHeadersMiddleware"/> points its
/// <c>report-uri</c> directive at this endpoint. Browsers <c>POST</c> a
/// JSON-encoded violation report whenever a policy directive is breached.
/// <para>
/// The controller deliberately does <b>no</b> persistence — violation reports
/// are operator-attested truthful only to a point (they are untrusted input)
/// and we do not want to give a hostile UA a write amplification vector. The
/// body is truncated to a safe limit, logged at <c>Warning</c> via Serilog,
/// and dropped. A SIEM scraping the log files can then alert on CSP drift.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[Route("api/v1/public/csp-report")]
[NodeRole(ProcessRole.Control)]
public class CspReportController : ControllerBase
{
    private const int MaxBodyBytes = 8 * 1024; // 8 KB — plenty for a report-uri payload

    /// <summary>
    /// Accepts a CSP violation report. Always returns 204 regardless of body
    /// shape so a misbehaving browser cannot retry-spam the endpoint.
    /// </summary>
    [HttpPost]
    [Consumes("application/csp-report", "application/json", "application/reports+json")]
    public async Task<IActionResult> ReportAsync()
    {
        try
        {
            Request.EnableBuffering();
            using var reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8, leaveOpen: true);
            var buffer = new char[MaxBodyBytes];
            var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            var body = new string(buffer, 0, read);

            var remote = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "-";
            var ua = Request.Headers.UserAgent.ToString();
            Log.Warning(
                "CSP violation report received from {RemoteIp} ua={UserAgent} bodyBytes={BodyBytes} body={Body}",
                remote,
                ua.Length > 256 ? ua[..256] : ua,
                read,
                body);
        }
        catch
        {
            // Never propagate parse errors — CSP reports are best-effort diagnostics.
        }

        return NoContent();
    }
}
