using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Est;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using Serilog;

namespace ModularCA.API.Controllers.v1.Est;

/// <summary>
/// EST (Enrollment over Secure Transport) endpoints per RFC 7030.
/// In production these should be served over mutually-authenticated TLS.
/// </summary>
[ApiController]
[Route("api/v1/est")]
[Route("api/v1/est/{caLabel}")]
[Route("est/{caLabel}")]
[AllowAnonymous]
public class EstController(IEstService estService, ModularCADbContext db) : ControllerBase
{
    private const string Pkcs7MimeType = "application/pkcs7-mime";
    private const string CsrAttrsContentType = "application/csrattrs";

    /// <summary>
    /// Maximum allowed request body size for EST enrollment requests (256 KB).
    /// CSRs should never approach this size; oversized payloads are rejected early.
    /// </summary>
    private const int MaxCsrBodySize = 256 * 1024;

    /// <summary>
    /// Resolves the authenticated caller's username for the EST CSR-to-caller binding.
    /// </summary>
    /// <remarks>
    /// This previously read <c>HttpContext.User?.Identity?.Name</c> alone. The JWT emits the
    /// username under the custom claim <c>username</c>, so with no <c>NameClaimType</c> configured
    /// <c>Identity.Name</c> was always null and the entire Basic/bearer binding branch in
    /// <c>EstService</c> — both the CN check and the SAN binding — was unreachable. Any account
    /// that could log in could enroll <c>CN=root-admin</c> with arbitrary SANs.
    ///
    /// <c>NameClaimType</c> is now set on the bearer handler, so <c>Identity.Name</c> is correct.
    /// The explicit claim read stays as the fallback so this binding does not depend on a setting
    /// in a different file to remain enforced — the same coupling that produced the original
    /// defect. The claim name matches the rest of the codebase (<c>AuthController</c>).
    /// </remarks>
    /// <returns>The caller's username, or null when no authenticated username is present.</returns>
    private string? ResolveCallerUsername()
    {
        var name = HttpContext.User?.Identity?.Name;
        if (!string.IsNullOrWhiteSpace(name))
            return name;
        return HttpContext.User?.FindFirst("username")?.Value;
    }

    /// <summary>
    /// CA Certificates Distribution (RFC 7030 §4.1).
    /// Returns the CA certificate chain as a certs-only PKCS#7 (base64-encoded).
    /// </summary>
    [HttpGet("cacerts")]
    public async Task<IActionResult> CaCerts(string? caLabel = null)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var pkcs7Der = await estService.GetCaCertsAsync(caLabel);
            stopwatch.Stop();
            MetricsService.EstRequestsTotal.WithLabels("cacerts", "ok").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels("EST").Observe(stopwatch.Elapsed.TotalSeconds);
            // RFC 7030 §4.1.3 requires the Content-Transfer-Encoding
            // header when the response body is base64-encoded over HTTP. Strict clients
            // (libest / estclient) reject without it.
            Response.Headers.Append("Content-Transfer-Encoding", "base64");
            var base64 = Convert.ToBase64String(pkcs7Der);
            return Content(base64, $"{Pkcs7MimeType}; smime-type=certs-only");
        }
        catch (InvalidOperationException ex)
        {
            Log.Error(ex, "EST cacerts failed");
            MetricsService.EstRequestsTotal.WithLabels("cacerts", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "invalid_operation").Inc();
            return BadRequest(new { error = "EST enrollment failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// Simple Enrollment (RFC 7030 §4.2).
    /// Accepts a base64-encoded PKCS#10 CSR, issues a certificate,
    /// and returns it wrapped in a PKCS#7 certs-only message (base64).
    /// Enforces request size limits and returns protocol-appropriate errors.
    /// </summary>
    [HttpPost("simpleenroll")]
    [Consumes("application/pkcs10")]
    [RequestSizeLimit(MaxCsrBodySize)]
    public async Task<IActionResult> SimpleEnroll(string? caLabel = null)
    {
        var authPrecondition = await EnsureEstAuthConfiguredAsync(caLabel);
        if (authPrecondition != null) return authPrecondition;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var body = await ReadBodyAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            return BadRequest("Empty request body.");
        }

        if (body.Length > MaxCsrBodySize)
        {
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            return StatusCode(413, "Request body exceeds maximum allowed size for CSR.");
        }

        try
        {
            var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
            var callerName = ResolveCallerUsername();
            var pkcs7Der = await estService.SimpleEnrollAsync(body, caLabel,
                HttpContext.Connection.RemoteIpAddress?.ToString(), clientCert,
                HttpContext.User?.Identity?.IsAuthenticated ?? false, callerName);
            stopwatch.Stop();
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "ok").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels("EST").Observe(stopwatch.Elapsed.TotalSeconds);
            Response.Headers.Append("Content-Transfer-Encoding", "base64");
            var base64 = Convert.ToBase64String(pkcs7Der);
            return Content(base64, $"{Pkcs7MimeType}; smime-type=certs-only");
        }
        catch (EstPendingApprovalException)
        {
            // RFC 7030 §4.2.3: Return 202 Accepted when approval is required
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "pending").Inc();
            return StatusCode(202, "Certificate request is pending approval. Retry later.");
        }
        catch (InvalidOperationException ex)
        {
            Log.Error(ex, "EST simple enrollment failed");
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "invalid_operation").Inc();
            return BadRequest(new { error = "EST enrollment failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex) when (ex is FormatException
            || ex.GetType().Name.Contains("Pem")
            || ex.GetType().Name.Contains("Asn1")
            || ex.GetType().Name.Contains("IOException"))
        {
            Log.Error(ex, "EST simple enrollment received invalid CSR");
            MetricsService.EstRequestsTotal.WithLabels("simpleenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "invalid_csr").Inc();
            return BadRequest(new { error = "EST enrollment failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// Simple Re-enrollment / Renewal (RFC 7030 §4.2.2).
    /// Validates the client certificate presented via mTLS is not expired/revoked,
    /// was issued by the target CA, is within its renewal window, and that the CSR
    /// subject matches the original certificate subject before re-issuing.
    /// </summary>
    [HttpPost("simplereenroll")]
    [Consumes("application/pkcs10")]
    [RequestSizeLimit(MaxCsrBodySize)]
    public async Task<IActionResult> SimpleReenroll(string? caLabel = null)
    {
        var authPrecondition = await EnsureEstAuthConfiguredAsync(caLabel);
        if (authPrecondition != null) return authPrecondition;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        // RFC 7030 §4.2.2: Re-enrollment requires mTLS — client must present
        // its existing certificate to prove possession of the prior key.
        var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
        if (clientCert == null)
        {
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            return Unauthorized(new { error = "Client certificate required for re-enrollment (mTLS)" });
        }

        var body = await ReadBodyAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            return BadRequest("Empty request body.");
        }

        if (body.Length > MaxCsrBodySize)
        {
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            return StatusCode(413, "Request body exceeds maximum allowed size for CSR.");
        }

        try
        {
            var callerName = ResolveCallerUsername();
            var pkcs7Der = await estService.SimpleReenrollAsync(body, caLabel,
                HttpContext.Connection.RemoteIpAddress?.ToString(), clientCert,
                HttpContext.User?.Identity?.IsAuthenticated ?? false, callerName);
            stopwatch.Stop();
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "ok").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels("EST").Observe(stopwatch.Elapsed.TotalSeconds);
            Response.Headers.Append("Content-Transfer-Encoding", "base64");
            var base64 = Convert.ToBase64String(pkcs7Der);
            return Content(base64, $"{Pkcs7MimeType}; smime-type=certs-only");
        }
        catch (EstPendingApprovalException)
        {
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "pending").Inc();
            return StatusCode(202, "Certificate request is pending approval. Retry later.");
        }
        catch (InvalidOperationException ex)
        {
            Log.Error(ex, "EST simple re-enrollment failed");
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "invalid_operation").Inc();
            return BadRequest(new { error = "EST enrollment failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex) when (ex is FormatException
            || ex.GetType().Name.Contains("Pem")
            || ex.GetType().Name.Contains("Asn1")
            || ex.GetType().Name.Contains("IOException"))
        {
            Log.Error(ex, "EST simple re-enrollment received invalid CSR");
            MetricsService.EstRequestsTotal.WithLabels("simplereenroll", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "invalid_csr").Inc();
            return BadRequest(new { error = "EST enrollment failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// CSR Attributes (RFC 7030 §4.5).
    /// Returns DER-encoded attributes the server requires in the CSR, base64-encoded.
    /// </summary>
    [HttpGet("csrattrs")]
    public IActionResult CsrAttrs()
    {
        MetricsService.EstRequestsTotal.WithLabels("csrattrs", "ok").Inc();
        var attrsDer = estService.GetCsrAttributes();
        var base64 = Convert.ToBase64String(attrsDer);
        return Content(base64, CsrAttrsContentType);
    }

    /// <summary>
    /// Reads the request body as a string, enforcing the maximum CSR body size limit.
    /// </summary>
    private async Task<string> ReadBodyAsStringAsync()
    {
        using var reader = new StreamReader(Request.Body);
        return await reader.ReadToEndAsync();
    }

    /// <summary>
    /// Security precondition: an EST CA must have at least one authentication mechanism
    /// configured (client-cert mTLS or HTTP auth). If an admin has saved a CaProtocolConfig
    /// with both <c>EstRequireClientCert</c> and <c>EstHttpAuthEnabled</c> set to false,
    /// this method returns a 403 Forbidden problem+json result to prevent anonymous
    /// certificate issuance. Returns <c>null</c> when the config is safe to proceed.
    /// </summary>
    /// <remarks>
    /// This check runs BEFORE CSR parsing and before delegation to the enrollment service
    /// to fail closed as early as possible. A matching defense-in-depth refusal also lives
    /// in <see cref="EnrollmentAuthorizationService"/> in case this check is ever bypassed.
    /// </remarks>
    private async Task<IActionResult?> EnsureEstAuthConfiguredAsync(string? caLabel)
    {
        var protocolConfig = await db.CaProtocolConfigs
            .AsNoTracking()
            .Include(c => c.Ca)
            .Where(c => c.Protocol == "EST" && c.IsEnabled)
            .FirstOrDefaultAsync(c => caLabel == null || c.Ca.Label == caLabel);

        // If no config exists the downstream service will return an appropriate error;
        // don't short-circuit with 403 here for missing config.
        if (protocolConfig == null)
            return null;

        if (!protocolConfig.EstRequireClientCert && !protocolConfig.EstHttpAuthEnabled)
        {
            Log.Warning(
                "EST enrollment refused for CA {CaLabel}: neither EstRequireClientCert nor EstHttpAuthEnabled is set. Remote IP {RemoteIp}",
                caLabel ?? "(default)",
                HttpContext.Connection.RemoteIpAddress?.ToString());

            MetricsService.EstRequestsTotal.WithLabels("auth_precondition", "error").Inc();
            MetricsService.ProtocolRequestsTotal.WithLabels("EST", "error").Inc();
            MetricsService.ProtocolErrorsTotal.WithLabels("EST", "auth_not_configured").Inc();

            var problem = new ValidationProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc7231#section-6.5.3",
                Title = "EST enrollment forbidden",
                Status = StatusCodes.Status403Forbidden,
                Detail = "EST enrollment requires either client-certificate auth or HTTP-auth; this CA has neither enabled — contact the CA administrator.",
            };
            return new ObjectResult(problem)
            {
                StatusCode = StatusCodes.Status403Forbidden,
                ContentTypes = { "application/problem+json" },
            };
        }

        return null;
    }
}
