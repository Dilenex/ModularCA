using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Clean root-level URL aliases for the distribution endpoints: <c>/ca</c>, <c>/crl</c> and
/// <c>/ocsp</c>. These short paths are embedded in certificate AIA/CDP extensions so they're
/// permanent and human-readable. The <c>/tsa</c> alias lives on <see cref="TsaController"/>,
/// because timestamping is a signing protocol of the enrollment role, not distribution.
/// </summary>
[ApiController]
[AllowAnonymous]
[NodeRole(ProcessRole.Validation)]
public class PublicShortUrlController(
    ICertificateStore certStore,
    ICrlService crlService,
    ModularCADbContext db) : ControllerBase
{
    /// <summary>
    /// Resolves a CA certificate by serial number or CA label.
    /// Falls back to label-based lookup if serial lookup fails.
    /// Returns null (→ 404) when a cert is found but is not a CA. The
    /// previous behaviour let an attacker distinguish leaf serials from CA serials by the
    /// response code.
    /// </summary>
    private async Task<CertificateInfoModel?> ResolveCaCertAsync(string serialOrLabel)
    {
        var cert = await certStore.GetCertificateInfoAsync(serialOrLabel);
        // Only return when IsCA; non-CA matches fall through to the label
        // lookup or eventually return null so leaf enumeration is not possible.
        if (cert != null && cert.IsCA) return cert;

        // Try by CA label
        var ca = await db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Label == serialOrLabel && c.CertificateId != null);
        if (ca?.CertificateId != null)
        {
            var caCert = await certStore.GetCertificateByIdAsync(ca.CertificateId.Value);
            if (caCert != null && caCert.IsCA)
                return caCert;
        }

        return null;
    }

    /// <summary>GET /ca/{serialOrLabel} — Download CA certificate by serial number or CA label. Returns DER (.crt) by default, PEM (.pem) if Accept header requests it.
    /// Filename sanitization routes through <see cref="DownloadFilenameUtil"/>.</summary>
    [HttpGet("/ca/{serialOrLabel}")]
    public async Task<IActionResult> GetCaCert(string serialOrLabel)
    {
        var cert = await ResolveCaCertAsync(serialOrLabel);
        if (cert == null || !cert.IsCA) return NotFound();
        var serial = cert.SerialNumber;

        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? serial;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "ca-cert");
        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();

        if (accept.Contains("application/x-pem-file") || accept.Contains("pem"))
        {
            var pemBytes = System.Text.Encoding.UTF8.GetBytes(cert.Pem);
            return File(pemBytes, "application/x-pem-file", $"{safeName}.pem");
        }

        var raw = await certStore.GetRawCertificateAsync(serial);
        if (raw == null || raw.Length == 0) return NotFound();
        // DER certs use .cer (Windows-recognized) to match the other download
        // endpoints; .crt is avoided for DER since it conventionally implies PEM.
        return File(raw, "application/pkix-cert", $"{safeName}.cer");
    }

    /// <summary>GET /crl/{serialOrLabel} — Download full CRL by serial number or CA label. Returns DER (.crl) by default, PEM (.pem) if Accept header requests it.
    /// Sets <c>Cache-Control</c>/<c>ETag</c>/<c>Last-Modified</c> headers and
    /// serves the stored DER blob directly without re-parsing PEM on every hit.</summary>
    [HttpGet("/crl/{serialOrLabel}")]
    public async Task<IActionResult> GetCrl(string serialOrLabel)
    {
        var cert = await ResolveCaCertAsync(serialOrLabel);
        if (cert == null) return NotFound();

        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? cert.SerialNumber;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "crl");

        if (accept.Contains("application/x-pem-file") || accept.Contains("pem"))
        {
            var pem = await crlService.GetLatestCrlAsync(cert.CertificateId);
            if (pem == null) return NotFound();
            return File(System.Text.Encoding.UTF8.GetBytes(pem), "application/x-pem-file", $"{safeName}.crl.pem");
        }

        var blob = await crlService.GetLatestCrlRawAsync(cert.CertificateId);
        if (blob == null) return NotFound();
        return PublicCrlHttpHelper.ServeCrl(HttpContext, blob, "application/pkix-crl", $"{safeName}.crl");
    }

    /// <summary>GET /crl/{serialOrLabel}/delta — Download delta CRL by serial number or CA label. Returns DER (.crl) by default, PEM (.pem) if Accept header requests it.</summary>
    [HttpGet("/crl/{serialOrLabel}/delta")]
    public async Task<IActionResult> GetDeltaCrl(string serialOrLabel)
    {
        var cert = await ResolveCaCertAsync(serialOrLabel);
        if (cert == null) return NotFound();

        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? cert.SerialNumber;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "crl");

        if (accept.Contains("application/x-pem-file") || accept.Contains("pem"))
        {
            var pem = await crlService.GetLatestDeltaCrlAsync(cert.CertificateId);
            if (pem == null) return NotFound();
            return File(System.Text.Encoding.UTF8.GetBytes(pem), "application/x-pem-file", $"{safeName}-delta.crl.pem");
        }

        var blob = await crlService.GetLatestDeltaCrlRawAsync(cert.CertificateId);
        if (blob == null) return NotFound();
        return PublicCrlHttpHelper.ServeCrl(HttpContext, blob, "application/pkix-crl", $"{safeName}-delta.crl");
    }

    /// <summary>POST /ocsp — OCSP responder (auto-detects CA from request).
    /// Body capped at 8 KB — legitimate DER OCSP requests are
    /// under 1 KB, anything larger is either malformed or an amplification
    /// attempt. Per-outcome labelling is routed through
    /// <see cref="OcspProcessingResult"/>, <see cref="HttpContext.RequestAborted"/> is threaded
    /// through, and the
    /// <c>Cache-Control</c> header is emitted derived from the responder's nextUpdate.
    /// </summary>
    [HttpPost("/ocsp")]
    [HttpPost("/ocsp/ca/{caLabel}")]
    [RequestSizeLimit(8 * 1024)]
    public async Task<IActionResult> OcspPost(string? caLabel = null)
    {
        var ocspService = HttpContext.RequestServices.GetRequiredService<IOcspService>();
        var ct = HttpContext.RequestAborted;
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        return await RunOcspAsync(ocspService, ms.ToArray(), caLabel, ct);
    }

    /// <summary>GET /ocsp/{encodedRequest} — OCSP via GET (auto-detects CA from request).
    /// Malformed base64 returns HTTP 400 (previously threw
    /// <see cref="FormatException"/>). The body cap is dropped to
    /// 8 KB to match POST.</summary>
    [HttpGet("/ocsp/{encodedRequest}")]
    [HttpGet("/ocsp/ca/{caLabel}/{encodedRequest}")]
    [RequestSizeLimit(8 * 1024)]
    public async Task<IActionResult> OcspGet(string encodedRequest, string? caLabel = null)
    {
        var ocspService = HttpContext.RequestServices.GetRequiredService<IOcspService>();
        var ct = HttpContext.RequestAborted;
        if (!OcspGetDecoder.TryDecode(encodedRequest, out var requestBytes) || requestBytes == null)
        {
            ModularCA.Core.Services.MetricsService.OcspRequests.WithLabels("malformedRequest", caLabel ?? string.Empty).Inc();
            ModularCA.Core.Services.MetricsService.ProtocolRequestsTotal.WithLabels("OCSP", "error").Inc();
            return BadRequest();
        }
        return await RunOcspAsync(ocspService, requestBytes, caLabel, ct);
    }

    /// <summary>
    /// Shared handler that runs an OCSP request, records the
    /// post-processing metric label, and applies the <c>Cache-Control</c>
    /// header when the response carries a <c>nextUpdate</c>.
    /// </summary>
    private async Task<IActionResult> RunOcspAsync(IOcspService ocspService, byte[] derRequest, string? caLabel, CancellationToken ct)
    {
        var result = new OcspProcessingResult { CaLabel = caLabel ?? string.Empty };
        try
        {
            var response = await ocspService.ProcessOcspRequestAsync(derRequest, caLabel, result, ct);
            ModularCA.Core.Services.MetricsService.OcspRequests.WithLabels(result.Status, result.CaLabel).Inc();
            ModularCA.Core.Services.MetricsService.ProtocolRequestsTotal
                .WithLabels("OCSP", result.Status == "ok" ? "ok" : "error").Inc();
            if (result.Status == "ok" && result.CacheMaxAgeSeconds > 0)
            {
                Response.Headers.CacheControl = $"public, max-age={result.CacheMaxAgeSeconds}";
            }
            return File(response, "application/ocsp-response");
        }
        catch
        {
            if (result.Status == "unknown") result.Status = "internalError";
            ModularCA.Core.Services.MetricsService.OcspRequests.WithLabels(result.Status, result.CaLabel).Inc();
            ModularCA.Core.Services.MetricsService.ProtocolRequestsTotal.WithLabels("OCSP", "error").Inc();
            throw;
        }
    }
}
