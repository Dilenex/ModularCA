using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

[ApiController]
[Route("api/v1/public/crl")]
[AllowAnonymous]
[NodeRole(ProcessRole.Validation)]
public class PublicCrlController(ICrlService crlService, ICertificateStore certStore, ModularCADbContext db) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    /// <summary>
    /// Public CRL Distribution Point — returns DER-encoded full CRL by CA serial.
    /// Suitable for embedding in certificate CRL Distribution Point extensions.
    /// The controller reads the raw DER bytes from
    /// the service via <see cref="ICrlService.GetLatestCrlRawAsync"/> and sets
    /// <c>Cache-Control</c>, <c>ETag</c>, and <c>Last-Modified</c> headers so clients/CDNs can
    /// cache the response, honouring <c>If-None-Match</c> with a 304. For
    /// "cert exists but is not a CA" we return a 404 identical to "cert not found" so
    /// enumeration cannot distinguish CA serials from leaf serials.
    /// </summary>
    [HttpGet("{serial}")]
    public async Task<IActionResult> GetCrl(string serial)
    {
        var cert = await certStore.GetCertificateInfoAsync(serial);
        if (cert == null || !cert.IsCA)
            return NotFound();

        // Check per-CA protocol config
        var crlConfig = await _db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == cert.CertificateId && c.Protocol == "CRL");
        // Note: also check by CA entity ID if cert ID != CA ID
        if (crlConfig == null)
        {
            var ca = await _db.CertificateAuthorities.AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == cert.CertificateId);
            if (ca != null)
                crlConfig = await _db.CaProtocolConfigs.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == "CRL");
        }
        if (crlConfig != null && !crlConfig.IsEnabled)
            return NotFound();

        var blob = await crlService.GetLatestCrlRawAsync(cert.CertificateId);
        if (blob == null)
            return NotFound();

        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? serial;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "crl");

        return PublicCrlHttpHelper.ServeCrl(HttpContext, blob, contentType: "application/pkix-crl", fileName: $"{safeName}.crl");
    }

    /// <summary>
    /// Public Delta CRL Distribution Point — returns DER-encoded delta CRL by CA serial.
    /// RFC 5280 §5.2.4 — contains only changes since the last full CRL.
    /// </summary>
    [HttpGet("{serial}/delta")]
    public async Task<IActionResult> GetDeltaCrl(string serial)
    {
        var cert = await certStore.GetCertificateInfoAsync(serial);
        if (cert == null || !cert.IsCA)
            return NotFound();

        // Check per-CA protocol config
        var deltaCrlConfig = await _db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == cert.CertificateId && c.Protocol == "CRL");
        if (deltaCrlConfig == null)
        {
            var ca = await _db.CertificateAuthorities.AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == cert.CertificateId);
            if (ca != null)
                deltaCrlConfig = await _db.CaProtocolConfigs.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == "CRL");
        }
        if (deltaCrlConfig != null && !deltaCrlConfig.IsEnabled)
            return NotFound();

        var blob = await crlService.GetLatestDeltaCrlRawAsync(cert.CertificateId);
        if (blob == null)
            return NotFound();

        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? serial;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "crl");

        return PublicCrlHttpHelper.ServeCrl(HttpContext, blob, contentType: "application/pkix-crl", fileName: $"{safeName}-delta.crl");
    }
}

/// <summary>
/// Shared HTTP helper for serving CRLs with caching headers. Extracted so
/// both <see cref="PublicCrlController"/> and <see cref="PublicShortUrlController"/> share
/// identical 304 / ETag / Cache-Control behaviour.
/// </summary>
internal static class PublicCrlHttpHelper
{
    public static IActionResult ServeCrl(HttpContext context, CrlBlob blob, string contentType, string fileName)
    {
        var etag = $"\"crl-{blob.CrlNumber}\"";
        var lastModified = blob.ThisUpdate.ToUniversalTime();

        // Honour If-None-Match → 304
        var ifNoneMatch = context.Request.Headers[HeaderNames.IfNoneMatch].ToString();
        if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch.Contains(etag, StringComparison.Ordinal))
        {
            SetCrlCacheHeaders(context, etag, lastModified, blob.NextUpdate);
            context.Response.StatusCode = StatusCodes.Status304NotModified;
            return new EmptyResult();
        }

        SetCrlCacheHeaders(context, etag, lastModified, blob.NextUpdate);
        return new FileContentResult(blob.Der, contentType) { FileDownloadName = fileName };
    }

    private static void SetCrlCacheHeaders(HttpContext context, string etag, DateTime lastModified, DateTime nextUpdate)
    {
        var maxAgeSeconds = (long)Math.Max(60, (nextUpdate.ToUniversalTime() - DateTime.UtcNow).TotalSeconds / 2);
        context.Response.Headers[HeaderNames.CacheControl] = $"public, max-age={maxAgeSeconds}";
        context.Response.Headers[HeaderNames.ETag] = etag;
        context.Response.Headers[HeaderNames.LastModified] = lastModified.ToString("R");
    }
}
