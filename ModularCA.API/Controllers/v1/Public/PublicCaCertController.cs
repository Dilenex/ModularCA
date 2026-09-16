using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.Public;

[ApiController]
[Route("api/v1/public/ca")]
[AllowAnonymous]
public class PublicCaCertController(
    ICertificateStore certStore,
    ModularCADbContext db,
    ICaServiceUrlService caServiceUrls,
    IFeatureFlagService featureFlags) : ControllerBase
{
    /// <summary>
    /// Lists all enabled certificate authorities with basic info for the public portal.
    /// No authentication required — only returns non-sensitive public certificate metadata.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ListCAs()
    {
        var cas = await db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .Where(ca => ca.IsEnabled && ca.Certificate != null
                && !(ca.Certificate.SubjectDN != null && ca.Certificate.SubjectDN.Contains("System Signing CA")))
            .AsNoTracking()
            .ToListAsync();

        var protocolConfigs = await db.CaProtocolConfigs.AsNoTracking().ToListAsync();

        // Latest full-CRL generation time per CA. CRLs link to a CA via the CRL
        // configuration's TaskId (CrlEntity has no CA id), so resolve
        // CaCertificateId -> TaskId -> max(GeneratedAt) in two bulk queries rather
        // than per-CA round trips inside the loop.
        var caCertIds = cas.Where(c => c.CertificateId.HasValue)
            .Select(c => c.CertificateId!.Value).ToList();
        var crlConfigs = await db.CrlConfigurations.AsNoTracking()
            .Where(j => caCertIds.Contains(j.CaCertificateId) && !j.IsDelta)
            .Select(j => new { j.CaCertificateId, j.TaskId })
            .ToListAsync();
        var crlTaskIds = crlConfigs.Select(c => c.TaskId).ToList();
        var latestCrlByTask = (await db.Crls.AsNoTracking()
            .Where(c => crlTaskIds.Contains(c.TaskId) && !c.IsDelta)
            .GroupBy(c => c.TaskId)
            .Select(g => new { TaskId = g.Key, GeneratedAt = g.Max(x => x.GeneratedAt) })
            .ToListAsync())
            .ToDictionary(x => x.TaskId, x => x.GeneratedAt);
        var lastCrlByCa = new Dictionary<Guid, DateTime>();
        foreach (var cfg in crlConfigs)
            if (latestCrlByTask.TryGetValue(cfg.TaskId, out var gen)
                && (!lastCrlByCa.TryGetValue(cfg.CaCertificateId, out var existing) || gen > existing))
                lastCrlByCa[cfg.CaCertificateId] = gen;

        var result = new List<object>();
        foreach (var ca in cas)
        {
            var label = ca.Label ?? "default";
            var resolved = await caServiceUrls.ResolveForCaAsync(ca.CertificateId!.Value);

            // Build per-CA protocol endpoint URLs, filtered by public visibility AND
            // the system feature flag — a protocol that's disabled system-wide is gated
            // by ProtocolFeatureGateMiddleware, so the portal must not advertise it even
            // if a CA has it locally enabled.
            var protocols = protocolConfigs
                .Where(pc => pc.CaId == ca.Id && pc.IsEnabled && pc.IsPublicVisible
                    && featureFlags.IsEnabled($"{pc.Protocol}.Enabled"))
                .Select(pc => new
                {
                    pc.Protocol,
                    Url = pc.Protocol switch
                    {
                        "EST" => $"/est/{label}/cacerts",
                        "SCEP" => $"/scep/{label}?operation=GetCACert",
                        "CMP" => $"/cmp/{label}",
                        "ACME" => $"/acme/{label}/directory",
                        "OCSP" => $"/ocsp/ca/{label}",
                        // The CES URL a Windows client is pointed at (Group Policy or certreq -config).
                        "MSAE" => $"/msae/{label}/ces",
                        _ => (string?)null
                    }
                })
                .Where(p => p.Url != null)
                .ToList();

            // Parse the stored CA cert to surface its key & signature algorithm — the
            // public portal displays this, and the row carries no algorithm column.
            // Best-effort: leave blank if the stored material can't be parsed rather
            // than failing the whole listing.
            string keyAlgorithm = "", keySize = "", signatureAlgorithm = "";
            try
            {
                var certObj = !string.IsNullOrWhiteSpace(ca.Certificate!.Pem)
                    ? CertificateUtil.ParseFromPem(ca.Certificate.Pem)
                    : ca.Certificate.RawCertificate != null
                        ? new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(ca.Certificate.RawCertificate)
                        : null;
                if (certObj != null)
                {
                    var certInfo = CertificateUtil.ParseCertificate(certObj);
                    keyAlgorithm = certInfo.KeyAlgorithm;
                    keySize = certInfo.KeySize;
                    signatureAlgorithm = certInfo.SignatureAlgorithm;
                }
            }
            catch { /* unparseable stored cert — leave algorithm blank */ }

            DateTime? lastCrlGenerated = null;
            if (ca.CertificateId.HasValue && lastCrlByCa.TryGetValue(ca.CertificateId.Value, out var lg))
                lastCrlGenerated = lg;

            result.Add(new
            {
                ca.Name,
                ca.Label,
                ca.Type,
                ca.IsDefault,
                IsRoot = ca.Type == "Root",
                ca.Certificate!.SerialNumber,
                ca.Certificate.SubjectDN,
                ca.Certificate.Issuer,
                ca.Certificate.NotBefore,
                ca.Certificate.NotAfter,
                LastCrlGenerated = lastCrlGenerated,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                SignatureAlgorithm = signatureAlgorithm,
                CdpUrls = resolved.CdpUrls,
                OcspUrls = resolved.OcspUrls,
                CaIssuerUrls = resolved.CaIssuerUrls,
                Protocols = protocols,
            });
        }

        return Ok(result);
    }

    /// <summary>
    /// Public CA certificate download — returns the CA certificate in DER or PEM format
    /// via standard HTTP content negotiation. Send <c>Accept: application/x-pem-file</c> for PEM.
    /// Defaults to DER (<c>application/pkix-cert</c>) per RFC 5280 AIA conventions.
    /// </summary>
    [HttpGet("{serial}")]
    public async Task<IActionResult> GetCaCert(string serial)
    {
        var cert = await certStore.GetCertificateInfoAsync(serial);
        if (cert == null || !cert.IsCA)
            return NotFound();

        // Filename sanitization routes through the shared DownloadFilenameUtil.
        var cn = DownloadFilenameUtil.ExtractCn(cert.SubjectDN) ?? serial;
        var safeName = DownloadFilenameUtil.SafeDownloadFilename(cn, fallback: "ca-cert");

        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
        if (accept.Contains("application/x-pem-file"))
        {
            if (string.IsNullOrEmpty(cert.Pem))
                return NotFound();
            var pemBytes = System.Text.Encoding.UTF8.GetBytes(cert.Pem);
            return File(pemBytes, "application/x-pem-file", $"{safeName}.pem");
        }

        // Default: DER (RFC 5280 standard for AIA distribution)
        var rawCert = await certStore.GetRawCertificateAsync(serial);
        if (rawCert == null || rawCert.Length == 0)
            return NotFound();
        return File(rawCert, "application/pkix-cert", $"{safeName}.cer");
    }
}
