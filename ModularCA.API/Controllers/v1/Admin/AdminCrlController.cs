using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using System.Text;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin
{
    /// <summary>
    /// Admin endpoints for generating and retrieving CRLs by CA certificate.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/crl")]
    [Authorize(Policy = "CaAuditor")]
    [NodeRole(ProcessRole.Control)]
    public class AdminCrlController(ICrlService crlService, ICertificateStore certStore) : ControllerBase
    {
        private readonly ICrlService _crlService = crlService;
        private readonly ICertificateStore _certStore = certStore;

        /// <summary>
        /// Get the latest CRL by CA certificate database ID (GUID), format based on Accept header.
        /// </summary>
        [HttpGet("by-id/{caId:guid}")]
        public async Task<IActionResult> GetCrlByCaId(Guid caId)
        {
            var cert = await _certStore.GetCertificateByIdAsync(caId);
            if (cert == null)
                return NotFound(new { error = "CA certificate not found for the specified serial number." });
            if (!cert.IsCA)
                return BadRequest(new { error = "The specified certificate is not a CA certificate." });

            var crl = await _crlService.GetLatestCrlAsync(caId);
            if (crl == null)
                return NotFound(new { error = "No CRL found for the specified CA certificate ID." });

            var cnPart = cert.SubjectDN.Split(',')[0].Trim();
            var crlName = cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;

            var accept = Request.Headers["Accept"].ToString();
            if (accept.Contains("application/pkix-crl", StringComparison.OrdinalIgnoreCase))
            {
                // Serve stored DER blob directly — no PEM round-trip.
                var blob = await _crlService.GetLatestCrlRawAsync(caId);
                if (blob == null) return NotFound(new { error = "No CRL found for the specified CA certificate ID." });
                return File(blob.Der, "application/pkix-crl", $"{crlName}.crl");
            }
            else // Default to PEM
            {
                var fileName = $"{crlName}-crl.pem";
                return File(Encoding.UTF8.GetBytes(crl), "application/x-pem-file", fileName);
            }
        }

        /// <summary>
        /// Get the latest CRL by CA certificate serial number, format based on Accept header.
        /// </summary>
        [HttpGet("by-serial/{serial}")]
        public async Task<IActionResult> GetCrlByCaSerial(string serial)
        {
            var cert = await _certStore.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound(new { error = "CA certificate not found for the specified serial number." });
            if (!cert.IsCA)
                return BadRequest(new { error = "The specified certificate is not a CA certificate." });

            var crl = await _crlService.GetLatestCrlAsync(cert.CertificateId);
            if (crl == null)
                return NotFound(new { error = "No CRL found for the specified CA certificate serial number." });

            var cnPart = cert.SubjectDN.Split(',')[0].Trim();
            var crlName = cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;

            var accept = Request.Headers["Accept"].ToString();
            if (accept.Contains("application/pkix-crl", StringComparison.OrdinalIgnoreCase))
            {
                var blob = await _crlService.GetLatestCrlRawAsync(cert.CertificateId);
                if (blob == null) return NotFound(new { error = "No CRL found for the specified CA certificate serial number." });
                return File(blob.Der, "application/pkix-crl", $"{crlName}.crl");
            }
            else // Default to PEM
            {
                var fileName = $"{crlName}-crl.pem";
                return File(Encoding.UTF8.GetBytes(crl), "application/x-pem-file", fileName);
            }
        }
    }
}
