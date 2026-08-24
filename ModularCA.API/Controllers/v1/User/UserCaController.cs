using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.User
{
    /// <summary>
    /// User endpoints for viewing available Certificate Authorities and their certificates.
    /// </summary>
    [ApiController]
    [Route("api/v1/user/authorities")]
    [Authorize(Policy = "CaUser")]
    public class UserCaController(ICertificateStore certService, ModularCADbContext db) : ControllerBase
    {
        private readonly ICertificateStore _certService = certService;
        private readonly ModularCADbContext _db = db;

        /// <summary>
        /// Lists valid CA certificates visible to the user, filtered by tenant scope, with pagination.
        /// </summary>
        /// <param name="page">Page number (1-based). Defaults to 1.</param>
        /// <param name="pageSize">Number of items per page. Defaults to 25, clamped to 1-100.</param>
        /// <returns>A paginated result containing CA certificates and total count metadata.</returns>
        [HttpGet]
        public async Task<IActionResult> GetValidCaCertificates(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 25)
        {
            // Clamp pagination parameters
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 1;
            if (pageSize > 100) pageSize = 100;

            var certs = await _certService.GetAllCertificatesAsync();

            // Filter to CA certs only, and exclude those with "System Signing CA" in SubjectDN
            var caCerts = certs
                .Where(c => c.IsCA && !(c.SubjectDN?.Contains("System Signing CA") ?? false))
                .ToList();

            // Apply tenant filtering for non-system-admins
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds != null && HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var accessibleCertIds = await _db.CertificateAuthorities
                    .Where(ca => tenantIds.Contains(ca.TenantId) && ca.CertificateId != null)
                    .Select(ca => ca.CertificateId!.Value)
                    .ToListAsync();
                var accessibleCertIdSet = new HashSet<Guid>(accessibleCertIds);
                caCerts = caCerts.Where(c => accessibleCertIdSet.Contains(c.CertificateId)).ToList();
            }

            // Order before paging, for the same reason as UserCertificateController: the
            // underlying store query is unordered, so page boundaries were not stable and rows
            // could repeat or disappear between pages. Alphabetical by subject is the useful
            // order for a trust list; the serial makes the sequence total.
            var ordered = caCerts
                .OrderBy(c => c.SubjectDN, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.SerialNumber, StringComparer.Ordinal)
                .ToList();

            // Apply pagination after filtering
            var total = ordered.Count;
            var pagedItems = ordered
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            return Ok(new
            {
                total,
                page,
                pageSize,
                totalPages = (int)Math.Ceiling((double)total / pageSize),
                items = pagedItems
            });
        }

        /// <summary>
        /// Returns true when the caller's tenant set includes the CA's tenant.
        /// System admins always pass. Returns false when the certificate is not bound to any
        /// CA row — legacy/standalone trust anchors are not exposed through this API surface.
        /// </summary>
        private async Task<bool> CallerCanSeeCaCertAsync(Guid certificateId)
        {
            if (HttpContext.Items["IsSystemAdmin"] is true)
                return true;
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null)
                return false;
            var caTenant = await _db.CertificateAuthorities
                .AsNoTracking()
                .Where(c => c.CertificateId == certificateId)
                .Select(c => (Guid?)c.TenantId)
                .FirstOrDefaultAsync();
            return caTenant.HasValue && tenantIds.Contains(caTenant.Value);
        }

        [HttpGet("{serial}")]
        public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
        {
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();

            // Exclude and hide the System Signing CA from the response
            if (cert.SubjectDN?.Contains("System Signing CA") ?? false)
                return NotFound();

            // Tenant fence. Collapse cross-tenant mismatches to 404 to
            // avoid existence oracles.
            if (!await CallerCanSeeCaCertAsync(cert.CertificateId))
                return NotFound();

            return Ok(cert);
        }

        [HttpGet("{serial}/file")]
        public async Task<IActionResult> GetCertificate(string serial)
        {
            var raw = await _certService.GetCertificateInfoAsync(serial);
            // Hide CA certs and System cert
            if (raw == null || raw.IsCA || raw.SubjectDN?.Contains("System Signing CA") == true)
                return NotFound();

            // Tenant fence.
            if (!await CallerCanSeeCaCertAsync(raw.CertificateId))
                return NotFound();

            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-pem-file") || accept.Contains("application/pem-certificate-chain") || accept.Contains("pem"))
            {
                var certName = CertificateUtil.ParseCnFromPem(raw.Pem);
                var fileName = $"{certName}.pem";
                var pemBytes = System.Text.Encoding.UTF8.GetBytes(raw.Pem);
                return File(pemBytes, "application/x-pem-file", fileName);
            }
            else if (accept.Contains("application/x-x509-ca-cert") || accept.Contains("application/pkix-cert") || accept.Contains("der") || accept.Contains("application/octet-stream"))
            {
                var cert = CertificateUtil.ParseFromPem(raw.Pem);
                var cetName = CertificateUtil.ParseCnFromPem(raw.Pem);
                var fileName = $"{cetName}.cer";
                return File(cert.GetEncoded(), "application/x-x509-ca-cert", fileName);
            }
            return NotFound();
        }

        /// <summary>
        /// Downloads the PEM trust chain for a CA certificate, including the specified CA and all
        /// intermediate issuers. The self-signed root CA is excluded per RFC 8446 best practice.
        /// Every hop in the chain is tenant-checked so a low-privilege user
        /// cannot walk up the hierarchy into another tenant's CA. The walk stops at the first
        /// cross-tenant parent so the caller still receives the in-scope portion of the chain.
        /// </summary>
        [HttpGet("{serial}/chain")]
        public async Task<IActionResult> GetCaChain(string serial)
        {
            var caCert = await _certService.GetCertificateInfoAsync(serial);
            if (caCert == null || !caCert.IsCA)
                return NotFound();

            // Hide System Signing CA
            if (caCert.SubjectDN?.Contains("System Signing CA") ?? false)
                return NotFound();

            // Start-of-chain tenant fence.
            if (!await CallerCanSeeCaCertAsync(caCert.CertificateId))
                return NotFound();

            var isSystemAdmin = HttpContext.Items["IsSystemAdmin"] is true;
            var accessibleTenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;

            var chainPems = new List<string> { caCert.Pem.Trim() };

            // Materialise every CA (and its public certificate) in a single
            // query then walk the ParentCaId chain in memory. Previously this loop issued one
            // DB round-trip per hop up the hierarchy. O(N) hops now cost a single query.
            var allCas = await _db.CertificateAuthorities
                .AsNoTracking()
                .Include(ca => ca.Certificate)
                .ToDictionaryAsync(ca => ca.Id);

            var currentCa = allCas.Values.FirstOrDefault(ca => ca.CertificateId == caCert.CertificateId);

            if (currentCa != null)
            {
                var visited = new HashSet<Guid> { currentCa.Id };
                var parentCaId = currentCa.ParentCaId;
                var directParentIsRoot = false;

                if (parentCaId != null && allCas.TryGetValue(parentCaId.Value, out var directParent))
                    directParentIsRoot = directParent.ParentCaId == null;

                while (parentCaId != null)
                {
                    if (!visited.Add(parentCaId.Value))
                        break;

                    if (!allCas.TryGetValue(parentCaId.Value, out var parentCa) || parentCa.Certificate == null)
                        break;

                    // Skip root when intermediates exist; include when it's the direct parent
                    if (parentCa.ParentCaId == null && !directParentIsRoot)
                        break;

                    // Tenant check every hop — stop the walk at the first
                    // cross-tenant parent instead of adding that parent's PEM to the bundle.
                    if (!isSystemAdmin && (accessibleTenantIds == null || !accessibleTenantIds.Contains(parentCa.TenantId)))
                        break;

                    chainPems.Add(parentCa.Certificate.Pem.Trim());

                    if (parentCa.ParentCaId == null)
                        break;

                    parentCaId = parentCa.ParentCaId;
                }
            }

            var bundle = string.Join("\n", chainPems) + "\n";
            var certName = CertificateUtil.ParseCnFromPem(caCert.Pem);
            var fileName = $"{certName}-chain.pem";

            return File(Encoding.UTF8.GetBytes(bundle), "application/x-pem-file", fileName);
        }

        /// <summary>
        /// Redirects to the public CRL distribution point for the specified CA certificate.
        /// </summary>
        [HttpGet("{serial}/crl")]
        public IActionResult GetCaCrl(string serial)
        {
            return Redirect($"/crl/{serial}");
        }
    }

}
