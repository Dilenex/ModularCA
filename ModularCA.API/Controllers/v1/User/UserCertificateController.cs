using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using System.Text;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.User;


/// <summary>
/// User endpoints for viewing, downloading, and exporting certificates the user has access to.
/// </summary>
[ApiController]
[Route("api/v1/user/certificates")]
[Authorize(Policy = "CaUser")]
public class UserCertificateController(
    ICertificateStore certStore,
    ICurrentUserService currentUser,
    ICertificateAccessEvaluator certificateAccessEvaluator,
    ICertificateExportService exportService,
    ICertificateRevocationService revocationService,
    ModularCADbContext dbContext,
    IAuditService auditService,
    IDistributedCache cache
) : ControllerBase
{
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly ICertificateAccessEvaluator _certificateAccessEvaluator = certificateAccessEvaluator;
    private readonly ICertificateExportService _exportService = exportService;
    private readonly ICertificateRevocationService _revocationService = revocationService;
    private readonly ModularCADbContext _dbContext = dbContext;
    private readonly IAuditService _audit = auditService;
    private readonly IDistributedCache _cache = cache;

    /// <summary>
    /// Revocation reasons a user is permitted to select when self-revoking an owned
    /// end-entity certificate. CA-level reasons (<see cref="RevocationReason.CACompromise"/>,
    /// <see cref="RevocationReason.AaCompromise"/>) and the administrative hold state
    /// (<see cref="RevocationReason.CertificateHold"/>) are intentionally excluded — those are
    /// operator decisions, not subscriber-initiated ones.
    /// </summary>
    private static readonly HashSet<RevocationReason> SelfRevokeAllowedReasons =
    [
        RevocationReason.Unspecified,
        RevocationReason.KeyCompromise,
        RevocationReason.AffiliationChanged,
        RevocationReason.Superseded,
        RevocationReason.CessationOfOperation,
        RevocationReason.PrivilegeWithdrawn,
    ];

    /// <summary>
    /// Lists certificates the authenticated user has access to, filtered by tenant scope and access control, with pagination.
    /// </summary>
    /// <param name="page">Page number (1-based). Defaults to 1.</param>
    /// <param name="pageSize">Number of items per page. Defaults to 25, clamped to 1-100.</param>
    /// <returns>A paginated result containing accessible certificates and total count metadata.</returns>
    [HttpGet]
    public async Task<IActionResult> ListCertificates(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25)
    {

        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        // Clamp pagination parameters
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 1;
        if (pageSize > 100) pageSize = 100;

        var certs = await _certStore.ListAsync();

        // Filter to non-CA certs only
        var nonCaCerts = certs
            .Where(c => !c.IsCA && !(c.SubjectDN?.Contains("System Signing CA") ?? false))
            .ToList();

        // Apply tenant filtering for non-system-admins
        var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
        if (tenantIds != null && HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var accessibleCertIds = await _dbContext.CertificateAuthorities
                .Where(ca => tenantIds.Contains(ca.TenantId) && ca.CertificateId != null)
                .Select(ca => ca.CertificateId!.Value)
                .ToListAsync();

            // Get all certificate IDs issued by accessible CAs via signing profiles
            var accessibleSigningProfileIssuerIds = new HashSet<Guid>(accessibleCertIds);
            var accessibleIssuedCertIds = await _dbContext.Certificates
                .Where(c => c.SigningProfileId != null
                    && c.SigningProfile != null
                    && c.SigningProfile.IssuerId != null
                    && accessibleSigningProfileIssuerIds.Contains(c.SigningProfile.IssuerId.Value))
                .Select(c => c.CertificateId)
                .ToListAsync();
            var accessibleSet = new HashSet<Guid>(accessibleIssuedCertIds);
            nonCaCerts = nonCaCerts.Where(c => accessibleSet.Contains(c.CertificateId)).ToList();
        }

        var allowedCerts = new List<CertificateInfoModel>();
        foreach (var nonCaCert in nonCaCerts)
        {
            // check certificate access permissions
            var isAllowed = _certificateAccessEvaluator.CanViewCertificate(_currentUser.User.Id, nonCaCert.CertificateId);
            if (isAllowed)
            {
                allowedCerts.Add(nonCaCert);
            }
        }

        // Order before paging. CertificateStore.ListAsync issues an unordered query, so
        // "page 1" was whatever order MySQL happened to return -- typically insertion order,
        // which puts the NEWEST certificates last. A user with more than pageSize visible
        // certificates therefore never saw a certificate they had just been issued, and rows
        // could repeat or vanish between pages because the underlying order was not stable.
        // Newest first, with the serial as a tie-break so the sequence is total.
        var ordered = allowedCerts
            .OrderByDescending(c => c.NotBefore)
            .ThenBy(c => c.SerialNumber, StringComparer.Ordinal)
            .ToList();

        // Apply pagination after access control filtering
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

    [HttpGet("{serial}")]
    public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();
        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
            return NotFound();
        // Hide CA certs and System cert
        if (cert.IsCA || cert.SubjectDN?.Contains("System Signing CA") == true)
            return NotFound();
        var isAllowed = _certificateAccessEvaluator.CanViewCertificate(_currentUser.User.Id, cert.CertificateId);
        if (!isAllowed)
            return NotFound();

        return Ok(cert);
    }

    [HttpGet("{serial}/file")]
    public async Task<IActionResult> GetCertificate(string serial)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var raw = await _certStore.GetCertificateInfoAsync(serial);
        // Hide CA certs and System cert
        if (raw == null || raw.IsCA || raw.SubjectDN?.Contains("System Signing CA") == true)
            return NotFound();

        var isAllowed = _certificateAccessEvaluator.CanViewCertificate(_currentUser.User.Id, raw.CertificateId);
        if (!isAllowed)
            return NotFound();

        var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
        var certName = CertificateUtil.ParseCnFromPem(raw.Pem);

        if (accept.Contains("application/x-pem-file"))
        {
            var pemBytes = System.Text.Encoding.UTF8.GetBytes(raw.Pem);
            return File(pemBytes, "application/x-pem-file", $"{certName}.pem");
        }

        // Default: DER
        var cert = CertificateUtil.ParseFromPem(raw.Pem);
        return File(cert.GetEncoded(), "application/pkix-cert", $"{certName}.cer");
    }

    /// <summary>
    /// Exports a user-accessible certificate as a PKCS#12 (PFX) file with the private key.
    /// Requires Manage-level access and step-up MFA verification since the export includes the private key.
    /// </summary>
    /// <param name="serial">The serial number of the certificate to export.</param>
    /// <param name="request">Export request containing the password to protect the PFX file.</param>
    /// <param name="mfaToken">Step-up MFA token from X-MFA-Token header.</param>
    /// <returns>The PKCS#12 file as a download, or an error if the certificate is not found or not exportable.</returns>
    [HttpPost("{serial}/export")]
    public async Task<IActionResult> ExportCertificate(string serial, [FromBody] UserCertExportRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ExportCert, serial))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
            return NotFound();

        // Hide CA certs and System cert
        if (cert.IsCA || cert.SubjectDN?.Contains("System Signing CA") == true)
            return NotFound();

        // Require Manage-level access since we are exporting the private key
        if (!_certificateAccessEvaluator.CanManageCertificate(_currentUser.User.Id, cert.CertificateId))
            return NotFound();

        if (string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { error = "Password is required for PFX export." });

        var export = await _exportService.ExportPfxAsync(serial, request.Password, _currentUser.User.Username, includeChain: true);
        switch (export.Outcome)
        {
            case CertificateExportOutcome.NotFound:
                return NotFound(new { error = "Certificate not found." });
            case CertificateExportOutcome.KeyNotHeld:
                // Not a missing certificate: the holder is told where their key went.
                return Conflict(new { error = export.Detail });
            case CertificateExportOutcome.Refused:
                return StatusCode(403, new { error = "The signer refused the export.", detail = export.Detail });
        }
        var pfxBytes = export.Pkcs12!;

        // Audit log the PFX export
        await _audit.LogAsync(
            AuditActionType.CertificateExported,
            _currentUser.User.Id,
            _currentUser.User.Username,
            "Certificate", serial,
            new { Format = "pfx", IncludeChain = true },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return File(pfxBytes, "application/x-pkcs12", $"{serial}.pfx");
    }

    /// <summary>
    /// Initiates renewal of an existing certificate by creating a new CSR request
    /// pre-filled with the same subject, SANs, cert profile, and signing profile.
    /// The user must own the certificate and it must not be revoked.
    /// </summary>
    /// <summary>
    /// Downloads the PEM trust chain for an end-entity certificate, including the leaf and
    /// all intermediate CA certificates. The self-signed root is excluded per RFC 8446 best practice.
    /// </summary>
    /// <param name="serial">The serial number of the certificate.</param>
    /// <returns>A PEM bundle containing the certificate and its issuer chain.</returns>
    [HttpGet("{serial}/chain")]
    public async Task<IActionResult> GetCertificateChain(string serial)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
            return NotFound();

        // Hide CA certs and System cert
        if (cert.IsCA || cert.SubjectDN?.Contains("System Signing CA") == true)
            return NotFound();

        if (!_certificateAccessEvaluator.CanViewCertificate(_currentUser.User.Id, cert.CertificateId))
            return NotFound();

        var chainPems = new List<string> { cert.Pem.Trim() };

        // Find the issuing CA and walk up the hierarchy.
        //
        // Keyed on the ID already resolved above, not on the serial again. The access check a few
        // lines up authorized cert.CertificateId; re-resolving the serial could select a different
        // row (serials are unique only per issuer), and the chain returned would then describe a
        // certificate the caller was never granted.
        var certEntity = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == cert.CertificateId);

        if (certEntity != null && certEntity.SigningProfileId != null)
        {
            // Fetch every CA row in a single query, then walk the ParentCaId
            // chain in memory. Previous code issued one round-trip per hop which dominates
            // latency on deep PKIs and ACME/EST/SCEP `cacerts` responses.
            var allCas = await _dbContext.CertificateAuthorities
                .AsNoTracking()
                .Include(ca => ca.Certificate)
                .ToDictionaryAsync(ca => ca.Id);

            var sigProfile = await _dbContext.SigningProfiles
                .AsNoTracking()
                .FirstOrDefaultAsync(sp => sp.Id == certEntity.SigningProfileId);

            var issuingCa = sigProfile != null
                ? allCas.Values.FirstOrDefault(ca => ca.CertificateId == sigProfile.IssuerId)
                : null;

            var visited = new HashSet<Guid>();
            var directIssuerIsRoot = issuingCa?.ParentCaId == null;

            while (issuingCa?.Certificate != null)
            {
                if (!visited.Add(issuingCa.Id))
                    break;

                // Skip root when intermediates exist; include root when it's the direct issuer
                if (issuingCa.ParentCaId == null && !directIssuerIsRoot)
                    break;

                chainPems.Add(issuingCa.Certificate.Pem.Trim());

                if (issuingCa.ParentCaId == null)
                    break;

                if (!allCas.TryGetValue(issuingCa.ParentCaId.Value, out var nextCa))
                    break;
                issuingCa = nextCa;
            }
        }

        var bundle = string.Join("\n", chainPems) + "\n";
        var certName = CertificateUtil.ParseCnFromPem(cert.Pem);
        var fileName = $"{certName}-fullchain.pem";

        return File(Encoding.UTF8.GetBytes(bundle), "application/x-pem-file", fileName);
    }

    [HttpPost("{serial}/renew")]
    public async Task<IActionResult> RenewCertificate(string serial)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        // Load certificate info
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null)
            return NotFound(new { error = "Certificate not found." });

        // Require Manage-level access — renewal creates a new request that carries forward the
        // original CSR / encrypted private-key references, so it is an ownership-level action and
        // must not be available to view-only grantees. Mirrors the export/revoke access checks.
        if (!_certificateAccessEvaluator.CanManageCertificate(_currentUser.User.Id, certInfo.CertificateId))
            return NotFound(new { error = "Certificate not found." });

        // Verify the certificate is not revoked
        if (certInfo.Revoked)
            return BadRequest(new { error = "Cannot renew a revoked certificate." });

        // Load the certificate entity to get profile IDs
        var certEntity = await _dbContext.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serial);
        if (certEntity == null)
            return NotFound(new { error = "Certificate not found." });

        // Load the original CSR request that produced this certificate
        var originalRequest = await _dbContext.CertificateRequests
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.IssuedCertificateId == certEntity.CertificateId);

        // Use subject and SANs from the certificate itself (may have overrides from the original CSR)
        var subjectDn = certEntity.SubjectDN;
        var sanJson = certEntity.SubjectAlternativeNamesJson;

        // Get profile IDs from the certificate entity; fall back to the original request if needed
        var certProfileId = certEntity.CertProfileId
            ?? originalRequest?.CertProfileId;
        var signingProfileId = certEntity.SigningProfileId
            ?? originalRequest?.SigningProfileId;

        if (certProfileId == null || signingProfileId == null)
            return BadRequest(new { error = "Cannot determine certificate or signing profile for renewal." });

        // Carry forward key parameters from the original request when available
        var keyAlgorithm = originalRequest?.KeyAlgorithm ?? string.Empty;
        var keySize = originalRequest?.KeySize ?? string.Empty;
        var signatureAlgorithm = originalRequest?.SignatureAlgorithm ?? string.Empty;

        // Create the renewal CSR request entity
        var renewalRequest = new CertRequestEntity
        {
            Subject = subjectDn,
            SubjectAlternativeNames = sanJson,
            CSR = originalRequest?.CSR ?? string.Empty,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            SignatureAlgorithm = signatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = "Pending",
            CertProfileId = certProfileId.Value,
            SigningProfileId = signingProfileId.Value,
            RequestorUserId = _currentUser.User.Id,
            RenewalOfCertificateId = certEntity.CertificateId
        };

        _dbContext.CertificateRequests.Add(renewalRequest);
        await _dbContext.SaveChangesAsync();

        return Ok(new { requestId = renewalRequest.Id, message = "Renewal request submitted" });
    }

    /// <summary>
    /// Revokes an end-entity certificate the authenticated user owns (Manage-level access).
    /// Requires step-up MFA. The revocation is permanent and triggers a best-effort CRL
    /// regeneration. CA certificates, the System signing cert, and CA-level revocation reasons
    /// are not permitted through this self-service path.
    /// </summary>
    /// <param name="serial">The serial number of the certificate to revoke.</param>
    /// <param name="request">Revocation request containing the reason and optional invalidity date.</param>
    /// <param name="mfaToken">Step-up MFA token from the X-MFA-Token header.</param>
    /// <returns>The revocation result, or an error if the certificate is not found or not revocable by this user.</returns>
    [HttpPost("{serial}/revoke")]
    public async Task<IActionResult> RevokeOwnCertificate(string serial, [FromBody] UserCertRevokeRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.RevokeSelfCert, serial))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (!SelfRevokeAllowedReasons.Contains(request.Reason))
            return BadRequest(new { error = "The selected revocation reason is not permitted for self-service revocation." });

        var cert = await _certStore.GetCertificateInfoAsync(serial);
        if (cert == null)
            return NotFound();

        // Hide CA certs and System cert — these are never self-revocable.
        if (cert.IsCA || cert.SubjectDN?.Contains("System Signing CA") == true)
            return NotFound();

        // Require Manage-level access since revocation is a destructive, ownership-level action.
        if (!_certificateAccessEvaluator.CanManageCertificate(_currentUser.User.Id, cert.CertificateId))
            return NotFound();

        if (cert.Revoked)
            return BadRequest(new { error = "Certificate is already revoked." });

        RevocationResult result;
        try
        {
            result = await _revocationService.RevokeCertificateAsync(null, serial, request.Reason, request.InvalidityDate);
        }
        catch (InvalidOperationException ex)
        {
            // e.g. concurrent revoke hit the service-level idempotency guard.
            return BadRequest(new { error = ex.Message });
        }

        await _audit.LogAsync(
            AuditActionType.CertificateRevoked,
            _currentUser.User.Id,
            _currentUser.User.Username,
            "Certificate", serial,
            new { Reason = request.Reason.ToString(), SelfService = true, request.InvalidityDate },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            serialNumber = result.SerialNumber,
            status = result.NewStatus,
            reason = result.Reason?.ToString(),
            revocationDate = result.EffectiveAt,
            crlNumber = result.CrlNumber
        });
    }

}

/// <summary>
/// Request model for user-level PKCS#12 certificate export.
/// </summary>
public class UserCertExportRequest
{
    /// <summary>
    /// The password used to protect the exported PFX file. Must not be empty.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Request model for user self-service certificate revocation.
/// </summary>
public class UserCertRevokeRequest
{
    /// <summary>
    /// The reason for revocation. Restricted to subscriber-permissible reasons; CA-level
    /// reasons and the administrative hold state are rejected server-side.
    /// </summary>
    public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;

    /// <summary>
    /// Optional RFC 5280 §5.3.2 invalidity date — when the compromise is believed to have
    /// actually occurred. May precede the revocation date.
    /// </summary>
    public DateTime? InvalidityDate { get; set; }
}

