using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Utils;
using Serilog;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.Integration;

/// <summary>
/// Infrastructure-as-code integration endpoints for Terraform, Ansible, and similar tools.
/// Provides a predictable, idempotent REST API for certificate lifecycle management,
/// profile discovery, and CA enumeration. Authenticated via a static API key
/// in the X-API-Key header (configured in IntegrationApi.ApiKey).
/// AUTH-06: when <see cref="IntegrationApiConfig.TenantId"/> is configured, all operations
/// are scoped to CAs belonging to that tenant.
/// </summary>
[ApiController]
[Route("api/v1/integration/infra")]
[AllowAnonymous]
[ApiKeyAuth]
public class InfraController(
    ICsrService csrService,
    ICertificateIssuanceService issuanceService,
    ICertificateStore certStore,
    ICertificateRevocationService revocationService,
    ICertProfileService certProfileService,
    ISigningProfileService signingProfileService,
    RequestProfileService requestProfileService,
    ModularCADbContext db,
    SystemConfig config
) : ControllerBase
{
    private readonly ICsrService _csrService = csrService;
    private readonly ICertificateIssuanceService _issuanceService = issuanceService;
    private readonly ICertificateStore _certStore = certStore;
    private readonly ICertificateRevocationService _revocationService = revocationService;
    private readonly ICertProfileService _certProfileService = certProfileService;
    private readonly ISigningProfileService _signingProfileService = signingProfileService;
    private readonly RequestProfileService _requestProfileService = requestProfileService;
    private readonly ModularCADbContext _db = db;
    private readonly SystemConfig _config = config;

    // ───────────────────────── Certificate Lifecycle ─────────────────────────

    /// <summary>
    /// Issues a certificate from a PEM-encoded CSR. Uploads the CSR, auto-approves it,
    /// and immediately issues the certificate. Returns the certificate with an id field
    /// suitable for Terraform state tracking.
    /// Returns 400 on invalid input or issuance failure (InvalidOperationException),
    /// 502 when issuance succeeds but the follow-up state read fails (to prevent
    /// Terraform retry causing double-issue), and 500 on unknown server-side anomalies.
    /// </summary>
    /// <param name="request">The certificate issuance request containing the CSR and profile IDs.</param>
    /// <returns>The issued certificate details including PEM, chain, and metadata.</returns>
    [HttpPost("certificates")]
    public async Task<IActionResult> IssueCertificate([FromBody] InfraIssueCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Csr))
            return BadRequest(new { error = "CSR is required." });

        if (request.CertProfileId == Guid.Empty)
            return BadRequest(new { error = "certProfileId is required." });

        if (request.SigningProfileId == Guid.Empty)
            return BadRequest(new { error = "signingProfileId is required." });

        // AUTH-06: verify the signing profile's CA belongs to the configured tenant
        var tenantCheck = await VerifySigningProfileTenantAsync(request.SigningProfileId);
        if (tenantCheck != null)
            return tenantCheck;

        try
        {
            // Upload CSR with optional overrides. Use a zero GUID as the system user for API key auth.
            var csrIdString = await _csrService.UploadCsrAsync(
                request.Csr,
                request.CertProfileId,
                request.SigningProfileId,
                Guid.Empty,
                request.SubjectOverrides,
                request.SanOverrides);

            if (!Guid.TryParse(csrIdString, out var csrId))
                return StatusCode(502, new { error = "CSR was uploaded but the returned ID could not be parsed; try fetching by serial later." });

            // Auto-approve and issue
            var issuanceResult = await _issuanceService.IssueCertificateAsync(csrId, null, null);
            var certPem = issuanceResult.Pem;

            // Look up the issued certificate
            var certDer = CertificateUtil.ParseFromPem(certPem);
            var serial = CertificateUtil.FormatSerialNumber(certDer.SerialNumber);
            var certInfo = await _certStore.GetCertificateInfoAsync(serial);

            if (certInfo == null)
                return StatusCode(502, new { error = "Certificate was issued but the follow-up state read failed; fetch by serial later to retrieve it." });

            var chainPem = await BuildChainPemAsync(certInfo.Pem);

            return Ok(new InfraCertificateResponse
            {
                Id = certInfo.SerialNumber,
                SerialNumber = certInfo.SerialNumber,
                SubjectDn = certInfo.SubjectDN,
                Issuer = certInfo.Issuer,
                NotBefore = certInfo.NotBefore,
                NotAfter = certInfo.NotAfter,
                Pem = certInfo.Pem,
                ChainPem = chainPem,
                Revoked = certInfo.Revoked,
                SubjectAlternativeNames = certInfo.SubjectAlternativeNames
            });
        }
        catch (InvalidOperationException ex)
        {
            Log.Error(ex, "Infrastructure certificate issuance failed (invalid operation)");
            return BadRequest(new { error = "Certificate issuance failed. Contact administrator if the problem persists." });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Infrastructure certificate issuance failed");
            return StatusCode(500, new { error = "Certificate issuance failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// Retrieves certificate details by serial number. Returns the certificate with
    /// full PEM and chain data suitable for Terraform state refresh.
    /// </summary>
    /// <param name="serial">The serial number of the certificate.</param>
    /// <returns>The certificate details or 404 if not found.</returns>
    [HttpGet("certificates/{serial}")]
    public async Task<IActionResult> GetCertificate(string serial)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null)
            return NotFound(new { error = "Certificate not found." });

        // AUTH-06: verify the certificate's issuing CA belongs to the configured tenant
        var tenantCheck = await VerifyCertificateTenantBySerialAsync(serial);
        if (tenantCheck != null)
            return tenantCheck;

        var chainPem = await BuildChainPemAsync(certInfo.Pem);

        return Ok(new InfraCertificateResponse
        {
            Id = certInfo.SerialNumber,
            SerialNumber = certInfo.SerialNumber,
            SubjectDn = certInfo.SubjectDN,
            Issuer = certInfo.Issuer,
            NotBefore = certInfo.NotBefore,
            NotAfter = certInfo.NotAfter,
            Pem = certInfo.Pem,
            ChainPem = chainPem,
            Revoked = certInfo.Revoked,
            RevocationReason = certInfo.Revoked ? certInfo.RevocationReason : null,
            SubjectAlternativeNames = certInfo.SubjectAlternativeNames
        });
    }

    /// <summary>
    /// Revokes a certificate by serial number. Idempotent: revoking an already-revoked
    /// certificate returns success. The optional reason defaults to "unspecified".
    /// </summary>
    /// <param name="serial">The serial number of the certificate to revoke.</param>
    /// <param name="request">Optional revocation reason.</param>
    /// <returns>Confirmation of revocation with the certificate's current state.</returns>
    [HttpDelete("certificates/{serial}")]
    public async Task<IActionResult> RevokeCertificate(string serial, [FromBody] InfraRevokeCertificateRequest? request)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null)
            return NotFound(new { error = "Certificate not found." });

        // AUTH-06: verify the certificate's issuing CA belongs to the configured tenant
        var tenantCheck = await VerifyCertificateTenantBySerialAsync(serial);
        if (tenantCheck != null)
            return tenantCheck;

        // Idempotent: if already revoked, return success
        if (certInfo.Revoked)
        {
            return Ok(new
            {
                id = certInfo.SerialNumber,
                serialNumber = certInfo.SerialNumber,
                revoked = true,
                revocationReason = certInfo.RevocationReason,
                message = "Certificate was already revoked."
            });
        }

        // Parse and validate the revocation reason string against the enum.
        // Unknown values return 400 instead of silently being stored as "unspecified" garbage.
        ModularCA.Shared.Enums.RevocationReason reasonEnum;
        if (string.IsNullOrWhiteSpace(request?.Reason))
        {
            reasonEnum = ModularCA.Shared.Enums.RevocationReason.Unspecified;
        }
        else if (!Enum.TryParse(request!.Reason, ignoreCase: true, out reasonEnum))
        {
            return BadRequest(new
            {
                error = $"Invalid revocation reason '{request.Reason}'. Expected one of: {string.Join(", ", Enum.GetNames<ModularCA.Shared.Enums.RevocationReason>())}.",
            });
        }

        try
        {
            await _revocationService.RevokeCertificateAsync(null, serial, reasonEnum);

            return Ok(new
            {
                id = certInfo.SerialNumber,
                serialNumber = certInfo.SerialNumber,
                revoked = true,
                revocationReason = reasonEnum.ToString(),
                message = "Certificate revoked."
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Infrastructure certificate revocation failed for serial {Serial}", serial);
            return StatusCode(500, new { error = "Certificate revocation failed. Contact administrator if the problem persists." });
        }
    }

    /// <summary>
    /// Renews a certificate by serial number. Creates a new certificate request based on the
    /// original certificate's subject, SANs, and profile configuration, then issues it immediately.
    /// Returns the new certificate with Terraform-compatible id and PEM output.
    /// Returns 404 when the source certificate is missing, 400 for invalid renewal input
    /// (e.g. revoked source, missing profile), 502 when renewal succeeds but the follow-up
    /// state read fails (to prevent Terraform retry causing double-issue), and 500 on unknown
    /// server-side anomalies.
    /// </summary>
    /// <param name="serial">The serial number of the certificate to renew.</param>
    /// <returns>The newly issued certificate details.</returns>
    [HttpPost("certificates/{serial}/renew")]
    public async Task<IActionResult> RenewCertificate(string serial)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null)
            return NotFound(new { error = "Certificate not found." });

        if (certInfo.Revoked)
            return BadRequest(new { error = "Cannot renew a revoked certificate." });

        // Look up the certificate entity to get profile IDs
        var certEntity = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serial);
        if (certEntity == null)
            return NotFound(new { error = "Certificate not found." });

        // Find the original CSR request to carry forward profile and key info
        var originalRequest = await _db.CertificateRequests
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.IssuedCertificateId == certEntity.CertificateId);

        var certProfileId = certEntity.CertProfileId ?? originalRequest?.CertProfileId;
        var signingProfileId = certEntity.SigningProfileId ?? originalRequest?.SigningProfileId;

        if (certProfileId == null || signingProfileId == null)
            return BadRequest(new { error = "Cannot determine certificate or signing profile for renewal." });

        // AUTH-06: verify the signing profile's CA belongs to the configured tenant
        var tenantCheck = await VerifySigningProfileTenantAsync(signingProfileId.Value);
        if (tenantCheck != null)
            return tenantCheck;

        try
        {
            // Reissue using the existing certificate
            var reissueResult = await _issuanceService.ReissueCertificateAsync(
                certEntity.CertificateId, null, null, null, null);
            var newCertPem = reissueResult.Pem;

            var newCertDer = CertificateUtil.ParseFromPem(newCertPem);
            var newSerial = CertificateUtil.FormatSerialNumber(newCertDer.SerialNumber);
            var newCertInfo = await _certStore.GetCertificateInfoAsync(newSerial);

            if (newCertInfo == null)
                return StatusCode(502, new { error = "Renewal succeeded but the follow-up state read failed; fetch by serial later to retrieve the new certificate." });

            var chainPem = await BuildChainPemAsync(newCertInfo.Pem);

            return Ok(new InfraCertificateResponse
            {
                Id = newCertInfo.SerialNumber,
                SerialNumber = newCertInfo.SerialNumber,
                SubjectDn = newCertInfo.SubjectDN,
                Issuer = newCertInfo.Issuer,
                NotBefore = newCertInfo.NotBefore,
                NotAfter = newCertInfo.NotAfter,
                Pem = newCertInfo.Pem,
                ChainPem = chainPem,
                Revoked = newCertInfo.Revoked,
                SubjectAlternativeNames = newCertInfo.SubjectAlternativeNames
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Infrastructure certificate renewal failed for serial {Serial}", serial);
            return StatusCode(500, new { error = "Certificate renewal failed. Contact administrator if the problem persists." });
        }
    }

    // ───────────────────────── Profile Read Endpoints ��────────────────────────

    /// <summary>
    /// Lists all certificate profiles. Used by Terraform data sources to discover
    /// available profiles for certificate issuance.
    /// </summary>
    /// <returns>A list of all certificate profiles.</returns>
    [HttpGet("cert-profiles")]
    public async Task<IActionResult> ListCertProfiles()
    {
        var profiles = await _certProfileService.GetAllAsync();
        return Ok(profiles);
    }

    /// <summary>
    /// Lists all signing profiles. Used by Terraform data sources to discover
    /// available signing profiles for certificate issuance.
    /// </summary>
    /// <returns>A list of all signing profiles.</returns>
    [HttpGet("signing-profiles")]
    public async Task<IActionResult> ListSigningProfiles()
    {
        var profiles = await _signingProfileService.GetAllAsync();
        return Ok(profiles);
    }

    /// <summary>
    /// Lists all request profiles. Used by Terraform data sources to discover
    /// available request profiles and their enrollment constraints.
    /// </summary>
    /// <returns>A list of all request profiles.</returns>
    [HttpGet("request-profiles")]
    public async Task<IActionResult> ListRequestProfiles()
    {
        var profiles = await _requestProfileService.GetAllAsync();
        return Ok(profiles);
    }

    // ──���────────────────────── CA Read Endpoints ────��────────────────────

    /// <summary>
    /// Lists all enabled Certificate Authorities. Returns CA metadata including
    /// certificate serial number and subject DN for Terraform data source lookups.
    /// </summary>
    /// <returns>A list of all CAs with their basic metadata.</returns>
    [HttpGet("authorities")]
    public async Task<IActionResult> ListAuthorities()
    {
        var tenantId = _config.IntegrationApi.TenantId;
        var cas = await _db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .AsNoTracking()
            .Where(ca => ca.IsEnabled && (tenantId == null || ca.TenantId == tenantId.Value))
            .ToListAsync();

        var result = cas.Select(ca => new
        {
            id = ca.Label ?? ca.Id.ToString(),
            ca.Id,
            ca.Name,
            ca.Label,
            ca.Type,
            IsRoot = ca.Type == "Root",
            ca.IsDefault,
            certificateSerial = ca.Certificate?.SerialNumber,
            subjectDn = ca.Certificate?.SubjectDN,
            notAfter = ca.Certificate?.NotAfter
        });

        return Ok(result);
    }

    /// <summary>
    /// Retrieves a Certificate Authority by its label. Returns CA metadata and
    /// the CA certificate PEM for trust anchor configuration in Terraform.
    /// </summary>
    /// <param name="label">The unique label of the Certificate Authority.</param>
    /// <returns>The CA details including certificate PEM, or 404 if not found.</returns>
    [HttpGet("authorities/{label}")]
    public async Task<IActionResult> GetAuthorityByLabel(string label)
    {
        var tenantId = _config.IntegrationApi.TenantId;
        var ca = await _db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.Label == label && ca.IsEnabled
                && (tenantId == null || ca.TenantId == tenantId.Value));

        if (ca == null)
            return NotFound(new { error = $"CA with label '{label}' not found or disabled." });

        return Ok(new
        {
            id = ca.Label ?? ca.Id.ToString(),
            ca.Id,
            ca.Name,
            ca.Label,
            ca.Type,
            IsRoot = ca.Type == "Root",
            ca.IsDefault,
            certificateSerial = ca.Certificate?.SerialNumber,
            subjectDn = ca.Certificate?.SubjectDN,
            notBefore = ca.Certificate?.NotBefore,
            notAfter = ca.Certificate?.NotAfter,
            pem = ca.Certificate?.Pem
        });
    }

    // ���──────────────────────── Helpers ─────────────────────────

    /// <summary>
    /// AUTH-06: verifies that the signing profile's issuing CA belongs to the configured
    /// tenant. Returns null if the check passes (or no tenant restriction is configured),
    /// or an <see cref="IActionResult"/> to short-circuit the action if the tenant does not match.
    /// </summary>
    private async Task<IActionResult?> VerifySigningProfileTenantAsync(Guid signingProfileId)
    {
        var tenantId = _config.IntegrationApi.TenantId;
        if (tenantId == null)
            return null;

        var signingProfile = await _db.SigningProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(sp => sp.Id == signingProfileId);

        if (signingProfile?.IssuerId == null)
            return TenantFenceDenied("the target's issuing CA could not be determined.");

        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.CertificateId == signingProfile.IssuerId);

        if (ca == null)
            return TenantFenceDenied("the target's issuing CA could not be determined.");

        if (ca.TenantId != tenantId.Value)
        {
            Log.Warning("AUTH-06: integration API tenant isolation violation — API key tenant {ConfiguredTenant} attempted to use CA {CaId} belonging to tenant {CaTenant}",
                tenantId.Value, ca.Id, ca.TenantId);
            return new ObjectResult(new { error = "Access denied: the target CA does not belong to the configured tenant." })
            {
                StatusCode = 403
            };
        }

        return null;
    }

    /// <summary>
    /// AUTH-06: verifies that a certificate (by serial) was issued by a CA belonging to
    /// the configured tenant. Returns null if the check passes, or an <see cref="IActionResult"/>
    /// to short-circuit the action if the tenant does not match.
    /// </summary>
    /// <summary>
    /// The tenant fence's DENY result. Used wherever the fence cannot positively establish that
    /// the target belongs to the configured tenant.
    /// </summary>
    /// <remarks>
    /// Every "cannot determine" path in this fence used to `return null`, which is the ALLOW
    /// sentinel — so a certificate the lookup could not resolve, or one with no SigningProfileId,
    /// sailed through. MtlsController persists mTLS login certificates without a
    /// SigningProfileId at all, so a key scoped to tenant A could read another tenant's admin
    /// mTLS certificate and revoke it. An unestablished tenant is not a matching tenant.
    /// </remarks>
    private static IActionResult TenantFenceDenied(string reason) =>
        new ObjectResult(new { error = $"Access denied: {reason}" }) { StatusCode = 403 };

    private async Task<IActionResult?> VerifyCertificateTenantBySerialAsync(string serial)
    {
        var tenantId = _config.IntegrationApi.TenantId;
        if (tenantId == null)
            return null;

        var certEntity = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serial);

        if (certEntity == null)
            return TenantFenceDenied("the target certificate could not be found.");

        // Walk from the cert's signing profile to the issuing CA
        var signingProfileId = certEntity.SigningProfileId;
        if (signingProfileId == null)
            return TenantFenceDenied("the target certificate is not associated with a signing profile, "
                                   + "so its owning tenant cannot be established.");

        return await VerifySigningProfileTenantAsync(signingProfileId.Value);
    }

    /// <summary>
    /// Builds the full PEM certificate chain by walking up the CA hierarchy
    /// from the issuing CA to the root. Returns the concatenated PEM bundle
    /// (issuer chain only, not including the leaf certificate).
    /// </summary>
    private async Task<string> BuildChainPemAsync(string leafPem)
    {
        try
        {
            var leafCert = CertificateUtil.ParseFromPem(leafPem);
            var issuerDn = leafCert.IssuerDN.ToString();

            // Find the issuing CA certificate by matching its SubjectDN to our Issuer
            var issuerCertEntity = await _db.Certificates
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.SubjectDN == issuerDn && c.IsCA);

            if (issuerCertEntity == null)
                return string.Empty;

            var chainPems = new List<string> { issuerCertEntity.Pem.Trim() };

            // Walk up the CA hierarchy
            var currentCa = await _db.CertificateAuthorities
                .Include(ca => ca.Certificate)
                .AsNoTracking()
                .FirstOrDefaultAsync(ca => ca.CertificateId == issuerCertEntity.CertificateId);

            if (currentCa != null)
            {
                var visited = new HashSet<Guid> { currentCa.Id };
                var parentCaId = currentCa.ParentCaId;

                while (parentCaId.HasValue && visited.Count < 10)
                {
                    var parentCa = await _db.CertificateAuthorities
                        .Include(ca => ca.Certificate)
                        .AsNoTracking()
                        .FirstOrDefaultAsync(ca => ca.Id == parentCaId.Value);

                    if (parentCa?.Certificate == null)
                        break;

                    visited.Add(parentCa.Id);
                    chainPems.Add(parentCa.Certificate.Pem.Trim());
                    parentCaId = parentCa.ParentCaId;
                }
            }

            return string.Join("\n", chainPems) + "\n";
        }
        catch
        {
            return string.Empty;
        }
    }
}

// ──��────────────────────── Request / Response Models ─────────────────────────

/// <summary>
/// Request body for issuing a certificate from a PEM-encoded CSR via the infrastructure API.
/// </summary>
public class InfraIssueCertificateRequest
{
    /// <summary>PEM-encoded PKCS#10 certificate signing request.</summary>
    public string Csr { get; set; } = string.Empty;

    /// <summary>ID of the certificate profile that defines extensions, key usage, and validity constraints.</summary>
    public Guid CertProfileId { get; set; }

    /// <summary>ID of the signing profile that determines the issuing CA and signature algorithm.</summary>
    public Guid SigningProfileId { get; set; }

    /// <summary>
    /// Optional subject DN component overrides. Keys are RDN types (CN, O, OU, L, ST, C).
    /// When provided, these replace the corresponding values from the CSR subject.
    /// </summary>
    public Dictionary<string, string>? SubjectOverrides { get; set; }

    /// <summary>
    /// Optional SAN overrides. When provided, these replace the SANs embedded in the CSR.
    /// Each entry specifies a type (DNS, IP, Email, URI) and value.
    /// </summary>
    public List<SanOverride>? SanOverrides { get; set; }
}

/// <summary>
/// Request body for revoking a certificate via the infrastructure API.
/// </summary>
public class InfraRevokeCertificateRequest
{
    /// <summary>
    /// Revocation reason per RFC 5280 (e.g., "keyCompromise", "cessationOfOperation", "unspecified").
    /// Defaults to "unspecified" when omitted.
    /// </summary>
    public string? Reason { get; set; }
}

/// <summary>
/// Terraform-compatible certificate response with an id field for state tracking.
/// All fields use consistent naming for HCL attribute mapping.
/// </summary>
public class InfraCertificateResponse
{
    /// <summary>Unique identifier for Terraform state tracking. Set to the certificate serial number.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Certificate serial number in colon-delimited hex format.</summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>Full subject distinguished name (e.g., "CN=example.com, O=Acme Corp").</summary>
    public string SubjectDn { get; set; } = string.Empty;

    /// <summary>Issuer distinguished name.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>Certificate validity start time (UTC).</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>Certificate validity end time (UTC).</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>PEM-encoded leaf certificate.</summary>
    public string Pem { get; set; } = string.Empty;

    /// <summary>PEM-encoded issuer certificate chain (does not include the leaf).</summary>
    public string ChainPem { get; set; } = string.Empty;

    /// <summary>Whether the certificate has been revoked.</summary>
    public bool Revoked { get; set; }

    /// <summary>Revocation reason if the certificate is revoked, null otherwise.</summary>
    public string? RevocationReason { get; set; }

    /// <summary>Subject alternative names on the certificate.</summary>
    public List<string> SubjectAlternativeNames { get; set; } = new();
}
