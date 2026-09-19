using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Integration;

/// <summary>
/// Integration endpoints for Kubernetes cert-manager external issuer.
/// Authenticates via <c>X-API-Key</c> header (no JWT/MFA) to support
/// machine-to-machine certificate signing workflows.
/// </summary>
[ApiController]
[Route("api/v1/integration/cert-manager")]
[AllowAnonymous]
[ServiceFilter(typeof(CertManagerApiKeyFilter))]
[NodeRole(ProcessRole.Enrollment)]
public class CertManagerController : ControllerBase
{
    private readonly ModularCADbContext _db;
    private readonly ICertificateIssuanceService _issuanceService;
    private readonly SystemConfig _config;
    private readonly IAuditService _audit;
    private readonly ILogger<CertManagerController> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="CertManagerController"/>.
    /// </summary>
    /// <param name="db">Database context for CSR and certificate operations.</param>
    /// <param name="issuanceService">Service for issuing certificates from CSRs.</param>
    /// <param name="config">System configuration containing cert-manager settings.</param>
    /// <param name="audit">Audit logging service.</param>
    /// <param name="logger">Logger instance.</param>
    public CertManagerController(
        ModularCADbContext db,
        ICertificateIssuanceService issuanceService,
        SystemConfig config,
        IAuditService audit,
        ILogger<CertManagerController> logger)
    {
        _db = db;
        _issuanceService = issuanceService;
        _config = config;
        _audit = audit;
        _logger = logger;
    }

    /// <summary>
    /// Signs a CSR submitted by cert-manager. Decodes the base64-encoded PEM CSR,
    /// validates it against the specified (or default) certificate and signing profiles,
    /// issues the certificate, and returns the signed certificate and CA chain in base64 PEM format.
    /// </summary>
    /// <param name="request">The signing request containing the CSR and metadata.</param>
    /// <returns>The signed certificate and CA certificate in base64 PEM format.</returns>
    [HttpPost("sign")]
    public async Task<IActionResult> Sign([FromBody] CertManagerSignRequest request)
    {
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (string.IsNullOrWhiteSpace(request.Csr))
            return BadRequest(new { error = "CSR is required" });

        // Decode the CSR from base64 — cert-manager sends the PEM as base64
        string csrPem;
        try
        {
            var csrBytes = Convert.FromBase64String(request.Csr);
            csrPem = System.Text.Encoding.UTF8.GetString(csrBytes);

            // If the decoded result is not PEM, treat the original input as raw PEM
            if (!csrPem.Contains("BEGIN CERTIFICATE REQUEST"))
                csrPem = request.Csr;
        }
        catch (FormatException)
        {
            // Not valid base64 — assume it is already PEM
            csrPem = request.Csr;
        }

        if (!csrPem.Contains("BEGIN CERTIFICATE REQUEST"))
            return BadRequest(new { error = "Invalid CSR: expected PEM-encoded PKCS#10 certificate request" });

        // Parse the CSR to extract metadata
        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "cert-manager sign request contained invalid CSR");
            return BadRequest(new { error = "Invalid CSR. The submitted certificate signing request could not be parsed." });
        }

        // Resolve cert profile: request > config default
        var certProfileId = request.ProfileId ?? _config.CertManager.DefaultCertProfileId;
        if (certProfileId == null)
            return BadRequest(new { error = "No certificate profile specified and no default configured" });

        var certProfile = await _db.CertProfiles.FindAsync(certProfileId.Value);
        if (certProfile == null)
            return BadRequest(new { error = $"Certificate profile not found: {certProfileId}" });

        // Resolve signing profile from config default
        var signingProfileId = _config.CertManager.DefaultSigningProfileId;
        if (signingProfileId == null)
            return BadRequest(new { error = "No signing profile configured for cert-manager integration" });

        var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId.Value);
        if (signingProfile == null)
            return BadRequest(new { error = $"Signing profile not found: {signingProfileId}" });

        // AUTH-06: verify the signing profile's issuing CA belongs to the configured tenant
        var tenantCheck = await VerifySigningProfileTenantAsync(signingProfile);
        if (tenantCheck != null)
            return tenantCheck;

        // Calculate validity period
        var notBefore = DateTime.UtcNow;
        DateTime notAfter;

        if (!string.IsNullOrWhiteSpace(request.Duration))
        {
            var duration = ParseGoDuration(request.Duration);
            if (duration == null)
                return BadRequest(new { error = $"Invalid duration format: {request.Duration}. Expected Go-style (e.g., '8760h') or ISO 8601 (e.g., 'P365D')." });
            notAfter = notBefore.Add(duration.Value);
        }
        else
        {
            // Fall back to profile max validity
            var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
            notAfter = notBefore.Add(maxValidity);
        }

        // Create the CSR entity in the database
        var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);
        var csrEntity = new CertRequestEntity
        {
            Subject = parsedCsr.SubjectName,
            SubjectAlternativeNames = sanJson,
            CSR = csrPem,
            KeyAlgorithm = parsedCsr.KeyAlgorithm,
            KeySize = parsedCsr.KeySize,
            SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = "Pending",
            CertProfileId = certProfileId.Value,
            CertProfile = certProfile,
            SigningProfileId = signingProfileId.Value,
            SigningProfile = signingProfile
        };

        _db.CertificateRequests.Add(csrEntity);
        await _db.SaveChangesAsync();

        // Issue the certificate
        string certPem;
        try
        {
            var issuanceResult = await _issuanceService.IssueCertificateAsync(
                csrEntity.Id, notBefore, notAfter);
            certPem = issuanceResult.Pem;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "cert-manager certificate issuance failed for CSR {CsrId}", csrEntity.Id);

            await _audit.LogAsync(AuditActionType.CertManagerSignFailed, null, "cert-manager",
                "CertificateRequest", csrEntity.Id.ToString(),
                new { Subject = parsedCsr.SubjectName, Namespace = request.Namespace, Name = request.Name, Error = "Certificate issuance failed" },
                sourceIp, success: false, errorMessage: "Certificate issuance failed");

            return StatusCode(500, new { error = "Certificate issuance failed. Contact administrator if the problem persists." });
        }

        // Retrieve the CA certificate PEM for the response
        string caPem = await GetCaCertPemAsync(signingProfile);

        // Encode both as base64 for the cert-manager response
        var certBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(certPem));
        var caBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(caPem));

        // Retrieve issued cert serial for audit
        var issuedCert = await _db.CertificateRequests
            .Where(c => c.Id == csrEntity.Id)
            .Select(c => c.IssuedCertificate)
            .FirstOrDefaultAsync();

        await _audit.LogAsync(AuditActionType.CertManagerSignCompleted, null, "cert-manager",
            "Certificate", issuedCert?.SerialNumber,
            new { Subject = parsedCsr.SubjectName, Namespace = request.Namespace, Name = request.Name },
            sourceIp);

        MetricsService.ProtocolRequestsTotal.WithLabels("CertManager", "ok").Inc();

        _logger.LogInformation("cert-manager: issued certificate for {Subject} (ns={Namespace}, name={Name})",
            parsedCsr.SubjectName, request.Namespace, request.Name);

        return Ok(new CertManagerSignResponse
        {
            Certificate = certBase64,
            Ca = caBase64
        });
    }

    /// <summary>
    /// Health check endpoint for cert-manager. Returns a simple readiness status
    /// that cert-manager uses to verify the external issuer is operational.
    /// </summary>
    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(new { ready = true });
    }

    /// <summary>
    /// AUTH-06: verifies that the signing profile's issuing CA belongs to the configured
    /// tenant. Returns null if the check passes (or no tenant restriction is configured),
    /// or an <see cref="IActionResult"/> to short-circuit the action if the tenant does not match.
    /// </summary>
    private async Task<IActionResult?> VerifySigningProfileTenantAsync(SigningProfileEntity signingProfile)
    {
        var tenantId = _config.CertManager.TenantId;
        if (tenantId == null)
            return null;

        if (signingProfile.IssuerId == null)
            return null;

        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.CertificateId == signingProfile.IssuerId);

        if (ca == null)
            return null;

        if (ca.TenantId != tenantId.Value)
        {
            _logger.LogWarning("AUTH-06: cert-manager tenant isolation violation — API key tenant {ConfiguredTenant} attempted to use CA {CaId} belonging to tenant {CaTenant}",
                tenantId.Value, ca.Id, ca.TenantId);
            return new ObjectResult(new { error = "Access denied: the target CA does not belong to the configured tenant." })
            {
                StatusCode = 403
            };
        }

        return null;
    }

    /// <summary>
    /// Retrieves the PEM-encoded CA certificate for the signing profile's issuer.
    /// Walks the issuer chain to collect the full CA chain if intermediate CAs exist.
    /// </summary>
    /// <param name="signingProfile">The signing profile whose issuer chain to resolve.</param>
    /// <returns>The PEM-encoded CA certificate chain.</returns>
    private async Task<string> GetCaCertPemAsync(SigningProfileEntity signingProfile)
    {
        var pems = new List<string>();
        var visited = new HashSet<Guid>();
        var issuerId = signingProfile.IssuerId;

        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuerEntity = await _db.Certificates
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
            if (issuerEntity == null) break;

            pems.Add(issuerEntity.Pem);
            issuerId = issuerEntity.SigningProfile?.IssuerId;
        }

        return string.Join("\n", pems);
    }

    /// <summary>
    /// Parses a Go-style duration string (e.g., "8760h", "30m", "24h30m") or ISO 8601 duration
    /// into a <see cref="TimeSpan"/>. Returns null if the format is unrecognized.
    /// </summary>
    /// <param name="duration">The duration string to parse.</param>
    /// <returns>A <see cref="TimeSpan"/> or null if parsing fails.</returns>
    private static TimeSpan? ParseGoDuration(string duration)
    {
        if (string.IsNullOrWhiteSpace(duration))
            return null;

        // Try ISO 8601 first (P1Y, P365D, etc.)
        if (duration.StartsWith("P", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return Iso8601ParserUtil.ParseIso8601(duration);
            }
            catch
            {
                return null;
            }
        }

        // Go-style duration: combinations of "Nh", "Nm", "Ns"
        var match = Regex.Match(duration, @"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$");
        if (!match.Success || match.Length == 0 || match.Value != duration)
            return null;

        int hours = match.Groups[1].Success ? int.Parse(match.Groups[1].Value) : 0;
        int minutes = match.Groups[2].Success ? int.Parse(match.Groups[2].Value) : 0;
        int seconds = match.Groups[3].Success ? int.Parse(match.Groups[3].Value) : 0;

        if (hours == 0 && minutes == 0 && seconds == 0)
            return null;

        return new TimeSpan(hours, minutes, seconds);
    }
}

/// <summary>
/// Request body for the cert-manager sign endpoint.
/// </summary>
public class CertManagerSignRequest
{
    /// <summary>Base64-encoded PEM CSR generated by cert-manager.</summary>
    [Required, MaxLength(65536)]
    public string Csr { get; set; } = string.Empty;

    /// <summary>Kubernetes namespace of the Certificate resource.</summary>
    [MaxLength(255)]
    public string? Namespace { get; set; }

    /// <summary>Name of the Certificate resource in Kubernetes.</summary>
    [MaxLength(255)]
    public string? Name { get; set; }

    /// <summary>
    /// Requested certificate validity duration in Go format (e.g., "8760h")
    /// or ISO 8601 format (e.g., "P365D"). Falls back to profile default if omitted.
    /// </summary>
    [MaxLength(50)]
    public string? Duration { get; set; }

    /// <summary>
    /// Optional certificate profile ID override. Falls back to the configured default
    /// in <see cref="CertManagerConfig.DefaultCertProfileId"/> if omitted.
    /// </summary>
    public Guid? ProfileId { get; set; }
}

/// <summary>
/// Response body for the cert-manager sign endpoint.
/// </summary>
public class CertManagerSignResponse
{
    /// <summary>Base64-encoded PEM of the issued certificate.</summary>
    public string Certificate { get; set; } = string.Empty;

    /// <summary>Base64-encoded PEM of the issuing CA certificate chain.</summary>
    public string Ca { get; set; } = string.Empty;
}
