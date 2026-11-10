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
using ModularCA.Shared.Errors;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Integration;

/// <summary>
/// Infrastructure-as-code integration endpoints for Terraform, Ansible, and similar tools.
/// Provides a predictable, idempotent REST API for certificate lifecycle management,
/// profile discovery, and CA enumeration. Authenticated via a static API key
/// in the X-API-Key header (configured in IntegrationApi.ApiKey).
/// AUTH-06: when <see cref="IntegrationApiConfig.SpaceId"/> is configured, all operations
/// are scoped to CAs belonging to that space, or with <c>instance</c> to the instance's CAs.
/// </summary>
[ApiController]
[Route("api/v1/integration/infra")]
[AllowAnonymous]
[ApiKeyAuth]
[NodeRole(ProcessRole.Enrollment)]
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

        // AUTH-06: verify the signing profile's CA belongs to the configured space
        var spaceCheck = await VerifySigningProfileSpaceAsync(request.SigningProfileId);
        if (spaceCheck != null)
            return spaceCheck;

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

            var chainPem = await BuildChainPemAsync(certInfo.CertificateId);

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
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
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
    /// full PEM and chain data suitable for Terraform state refresh. A certificate outside the
    /// key's space scope is answered 404, exactly as one that does not exist
    /// (<see cref="CertificateInScopeBySerialAsync"/>).
    /// </summary>
    /// <param name="serial">The serial number of the certificate.</param>
    /// <returns>The certificate details, or 404 if it is missing or outside the key's scope.</returns>
    [HttpGet("certificates/{serial}")]
    public async Task<IActionResult> GetCertificate(string serial)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null || !await CertificateInScopeBySerialAsync(serial))
            return NotFound(new { error = "Certificate not found." });

        var chainPem = await BuildChainPemAsync(certInfo.CertificateId);

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
    /// Revokes a certificate by serial number. Idempotent: revoking a certificate already revoked
    /// permanently returns success and changes nothing. The optional reason defaults to
    /// "unspecified"; any other value must be the name of an RFC 5280 reason
    /// (<see cref="TryParseRevocationReason"/>), or the request is refused with 400 and
    /// <see cref="ErrorCodes.RequestInvalid"/>.
    /// <para>
    /// A certificate on hold is revoked permanently with the reason given, under the same rules as
    /// the admin revoke (RFC 5280 §5.3.1, <see cref="ICertificateRevocationService.RevokeCertificateAsync"/>);
    /// the response carries <c>previousReason</c> = <c>CertificateHold</c>. Asking for
    /// <c>certificateHold</c> on a certificate already on hold returns success and changes nothing,
    /// in keeping with the endpoint's idempotence. A revocation state that changed under the request
    /// answers 409 with <see cref="ErrorCodes.CertificateRevocationState"/>.
    /// </para>
    /// A certificate outside the key's space scope is answered 404, exactly as one that does not
    /// exist, before anything about its state is said (<see cref="CertificateInScopeBySerialAsync"/>).
    /// The revocation acts on the ID of the certificate that lookup and scope check found, not on
    /// the serial again; a certificate gone by the time it runs is answered with the same 404 and
    /// body as one that never existed.
    /// </summary>
    /// <param name="serial">The serial number of the certificate to revoke.</param>
    /// <param name="request">Optional revocation reason.</param>
    /// <returns>Confirmation of revocation with the certificate's current state.</returns>
    [HttpDelete("certificates/{serial}")]
    public async Task<IActionResult> RevokeCertificate(string serial, [FromBody] InfraRevokeCertificateRequest? request)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null || !await CertificateInScopeBySerialAsync(serial))
            return NotFound(new { error = "Certificate not found." });

        // Idempotent: a permanent revocation is final, so a repeat returns success. A hold is not
        // final: it falls through and is made permanent with the reason given.
        if (RevocationStatus.IsPermanentlyRevoked(certInfo.Revoked, certInfo.RevocationReason))
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

        // The reason is taken by name only. Enum.TryParse also accepts a number, defined or not,
        // and a comma list whose values it ORs together, so "8", "99" or
        // "KeyCompromise,CACompromise" (= AffiliationChanged) used to be stored as given.
        if (!TryParseRevocationReason(request?.Reason, out var reasonEnum))
        {
            return BadRequest(new
            {
                error = $"Invalid revocation reason '{request!.Reason}'. Expected one of: {string.Join(", ", RevocationReasonNames)}.",
                code = ErrorCodes.RequestInvalid,
            });
        }

        var onHold = RevocationStatus.IsOnHold(certInfo.Revoked, certInfo.RevocationReason);
        if (onHold && reasonEnum == ModularCA.Shared.Enums.RevocationReason.CertificateHold)
        {
            return Ok(new
            {
                id = certInfo.SerialNumber,
                serialNumber = certInfo.SerialNumber,
                revoked = true,
                revocationReason = certInfo.RevocationReason,
                message = "Certificate is already on hold."
            });
        }

        try
        {
            // By ID: the certificate that was looked up and scope-checked above, not whichever row
            // the serial resolves to now.
            var result = await _revocationService.RevokeCertificateAsync(certInfo.CertificateId, null, reasonEnum);

            return Ok(new
            {
                id = certInfo.SerialNumber,
                serialNumber = certInfo.SerialNumber,
                revoked = true,
                revocationReason = reasonEnum.ToString(),
                previousReason = result.PreviousReason?.ToString(),
                message = result.PreviousReason == ModularCA.Shared.Enums.RevocationReason.CertificateHold
                    ? "Certificate on hold revoked permanently."
                    : "Certificate revoked."
            });
        }
        catch (CertificateRevocationStateException ex)
        {
            // The certificate's state changed between the read above and the revoke.
            return Conflict(new { error = ex.Message, code = ex.Code });
        }
        catch (ResourceNotFoundException)
        {
            // Gone between the lookup and the revoke. The same answer as a missing or out-of-scope
            // certificate, so nothing here tells them apart.
            return NotFound(new { error = "Certificate not found." });
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
    /// Returns 404 when the source certificate is missing or outside the key's space scope
    /// (the two are indistinguishable, and the scope is checked before anything is said about the
    /// certificate's state), 400 for invalid renewal input (e.g. revoked source, missing profile),
    /// 409 for a retired source, 502 when renewal succeeds but the follow-up state read fails (to
    /// prevent Terraform retry causing double-issue), and 500 on unknown server-side anomalies.
    /// </summary>
    /// <param name="serial">The serial number of the certificate to renew.</param>
    /// <returns>The newly issued certificate details.</returns>
    [HttpPost("certificates/{serial}/renew")]
    public async Task<IActionResult> RenewCertificate(string serial)
    {
        var certInfo = await _certStore.GetCertificateInfoAsync(serial);
        if (certInfo == null)
            return NotFound(new { error = "Certificate not found." });

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

        // AUTH-06, before anything about the certificate is told: its revoked or retired state,
        // or its profiles. A certificate outside the key's scope, including one whose space
        // cannot be established, is answered exactly as one that does not exist.
        if (!await RenewalSourceInScopeAsync(signingProfileId))
            return NotFound(new { error = "Certificate not found." });

        if (certInfo.Revoked)
            return BadRequest(new { error = "Cannot renew a revoked certificate." });

        if (certInfo.RetiredAt != null)
            return Conflict(new { error = CertificateIssuanceService.RetiredMessage, code = ModularCA.Shared.Errors.ErrorCodes.CertificateRetired });

        if (certProfileId == null || signingProfileId == null)
            return BadRequest(new { error = "Cannot determine certificate or signing profile for renewal." });

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

            var chainPem = await BuildChainPemAsync(newCertInfo.CertificateId);

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

    /// <summary>
    /// The RFC 5280 §5.3.1 names of the reasons <see cref="RevokeCertificate"/> accepts, in code
    /// order, as the refusal lists them.
    /// </summary>
    private static readonly string[] RevocationReasonNames =
    [
        "unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded",
        "cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise",
    ];

    /// <summary>
    /// Parses a revocation reason given by name: one of the defined
    /// <see cref="ModularCA.Shared.Enums.RevocationReason"/> names, compared without regard to case,
    /// so the RFC 5280 spelling (<c>keyCompromise</c>, <c>cACompromise</c>) and the enum's both
    /// match. Null, empty or blank is <see cref="ModularCA.Shared.Enums.RevocationReason.Unspecified"/>.
    /// A number, a comma list or any other name is refused, where <c>Enum.TryParse</c> would accept
    /// it.
    /// </summary>
    /// <param name="value">The reason as the client sent it.</param>
    /// <param name="reason">The parsed reason; <see cref="ModularCA.Shared.Enums.RevocationReason.Unspecified"/> when refused.</param>
    /// <returns>Whether <paramref name="value"/> names a defined reason or is empty.</returns>
    internal static bool TryParseRevocationReason(string? value, out ModularCA.Shared.Enums.RevocationReason reason)
    {
        reason = ModularCA.Shared.Enums.RevocationReason.Unspecified;
        if (string.IsNullOrWhiteSpace(value))
            return true;
        var name = Enum.GetNames<ModularCA.Shared.Enums.RevocationReason>()
            .FirstOrDefault(n => string.Equals(n, value.Trim(), StringComparison.OrdinalIgnoreCase));
        if (name == null)
            return false;
        reason = Enum.Parse<ModularCA.Shared.Enums.RevocationReason>(name);
        return true;
    }

    // ───────────────────────── Profile Read Endpoints��────────────────────────

    /// <summary>
    /// Lists the certificate profiles inside the key's space scope. Used by Terraform data sources
    /// to discover available profiles for certificate issuance. A profile bound to no CA is
    /// instance-wide configuration and is listed to every key whose scope is valid; one bound to a
    /// CA is listed only when that CA is inside the scope (<see cref="ProfileCaInScope"/>).
    /// </summary>
    /// <returns>The certificate profiles inside the key's scope.</returns>
    [HttpGet("cert-profiles")]
    public async Task<IActionResult> ListCertProfiles()
    {
        var profiles = await _certProfileService.GetAllAsync(Caller.Scope.Allows);
        var inScope = await ProfileCaInScopeAsync();
        return Ok(profiles.Where(p => inScope.ByCaId(p.CertificateAuthorityId, unbound: true)).ToList());
    }

    /// <summary>
    /// Lists the signing profiles inside the key's space scope: those whose issuing CA is inside
    /// it. Used by Terraform data sources to discover available signing profiles for certificate
    /// issuance. A key restricted to a space or to the instance does not see a profile with no
    /// issuer, which it could not issue under (<see cref="VerifySigningProfileSpaceAsync"/>).
    /// </summary>
    /// <returns>The signing profiles inside the key's scope.</returns>
    [HttpGet("signing-profiles")]
    public async Task<IActionResult> ListSigningProfiles()
    {
        var profiles = await _signingProfileService.GetAllAsync();
        var inScope = await ProfileCaInScopeAsync();
        return Ok(profiles.Where(p => inScope.ByCertificateId(p.IssuerId)).ToList());
    }

    /// <summary>
    /// Lists the request profiles inside the key's space scope. Used by Terraform data sources to
    /// discover available request profiles and their enrollment constraints. A profile bound to no
    /// CA is listed to every key whose scope is valid; one bound to a CA only when that CA is inside
    /// the scope.
    /// </summary>
    /// <returns>The request profiles inside the key's scope.</returns>
    [HttpGet("request-profiles")]
    public async Task<IActionResult> ListRequestProfiles()
    {
        var profiles = await _requestProfileService.GetAllAsync();
        var inScope = await ProfileCaInScopeAsync();
        return Ok(profiles.Where(p => inScope.ByCaId(p.CertificateAuthorityId, unbound: true)).ToList());
    }

    // ──���────────────────────── CA Read Endpoints ────��────────────────────

    /// <summary>
    /// Lists all enabled Certificate Authorities inside the key's space scope. Returns CA metadata
    /// including certificate serial number and subject DN for Terraform data source lookups.
    /// </summary>
    /// <returns>A list of all CAs with their basic metadata.</returns>
    [HttpGet("authorities")]
    public async Task<IActionResult> ListAuthorities()
    {
        var cas = await InScope(_db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .AsNoTracking()
            .Where(ca => ca.IsEnabled))
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
    /// Retrieves a Certificate Authority by its label, inside the key's space scope. Returns CA
    /// metadata and the CA certificate PEM for trust anchor configuration in Terraform.
    /// </summary>
    /// <param name="label">The unique label of the Certificate Authority.</param>
    /// <returns>The CA details including certificate PEM, or 404 if not found.</returns>
    [HttpGet("authorities/{label}")]
    public async Task<IActionResult> GetAuthorityByLabel(string label)
    {
        var ca = await InScope(_db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .AsNoTracking())
            .FirstOrDefaultAsync(ca => ca.Label == label && ca.IsEnabled);

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
    /// The key this request was admitted with, and the CAs it reaches: a named key's own scope
    /// within the integration's, or the integration's (<see cref="IntegrationApiConfig.SpaceScope"/>).
    /// </summary>
    private ModularCA.Core.Services.IntegrationCaller Caller =>
        ModularCA.API.Filters.IntegrationKeyGate.CallerOf(HttpContext, _config.IntegrationApi.SpaceScope());

    /// <summary>
    /// AUTH-06: the CAs inside the key's space scope: every CA when it is unset, the instance's
    /// with <c>instance</c>, one space's with a space id, and none for any other value.
    /// </summary>
    private IQueryable<ModularCA.Shared.Entities.CertificateAuthorityEntity> InScope(IQueryable<ModularCA.Shared.Entities.CertificateAuthorityEntity> cas)
    {
        var scope = Caller.Scope;
        var everything = scope.Kind == IntegrationScopeKind.Everything;
        var instanceOnly = scope.Kind == IntegrationScopeKind.Instance;
        var spaceId = scope.Kind == IntegrationScopeKind.Space ? scope.SpaceId : null;
        return cas.Where(ca => everything || (instanceOnly && ca.SpaceId == null) || (spaceId != null && ca.SpaceId == spaceId));
    }

    /// <summary>
    /// Which profiles a listing may return to this key, by the CA each is bound to. A key that
    /// reaches everything sees every profile. A restricted key sees a profile bound to a CA inside
    /// its scope (<see cref="InScope"/>), and a certificate or request profile bound to no CA; a
    /// scope that is neither a space nor <c>instance</c> sees none.
    /// </summary>
    /// <param name="Scope">The key's scope.</param>
    /// <param name="CaIds">The ids of the CAs inside a restricted scope.</param>
    /// <param name="CaCertificateIds">The certificate ids of the CAs inside a restricted scope.</param>
    private sealed record ProfileCaInScope(IntegrationSpaceScope Scope, HashSet<Guid> CaIds, HashSet<Guid> CaCertificateIds)
    {
        /// <summary>Whether a profile bound to CA <paramref name="caId"/> (null for none) is listed; <paramref name="unbound"/> says whether one bound to none is.</summary>
        public bool ByCaId(Guid? caId, bool unbound) =>
            !Scope.IsRestricted || (Scope.Kind != IntegrationScopeKind.Invalid && (caId is Guid id ? CaIds.Contains(id) : unbound));

        /// <summary>Whether a profile issuing from CA certificate <paramref name="issuerId"/> is listed; a restricted key does not see one with no issuer.</summary>
        public bool ByCertificateId(Guid? issuerId) =>
            !Scope.IsRestricted || (issuerId is Guid id && CaCertificateIds.Contains(id));
    }

    /// <summary>
    /// The CAs inside this key's scope, for filtering the profile listings; see
    /// <see cref="ProfileCaInScope"/>. Reads nothing when the key reaches everything.
    /// </summary>
    private async Task<ProfileCaInScope> ProfileCaInScopeAsync()
    {
        var scope = Caller.Scope;
        if (!scope.IsRestricted)
            return new ProfileCaInScope(scope, [], []);
        var cas = await InScope(_db.CertificateAuthorities.AsNoTracking())
            .Select(ca => new { ca.Id, ca.CertificateId })
            .ToListAsync();
        return new ProfileCaInScope(scope,
            cas.Select(ca => ca.Id).ToHashSet(),
            cas.Where(ca => ca.CertificateId != null).Select(ca => ca.CertificateId!.Value).ToHashSet());
    }

    /// <summary>
    /// AUTH-06 for <see cref="RenewCertificate"/>: whether the certificate being renewed, issued
    /// under <paramref name="signingProfileId"/>, is inside the key's space scope. An unrestricted
    /// key reaches everything; for a restricted key, a certificate with no signing profile, or one
    /// whose issuing CA cannot be resolved, is outside the scope, as
    /// <see cref="VerifySigningProfileSpaceAsync"/> decides.
    /// </summary>
    /// <param name="signingProfileId">The certificate's signing profile, or its original request's; null when neither has one.</param>
    private async Task<bool> RenewalSourceInScopeAsync(Guid? signingProfileId)
    {
        if (!Caller.Scope.IsRestricted)
            return true;
        return signingProfileId != null && await VerifySigningProfileSpaceAsync(signingProfileId.Value) == null;
    }

    /// <summary>
    /// AUTH-06: verifies that the signing profile's issuing CA is inside the configured space
    /// scope (<see cref="IntegrationApiConfig.SpaceScope"/>). Returns null if the check passes (or
    /// no space restriction is configured), or an <see cref="IActionResult"/> to short-circuit the
    /// action if it does not.
    /// </summary>
    private async Task<IActionResult?> VerifySigningProfileSpaceAsync(Guid signingProfileId)
    {
        var scope = Caller.Scope;
        if (!scope.IsRestricted)
            return null;

        var signingProfile = await _db.SigningProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(sp => sp.Id == signingProfileId);

        if (signingProfile?.IssuerId == null)
            return SpaceFenceDenied("the target's issuing CA could not be determined.");

        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.CertificateId == signingProfile.IssuerId);

        if (ca == null)
            return SpaceFenceDenied("the target's issuing CA could not be determined.");

        if (!scope.Allows(ca.SpaceId))
        {
            Log.Warning("AUTH-06: integration API space isolation violation — API key scoped to {ConfiguredSpace} attempted to use CA {CaId} belonging to space {CaSpace}",
                scope.ToString(), ca.Id, ca.SpaceId?.ToString() ?? "instance");
            return new ObjectResult(new { error = "Access denied: the target CA does not belong to the configured space." })
            {
                StatusCode = 403
            };
        }

        return null;
    }

    /// <summary>
    /// The space fence's DENY result. Used wherever the fence cannot positively establish that
    /// the target belongs to the configured space.
    /// </summary>
    /// <remarks>
    /// Every "cannot determine" path in this fence used to `return null`, which is the ALLOW
    /// sentinel — so a certificate the lookup could not resolve, or one with no SigningProfileId,
    /// sailed through. MtlsController persists mTLS login certificates without a
    /// SigningProfileId at all, so a key scoped to space A could read another space's admin
    /// mTLS certificate and revoke it. An unestablished space is not a matching space.
    /// </remarks>
    private static IActionResult SpaceFenceDenied(string reason) =>
        new ObjectResult(new { error = $"Access denied: {reason}" }) { StatusCode = 403 };

    /// <summary>
    /// AUTH-06 for the certificate read and revoke: whether the certificate with
    /// <paramref name="serial"/> was issued by a CA inside the key's space scope. An unrestricted
    /// key reaches everything. For a restricted key, a certificate the lookup cannot resolve, one
    /// with no signing profile, or one whose issuing CA cannot be established is outside the
    /// scope, as <see cref="VerifySigningProfileSpaceAsync"/> decides.
    /// </summary>
    /// <remarks>
    /// The callers answer false with the same 404 as a certificate that does not exist. A 403
    /// for a certificate outside the scope, against 404 for one that is missing, told a key scoped
    /// to one space which serials exist in every other.
    /// </remarks>
    /// <param name="serial">The certificate's serial number.</param>
    private async Task<bool> CertificateInScopeBySerialAsync(string serial)
    {
        if (!Caller.Scope.IsRestricted)
            return true;

        var certEntity = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serial);

        // Walk from the cert's signing profile to the issuing CA. A certificate the lookup cannot
        // resolve, or one with no signing profile, has no establishable space.
        var signingProfileId = certEntity?.SigningProfileId;
        return signingProfileId != null && await VerifySigningProfileSpaceAsync(signingProfileId.Value) == null;
    }

    /// <summary>
    /// Builds the PEM chain of certificate <paramref name="certificateId"/>: its issuers, nearest
    /// first, up to and including the root, without the certificate itself. The issuers are the
    /// certificate's own, followed through <see cref="IssuerChainResolver.ResolveIssuerCertificatesAsync"/>,
    /// never a CA certificate found by issuer DN, which another CA can share. Empty when no issuer
    /// can be resolved.
    /// </summary>
    private async Task<string> BuildChainPemAsync(Guid certificateId)
    {
        try
        {
            var cert = await _db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == certificateId);
            if (cert == null)
                return string.Empty;

            var chain = await IssuerChainResolver.ResolveIssuerCertificatesAsync(_db, cert);
            if (chain.Count == 0)
                return string.Empty;

            // The resolver stops below a root that is not the direct issuer; this response has
            // always carried the root too.
            var seen = chain.Select(c => c.CertificateId).Append(cert.CertificateId).ToHashSet();
            foreach (var root in await IssuerChainResolver.ResolveIssuerCertificatesAsync(_db, chain[^1]))
                if (seen.Add(root.CertificateId))
                    chain.Add(root);

            return string.Join("\n", chain.Select(c => c.Pem.Trim())) + "\n";
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
    /// Revocation reason per RFC 5280, by name and in any case (e.g., "keyCompromise",
    /// "cessationOfOperation", "unspecified"). Defaults to "unspecified" when omitted. A numeric
    /// code, a comma list or an undefined name is refused with 400.
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
