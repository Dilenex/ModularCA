using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing per-CA protocol configurations (ACME, EST, SCEP, CMP signing/cert profiles).
/// </summary>
[ApiController]
[Route("api/v1/admin/protocol-configs")]
[Authorize(Policy = "CaOperator")]
public class AdminProtocolConfigController(
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IDistributedCache _cache = cache;

    /// <summary>
    /// Reserved CA labels that may not have protocol configurations exposed via this
    /// admin API. The System Signing CA is for internal use only and must never serve
    /// any enrollment protocol — its protocols are hardcoded off and editing is rejected.
    /// </summary>
    private static readonly HashSet<string> ReservedSystemLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "system-signing-ca",
    };

    /// <summary>
    /// Get all protocol configs for a given CA.
    /// </summary>
    [HttpGet("{caId:guid}")]
    public async Task<IActionResult> GetByCa(Guid caId)
    {
        // SSH CAs don't use X.509 protocols
        var ca = await _db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(c => c.Id == caId);
        if (ca == null) return NotFound(new { error = "CA not found." });
        if (ca.IsSshCa) return BadRequest(new { error = "SSH CAs do not support X.509 protocol configuration." });
        if (ca.Label != null && ReservedSystemLabels.Contains(ca.Label))
            return NotFound(new { error = "Protocol configuration is not available for the system signing CA." });

        var configs = await _db.CaProtocolConfigs
            .Include(c => c.SigningProfile)
            .Include(c => c.CertProfile)
            .Where(c => c.CaId == caId)
            .AsNoTracking()
            .Select(c => new
            {
                c.Id,
                c.CaId,
                c.Protocol,
                Enabled = c.IsEnabled,
                c.SigningProfileId,
                SigningProfileName = c.SigningProfile != null ? c.SigningProfile.Name : null,
                c.CertProfileId,
                CertProfileName = c.CertProfile != null ? c.CertProfile.Name : null,
                // Consumed by PublicCaCertController when deciding what to advertise. It was
                // absent from this projection, so the admin UI's "Show on Public Portal"
                // toggle read undefined, defaulted to on, and could never be turned off.
                c.IsPublicVisible,
                // EST
                c.EstRequireClientCert,
                c.EstHttpAuthEnabled,
                // SCEP
                c.ScepChallengeRequired,
                c.CmpRequireSignature,
                // Whether the CA has a dedicated CMP message signer. Without one, signature-protected
                // responses are signed with the CA certificate, which OpenSSL-based clients reject; the
                // UI shows that beside the CMP toggle rather than leaving it to be found by a client.
                CmpSignerConfigured = ca.CmpSigningCertificateId != null,
                // ACME
                c.AcmeRequireEab,
                c.AcmeAllowedChallengeTypes,
                c.AcmeAllowPrivateAddressValidation,
                // OCSP
                c.OcspSignResponses,
                c.MsaeAllowUsernameToken,
                c.MsaeAllowKerberos,
            })
            .ToListAsync();
        return Ok(configs);
    }

    /// <summary>
    /// Create or update a protocol config for a CA.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("{caId:guid}/{protocol}")]
    public async Task<IActionResult> Upsert(Guid caId, string protocol, [FromBody] ProtocolConfigUpdateRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        // SSH CAs don't use X.509 protocols
        var ca = await _db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(c => c.Id == caId);
        if (ca == null) return NotFound(new { error = "CA not found." });
        if (ca.IsSshCa) return BadRequest(new { error = "SSH CAs do not support X.509 protocol configuration." });
        if (ca.Label != null && ReservedSystemLabels.Contains(ca.Label))
            return NotFound(new { error = "Protocol configuration is not available for the system signing CA." });

        // The admin UI mints the step-up token scoped to this CA id (targetId), so the
        // validation must look it up under the same scope. Omitting caId here built a
        // target-less cache key that never matched the issued token — every save 403'd
        // even after a successful TOTP/WebAuthn step-up.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateProtocolConfig, caId.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var normalizedProtocol = protocol.ToUpperInvariant();
        var config = await _db.CaProtocolConfigs
            .FirstOrDefaultAsync(c => c.CaId == caId && c.Protocol == normalizedProtocol);

        if (config == null)
        {
            config = new ModularCA.Shared.Entities.CaProtocolConfigEntity
            {
                CaId = caId,
                Protocol = normalizedProtocol,
            };
            _db.CaProtocolConfigs.Add(config);
        }

        config.IsEnabled = request.Enabled;
        config.SigningProfileId = request.SigningProfileId ?? config.SigningProfileId;
        config.CertProfileId = request.CertProfileId ?? config.CertProfileId;
        config.IsPublicVisible = request.IsPublicVisible ?? config.IsPublicVisible;

        // Protocol-specific fields
        // Capture the prior EST auth state so we can detect when an admin is turning OFF the
        // last remaining enabled auth method (both becoming false after save).
        var priorEstRequireClientCert = config.EstRequireClientCert;
        var priorEstHttpAuthEnabled = config.EstHttpAuthEnabled;
        if (request.EstRequireClientCert.HasValue) config.EstRequireClientCert = request.EstRequireClientCert.Value;
        if (request.EstHttpAuthEnabled.HasValue) config.EstHttpAuthEnabled = request.EstHttpAuthEnabled.Value;

        // SECURITY AUDIT: warn when an admin stages an EST config with NO authentication at all.
        // We don't block the save (staged config is a legitimate admin workflow), but the attempt
        // must be auditable. Fire only when at least one of the EST auth flags actually changed
        // in this request to avoid spamming on unrelated updates (e.g. profile-only changes).
        var estAuthChanged = request.EstRequireClientCert.HasValue || request.EstHttpAuthEnabled.HasValue;
        var bothNowDisabled = !config.EstRequireClientCert && !config.EstHttpAuthEnabled;
        var atLeastOneWasEnabled = priorEstRequireClientCert || priorEstHttpAuthEnabled;
        if (normalizedProtocol == "EST" && estAuthChanged && bothNowDisabled && atLeastOneWasEnabled)
        {
            Serilog.Log.Warning(
                "EST auth DISABLED: CA {CaId} protocol config saved with both EstRequireClientCert=false AND EstHttpAuthEnabled=false. Admin {AdminUser} from {RemoteIp}. Enrollment endpoint will refuse (403) until an auth method is re-enabled.",
                caId,
                currentUser.User?.Username ?? "(unknown)",
                HttpContext.Connection.RemoteIpAddress?.ToString() ?? "(unknown)");
        }
        if (request.ScepChallengeRequired.HasValue)
        {
            // Loud-log when an admin disables the SCEP challenge password.
            // Default remains true; disabling makes the SCEP endpoint accept any PKCSReq with
            // no authentication whatsoever.
            if (!request.ScepChallengeRequired.Value && config.ScepChallengeRequired)
                Serilog.Log.Warning(
                    "SCEP challenge password DISABLED for CA {CaId}. Endpoint will accept any PKCSReq without authentication.",
                    caId);
            config.ScepChallengeRequired = request.ScepChallengeRequired.Value;
        }
        if (request.CmpRequireSignature.HasValue) config.CmpRequireSignature = request.CmpRequireSignature.Value;
        if (request.AcmeRequireEab.HasValue) config.AcmeRequireEab = request.AcmeRequireEab.Value;
        if (request.AcmeAllowedChallengeTypes != null) config.AcmeAllowedChallengeTypes = request.AcmeAllowedChallengeTypes;
        if (request.AcmeAllowPrivateAddressValidation.HasValue) config.AcmeAllowPrivateAddressValidation = request.AcmeAllowPrivateAddressValidation.Value;
        if (request.OcspSignResponses.HasValue) config.OcspSignResponses = request.OcspSignResponses.Value;
        if (request.MsaeAllowUsernameToken.HasValue) config.MsaeAllowUsernameToken = request.MsaeAllowUsernameToken.Value;
        if (request.MsaeAllowKerberos.HasValue)
        {
            // Kerberos is only meaningful with a forest to accept tickets from; refusing here keeps
            // the switch from silently producing 401 challenges no client can answer.
            if (request.MsaeAllowKerberos.Value && !await _db.KerberosRealms.AnyAsync(r => r.TenantId == ca.TenantId && r.IsEnabled))
                return BadRequest(new { error = "Kerberos needs an enabled realm binding on this tenant. Add one on the tenant page first." });
            config.MsaeAllowKerberos = request.MsaeAllowKerberos.Value;
        }
        if (string.Equals(normalizedProtocol, "MSAE", StringComparison.OrdinalIgnoreCase) && !config.MsaeAllowUsernameToken && !config.MsaeAllowKerberos)
            return BadRequest(new { error = "At least one MSAE authentication method must stay enabled." });

        await _db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.ProtocolConfigUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "ProtocolConfig", $"{caId}/{normalizedProtocol}", new { config.Protocol, config.IsEnabled },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            config.Id,
            config.CaId,
            config.Protocol,
            Enabled = config.IsEnabled,
            config.SigningProfileId,
            config.CertProfileId,
        });
    }
}

public class ProtocolConfigUpdateRequest
{
    public bool Enabled { get; set; }
    public Guid? SigningProfileId { get; set; }
    public Guid? CertProfileId { get; set; }

    /// <summary>
    /// Whether this protocol endpoint is advertised on the public portal. Null leaves the
    /// stored value alone.
    /// </summary>
    public bool? IsPublicVisible { get; set; }
    // EST
    public bool? EstRequireClientCert { get; set; }
    public bool? EstHttpAuthEnabled { get; set; }
    // SCEP
    public bool? ScepChallengeRequired { get; set; }
    // CMP
    public bool? CmpRequireSignature { get; set; }
    // ACME
    public bool? AcmeRequireEab { get; set; }
    public string? AcmeAllowedChallengeTypes { get; set; }
    public bool? AcmeAllowPrivateAddressValidation { get; set; }
    // OCSP
    public bool? OcspSignResponses { get; set; }

    /// <summary>MSAE: accept UsernameToken and Basic credentials. Null leaves the setting unchanged.</summary>
    public bool? MsaeAllowUsernameToken { get; set; }
    /// <summary>MSAE: accept Kerberos tickets from the tenant's bound forests. Needs an enabled realm binding.</summary>
    public bool? MsaeAllowKerberos { get; set; }
}
