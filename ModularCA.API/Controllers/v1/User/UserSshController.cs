using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using System.Text.Json;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User-facing endpoints for SSH CA key discovery, user-key signing, and certificate management.
/// </summary>
[ApiController]
[Route("api/v1/user/ssh")]
[Authorize]
public class UserSshController(
    ModularCADbContext db,
    ISshCaService sshCaService,
    ICurrentUserService currentUser,
    IAuditService audit,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ISshCaService _sshCaService = sshCaService;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Lists SSH CA keys that are designated as user CAs and available for signing,
    /// filtered to only those belonging to CAs the current user has access to.
    /// </summary>
    [HttpGet("ca-keys")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> GetCaKeys()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(_currentUser.User.Id, Capabilities.CertRequest);
        var keys = await _db.SshCaKeys
            .Where(k => k.IsUserCa && accessibleCaIds.Contains(k.CertificateAuthorityId))
            .Select(k => new { k.Id, k.Name, k.KeyType, k.IsUserCa, k.IsHostCa, k.PublicKey, k.MaxValidityHours })
            .ToListAsync();
        return Ok(keys);
    }

    /// <summary>
    /// Signs the caller's SSH public key, producing an SSH user certificate.
    /// Defaults the KeyId to the authenticated user's username when not provided.
    /// Requires an SshRequestProfileId to derive signing and cert profiles from the
    /// request profile's allowed lists; validates that approval is not required.
    /// The cert profile's AllowedPrincipalPatterns are matched via <see cref="ProfileRegex"/> so a
    /// caller-supplied principal cannot trigger catastrophic backtracking in an operator-authored
    /// pattern (bounded match timeout), and a pattern that times out or does not compile is treated
    /// as "did not match" — the request is refused rather than issued unchecked.
    /// </summary>
    [HttpPost("sign-user")]
    [Authorize]
    public async Task<IActionResult> SignUserKey([FromBody] UserSshSignRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // Validate against request profile (required)
        var reqProfile = await _db.SshRequestProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshRequestProfileId);
        if (reqProfile == null)
            return BadRequest(new { error = "SSH request profile not found" });

        if (reqProfile.RequireApproval)
            return BadRequest(new { error = "This request profile requires approval; use the approval workflow instead" });

        // Validate validity against request profile max
        if (request.ValidityHours.HasValue && request.ValidityHours.Value > reqProfile.MaxValidityHours)
            return BadRequest(new { error = $"Validity exceeds request profile maximum of {reqProfile.MaxValidityHours} hours" });

        // Derive signing profile from request profile's allowed list
        var allowedSigning = JsonSerializer.Deserialize<List<Guid>>(reqProfile.AllowedSshSigningProfileIds) ?? new();
        Guid signingProfileId;
        if (request.SshSigningProfileId.HasValue)
        {
            if (allowedSigning.Count > 0 && !allowedSigning.Contains(request.SshSigningProfileId.Value))
                return BadRequest(new { error = "The chosen signing profile is not allowed by this request profile" });
            signingProfileId = request.SshSigningProfileId.Value;
        }
        else if (allowedSigning.Count == 1)
        {
            signingProfileId = allowedSigning[0];
        }
        else
        {
            return BadRequest(new { error = "SshSigningProfileId is required when the request profile allows multiple signing profiles" });
        }

        // Derive cert profile from request profile's allowed list
        var allowedCert = JsonSerializer.Deserialize<List<Guid>>(reqProfile.AllowedSshCertProfileIds) ?? new();
        Guid certProfileId;
        if (request.SshCertProfileId.HasValue)
        {
            if (allowedCert.Count > 0 && !allowedCert.Contains(request.SshCertProfileId.Value))
                return BadRequest(new { error = "The chosen cert profile is not allowed by this request profile" });
            certProfileId = request.SshCertProfileId.Value;
        }
        else if (allowedCert.Count == 1)
        {
            certProfileId = allowedCert[0];
        }
        else
        {
            return BadRequest(new { error = "SshCertProfileId is required when the request profile allows multiple cert profiles" });
        }

        var extensions = request.Extensions;
        var validityHours = request.ValidityHours;

        // Caller-requested extensions are checked against the cert profile below, once it is
        // loaded; server-added ones (the signing profile's force-command, source-address and
        // required extensions) are not the caller's to be restricted on. Captured here, before
        // the merges, so the check sees only what was asked for.
        var requestedExtensions = request.Extensions?.ToList();

        // Validate against signing profile (required)
        var signingProfile = await _db.SshSigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == signingProfileId);
        if (signingProfile == null)
            return BadRequest(new { error = "SSH signing profile not found" });
        if (!signingProfile.AllowUserCerts)
            return BadRequest(new { error = "Signing profile does not allow user certificates" });
        if (validityHours.HasValue && validityHours.Value > signingProfile.MaxValidityHours)
            return BadRequest(new { error = $"Validity exceeds signing profile maximum of {signingProfile.MaxValidityHours} hours" });
        validityHours = validityHours.HasValue
            ? Math.Min(validityHours.Value, signingProfile.MaxValidityHours)
            : signingProfile.MaxValidityHours;
        if (signingProfile.SshCaKeyId == null)
            return BadRequest(new { error = "Signing profile has no SSH CA key assigned." });
        var caKeyId = signingProfile.SshCaKeyId.Value;

        // Verify the user has access to the CA that owns this SSH CA key
        var sshCaKey = await _db.SshCaKeys.AsNoTracking()
            .FirstOrDefaultAsync(k => k.Id == caKeyId);
        if (sshCaKey == null)
            return BadRequest(new { error = "SSH CA key not found" });

        var hasAccess = await _authService.HasCaCapabilityAsync(
            _currentUser.User.Id, sshCaKey.CertificateAuthorityId, Capabilities.CertRequest);
        if (!hasAccess)
            return Forbid();

        if (extensions == null || extensions.Count == 0)
            extensions = JsonSerializer.Deserialize<List<string>>(signingProfile.DefaultExtensions) ?? new();

        if (!string.IsNullOrEmpty(signingProfile.ForceCommand))
        {
            extensions ??= new();
            extensions.RemoveAll(e => e.StartsWith("force-command="));
            extensions.Add($"force-command={signingProfile.ForceCommand}");
        }

        var sourceRestrictions = JsonSerializer.Deserialize<List<string>>(signingProfile.SourceAddressRestrictions) ?? new();
        if (sourceRestrictions.Count > 0)
        {
            extensions ??= new();
            extensions.RemoveAll(e => e.StartsWith("source-address="));
            extensions.Add($"source-address={string.Join(",", sourceRestrictions)}");
        }

        // Validate against cert profile (required)
        var certProfile = await _db.SshCertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == certProfileId);
        if (certProfile == null)
            return BadRequest(new { error = "SSH cert profile not found" });

        if (request.Principals.Count > certProfile.MaxPrincipals)
            return BadRequest(new { error = $"Too many principals; cert profile allows max {certProfile.MaxPrincipals}" });
        if (validityHours.HasValue && validityHours.Value > certProfile.MaxValidityHours)
            return BadRequest(new { error = $"Validity exceeds cert profile maximum of {certProfile.MaxValidityHours} hours" });

        var patterns = JsonSerializer.Deserialize<List<string>>(certProfile.AllowedPrincipalPatterns) ?? new();
        if (patterns.Count > 0)
        {
            foreach (var principal in request.Principals)
            {
                if (!patterns.Any(p => ProfileRegex.IsMatch(principal, p)))
                    return BadRequest(new { error = $"Principal '{principal}' does not match any allowed pattern" });
            }
        }

        // The admin path has always enforced AllowedExtensions; this path never did, so a user
        // could request any extension the profile never offered, force-command included.
        var extensionError = ModularCA.Core.Services.SshExtensionPolicy.Validate(requestedExtensions, certProfile.AllowedExtensions);
        if (extensionError != null)
            return BadRequest(new { error = extensionError });

        var required = JsonSerializer.Deserialize<List<string>>(certProfile.RequiredExtensions) ?? new();
        if (required.Count > 0)
        {
            extensions ??= new();
            foreach (var ext in required.Where(e => !extensions.Contains(e)))
                extensions.Add(ext);
        }

        var cert = await _sshCaService.SignUserKeyAsync(
            caKeyId, request.PublicKey, request.Principals,
            validityHours, request.KeyId ?? _currentUser.User.Username,
            extensions, _currentUser.User.Id,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            cert.Id,
            cert.SerialNumber,
            cert.Principals,
            cert.ValidAfter,
            cert.ValidBefore,
            cert.SignedCertificate,
            cert.KeyId
        });
    }

    /// <summary>
    /// Lists SSH certificates issued by or for the currently authenticated user.
    /// </summary>
    [HttpGet("certificates")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> GetCertificates()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var userId = _currentUser.User.Id;
        var certs = await _db.SshCertificates
            .Where(c => c.IssuedByUserId == userId)
            .OrderByDescending(c => c.ValidAfter)
            .Select(c => new
            {
                c.Id,
                c.SerialNumber,
                c.KeyId,
                c.Principals,
                c.ValidAfter,
                c.ValidBefore,
                c.IsRevoked,
                c.SshCaKeyId
            })
            .ToListAsync();
        return Ok(certs);
    }

    /// <summary>
    /// Downloads the signed SSH certificate content for a certificate owned by the current user.
    /// </summary>
    [HttpGet("certificates/{id:guid}/download")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var cert = await _sshCaService.GetCertificateByIdAsync(id);
        if (cert == null || cert.IssuedByUserId != _currentUser.User.Id)
            return NotFound();

        return Content(cert.SignedCertificate, "text/plain");
    }
}

/// <summary>
/// Request model for signing a user SSH public key via the user-facing endpoint.
/// </summary>
public class UserSshSignRequest
{
    /// <summary>Gets or sets the user's SSH public key to be signed.</summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>Gets or sets the list of principals (usernames) allowed on the certificate.</summary>
    public List<string> Principals { get; set; } = new();

    /// <summary>Gets or sets the optional validity duration in hours.</summary>
    public int? ValidityHours { get; set; }

    /// <summary>Gets or sets an optional key identifier; defaults to the user's username.</summary>
    public string? KeyId { get; set; }

    /// <summary>Gets or sets optional SSH extensions to include on the certificate.</summary>
    public List<string>? Extensions { get; set; }

    /// <summary>Gets or sets the required SSH request profile ID for access and approval validation.</summary>
    public Guid SshRequestProfileId { get; set; }

    /// <summary>Gets or sets an optional SSH signing profile ID; derived from request profile when not specified.</summary>
    public Guid? SshSigningProfileId { get; set; }

    /// <summary>Gets or sets an optional SSH cert profile ID; derived from request profile when not specified.</summary>
    public Guid? SshCertProfileId { get; set; }
}
