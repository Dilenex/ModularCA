using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using System.Linq.Expressions;
using System.Text.Json;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User-facing endpoints for SSH CA key discovery, user-key signing, and certificate management.
/// A certificate asked for here is for the caller: the CA writes the caller's username as its
/// key id, and it carries only login names the caller holds on the SSH CA key
/// (<see cref="ISshLoginNameService"/>).
/// </summary>
[ApiController]
[Route("api/v1/user/ssh")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class UserSshController(
    ModularCADbContext db,
    ISshCaService sshCaService,
    ICurrentUserService currentUser,
    IAuditService audit,
    ICaGroupAuthorizationService authService,
    ISshLoginNameService loginNames) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ISshCaService _sshCaService = sshCaService;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly ICaGroupAuthorizationService _authService = authService;
    private readonly ISshLoginNameService _loginNames = loginNames;

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
    /// Everything the request form needs for the caller: the key id the CA will write, and per
    /// SSH CA key the caller holds cert.request on, the profile combinations that can be
    /// submitted (a request profile that requires no approval, its signing profiles that point
    /// at the key and allow user certificates, its certificate profiles) and the login names the
    /// caller holds, each with where it comes from, its limit in hours and its end. A request
    /// profile or certificate profile whose type is <c>host</c> is left out. A held name
    /// that a certificate profile's patterns do not allow is listed with that combination as
    /// unavailable.
    /// </summary>
    [HttpGet("request-options")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> GetRequestOptions()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var requestable = await _authService.GetAccessibleCaIdsAsync(_currentUser.User.Id, Capabilities.CertRequest);
        return Ok(await _loginNames.RequestOptionsAsync(_currentUser.User.Id, requestable, HttpContext.RequestAborted));
    }

    /// <summary>
    /// Signs the caller's SSH public key, producing an SSH user certificate for the caller.
    /// The CA writes the key id, the caller's username: a <c>keyId</c> in the body is refused
    /// (400) unless it is exactly that. Every principal must be a login name the caller holds on
    /// the SSH CA key (400 naming the one that is not), and at least one is required.
    /// Requires an SshRequestProfileId to derive signing and cert profiles from the
    /// request profile's allowed lists; validates that approval is not required.
    /// A request profile or certificate profile whose type is <c>host</c> is refused (400
    /// saying so); one with no type serves either (<see cref="SshProfileCertificateType"/>).
    /// The cert profile's AllowedPrincipalPatterns are matched via <see cref="ProfileRegex"/> so a
    /// caller-supplied principal cannot trigger catastrophic backtracking in an operator-authored
    /// pattern (bounded match timeout), and a pattern that times out or does not compile is treated
    /// as "did not match" — the request is refused rather than issued unchecked.
    /// A validity over a profile's maximum, or over what a login name asked for allows, is 400;
    /// with none asked the certificate lasts as long as the profiles, the key and the login
    /// names allow, and no longer than the earliest end among the grants used.
    /// The certificate carries exactly the extensions the profiles and the request come to. A
    /// locked signer, a key the signer cannot serve and a key awaiting its import into the signer
    /// are 503 with the reason; a certificate the signer's rules refuse is 400 with its reason.
    /// The audit entry is written by <see cref="ISshCaService"/>.
    /// </summary>
    [HttpPost("sign-user")]
    [Authorize]
    [ModularCA.API.Filters.RequireUnlockedSigner]
    public async Task<IActionResult> SignUserKey([FromBody] UserSshSignRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        request.Principals ??= new();
        if (request.Principals.Count == 0)
            return BadRequest(new { error = "At least one principal is required: name the login names the certificate is for." });

        var subject = SshCertificateSubject.ForUser(_currentUser.User.Id);
        if (request.KeyId != null && request.KeyId != await _sshCaService.KeyIdOfAsync(subject))
            return BadRequest(new { error = "The CA writes the key id of an SSH certificate: for your certificates it is your username. Leave keyId out." });

        // Validate against request profile (required)
        var reqProfile = await _db.SshRequestProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshRequestProfileId);
        if (reqProfile == null)
            return BadRequest(new { error = "SSH request profile not found" });

        if (SshProfileCertificateType.Refusal("request profile", reqProfile.Name, reqProfile.CertificateType, SshProfileCertificateType.User) is { } requestTypeRefusal)
            return BadRequest(new { error = requestTypeRefusal });

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
        if (request.ValidityHours.HasValue && request.ValidityHours.Value > signingProfile.MaxValidityHours)
            return BadRequest(new { error = $"Validity exceeds signing profile maximum of {signingProfile.MaxValidityHours} hours" });
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
        if (SshProfileCertificateType.Refusal("certificate profile", certProfile.Name, certProfile.CertificateType, SshProfileCertificateType.User) is { } certTypeRefusal)
            return BadRequest(new { error = certTypeRefusal });

        if (request.Principals.Count > certProfile.MaxPrincipals)
            return BadRequest(new { error = $"Too many principals; cert profile allows max {certProfile.MaxPrincipals}" });
        if (request.ValidityHours.HasValue && request.ValidityHours.Value > certProfile.MaxValidityHours)
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

        var profileMaxValidityHours = Math.Min(reqProfile.MaxValidityHours, Math.Min(signingProfile.MaxValidityHours, certProfile.MaxValidityHours));
        SshCertificateEntity cert;
        try
        {
            cert = await _sshCaService.SignUserKeyAsync(
                caKeyId, request.PublicKey, subject, request.Principals,
                request.ValidityHours, extensions,
                new SshCaActor(_currentUser.User.Id, _currentUser.User.Username, HttpContext.Connection.RemoteIpAddress?.ToString()),
                profileMaxValidityHours);
        }
        catch (ModularCA.Shared.Errors.SshCaKeyUnavailableException ex)
        {
            return ModularCA.API.Filters.RequireUnlockedSignerAttribute.Unavailable(HttpContext, ex.Message, ex.RetryMayHelp);
        }

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
    /// The certificates that are the caller's: those issued for the caller, whoever asked, and
    /// those from before login names that the caller asked for and that record no subject.
    /// </summary>
    private static Expression<Func<SshCertificateEntity, bool>> Mine(Guid userId)
        => c => c.SubjectUserId == userId || (c.SubjectUserId == null && c.LoginNameGrounds == null && c.IssuedByUserId == userId);

    /// <summary>
    /// Lists the SSH certificates issued for the currently authenticated user, whoever asked for
    /// them, with who each is for, who issued it and whether that was the user, and why the
    /// user held each login name. Certificates from before login names that the user asked for
    /// are listed too.
    /// </summary>
    [HttpGet("certificates")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> GetCertificates()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var certs = await _db.SshCertificates.AsNoTracking()
            .Where(Mine(_currentUser.User.Id))
            .OrderByDescending(c => c.ValidAfter)
            .ToListAsync();
        var described = await _loginNames.DescribeAsync(certs, HttpContext.RequestAborted);
        return Ok(described.Select(c => new
        {
            c.Id,
            c.SerialNumber,
            c.KeyId,
            c.Principals,
            c.ValidAfter,
            c.ValidBefore,
            c.IsRevoked,
            c.SshCaKeyId,
            c.CertificateType,
            c.Status,
            c.SshCaKey,
            c.KeyFingerprint,
            c.Subject,
            IssuedBy = c.IssuedBy with { SourceIp = null },
            c.LoginNameGrounds,
        }));
    }

    /// <summary>
    /// Downloads the signed SSH certificate content of a certificate that is the current user's:
    /// issued for the user, or asked for by the user before login names.
    /// </summary>
    [HttpGet("certificates/{id:guid}/download")]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var cert = await _db.SshCertificates.AsNoTracking().Where(Mine(_currentUser.User.Id)).FirstOrDefaultAsync(c => c.Id == id);
        if (cert == null)
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

    /// <summary>Gets or sets the login names the certificate is for; each must be one the caller holds on the SSH CA key.</summary>
    public List<string> Principals { get; set; } = new();

    /// <summary>Gets or sets the optional validity duration in hours; omitted, the most allowed.</summary>
    public int? ValidityHours { get; set; }

    /// <summary>
    /// The CA writes the key id, the caller's username. Leave this out: a value is refused
    /// unless it is exactly that username.
    /// </summary>
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
