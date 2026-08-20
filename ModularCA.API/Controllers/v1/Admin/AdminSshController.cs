using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using System.Text.Json;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing SSH CA keys and issuing SSH certificates.
/// </summary>
[ApiController]
[Route("api/v1/admin/ssh")]
[Authorize(Policy = "CaOperator")]
public class AdminSshController(ISshCaService sshCaService, ICurrentUserService currentUser, IAuditService audit, ModularCADbContext db, ModularCA.Shared.Models.Config.SystemConfig config, IKeyCeremonyService ceremonySvc, IDistributedCache cache) : ControllerBase
{
    /// <summary>
    /// Lists all SSH CA keys with their metadata, including the public KRL download URL.
    /// </summary>
    [HttpGet("ca-keys")]
    public async Task<IActionResult> GetCaKeys()
    {
        var baseUrl = !string.IsNullOrWhiteSpace(config.Https.PublicDomain)
            ? config.Https.GetPublicHttpsBaseUrl()
            : $"{Request.Scheme}://{Request.Host}";

        var keys = await sshCaService.GetCaKeysAsync();
        return Ok(keys.Select(k => new
        {
            k.Id, k.Name, k.KeyType, k.KeySize, k.PublicKey, k.IsUserCa, k.IsHostCa,
            k.MaxValidityHours, k.IsEnabled, k.CreatedAt,
            KrlUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}/krl",
            PublicKeyUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}",
        }));
    }

    /// <summary>
    /// Generates a new SSH CA key pair using ssh-keygen.
    /// If the target tenant requires key ceremonies, initiates a ceremony instead.
    /// </summary>
    [HttpPost("ca-keys")]
    public async Task<IActionResult> GenerateCaKey(
        [FromBody] GenerateSshCaKeyRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.CreateSshCa))
            return StatusCode(403, new { error = "MFA re-verification required.", requiresStepUp = true });

        // SSH CA keys are ALWAYS created under the System tenant (see SshCaService.GenerateKeyPairAsync,
        // which ignores request.TenantId entirely). The ceremony requirement must therefore be
        // evaluated against the System tenant — the tenant the key actually lands in — NOT
        // request.TenantId. Keying the gate off request.TenantId allowed an SSH CA to be created
        // directly, bypassing the ceremony, whenever the request omitted a ceremony-requiring tenant
        // (e.g. sent no TenantId at all): the gate was skipped but the key was still minted into the
        // System tenant, which requires ceremonies. We now resolve the System tenant up front and gate
        // on its flag so the bypass is closed.
        var sshTenant = await db.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.IsSystemTenant);
        if (sshTenant?.RequireKeyCeremony == true)
        {
            var sshParams = new SshKeyCeremonyParameters
            {
                Name = request.Name,
                KeyType = request.KeyType ?? "ed25519",
                KeySize = request.KeySize,
                IsUserCa = request.IsUserCa ?? true,
                IsHostCa = request.IsHostCa ?? false,
                MaxValidityHours = request.MaxValidityHours ?? 24,
                TenantId = sshTenant.Id
            };
            var ceremony = await ceremonySvc.InitiateAsync(
                "CreateSshCa",
                $"Create SSH CA '{request.Name}'",
                string.Empty,
                currentUser.User.Id,
                currentUser.User.Username ?? string.Empty,
                JsonSerializer.Serialize(sshParams));
            return Ok(new { requiresCeremony = true, ceremonyId = ceremony.Id, ceremony.Status, ceremony.RequiredApprovals,
                message = $"Key ceremony required. {ceremony.RequiredApprovals} approval(s) needed." });
        }

        var key = await sshCaService.GenerateKeyPairAsync(
            request.Name, request.KeyType ?? "ed25519",
            request.IsUserCa ?? true, request.IsHostCa ?? false,
            request.MaxValidityHours ?? 24, request.KeySize);
        return Ok(new { key.Id, key.Name, key.KeyType, key.KeySize, key.PublicKey, key.CreatedAt });
    }

    /// <summary>
    /// Returns the public key text for a specific SSH CA key.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/public-key")]
    public async Task<IActionResult> GetCaPublicKey(Guid id)
    {
        var pubKey = await sshCaService.GetPublicKeyAsync(id);
        return Content(pubKey, "text/plain");
    }

    /// <summary>
    /// Signs a user public key, producing an SSH user certificate.
    /// Requires both an SSH signing profile and cert profile for validation.
    /// The CA key is identified by the route parameter; the signing profile must reference the same key.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/certificates/sign-user")]
    public async Task<IActionResult> SignUserKey(Guid caKeyId, [FromBody] SignSshUserKeyRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        var extensions = request.Extensions;
        var validityHours = request.ValidityHours;

        // Validate against signing profile (required)
        var signingProfile = await db.SshSigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshSigningProfileId);
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
            return BadRequest(new { error = "Signing profile has no SSH CA key assigned. Generate an SSH CA key and assign it to this profile first." });
        if (signingProfile.SshCaKeyId.Value != caKeyId)
            return BadRequest(new { error = "Signing profile's SSH CA key does not match the route CA key" });

        // Apply default extensions from signing profile when none specified
        if (extensions == null || extensions.Count == 0)
            extensions = JsonSerializer.Deserialize<List<string>>(signingProfile.DefaultExtensions) ?? new();

        // Apply force command if set
        if (!string.IsNullOrEmpty(signingProfile.ForceCommand))
            extensions = ApplyForceCommand(extensions ?? new(), signingProfile.ForceCommand);

        // Apply source address restrictions
        var sourceRestrictions = JsonSerializer.Deserialize<List<string>>(signingProfile.SourceAddressRestrictions) ?? new();
        if (sourceRestrictions.Count > 0)
            extensions = ApplySourceAddressRestrictions(extensions ?? new(), sourceRestrictions);

        // Validate against cert profile (required)
        var certProfile = await db.SshCertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshCertProfileId);
        if (certProfile == null)
            return BadRequest(new { error = "SSH cert profile not found" });

        var validationError = ValidateCertProfile(certProfile, request.Principals, extensions, validityHours);
        if (validationError != null)
            return BadRequest(new { error = validationError });

        // Ensure required extensions are present
        var required = JsonSerializer.Deserialize<List<string>>(certProfile.RequiredExtensions) ?? new();
        if (required.Count > 0)
        {
            extensions ??= new();
            foreach (var ext in required.Where(e => !extensions.Contains(e)))
                extensions.Add(ext);
        }

        var cert = await sshCaService.SignUserKeyAsync(
            caKeyId, request.PublicKey, request.Principals,
            validityHours, request.KeyId, extensions,
            currentUser.User?.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

        await audit.LogAsync(AuditActionType.SshCertIssued, currentUser.User?.Id, currentUser.User?.Username,
            "SshCertificate", cert.Id.ToString(),
            new { cert.CertificateType, cert.KeyId, cert.SerialNumber, cert.Principals },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { cert.Id, cert.KeyId, cert.SerialNumber, cert.SignedCertificate, cert.ValidAfter, cert.ValidBefore });
    }

    /// <summary>
    /// Signs a host public key, producing an SSH host certificate.
    /// Requires both an SSH signing profile and cert profile for validation.
    /// The CA key is identified by the route parameter; the signing profile must reference the same key.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/certificates/sign-host")]
    public async Task<IActionResult> SignHostKey(Guid caKeyId, [FromBody] SignSshHostKeyRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        var validityHours = request.ValidityHours;

        // Validate against signing profile (required)
        var signingProfile = await db.SshSigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshSigningProfileId);
        if (signingProfile == null)
            return BadRequest(new { error = "SSH signing profile not found" });
        if (!signingProfile.AllowHostCerts)
            return BadRequest(new { error = "Signing profile does not allow host certificates" });
        if (validityHours.HasValue && validityHours.Value > signingProfile.MaxValidityHours)
            return BadRequest(new { error = $"Validity exceeds signing profile maximum of {signingProfile.MaxValidityHours} hours" });
        validityHours = validityHours.HasValue
            ? Math.Min(validityHours.Value, signingProfile.MaxValidityHours)
            : signingProfile.MaxValidityHours;
        if (signingProfile.SshCaKeyId == null)
            return BadRequest(new { error = "Signing profile has no SSH CA key assigned. Generate an SSH CA key and assign it to this profile first." });
        if (signingProfile.SshCaKeyId.Value != caKeyId)
            return BadRequest(new { error = "Signing profile's SSH CA key does not match the route CA key" });

        // Validate against cert profile (required)
        var certProfile = await db.SshCertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == request.SshCertProfileId);
        if (certProfile == null)
            return BadRequest(new { error = "SSH cert profile not found" });

        var validationError = ValidateCertProfile(certProfile, request.Hostnames, null, validityHours);
        if (validationError != null)
            return BadRequest(new { error = validationError });

        var cert = await sshCaService.SignHostKeyAsync(
            caKeyId, request.PublicKey, request.Hostnames,
            validityHours, request.KeyId,
            currentUser.User?.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

        await audit.LogAsync(AuditActionType.SshCertIssued, currentUser.User?.Id, currentUser.User?.Username,
            "SshCertificate", cert.Id.ToString(),
            new { cert.CertificateType, cert.KeyId, cert.SerialNumber, cert.Principals },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { cert.Id, cert.KeyId, cert.SerialNumber, cert.SignedCertificate, cert.ValidAfter, cert.ValidBefore });
    }

    /// <summary>
    /// Validates principals, extensions, and validity against an SSH cert profile.
    /// Returns an error message string if validation fails, or null if valid.
    /// AllowedPrincipalPatterns are operator-authored regexes matched against caller-supplied
    /// principals, so they run through <see cref="ProfileRegex"/>: the match is time-boxed (a
    /// backtracking-prone pattern plus a crafted principal would otherwise pin a CPU core) and a
    /// pattern that times out or fails to compile counts as "did not match", so a broken pattern
    /// narrows what can be issued rather than widening it.
    /// </summary>
    private static string? ValidateCertProfile(Shared.Entities.SshCertProfileEntity certProfile,
        List<string> principals, List<string>? extensions, int? validityHours)
    {
        // Check principal count
        if (principals.Count > certProfile.MaxPrincipals)
            return $"Too many principals ({principals.Count}); cert profile allows max {certProfile.MaxPrincipals}";

        // Check validity
        if (validityHours.HasValue && validityHours.Value > certProfile.MaxValidityHours)
            return $"Validity exceeds cert profile maximum of {certProfile.MaxValidityHours} hours";

        // Check principal patterns
        var patterns = JsonSerializer.Deserialize<List<string>>(certProfile.AllowedPrincipalPatterns) ?? new();
        if (patterns.Count > 0)
        {
            foreach (var principal in principals)
            {
                if (!patterns.Any(p => ProfileRegex.IsMatch(principal, p)))
                    return $"Principal '{principal}' does not match any allowed pattern";
            }
        }

        // Check extensions are allowed
        if (extensions != null && extensions.Count > 0)
        {
            var allowed = JsonSerializer.Deserialize<List<string>>(certProfile.AllowedExtensions) ?? new();
            if (allowed.Count > 0)
            {
                foreach (var ext in extensions)
                {
                    // Compare base extension name (before '=')
                    var extName = ext.Contains('=') ? ext[..ext.IndexOf('=')] : ext;
                    if (!allowed.Any(a => a == extName || a == ext))
                        return $"Extension '{ext}' is not allowed by the cert profile";
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Adds a force-command extension to the extensions list.
    /// </summary>
    private static List<string> ApplyForceCommand(List<string> extensions, string forceCommand)
    {
        extensions.RemoveAll(e => e.StartsWith("force-command="));
        extensions.Add($"force-command={forceCommand}");
        return extensions;
    }

    /// <summary>
    /// Adds source-address restriction extensions to the extensions list.
    /// </summary>
    private static List<string> ApplySourceAddressRestrictions(List<string> extensions, List<string> restrictions)
    {
        extensions.RemoveAll(e => e.StartsWith("source-address="));
        var addresses = string.Join(",", restrictions);
        extensions.Add($"source-address={addresses}");
        return extensions;
    }

    /// <summary>
    /// Lists issued SSH certificates for a specific CA key with pagination.
    /// </summary>
    [HttpGet("ca-keys/{caKeyId:guid}/certificates")]
    public async Task<IActionResult> GetCertificates(Guid caKeyId, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        var certs = await sshCaService.GetCertificatesAsync(page, pageSize, caKeyId);
        return Ok(certs);
    }

    /// <summary>
    /// Downloads the signed SSH certificate content as a text file.
    /// </summary>
    [HttpGet("certificates/{id:guid}/download")]
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        var cert = await sshCaService.GetCertificateByIdAsync(id);
        if (cert == null) return NotFound();
        return File(
            System.Text.Encoding.UTF8.GetBytes(cert.SignedCertificate),
            "text/plain",
            $"{cert.KeyId}-cert.pub");
    }

    /// <summary>
    /// Generates and downloads a binary KRL (Key Revocation List) for the specified SSH CA key.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/krl")]
    public async Task<IActionResult> DownloadKrl(Guid id)
    {
        try
        {
            var krlBytes = await sshCaService.GenerateKrlAsync(id);
            if (krlBytes.Length == 0)
                return Ok(new { message = "No revoked certificates; KRL is empty." });

            return File(krlBytes, "application/octet-stream", "revoked_keys.krl");
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Revokes an SSH certificate by its identifier, scoped to a specific CA key.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/certificates/{id:guid}/revoke")]
    public async Task<IActionResult> RevokeCertificate(Guid caKeyId, Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        if (await sshCaService.RevokeCertificateAsync(id))
        {
            await audit.LogAsync(AuditActionType.SshCertRevoked, currentUser.User?.Id, currentUser.User?.Username,
                "SshCertificate", id.ToString(),
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
            return Ok(new { message = "SSH certificate revoked" });
        }
        return NotFound();
    }

    /// <summary>
    /// Disables an SSH CA key and revokes all active certificates issued by it.
    /// If the CA's tenant requires key ceremonies, initiates a ceremony instead.
    /// </summary>
    [HttpDelete("ca-keys/{id:guid}")]
    public async Task<IActionResult> DisableSshCaKey(
        Guid id,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.DisableSshCa, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required.", requiresStepUp = true });

        var key = await db.SshCaKeys.Include(k => k.CertificateAuthority).FirstOrDefaultAsync(k => k.Id == id);
        if (key == null) return NotFound(new { error = "SSH CA key not found." });

        // Check ceremony requirement via the CA's tenant
        if (key.CertificateAuthority?.TenantId != null)
        {
            var tenant = await db.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == key.CertificateAuthority.TenantId);
            if (tenant?.RequireKeyCeremony == true)
            {
                var sshParams = new SshKeyCeremonyParameters
                {
                    SshCaKeyId = id,
                    Name = key.Name,
                    TenantId = tenant.Id
                };
                var ceremony = await ceremonySvc.InitiateAsync(
                    "DeleteSshCa",
                    $"Disable SSH CA '{key.Name}'",
                    id.ToString(),
                    currentUser.User.Id,
                    currentUser.User.Username ?? string.Empty,
                    JsonSerializer.Serialize(sshParams));
                return Ok(new { requiresCeremony = true, ceremonyId = ceremony.Id, message = "Key ceremony required to disable this SSH CA." });
            }
        }

        await sshCaService.DisableAsync(id);
        await audit.LogAsync(AuditActionType.SshCaKeyDisabled, currentUser.User.Id, currentUser.User.Username,
            "SshCaKey", id.ToString(), new { key.Name });
        return Ok(new { message = $"SSH CA '{key.Name}' disabled. All active certificates revoked." });
    }
}

public class GenerateSshCaKeyRequest
{
    public string Name { get; set; } = string.Empty;
    public string? KeyType { get; set; }
    /// <summary>
    /// Key size in bits. RSA: 2048/3072/4096/7680/8192 (default 3072). ECDSA: 256/384/521 (default 256).
    /// Ignored for ed25519 (fixed size).
    /// </summary>
    public int? KeySize { get; set; }
    public bool? IsUserCa { get; set; }
    public bool? IsHostCa { get; set; }
    public int? MaxValidityHours { get; set; }
    /// <summary>
    /// Optional tenant ID. If the tenant requires key ceremonies, a ceremony will be initiated instead of immediate creation.
    /// </summary>
    public Guid? TenantId { get; set; }
}

/// <summary>Request model for signing a user SSH public key via the admin endpoint.</summary>
public class SignSshUserKeyRequest
{
    /// <summary>The user's SSH public key to be signed.</summary>
    public string PublicKey { get; set; } = string.Empty;
    /// <summary>List of principals (usernames) allowed on the certificate.</summary>
    public List<string> Principals { get; set; } = new();
    /// <summary>Optional validity duration in hours.</summary>
    public int? ValidityHours { get; set; }
    /// <summary>Optional key identifier for the certificate.</summary>
    public string? KeyId { get; set; }
    /// <summary>Optional SSH extensions to include.</summary>
    public List<string>? Extensions { get; set; }
    /// <summary>Required SSH signing profile ID; determines the CA key, extensions, and restrictions.</summary>
    public Guid SshSigningProfileId { get; set; }
    /// <summary>Required SSH cert profile ID; validates principals, extensions, and validity.</summary>
    public Guid SshCertProfileId { get; set; }
}

/// <summary>Request model for signing a host SSH public key via the admin endpoint.</summary>
public class SignSshHostKeyRequest
{
    /// <summary>The host's SSH public key to be signed.</summary>
    public string PublicKey { get; set; } = string.Empty;
    /// <summary>List of hostnames to include in the certificate.</summary>
    public List<string> Hostnames { get; set; } = new();
    /// <summary>Optional validity duration in hours.</summary>
    public int? ValidityHours { get; set; }
    /// <summary>Optional key identifier for the certificate.</summary>
    public string? KeyId { get; set; }
    /// <summary>Required SSH signing profile ID; determines the CA key and restrictions.</summary>
    public Guid SshSigningProfileId { get; set; }
    /// <summary>Required SSH cert profile ID; validates principals and validity.</summary>
    public Guid SshCertProfileId { get; set; }
}
