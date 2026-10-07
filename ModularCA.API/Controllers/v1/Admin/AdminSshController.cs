using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using System.Text.Json;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing SSH CA keys and issuing SSH certificates. The audit entries of
/// creating, signing, revoking and disabling are written by <see cref="ISshCaService"/>, not here.
/// The CA writes the key id of every certificate, and a user certificate is for a named user,
/// carrying only login names that user holds, or for a service identity.
/// </summary>
[ApiController]
[Route("api/v1/admin/ssh")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminSshController(ISshCaService sshCaService, ICurrentUserService currentUser, ModularCADbContext db, ModularCA.Shared.Models.Config.SystemConfig config, IKeyCeremonyService ceremonySvc, IDistributedCache cache,
    ModularCA.Shared.Signing.ISigningService signer, SshKeyImportState sshImports, ISshLoginNameService loginNames) : ControllerBase
{
    /// <summary>The sentence for a key id sent with a sign request.</summary>
    private const string KeyIdRefused = "The CA writes the key id of an SSH certificate: the username of the user it is for, svc: and the label of a "
        + "service identity, or the first hostname of a host certificate. Leave keyId out.";

    /// <summary>Who is asking, as the SSH service records it in the audit and on a certificate row.</summary>
    private SshCaActor Actor() => new(currentUser.User?.Id, currentUser.User?.Username, HttpContext.Connection.RemoteIpAddress?.ToString());

    /// <summary>
    /// Lists the SSH CA keys whose CA is inside the caller's <see cref="SpaceFence"/> (SSH CAs are
    /// instance CAs, so this needs instance scope), with their metadata, including the id of the
    /// certificate authority each belongs to (which rights on the key are held on), the public KRL
    /// download URL and where each private key is held (<c>keyStorage</c>: <c>signer</c>,
    /// <c>legacyFile</c> for a key file still awaiting its import into the signer, or <c>pkcs11</c>).
    /// </summary>
    /// <remarks>
    /// Each key also says what the signer and its row come to (<see cref="SshKeyCustody"/>):
    /// <c>signerState</c> is <c>held</c>, <c>awaitingImport</c> (still a key file on the node),
    /// <c>notHeld</c> (its row gives the key to the signer, which lists none) or <c>unknown</c>
    /// (the signer is locked or did not answer). For a key that is not held,
    /// <c>signerStateCode</c> is the reason as a code and <c>signerStateReason</c> the reason
    /// for an operator, with the path looked at and what the signer answered; <c>keyFile</c> is
    /// where the key file is expected. <c>importedAt</c> is set on a key that was a plaintext
    /// file on the node and has been imported.
    /// </remarks>
    [HttpGet("ca-keys")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetCaKeys()
    {
        var baseUrl = !string.IsNullOrWhiteSpace(config.Https.PublicDomain)
            ? config.Https.GetPublicHttpsBaseUrl()
            : $"{Request.Scheme}://{Request.Host}";

        var fence = SpaceFence.From(HttpContext, ModularCA.Shared.Authorization.Capabilities.CertRevoke);
        var keys = await sshCaService.GetCaKeysAsync();
        var caIds = keys.Select(k => k.CertificateAuthorityId).Distinct().ToList();
        var caSpaces = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => caIds.Contains(c.Id))
            .Select(c => new { c.Id, c.SpaceId })
            .ToDictionaryAsync(c => c.Id, c => c.SpaceId);
        keys = keys.Where(k => caSpaces.TryGetValue(k.CertificateAuthorityId, out var t) && fence.Allows(t)).ToList();
        var custody = keys.Count == 0
            ? new Dictionary<Guid, SshKeyCustodyEntry>()
            : (await SshKeyCustody.ReadAsync(db, signer, sshImports, HttpContext.RequestAborted)).Keys.ToDictionary(c => c.Id);
        return Ok(keys.Select(k =>
        {
            var held = custody.GetValueOrDefault(k.Id);
            return new
            {
                k.Id, k.Name, k.CertificateAuthorityId, k.KeyType, k.KeySize, k.PublicKey, k.IsUserCa, k.IsHostCa,
                k.MaxValidityHours, k.IsEnabled, k.CreatedAt,
                KeyStorage = JsonNamingPolicy.CamelCase.ConvertName(k.KeyStorage),
                SignerState = held?.State ?? SshKeyCustody.Unknown,
                SignerStateCode = held?.ReasonCode,
                SignerStateReason = held?.Detail,
                held?.KeyFile,
                held?.ImportedAt,
                KrlUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}/krl",
                PublicKeyUrl = $"{baseUrl}/ssh/ca-keys/{k.Id}/public-key",
            };
        }));
    }

    /// <summary>
    /// The notice that this install kept SSH CA keys in plaintext before the signer held them:
    /// whether it applies, which keys were imported and when, where each file was and whether
    /// it has been removed, how many keys still await import, the backup archives and
    /// pre-restore snapshots in the backup directory written before the last import, and the
    /// text for the operator. SSH CAs are instance CAs, so a caller without instance scope
    /// gets 404.
    /// </summary>
    [HttpGet("plaintext-notice")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetPlaintextNotice()
    {
        if (!SpaceFence.From(HttpContext, ModularCA.Shared.Authorization.Capabilities.CertRevoke).Allows(null))
            return NotFound();
        var backupDirectory = ModularCA.Bootstrap.BackupRestore.ResolveBackupDirectory(AppContext.BaseDirectory, config.Backup?.OutputPath);
        var notice = await SshPlaintextNotices.ReadAsync(db, backupDirectory, HttpContext.RequestAborted);
        return Ok(new
        {
            notice.Applies,
            notice.AwaitingImport,
            notice.FirstImportedAt,
            notice.LastImportedAt,
            notice.Message,
            Keys = notice.Imported.Select(k => new { k.Id, k.Name, k.Fingerprint, k.ImportedAt, KeyFile = k.File, KeyFileRemoved = k.FileRemoved }),
            EarlierArchives = notice.EarlierArchives.Select(a => new { a.Name, a.WrittenAt }),
        });
    }

    /// <summary>
    /// Creates an SSH CA whose key the signer generates and holds. SSH CAs are instance CAs: if
    /// the instance requires key ceremonies, initiates a ceremony instead. A non-null
    /// <c>spaceId</c> is 400, since an SSH CA cannot belong to a space. The derived label is
    /// checked first, ceremony or not: a control character in the name or key type, or an invalid
    /// or reserved label, is 400; a label or name another CA has (or takes while this one is saved)
    /// is 409. A signer that is locked, or cannot hold SSH CA keys, is 503 with the reason.
    /// </summary>
    [HttpPost("ca-keys")]
    [Authorize(Policy = "SystemOperator")]
    public async Task<IActionResult> GenerateCaKey(
        [FromBody] GenerateSshCaKeyRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.CreateSshCa))
            return StatusCode(403, new { error = "MFA re-verification required.", requiresStepUp = true });

        if (request.SpaceId != null)
            return BadRequest(new { error = "SSH CAs are instance CAs and cannot belong to a space. Omit spaceId." });

        if (ModularCA.Shared.Utils.DnComponentSanitizer.HasControlCharacter(request.Name)
            || ModularCA.Shared.Utils.DnComponentSanitizer.HasControlCharacter(request.KeyType))
            return BadRequest(new { error = "Name and KeyType must not contain control characters." });

        var sshLabel = request.Name.ToLowerInvariant().Replace(" ", "-");
        try
        {
            CaLabelRules.Validate(sshLabel, paramName: nameof(request.Name));
            await CaLabelRules.EnsureUniqueAsync(db, sshLabel, request.Name);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (ModularCA.Shared.Errors.ResourceConflictException ex)
        {
            return Conflict(new { error = ex.Message, code = ex.Code });
        }

        // SSH CA keys are ALWAYS instance CAs (see SshCaService.GenerateKeyPairAsync), so the
        // ceremony requirement is the instance's. Keying the gate off request.SpaceId once allowed
        // an SSH CA to be created directly, bypassing the ceremony, whenever the request omitted a
        // ceremony-requiring space.
        var sshPolicy = await new EffectivePolicyResolver(db).ResolveAsync(null);
        if (sshPolicy.RequireKeyCeremony)
        {
            var sshParams = new SshKeyCeremonyParameters
            {
                Name = request.Name,
                KeyType = request.KeyType ?? "ed25519",
                KeySize = request.KeySize,
                IsUserCa = request.IsUserCa ?? true,
                IsHostCa = request.IsHostCa ?? false,
                MaxValidityHours = request.MaxValidityHours ?? 24,
                SpaceId = null
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

        try
        {
            var key = await sshCaService.GenerateKeyPairAsync(
                request.Name, request.KeyType ?? "ed25519",
                request.IsUserCa ?? true, request.IsHostCa ?? false,
                request.MaxValidityHours ?? 24, request.KeySize, actor: Actor());
            return Ok(new { key.Id, key.Name, key.KeyType, key.KeySize, key.PublicKey, key.CreatedAt });
        }
        catch (ModularCA.Shared.Errors.ResourceConflictException ex)
        {
            return Conflict(new { error = ex.Message, code = ex.Code });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException)
        {
            // As X.509 CA creation answers these three (AdminCaController.DescribeCreationFailure):
            // an unsupported key type or size, or a signer that cannot write the key, is the
            // operator's to act on. A refusal from the signer is not one of them.
            return BadRequest(new { error = ex.Message });
        }
        catch (ModularCA.Shared.Errors.SshCaKeyUnavailableException ex)
        {
            return RequireUnlockedSignerAttribute.Unavailable(HttpContext, ex.Message, ex.RetryMayHelp);
        }
    }

    /// <summary>
    /// Returns the public key text for a specific SSH CA key.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/public-key")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetCaPublicKey(Guid id)
    {
        var pubKey = await sshCaService.GetPublicKeyAsync(id);
        return Content(pubKey, "text/plain");
    }

    /// <summary>
    /// Signs a user public key, producing an SSH user certificate for exactly one of a user of
    /// this console (<c>subjectUserId</c>) or a service identity with no account
    /// (<c>serviceLabel</c>); neither or both is 400. For a user, who must exist and be active,
    /// every principal must be a login name that user holds on the key (400 naming the one that
    /// is not): an administrator grants a name first and cannot add one here. For a service
    /// identity the principals are typed and checked against the certificate profile. The CA
    /// writes the key id: a <c>keyId</c> in the body is refused (400) unless it is exactly what
    /// the CA would write. At least one principal is required. Whoever signs here decides whose
    /// name a public key is certified under, so the route asks step-up MFA
    /// (<c>sign-ssh-user-cert</c>, issued for the key id).
    /// Requires both an SSH signing profile and cert profile for validation.
    /// The CA key is identified by the route parameter; the signing profile must reference the same key.
    /// A validity over a profile's maximum, or over what a login name asked for allows, is 400;
    /// with none asked the certificate lasts as long as the profiles, the key and the login
    /// names allow.
    /// The certificate carries exactly the extensions the profiles and the request come to. A
    /// locked signer, a key the signer cannot serve and a key awaiting its import into the signer
    /// are 503 with the reason; a certificate the signer's rules refuse is 400 with its reason.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/certificates/sign-user")]
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.SignSshUserCert, "caKeyId")]
    [RequireUnlockedSigner]
    public async Task<IActionResult> SignUserKey(Guid caKeyId, [FromBody] SignSshUserKeyRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        if (request.SubjectUserId.HasValue == !string.IsNullOrEmpty(request.ServiceLabel))
            return BadRequest(new { error = "Name exactly one of subjectUserId, a user of this console, or serviceLabel, a service identity with no account." });
        request.Principals ??= new();
        if (request.Principals.Count == 0)
            return BadRequest(new { error = "At least one principal is required: name the login names the certificate is for." });

        var subject = request.SubjectUserId is Guid subjectUserId
            ? SshCertificateSubject.ForUser(subjectUserId)
            : SshCertificateSubject.ForService(request.ServiceLabel!);
        if (request.KeyId != null && request.KeyId != await sshCaService.KeyIdOfAsync(subject))
            return BadRequest(new { error = KeyIdRefused });

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

        Shared.Entities.SshCertificateEntity cert;
        try
        {
            cert = await sshCaService.SignUserKeyAsync(
                caKeyId, request.PublicKey, subject, request.Principals,
                validityHours, extensions, Actor(), Math.Min(signingProfile.MaxValidityHours, certProfile.MaxValidityHours));
        }
        catch (ModularCA.Shared.Errors.SshCaKeyUnavailableException ex)
        {
            return RequireUnlockedSignerAttribute.Unavailable(HttpContext, ex.Message, ex.RetryMayHelp);
        }

        return Ok(new { cert.Id, cert.KeyId, cert.SerialNumber, cert.SignedCertificate, cert.ValidAfter, cert.ValidBefore });
    }

    /// <summary>
    /// Signs a host public key, producing an SSH host certificate.
    /// The CA writes the key id, the first hostname: a <c>keyId</c> in the body is refused (400)
    /// unless it is exactly that.
    /// Requires both an SSH signing profile and cert profile for validation.
    /// The CA key is identified by the route parameter; the signing profile must reference the same key.
    /// With no validity asked the certificate lasts as long as the profiles and the key allow.
    /// A locked signer, a key the signer cannot serve and a key awaiting its import into the
    /// signer are 503 with the reason; a certificate the signer's rules refuse is 400 with its reason.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/certificates/sign-host")]
    [Authorize(Policy = "CaOperator")]
    [RequireUnlockedSigner]
    public async Task<IActionResult> SignHostKey(Guid caKeyId, [FromBody] SignSshHostKeyRequest request)
    {
        await currentUser.EnsureLoadedAsync();

        request.Hostnames ??= new();
        if (request.KeyId != null && request.KeyId != SshKeyIds.ForHost(request.Hostnames))
            return BadRequest(new { error = KeyIdRefused });

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

        Shared.Entities.SshCertificateEntity cert;
        try
        {
            cert = await sshCaService.SignHostKeyAsync(
                caKeyId, request.PublicKey, request.Hostnames,
                validityHours, Actor(), Math.Min(signingProfile.MaxValidityHours, certProfile.MaxValidityHours));
        }
        catch (ModularCA.Shared.Errors.SshCaKeyUnavailableException ex)
        {
            return RequireUnlockedSignerAttribute.Unavailable(HttpContext, ex.Message, ex.RetryMayHelp);
        }

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

        // Check extensions are allowed. Shared with the self-service controller so the rule
        // cannot drift between the two paths.
        var extensionError = ModularCA.Core.Services.SshExtensionPolicy.Validate(extensions, certProfile.AllowedExtensions);
        if (extensionError != null)
            return extensionError;

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
    /// Lists issued SSH certificates for a specific CA key with pagination. Each carries, besides
    /// its row, who it is for (a user, a service identity, a host, or unknown for a user
    /// certificate from before login names), who issued it and whether that was the subject, and
    /// why the subject held each login name.
    /// </summary>
    [HttpGet("ca-keys/{caKeyId:guid}/certificates")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetCertificates(Guid caKeyId, [FromQuery] int page = 1, [FromQuery] int pageSize = 50, [FromQuery] string? sort = null)
    {
        var certs = await sshCaService.GetCertificatesAsync(page, pageSize, caKeyId, sort);
        return Ok(await loginNames.DescribeAsync(certs, HttpContext.RequestAborted));
    }

    /// <summary>
    /// Downloads the signed SSH certificate content as a text file, when its SSH CA is inside the
    /// caller's <see cref="SpaceFence"/>.
    /// </summary>
    [HttpGet("certificates/{id:guid}/download")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        var cert = await sshCaService.GetCertificateByIdAsync(id);
        if (cert == null) return NotFound();
        var caSpace = await db.SshCaKeys.AsNoTracking()
            .Where(k => k.Id == cert.SshCaKeyId)
            .Select(k => new { k.CertificateAuthority.SpaceId })
            .FirstOrDefaultAsync();
        if (caSpace == null || !SpaceFence.From(HttpContext, ModularCA.Shared.Authorization.Capabilities.CertRevoke).Allows(caSpace.SpaceId))
            return NotFound();
        return File(
            System.Text.Encoding.UTF8.GetBytes(cert.SignedCertificate),
            "text/plain",
            $"{cert.KeyId}-cert.pub");
    }

    /// <summary>
    /// Downloads the binary KRL (Key Revocation List) of the specified SSH CA key, built from its
    /// public key and its revoked serials. With nothing revoked it is a KRL with no entries; the
    /// JSON message below is answered only when
    /// <see cref="ModularCA.Core.Services.SshCaService.ServeKrlWithNoEntries"/> is turned off.
    /// </summary>
    [HttpGet("ca-keys/{id:guid}/krl")]
    [Authorize(Policy = "CaOperator")]
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
    [Authorize(Policy = "CaOperator")]
    [RequireStepUp(StepUpOps.RevokeSshCert, "id")]
    public async Task<IActionResult> RevokeCertificate(Guid caKeyId, Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        // Constrain the target to the CA key in the route: that is the CA the policy handler
        // authorized against, and without this the {id} was free to name any SSH certificate
        // in the deployment.
        if (await sshCaService.RevokeCertificateAsync(id, requiredCaKeyId: caKeyId, actor: Actor()))
            return Ok(new { message = "SSH certificate revoked" });
        return NotFound();
    }

    /// <summary>
    /// Disables an SSH CA key and revokes all active certificates issued by it.
    /// If the CA's scope (the instance, for an SSH CA) requires key ceremonies, initiates a
    /// ceremony instead.
    /// </summary>
    [HttpDelete("ca-keys/{id:guid}")]
    [Authorize(Policy = "CaOperator")]
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

        // Check the ceremony requirement of the CA's scope: its space, or the instance for an
        // instance SSH CA (every SSH CA). A null space is never read as "no ceremony".
        {
            var policy = await new EffectivePolicyResolver(db).ResolveAsync(key.CertificateAuthority?.SpaceId);
            if (policy.RequireKeyCeremony)
            {
                var sshParams = new SshKeyCeremonyParameters
                {
                    SshCaKeyId = id,
                    Name = key.Name,
                    SpaceId = policy.SpaceId
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

        await sshCaService.DisableAsync(id, Actor());
        return Ok(new { message = $"SSH CA '{key.Name}' disabled. All active certificates revoked." });
    }
}

/// <summary>
/// Request model for generating an SSH CA key. An unknown member (a pre-0.4.0 <c>tenantId</c>) is
/// refused with 400, never read as no space.
/// </summary>
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
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
    /// Must be null or omitted: SSH CAs are instance CAs, and a space id is refused with 400. The
    /// instance's key-ceremony requirement decides whether a ceremony is initiated.
    /// </summary>
    public Guid? SpaceId { get; set; }
}

/// <summary>
/// Request model for signing a user SSH public key via the admin endpoint. It names exactly one
/// of <see cref="SubjectUserId"/> and <see cref="ServiceLabel"/>.
/// </summary>
public class SignSshUserKeyRequest
{
    /// <summary>The user's SSH public key to be signed.</summary>
    public string PublicKey { get; set; } = string.Empty;
    /// <summary>The user of this console the certificate is for; its principals must be login names that user holds.</summary>
    public Guid? SubjectUserId { get; set; }
    /// <summary>The label of the service identity the certificate is for: 1 to 64 letters, digits and <c>. _ -</c>. Hosts log it as <c>svc:label</c>.</summary>
    public string? ServiceLabel { get; set; }
    /// <summary>The login names the certificate is for.</summary>
    public List<string> Principals { get; set; } = new();
    /// <summary>Optional validity duration in hours; omitted, the most allowed.</summary>
    public int? ValidityHours { get; set; }
    /// <summary>The CA writes the key id. Leave this out: a value is refused unless it is exactly what the CA would write.</summary>
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
    /// <summary>Optional validity duration in hours; omitted, the most allowed.</summary>
    public int? ValidityHours { get; set; }
    /// <summary>The CA writes the key id, the first hostname. Leave this out: a value is refused unless it is exactly that.</summary>
    public string? KeyId { get; set; }
    /// <summary>Required SSH signing profile ID; determines the CA key and restrictions.</summary>
    public Guid SshSigningProfileId { get; set; }
    /// <summary>Required SSH cert profile ID; validates principals and validity.</summary>
    public Guid SshCertProfileId { get; set; }
}
