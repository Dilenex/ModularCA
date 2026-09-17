using System.Security.Claims;
using ModularCA.API.Services;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Fido2NetLib;
using Fido2NetLib.Objects;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using Serilog;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Auth;

/// <summary>
/// Step-up MFA verification for sensitive operations.
/// Authenticated users must re-verify their identity via TOTP or WebAuthn before
/// performing high-risk actions such as changing passwords or modifying MFA methods.
/// Tokens are scoped to a specific operation and target — a token issued for
/// <c>delete-user:abc</c> cannot be used for <c>revoke-ca:xyz</c>.
/// <para>
/// Tokens are also bound to the issuing JWT's <c>jti</c>
/// claim, so a leaked step-up token cannot be replayed from a different session
/// even if the attacker has a valid JWT for the same user.
/// </para>
/// mTLS is not accepted for step-up on destructive operations — only MFA
/// enrollment actions can be authorized with a client certificate.
/// </summary>
[ApiController]
[Route("api/v1/auth/mfa")]
[Route("auth/mfa")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class MfaStepUpController : ControllerBase
{
    private readonly ModularCADbContext _db;
    private readonly IDistributedCache _cache;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuditService _audit;
    private readonly IFido2? _fido2;

    // FIDO2 assertion responses must be deserialized with plain web JSON defaults, not the app's
    // MVC options: the global JsonStringEnumConverter (StartModularCA) outranks the FIDO2 types'
    // own [JsonConverter] attributes and fails to read "type":"public-key". See WebAuthnController.
    private static readonly System.Text.Json.JsonSerializerOptions Fido2JsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);
    private readonly IDataProtector _protector;
    private readonly SystemConfig _config;
    private readonly ISecurityPolicyService _securityPolicy;

    /// <summary>
    /// Initializes a new instance of the <see cref="MfaStepUpController"/> class.
    /// IFido2 is only injected when WebAuthn is enabled.
    /// </summary>
    public MfaStepUpController(
        ModularCADbContext db,
        IDistributedCache cache,
        ICurrentUserService currentUser,
        IAuditService audit,
        IDataProtectionProvider dataProtection,
        SystemConfig config,
        ISecurityPolicyService securityPolicy,
        IFido2? fido2 = null)
    {
        _db = db;
        _cache = cache;
        _currentUser = currentUser;
        _audit = audit;
        _fido2 = fido2;
        _protector = dataProtection.CreateProtector("TotpSecret");
        _config = config;
        _securityPolicy = securityPolicy;
    }

    /// <summary>
    /// The effective WebAuthn user-verification requirement
    /// for this deployment. Driven by <c>SecurityPolicyEntity.RequireWebAuthnUserVerification</c>.
    /// </summary>
    private async Task<UserVerificationRequirement> GetEffectiveUserVerificationAsync()
    {
        var policy = await _securityPolicy.GetAsync();
        return policy.RequireWebAuthnUserVerification
            ? UserVerificationRequirement.Required
            : UserVerificationRequirement.Preferred;
    }

    /// <summary>
    /// Effective WebAuthn challenge TTL (seconds) from policy,
    /// clamped to a sane range so a misconfiguration cannot trivially disable the
    /// ceremony.
    /// </summary>
    private async Task<int> GetWebAuthnChallengeTtlSecondsAsync()
    {
        var policy = await _securityPolicy.GetAsync();
        return Math.Clamp(policy.WebAuthnChallengeTtlSeconds, 30, 600);
    }

    /// <summary>
    /// Step-up verification using a TOTP code. The request must include the operation
    /// and target being authorized. On success, caches an operation-scoped step-up token
    /// valid for the configured <c>SecurityPolicyEntity.StepUpTokenTtlSeconds</c> window (default 90 s).
    /// </summary>
    [HttpPost("verify-stepup/totp")]
    public async Task<IActionResult> VerifyStepUpTotp([FromBody] StepUpTotpRequest request)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (string.IsNullOrWhiteSpace(request.Code))
            return BadRequest(new { error = "TOTP code is required" });

        if (string.IsNullOrWhiteSpace(request.Operation))
            return BadRequest(new { error = "Operation is required (e.g., 'delete-user', 'revoke-ca')" });

        // Enforce the canonical allow-list at issuance time.
        if (!StepUpOps.All.Contains(request.Operation))
            return BadRequest(new { error = "invalid_step_up_operation", operation = request.Operation });

        // Per-user step-up failure counter. Before any verification
        // attempt, check the sliding-window bucket — if the user is locked out, refuse
        // fast and emit an audit event so SIEM can alert.
        if (await IsStepUpLockedOutAsync(userId.Value))
        {
            await LogStepUpFailureAsync(userId.Value, "TOTP", request.Operation, request.TargetId, "locked_out");
            return StatusCode(429, new { error = "Too many step-up verification failures. Try again in a few minutes." });
        }

        var totpSecret = await _db.TotpSecrets
            .FirstOrDefaultAsync(t => t.UserId == userId.Value && t.IsVerified);

        if (totpSecret == null)
            return BadRequest(new { error = "No TOTP secret configured" });

        var secret = GetDecryptedSecret(totpSecret);
        // Step-up uses windowSize=0 (single current code) rather than
        // the ±1 login-flow tolerance. The user is actively at the keyboard, so clock drift
        // should be minimal and brute-force surface is halved.
        var (valid, timeStep) = TotpController.VerifyTotpCode(secret, request.Code, totpSecret.LastUsedTimeStep, windowSize: 0);
        if (!valid)
        {
            await RecordStepUpFailureAsync(userId.Value);
            await LogStepUpFailureAsync(userId.Value, "TOTP", request.Operation, request.TargetId, "invalid_code");
            return Unauthorized(new { error = "Invalid TOTP code" });
        }

        totpSecret.LastUsedTimeStep = timeStep;
        totpSecret.LastUsedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        // Success — clear any outstanding failure bucket.
        await _cache.RemoveAsync(StepUpFailKey(userId.Value));

        var jti = ExtractJti(User);
        var stepUpToken = await IssueStepUpTokenAsync(userId.Value, jti, request.Operation, request.TargetId);
        var ttl = await GetEffectiveStepUpTtlSecondsAsync();

        await _audit.LogAsync(
            AuditActionType.MfaStepUpVerified,
            userId.Value,
            _currentUser.User?.Username,
            details: new { Method = "TOTP", request.Operation, request.TargetId });

        return Ok(new { mfaToken = stepUpToken, expiresInSeconds = ttl, operation = request.Operation, targetId = request.TargetId });
    }

    /// <summary>
    /// Returns WebAuthn assertion options for step-up verification.
    /// The challenge is cached under a step-up-specific key for the configured
    /// <c>SecurityPolicyEntity.WebAuthnChallengeTtlSeconds</c> window.
    /// </summary>
    [HttpPost("verify-stepup/webauthn-options")]
    public async Task<IActionResult> StepUpWebAuthnOptions()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled" });

        var existingKeys = await _db.Fido2Credentials
            .Where(c => c.UserId == userId.Value)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync();

        if (!existingKeys.Any())
            return BadRequest(new { error = "No security keys registered" });

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = existingKeys,
            // Require user-verification (PIN/biometric) for step-up
            // unless the operator explicitly opted out via policy.
            UserVerification = await GetEffectiveUserVerificationAsync()
        });

        await _cache.SetStringAsync($"mfa-stepup:assert:{userId.Value}", options.ToJson(),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(await GetWebAuthnChallengeTtlSecondsAsync()) });

        // Return the FIDO2 library's own JSON rather than Ok(options): the global
        // JsonStringEnumConverter would stringify the WebAuthn enums (alg/type) into values
        // the browser rejects with NotSupportedError. See WebAuthnController for detail.
        return Content(options.ToJson(), "application/json");
    }

    /// <summary>
    /// Step-up verification using a WebAuthn assertion. The request must include the
    /// operation and target being authorized. On success, caches an operation-scoped
    /// step-up token valid for the configured <c>SecurityPolicyEntity.StepUpTokenTtlSeconds</c>
    /// window (default 90 s).
    /// </summary>
    [HttpPost("verify-stepup/webauthn")]
    public async Task<IActionResult> VerifyStepUpWebAuthn()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled" });

        // Parse manually (see Fido2JsonOptions) rather than via [FromBody] so the nested
        // assertion response's "type":"public-key" deserializes instead of failing model binding.
        StepUpWebAuthnRequest? request;
        try
        {
            using var reader = new System.IO.StreamReader(Request.Body, System.Text.Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            request = System.Text.Json.JsonSerializer.Deserialize<StepUpWebAuthnRequest>(body, Fido2JsonOptions);
        }
        catch (System.Text.Json.JsonException)
        {
            return BadRequest(new { error = "Malformed assertion response." });
        }
        if (request is null)
            return BadRequest(new { error = "Assertion response is required." });

        if (string.IsNullOrWhiteSpace(request.Operation))
            return BadRequest(new { error = "Operation is required" });

        // Enforce the canonical allow-list at issuance time.
        if (!StepUpOps.All.Contains(request.Operation))
            return BadRequest(new { error = "invalid_step_up_operation", operation = request.Operation });

        // Per-user failure counter applies to WebAuthn step-up too.
        if (await IsStepUpLockedOutAsync(userId.Value))
        {
            await LogStepUpFailureAsync(userId.Value, "WebAuthn", request.Operation, request.TargetId, "locked_out");
            return StatusCode(429, new { error = "Too many step-up verification failures. Try again in a few minutes." });
        }

        var cacheKey = $"mfa-stepup:assert:{userId.Value}";
        var optionsJson = await _cache.GetStringAsync(cacheKey);
        if (string.IsNullOrEmpty(optionsJson))
            return BadRequest(new { error = "Step-up assertion session expired. Request new options first." });

        var assertionOpts = AssertionOptions.FromJson(optionsJson);

        // Find the credential
        var assertionCredIdBytes = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(request.AssertionResponse.Id);
        var allUserCreds = await _db.Fido2Credentials
            .Where(c => c.UserId == userId.Value)
            .ToListAsync();

        var storedCredential = allUserCreds
            .FirstOrDefault(c => c.CredentialId.AsSpan().SequenceEqual(assertionCredIdBytes));

        if (storedCredential == null)
        {
            await RecordStepUpFailureAsync(userId.Value);
            await LogStepUpFailureAsync(userId.Value, "WebAuthn", request.Operation, request.TargetId, "unknown_credential");
            return Unauthorized(new { error = "Unknown credential" });
        }

        IsUserHandleOwnerOfCredentialIdAsync userHandleCallback = async (args, ct) =>
        {
            var matchingCreds = await _db.Fido2Credentials
                .Where(c => c.UserId == userId.Value)
                .ToListAsync(ct);
            var match = matchingCreds.FirstOrDefault(c => c.CredentialId.SequenceEqual(args.CredentialId));
            if (match == null) return false;
            return match.UserId.ToByteArray().SequenceEqual(args.UserHandle);
        };

        VerifyAssertionResult result;
        try
        {
            result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = request.AssertionResponse,
                OriginalOptions = assertionOpts,
                StoredPublicKey = storedCredential.PublicKey,
                StoredSignatureCounter = storedCredential.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = userHandleCallback
            }, HttpContext.RequestAborted);
        }
        catch (Fido2VerificationException ex)
        {
            // Do NOT surface ex.Message to the client — FIDO2 driver messages can
            // disclose internal verifier details. Log full exception server-side.
            Serilog.Log.Warning(ex, "WebAuthn assertion failed for user {UserId}, operation {Operation}", userId.Value, request.Operation);
            await RecordStepUpFailureAsync(userId.Value);
            await LogStepUpFailureAsync(userId.Value, "WebAuthn", request.Operation, request.TargetId, "verification_failed");
            return Unauthorized(new { error = "WebAuthn assertion failed" });
        }

        // When RequireWebAuthnUserVerification is true, the
        // assertion options above were issued with UserVerification=Required, so
        // fido2-net-lib's MakeAssertionAsync already throws Fido2VerificationException
        // if the authenticator did not satisfy UV. The catch above maps that to the
        // failure branch — no extra check needed here.

        storedCredential.SignCount = result.SignCount;
        storedCredential.LastUsedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _cache.RemoveAsync(cacheKey);
        await _cache.RemoveAsync(StepUpFailKey(userId.Value));

        var jti = ExtractJti(User);
        var stepUpToken = await IssueStepUpTokenAsync(userId.Value, jti, request.Operation, request.TargetId);
        var ttl = await GetEffectiveStepUpTtlSecondsAsync();

        await _audit.LogAsync(
            AuditActionType.MfaStepUpVerified,
            userId.Value,
            _currentUser.User?.Username,
            details: new { Method = "WebAuthn", request.Operation, request.TargetId });

        return Ok(new { mfaToken = stepUpToken, expiresInSeconds = ttl, operation = request.Operation, targetId = request.TargetId });
    }

    [HttpPost("verify-stepup/mtls")]
    public async Task<IActionResult> VerifyStepUpMtls([FromBody] StepUpMtlsRequest request)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (string.IsNullOrWhiteSpace(request.Operation))
            return BadRequest(new { error = "Operation is required" });

        // Even for mTLS, the operation must be in the canonical
        // registry before we apply the mTLS-restricted allow-list check.
        if (!StepUpOps.All.Contains(request.Operation))
            return BadRequest(new { error = "invalid_step_up_operation", operation = request.Operation });

        if (!StepUpOps.AllowedViaMtls.Contains(request.Operation))
            return StatusCode(403, new { error = $"mTLS step-up is not allowed for operation '{request.Operation}'. Use TOTP or WebAuthn for this operation." });

        var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
        if (clientCert == null)
            return Unauthorized(new { error = "No client certificate presented. Ensure your browser has a client certificate configured." });

        var thumbprint = clientCert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);

        var credential = await _db.MtlsCredentials.FirstOrDefaultAsync(c =>
            c.UserId == userId.Value
            && c.Thumbprint == thumbprint
            && !c.IsRevoked
            && c.ExpiresAt > DateTime.UtcNow);

        if (credential == null)
            return Unauthorized(new { error = "Client certificate does not match any active mTLS credential" });

        // Validate the chain and revocation status, as all four sibling mTLS paths do
        // (AuthController.CertLogin, MtlsController.Verify/LoginRedirect/Enroll).
        //
        // Matching a thumbprint against a credential row proves neither issuer binding nor
        // current validity. The Kestrel handshake does not compensate: it runs with
        // RevocationMode.Offline and IgnoreEndRevocationUnknown. And MtlsCredentialEntity
        // .IsRevoked is written only by MtlsController.RevokeCredential — so a certificate
        // revoked through the certificate admin UI still had IsRevoked = false on its
        // credential row. Such a certificate was rejected by /auth/cert-login and
        // /auth/mtls/verify but still minted step-up tokens here, and the operations reachable
        // via mTLS step-up include totp-remove, webauthn-delete and mtls-enroll — enough to
        // strip the rightful owner's remaining factors and enrol a fresh certificate.
        var stepUpChainOk = await MtlsChainValidator.ValidateAgainstCredentialCaAsync(
            _db, credential.SigningCaId, clientCert,
            requireRevocationCheck: (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck);
        if (!stepUpChainOk)
        {
            await _audit.LogAsync(
                AuditActionType.MfaStepUpFailed,
                userId.Value, _currentUser.User?.Username,
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(), success: false,
                details: new { reason = "mtls_chain_or_revocation_check_failed", request.Operation },
                errorMessage: "StepUpFailed");
            return Unauthorized(new { error = "Client certificate failed chain or revocation validation" });
        }

        var jti = ExtractJti(User);
        var stepUpToken = await IssueStepUpTokenAsync(userId.Value, jti, request.Operation, request.TargetId);
        var ttl = await GetEffectiveStepUpTtlSecondsAsync();

        await _audit.LogAsync(
            AuditActionType.MfaStepUpVerified,
            userId.Value,
            _currentUser.User?.Username,
            details: new { Method = "mTLS-restricted", request.Operation, request.TargetId });

        return Ok(new { mfaToken = stepUpToken, expiresInSeconds = ttl, operation = request.Operation, targetId = request.TargetId });
    }

    /// <summary>
    /// Returns the plaintext TOTP secret by decrypting <see cref="Shared.Entities.TotpSecretEntity.EncryptedSecretKey"/>.
    /// </summary>
    private string GetDecryptedSecret(Shared.Entities.TotpSecretEntity entity)
    {
        if (string.IsNullOrEmpty(entity.EncryptedSecretKey))
            throw new InvalidOperationException("No TOTP secret found");
        return _protector.Unprotect(entity.EncryptedSecretKey);
    }

    /// <summary>
    /// Issues an operation-scoped step-up token cached for the configured TTL.
    /// The cache key includes the JWT <c>jti</c> claim (when available), the
    /// operation, and the target so the token can only be used from the same
    /// session for the specific action it was authorized for.
    /// </summary>
    private async Task<string> IssueStepUpTokenAsync(Guid userId, string? jti, string operation, string? targetId)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var key = BuildStepUpCacheKey(userId, jti, operation, targetId);
        var ttlSeconds = await GetEffectiveStepUpTtlSecondsAsync();
        await _cache.SetStringAsync(key, token,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttlSeconds) });
        return token;
    }

    /// <summary>
    /// Effective step-up token TTL in seconds, clamped to a
    /// sane operator-tunable range.
    /// </summary>
    private async Task<int> GetEffectiveStepUpTtlSecondsAsync()
    {
        var policy = await _securityPolicy.GetAsync();
        return Math.Clamp(policy.StepUpTokenTtlSeconds, 30, 300);
    }

    /// <summary>
    /// Builds the cache key for a step-up token. When a
    /// JWT <c>jti</c> is available we bind the token to the session. When it is
    /// missing (e.g. legacy callers without the claim) we fall back to the
    /// userId-only scope so the system remains functional during upgrade.
    /// </summary>
    internal static string BuildStepUpCacheKey(Guid userId, string? jti, string operation, string? targetId)
    {
        var scope = string.IsNullOrWhiteSpace(targetId) ? operation : $"{operation}:{targetId}";
        if (string.IsNullOrWhiteSpace(jti))
            return $"mfa-stepup:{userId}:{scope}";
        return $"mfa-stepup:{userId}:{jti}:{scope}";
    }

    /// <summary>
    /// Reads the <c>jti</c> claim from a <see cref="ClaimsPrincipal"/>, returning
    /// null if the principal has no claim or is anonymous.
    /// </summary>
    internal static string? ExtractJti(ClaimsPrincipal? principal)
        => principal?.FindFirst("jti")?.Value;

    /// <summary>
    /// Cache key for the per-user step-up failure counter.
    /// </summary>
    private static string StepUpFailKey(Guid userId) => $"mfa-stepup-fail:{userId}";

    private async Task<bool> IsStepUpLockedOutAsync(Guid userId)
    {
        var raw = await _cache.GetStringAsync(StepUpFailKey(userId));
        if (!int.TryParse(raw, out var count)) return false;
        var policy = await _securityPolicy.GetAsync();
        return count >= policy.StepUpFailureThreshold;
    }

    /// <summary>
    /// Increments the per-user sliding-window failure counter. On reaching the
    /// configured threshold the JWT session itself is nominally untouched, but
    /// callers that saw this failure will now return 429 until the window expires.
    /// </summary>
    private async Task RecordStepUpFailureAsync(Guid userId)
    {
        var key = StepUpFailKey(userId);
        var raw = await _cache.GetStringAsync(key);
        var count = int.TryParse(raw, out var c) ? c + 1 : 1;
        var policy = await _securityPolicy.GetAsync();
        var window = Math.Clamp(policy.StepUpFailureWindowSeconds, 30, 3600);
        await _cache.SetStringAsync(key, count.ToString(),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(window) });
    }

    private async Task LogStepUpFailureAsync(Guid userId, string method, string operation, string? targetId, string reason)
    {
        try
        {
            await _audit.LogAsync(
                AuditActionType.MfaStepUpFailed,
                userId,
                _currentUser.User?.Username,
                targetEntityType: "User",
                targetEntityId: userId.ToString(),
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                details: new { Method = method, Operation = operation, TargetId = targetId, Reason = reason },
                errorMessage: reason);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to write MfaStepUpFailed audit entry for {UserId}", userId);
        }
    }

    /// <summary>
    /// Validates an operation-scoped step-up MFA token from the X-MFA-Token header.
    /// The token must match the specific operation and target being performed, and
    /// — when the caller supplies the current JWT <c>jti</c> — must have been
    /// issued from the same session. Consumes the token on success (single-use).
    /// </summary>
    /// <param name="cache">The distributed cache instance.</param>
    /// <param name="userId">The authenticated user's ID.</param>
    /// <param name="jti">The current JWT session identifier (<c>jti</c> claim), or null.</param>
    /// <param name="token">The step-up token from the X-MFA-Token header.</param>
    /// <param name="operation">The operation being performed (e.g. <c>delete-user</c>).</param>
    /// <param name="targetId">The target entity ID, or null for operations without a target.</param>
    public static async Task<bool> ValidateStepUpTokenAsync(
        IDistributedCache cache, Guid userId, string? jti, string? token, string operation, string? targetId = null)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        // Primary (session-bound) key
        var key = BuildStepUpCacheKey(userId, jti, operation, targetId);
        var cached = await cache.GetStringAsync(key);

        // No fallback to the userId-only key when jti is
        // present — we want session binding to be load-bearing. Fall back only
        // when the caller explicitly passed null (truly session-less context).
        if (cached == null)
            return false;

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(cached),
                Encoding.UTF8.GetBytes(token)))
            return false;

        // Consume the token (single-use)
        await cache.RemoveAsync(key);
        return true;
    }

    /// <summary>
    /// Legacy overload kept for call-sites that have not yet been updated to
    /// pass the current JWT <c>jti</c>. New code should pass <c>User.FindFirst("jti")?.Value</c>
    /// explicitly via the six-parameter overload so step-up tokens are bound to
    /// the session. This overload performs the validation with a null jti, which
    /// falls back to the userId-only cache key.
    /// </summary>
    public static Task<bool> ValidateStepUpTokenAsync(
        IDistributedCache cache, Guid userId, string? token, string operation, string? targetId = null)
        => ValidateStepUpTokenAsync(cache, userId, jti: null, token, operation, targetId);

    /// <summary>
    /// Convenience overload that extracts the user id and jti from a
    /// <see cref="ClaimsPrincipal"/>. Returns <c>false</c> if the principal does
    /// not carry a resolvable sub/nameid claim.
    /// </summary>
    public static Task<bool> ValidateStepUpTokenAsync(
        IDistributedCache cache, ClaimsPrincipal principal, string? token, string operation, string? targetId = null)
    {
        if (principal == null) return Task.FromResult(false);
        var sub = principal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value
                  ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(sub, out var userId))
            return Task.FromResult(false);
        var jti = principal.FindFirst("jti")?.Value;
        return ValidateStepUpTokenAsync(cache, userId, jti, token, operation, targetId);
    }
}

/// <summary>
/// Request body for TOTP-based step-up verification.
/// </summary>
public class StepUpTotpRequest
{
    /// <summary>The 6-digit TOTP code from the authenticator app.</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>The operation being authorized (e.g., "delete-user", "revoke-ca", "change-password").</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>The target entity ID for the operation (e.g., user ID, CA ID). Null for operations without a specific target.</summary>
    public string? TargetId { get; set; }
}

/// <summary>
/// Request body for WebAuthn-based step-up verification with operation scope.
/// </summary>
public class StepUpWebAuthnRequest
{
    /// <summary>The raw authenticator assertion response from the browser.</summary>
    public AuthenticatorAssertionRawResponse AssertionResponse { get; set; } = default!;

    /// <summary>The operation being authorized.</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>The target entity ID for the operation. Null for operations without a specific target.</summary>
    public string? TargetId { get; set; }
}

/// <summary>
/// Request body for mTLS-based step-up verification. Only allowed for MFA enrollment operations.
/// </summary>
public class StepUpMtlsRequest
{
    /// <summary>The MFA enrollment operation being authorized (e.g., "totp-setup", "webauthn-register").</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>The target entity ID for the operation. Null for operations without a specific target.</summary>
    public string? TargetId { get; set; }
}
