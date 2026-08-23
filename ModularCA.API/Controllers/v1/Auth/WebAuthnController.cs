using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Fido2NetLib;
using Fido2NetLib.Objects;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Utils;
using ModularCA.Auth.Models;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using Serilog;

namespace ModularCA.API.Controllers.v1.Auth;

/// <summary>
/// FIDO2/WebAuthn endpoints for registering security keys and performing
/// second-factor authentication during admin login.
/// </summary>
[ApiController]
[Route("api/v1/auth/webauthn")]
[Route("auth/webauthn")]
public class WebAuthnController : ControllerBase
{
    private readonly ModularCADbContext _db;
    private readonly IFido2? _fido2;
    private readonly IDistributedCache _cache;
    private readonly SystemConfig _config;
    private readonly ISecurityPolicyService _securityPolicy;
    private readonly IJwtTokenService _jwt;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuditService _audit;

    // FIDO2 client responses (attestation/assertion) must be deserialized with plain web JSON
    // defaults, NOT the app's MVC options. The global JsonStringEnumConverter registered in
    // StartModularCA sits in the serializer's Converters collection, which outranks the FIDO2
    // types' own [JsonConverter] attributes, so model binding can't turn "public-key" back into
    // PublicKeyCredentialType. These options honour the library's attributes instead.
    private static readonly System.Text.Json.JsonSerializerOptions Fido2JsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    /// <summary>
    /// Initializes a new instance of the <see cref="WebAuthnController"/> class.
    /// </summary>
    public WebAuthnController(
        ModularCADbContext db,
        IDistributedCache cache,
        SystemConfig config,
        ISecurityPolicyService securityPolicy,
        IJwtTokenService jwt,
        ICurrentUserService currentUser,
        IAuditService audit,
        IFido2? fido2 = null)
    {
        _db = db;
        _fido2 = fido2!;
        _cache = cache;
        _config = config;
        _securityPolicy = securityPolicy;
        _jwt = jwt;
        _currentUser = currentUser;
        _audit = audit;
    }

    // ── Registration ─────────────────────────────────────────────────

    /// <summary>
    /// Returns credential creation options (challenge) for the browser to begin
    /// registering a new FIDO2 security key. Requires an authenticated session.
    /// </summary>
    [Authorize]
    [HttpPost("register-options")]
    public async Task<IActionResult> RegisterOptions()
    {
        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled on this server" });
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
            return NotFound(new { error = "User not found" });

        var existingKeys = await _db.Fido2Credentials
            .Where(c => c.UserId == userId.Value)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync();

        var fido2User = new Fido2User
        {
            Id = userId.Value.ToByteArray(),
            Name = user.Username,
            DisplayName = user.DisplayName ?? user.Username
        };

        // Require user verification on enrollment so only
        // UV-capable authenticators can be registered. Controlled by
        // SecurityPolicyEntity.RequireWebAuthnUserVerification.
        var secPolicy = await _securityPolicy.GetAsync();
        var uv = secPolicy.RequireWebAuthnUserVerification
            ? UserVerificationRequirement.Required
            : UserVerificationRequirement.Preferred;

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = fido2User,
            ExcludeCredentials = existingKeys,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                UserVerification = uv,
                ResidentKey = ResidentKeyRequirement.Preferred,
            },
        });

        // Store options in cache for verification during the register call
        var cacheKey = $"webauthn:reg:{userId.Value}";
        var optionsJson = options.ToJson();
        var webAuthnTtl = Math.Clamp(secPolicy.WebAuthnChallengeTtlSeconds, 30, 600);
        await _cache.SetStringAsync(cacheKey, optionsJson, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(webAuthnTtl)
        });

        // Return the FIDO2 library's own JSON, NOT Ok(options). The global
        // JsonStringEnumConverter (see StartModularCA) would otherwise stringify the WebAuthn
        // enums — alg -7 becomes "ES256", type becomes "PublicKey" — and the browser rejects
        // those options with NotSupportedError. optionsJson is the spec-correct serialization.
        return Content(optionsJson, "application/json");
    }

    /// <summary>
    /// Completes security key registration by verifying the authenticator response
    /// and storing the credential in the database.
    /// </summary>
    [Authorize]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromQuery] string? deviceName = null, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled on this server" });
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        // Parse the attestation response manually (see Fido2JsonOptions) instead of via
        // [FromBody], so the FIDO2 enum/base64url converters apply and a malformed body yields a
        // clean 400 rather than the raw model-binding validation error ("$.type could not be
        // converted to PublicKeyCredentialType").
        AuthenticatorAttestationRawResponse? attestationResponse;
        try
        {
            using var reader = new System.IO.StreamReader(Request.Body, System.Text.Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            attestationResponse = System.Text.Json.JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(body, Fido2JsonOptions);
        }
        catch (System.Text.Json.JsonException)
        {
            return BadRequest(new { error = "Malformed attestation response." });
        }
        if (attestationResponse is null)
            return BadRequest(new { error = "Attestation response is required." });

        // If the user already has a verified MFA factor
        // (TOTP, another WebAuthn key, or an active mTLS credential), require
        // step-up to register a new one. Bootstrap case (no existing factor)
        // stays open so `mfa_setup_required` users can enroll their first key.
        var hasTotpPrecheck = await _db.TotpSecrets.AnyAsync(t => t.UserId == userId.Value && t.IsVerified);
        var hasWebAuthnPrecheck = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var hasMtlsPrecheck = await _db.MtlsCredentials.AnyAsync(c => c.UserId == userId.Value && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);
        if (hasTotpPrecheck || hasWebAuthnPrecheck || hasMtlsPrecheck)
        {
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.WebAuthnRegister))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });
        }

        var cacheKey = $"webauthn:reg:{userId.Value}";
        var optionsJson = await _cache.GetStringAsync(cacheKey);
        if (string.IsNullOrEmpty(optionsJson))
            return BadRequest(new { error = "Registration session expired or not found. Request new options first." });

        var options = CredentialCreateOptions.FromJson(optionsJson);

        // Callback to check whether this credential ID is already registered
        IsCredentialIdUniqueToUserAsyncDelegate credentialIdUniqueCallback = async (args, ct) =>
        {
            var exists = await _db.Fido2Credentials.AnyAsync(
                c => c.CredentialId == args.CredentialId, ct);
            return !exists;
        };

        RegisteredPublicKeyCredential result;
        try
        {
            result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = credentialIdUniqueCallback
            }, HttpContext.RequestAborted);
        }
        catch (Fido2VerificationException ex)
        {
            return BadRequest(new { error = $"Security key could not be verified: {ex.Message}" });
        }

        var credential = new Fido2CredentialEntity
        {
            UserId = userId.Value,
            CredentialId = result.Id,
            PublicKey = result.PublicKey,
            SignCount = result.SignCount,
            DeviceName = deviceName,
            RegisteredAt = DateTime.UtcNow
        };

        _db.Fido2Credentials.Add(credential);

        // Mark MFA enrollment timestamp if this is the user's first MFA method
        var userEntity = await _db.Users.FindAsync(userId.Value);
        if (userEntity != null && userEntity.MfaEnrolledAt == null)
        {
            userEntity.MfaEnrolledAt = DateTime.UtcNow;
        }

        await _db.SaveChangesAsync();

        // Clean up the registration session
        await _cache.RemoveAsync(cacheKey);

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserUpdated,
            userId.Value,
            _currentUser.User?.Username,
            details: new { Action = "WebAuthnCredentialRegistered", DeviceName = deviceName, CredentialId = credential.Id });

        return Ok(new { credentialId = credential.Id, message = "Security key registered successfully" });
    }

    // ── Assertion (login 2FA) ────────────────────────────────────────

    /// <summary>
    /// Returns assertion options (challenge) for second-factor verification during login.
    /// Requires a valid MFA token issued after successful password authentication.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("assertion-options")]
    public async Task<IActionResult> GetAssertionOptionsForUser([FromBody] WebAuthnAssertionOptionsRequest request)
    {
        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled on this server" });
        if (string.IsNullOrWhiteSpace(request.MfaToken))
            return BadRequest(new { error = "MFA token is required" });

        var cachedUserId = await _cache.GetStringAsync($"mfa:{request.MfaToken}");
        if (string.IsNullOrEmpty(cachedUserId) || !Guid.TryParse(cachedUserId, out var userId))
            return Unauthorized(new { error = "MFA token expired or invalid" });

        var user = await _db.Users.FindAsync(userId);
        if (user == null)
            return BadRequest(new { error = "Authentication failed" });

        var existingKeys = await _db.Fido2Credentials
            .Where(c => c.UserId == user.Id)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync();

        if (!existingKeys.Any())
            return BadRequest(new { error = "No security keys registered for this user" });

        // Login-flow assertion also honors the require-UV
        // posture; falls back to Preferred when the operator opts out.
        var loginSecPolicy = await _securityPolicy.GetAsync();
        var loginUv = loginSecPolicy.RequireWebAuthnUserVerification
            ? UserVerificationRequirement.Required
            : UserVerificationRequirement.Preferred;

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = existingKeys,
            UserVerification = loginUv
        });

        // Store options in cache keyed by the user for verification during the assertion call
        var cacheKey = $"webauthn:assert:{user.Id}";
        var optionsJson = options.ToJson();
        var loginWebAuthnTtl = Math.Clamp(loginSecPolicy.WebAuthnChallengeTtlSeconds, 30, 600);
        await _cache.SetStringAsync(cacheKey, optionsJson, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(loginWebAuthnTtl)
        });

        // Return the library's spec-correct JSON, not Ok(options) — the global
        // JsonStringEnumConverter mangles the WebAuthn enums into strings the browser rejects.
        return Content(optionsJson, "application/json");
    }

    /// <summary>
    /// Verifies the WebAuthn assertion response using a valid MFA token from the login flow.
    /// On success, issues a JWT token completing the two-factor login flow.
    /// Username-only resolution removed — MFA token is now mandatory to prevent
    /// assertion without prior password authentication.
    /// AUTH-009: Per-user failure counter added to match TOTP brute-force protection.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("assertion")]
    public async Task<IActionResult> VerifyAssertion()
    {
        if (_fido2 == null)
            return BadRequest(new { error = "WebAuthn is not enabled on this server" });

        // Parse manually (see Fido2JsonOptions) rather than via [FromBody]: the global
        // JsonStringEnumConverter would otherwise fail to read the nested assertion response's
        // "type":"public-key", producing a raw model-binding 400.
        WebAuthnAssertionRequest? request;
        try
        {
            using var reader = new System.IO.StreamReader(Request.Body, System.Text.Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            request = System.Text.Json.JsonSerializer.Deserialize<WebAuthnAssertionRequest>(body, Fido2JsonOptions);
        }
        catch (System.Text.Json.JsonException)
        {
            return BadRequest(new { error = "Malformed assertion response." });
        }
        if (request is null)
            return BadRequest(new { error = "Assertion response is required." });

        // MFA token is required — username-only fallback removed to ensure
        // the caller has completed password authentication before WebAuthn assertion.
        string? mfaToken = request.MfaToken;
        if (string.IsNullOrWhiteSpace(mfaToken))
            return BadRequest(new { error = "MFA token is required" });

        // Read MFA token but don't consume yet — consumed on success to allow retry on failure
        var cachedUserId = await _cache.GetStringAsync($"mfa:{mfaToken}");
        if (string.IsNullOrEmpty(cachedUserId) || !Guid.TryParse(cachedUserId, out var parsedId))
            return Unauthorized(new { error = "MFA token is invalid or expired" });

        // AUTH-009: per-user WebAuthn failure counter — mirrors TOTP brute-force
        // protection. Keyed by userId so attackers cannot reset
        // by reissuing a fresh MFA token via /auth/login.
        var verifySecPolicy = await _securityPolicy.GetAsync();
        var failureThreshold = verifySecPolicy.StepUpFailureThreshold;
        var webauthnFailKey = $"webauthn-failures:{parsedId}";
        var webauthnFailStr = await _cache.GetStringAsync(webauthnFailKey);
        var webauthnFailCount = int.TryParse(webauthnFailStr, out var wfc) ? wfc : 0;

        if (webauthnFailCount >= failureThreshold)
        {
            await _cache.RemoveAsync($"mfa:{mfaToken}");
            await _cache.RemoveAsync(webauthnFailKey);
            MetricsService.AuthMfaVerificationFailuresTotal.WithLabels("webauthn", "lockout").Inc();
            return StatusCode(429, new { error = "Too many failed WebAuthn attempts. Please log in again." });
        }

        Shared.Entities.UserEntity? user = await _db.Users.FindAsync(parsedId);

        if (user == null)
            return Unauthorized(new { error = "Invalid credentials" });

        var cacheKey = $"webauthn:assert:{user.Id}";
        var optionsJson = await _cache.GetStringAsync(cacheKey);
        if (string.IsNullOrEmpty(optionsJson))
            return BadRequest(new { error = "Assertion session expired or not found. Request new options first." });

        var assertionOpts = Fido2NetLib.AssertionOptions.FromJson(optionsJson);

        // Find the credential in our database by matching the raw credential ID bytes
        var assertionCredIdBytes = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(request.AssertionResponse.Id);
        var allUserCreds = await _db.Fido2Credentials
            .Where(c => c.UserId == user.Id)
            .ToListAsync();

        var storedCredential = allUserCreds
            .FirstOrDefault(c => c.CredentialId.AsSpan().SequenceEqual(assertionCredIdBytes));

        if (storedCredential == null)
            return Unauthorized(new { error = "Unknown credential" });

        // Callback to check that the credential belongs to the expected user
        IsUserHandleOwnerOfCredentialIdAsync userHandleCallback = async (args, ct) =>
        {
            var matchingCreds = await _db.Fido2Credentials
                .Where(c => c.UserId == user.Id)
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
            // AUTH-009: increment per-user failure counter on failed assertion
            webauthnFailCount++;
            await _cache.SetStringAsync(webauthnFailKey, webauthnFailCount.ToString(),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });

            Log.Warning(ex, "WebAuthn assertion verification failed for user {UserId} (attempt {FailCount}/{Threshold})",
                user?.Id, webauthnFailCount, failureThreshold);
            MetricsService.AuthMfaVerificationFailuresTotal.WithLabels("webauthn", "verification_failed").Inc();
            return Unauthorized(new { error = "WebAuthn verification failed. Contact administrator if the problem persists." });
        }

        // When RequireWebAuthnUserVerification is true, the
        // assertion-options endpoint above issued UserVerification=Required, so
        // MakeAssertionAsync's internal validator already throws when UV was not
        // satisfied. The catch block above handles that case — no extra branch
        // needed here.

        // Update the sign count to detect cloned authenticators
        storedCredential.SignCount = result.SignCount;
        storedCredential.LastUsedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        // Clean up the assertion session (MFA token already consumed at read time)
        await _cache.RemoveAsync(cacheKey);

        // AUTH-009: clear per-user failure counter on successful assertion
        await _cache.RemoveAsync(webauthnFailKey);

        MetricsService.AuthMfaVerificationsTotal.WithLabels("webauthn").Inc();

        // Consume MFA token on success
        await _cache.RemoveAsync($"mfa:{mfaToken}");

        // 2FA is complete; issue the JWT.
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        // Re-check account state at issuance. The gate ran when AuthController.Login minted the
        // MFA token, but that was up to MfaSessionTtlSeconds ago (clamped to 900s) — long enough
        // for an administrator to disable or lock the account while its owner is part-way through
        // MFA. Completing the second factor must not resurrect a session the operator just took
        // away.
        if (AccountStateGate.IsBlocked(user, out var blockedAtIssue))
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserLoginFailed,
                user.Id, user.Username,
                sourceIp: sourceIp,
                details: new { Reason = blockedAtIssue, Flow = "webauthn-verify" });
            return StatusCode(403, new { error = AccountStateGate.ClientMessage });
        }

        var groups = await _db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group)
            .Select(gm => gm.Group)
            .ToListAsync();
        var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp);
        var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
        var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash,
            await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Services.IDpopProofService>().GetValidatedJktAsync(HttpContext));
        // Plaintext goes to the client; DB stores the hash.
        var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

        user.LastLoginAt = DateTime.UtcNow;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;

        _db.RefreshTokens.Add(refreshToken);
        _db.Users.Update(user);
        await _db.SaveChangesAsync();

        // Enforce concurrent session limit
        if (verifySecPolicy.MaxConcurrentSessions > 0)
        {
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            if (activeTokens.Count > verifySecPolicy.MaxConcurrentSessions)
            {
                var tokensToRevoke = activeTokens.Skip(verifySecPolicy.MaxConcurrentSessions);
                foreach (var old in tokensToRevoke)
                {
                    old.IsRevoked = true;
                    old.RevokedAt = DateTime.UtcNow;
                }
                await _db.SaveChangesAsync();
            }
        }

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserLogin,
            user.Id,
            user.Username,
            sourceIp: sourceIp,
            details: new { TwoFactor = "WebAuthn" });

        return Ok(new LoginResponse
        {
            Token = Token,
            ExpiresAt = ExpiresAt,
            RefreshToken = refreshPlaintext
        });
    }

    // ── Credential management ────────────────────────────────────────

    /// <summary>
    /// Lists all registered FIDO2 credentials for the authenticated user.
    /// </summary>
    [Authorize]
    [HttpGet("credentials")]
    public async Task<IActionResult> ListCredentials()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var credentials = await _db.Fido2Credentials
            .Where(c => c.UserId == userId.Value)
            .Select(c => new
            {
                c.Id,
                c.DeviceName,
                c.RegisteredAt,
                c.LastUsedAt
            })
            .OrderByDescending(c => c.RegisteredAt)
            .ToListAsync();

        return Ok(credentials);
    }

    /// <summary>
    /// Removes a registered FIDO2 credential by its identifier.
    /// Requires a valid step-up MFA token via X-MFA-Token header.
    /// Blocks removal if this is the user's only remaining MFA method.
    /// </summary>
    [Authorize]
    [HttpDelete("credentials/{id:guid}")]
    public async Task<IActionResult> DeleteCredential(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        // Require step-up MFA verification
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.WebAuthnDelete, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var credential = await _db.Fido2Credentials
            .FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId.Value);

        if (credential == null)
            return NotFound(new { error = "Credential not found" });

        // Prevent removal of last MFA method
        var webAuthnCount = await _db.Fido2Credentials.CountAsync(c => c.UserId == userId.Value);
        var hasTotp = await _db.TotpSecrets.AnyAsync(t => t.UserId == userId.Value && t.IsVerified);
        var hasActiveMtls = await _db.MtlsCredentials.AnyAsync(c => c.UserId == userId.Value && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);
        if (webAuthnCount <= 1 && !hasTotp && !hasActiveMtls)
            return StatusCode(409, new { error = "Cannot remove your only MFA method. Set up TOTP, register another security key, or enroll an mTLS certificate first." });

        _db.Fido2Credentials.Remove(credential);
        await _db.SaveChangesAsync();

        // Emit the dedicated MfaWebAuthnRemoved action type
        // with the source IP so MFA removal detection rules can key off the action
        // enum instead of parsing DetailsJson.
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaWebAuthnRemoved,
            userId.Value,
            _currentUser.User?.Username,
            targetEntityType: "User",
            targetEntityId: userId.Value.ToString(),
            details: new { Action = "WebAuthnCredentialRemoved", CredentialId = id, DeviceName = credential.DeviceName },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Credential removed successfully" });
    }
}

/// <summary>
/// Request body for the assertion-options endpoint. Requires an MFA token
/// to identify the user without exposing usernames.
/// </summary>
public class WebAuthnAssertionOptionsRequest
{
    /// <summary>The temporary MFA token issued by the login endpoint after successful password verification.</summary>
    public string MfaToken { get; set; } = string.Empty;
}

/// <summary>
/// Request body for the assertion verification endpoint.
/// Username field removed — MFA token is now the only way to identify the user.
/// </summary>
public class WebAuthnAssertionRequest
{
    /// <summary>The temporary MFA token issued by the login endpoint after successful password verification.</summary>
    public string? MfaToken { get; set; }

    /// <summary>The raw authenticator assertion response from the browser.</summary>
    public AuthenticatorAssertionRawResponse AssertionResponse { get; set; } = default!;
}
