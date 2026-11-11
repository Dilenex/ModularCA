using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Utils;
using ModularCA.Auth.Models;
using ModularCA.Core.Services;
using ModularCA.Database;
using Serilog;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Auth;

/// <summary>
/// TOTP (Time-based One-Time Password, RFC 6238) endpoints for enrolling authenticator apps
/// and verifying one-time codes during multi-factor authentication.
/// </summary>
[ApiController]
[Route("api/v1/auth/totp")]
[Route("auth/totp")]
[NodeRole(ProcessRole.Control)]
public class TotpController : ControllerBase
{
    private readonly ModularCADbContext _db;
    private readonly IDistributedCache _cache;
    private readonly IJwtTokenService _jwt;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuditService _audit;
    private readonly SystemConfig _config;
    private readonly ISecurityPolicyService _securityPolicy;
    private readonly IDataProtector _protector;
    private readonly INotificationService _notifications;
    private readonly ModularCA.Auth.Services.IReplayGuard _replayGuard;

    /// <summary>
    /// Initializes a new instance of the <see cref="TotpController"/> class.
    /// <paramref name="notifications"/> tells administrators when wrong recovery codes lock an account.
    /// <paramref name="replayGuard"/> makes a TOTP time step and a pending-MFA token single-use
    /// under concurrency (<see cref="MfaSingleUse"/>, <see cref="PendingMfaToken.ConsumeAsync"/>).
    /// </summary>
    public TotpController(
        ModularCADbContext db,
        IDistributedCache cache,
        IJwtTokenService jwt,
        ICurrentUserService currentUser,
        IAuditService audit,
        SystemConfig config,
        ISecurityPolicyService securityPolicy,
        IDataProtectionProvider dataProtection,
        INotificationService notifications,
        ModularCA.Auth.Services.IReplayGuard replayGuard)
    {
        _db = db;
        _cache = cache;
        _jwt = jwt;
        _currentUser = currentUser;
        _audit = audit;
        _config = config;
        _securityPolicy = securityPolicy;
        _protector = dataProtection.CreateProtector("TotpSecret");
        _notifications = notifications;
        _replayGuard = replayGuard;
    }

    // ── Setup ────────────────────────────────────────────────────────

    /// <summary>
    /// Generates a new TOTP secret and returns the base32-encoded secret along with
    /// a provisioning URI suitable for QR code display. Requires an authenticated session.
    /// If the user already has an unverified secret, it is replaced.
    /// </summary>
    [Authorize]
    [HttpPost("setup")]
    public async Task<IActionResult> Setup([FromBody] TotpSetupRequest? request = null, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
            return NotFound(new { error = "User not found" });

        // Check if the user already has a verified TOTP secret
        var existingVerified = await _db.TotpSecrets.AnyAsync(t => t.UserId == userId.Value && t.IsVerified);
        if (existingVerified)
            return Conflict(new { error = "TOTP is already configured. Remove the existing TOTP secret before setting up a new one." });

        // If the user already has a verified MFA factor
        // (WebAuthn or mTLS), adding a new TOTP must be step-up gated. The
        // bootstrap case — no existing factor — stays open so `mfa_setup_required`
        // users can enroll their first method without chicken-and-egg deadlock.
        var hasWebAuthn = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var hasActiveMtls = await _db.MtlsCredentials.Where(await ModularCA.Core.Helpers.MtlsCredentialStatus.UsableAsync(_db, DateTime.UtcNow)).AnyAsync(c => c.UserId == userId.Value);
        if (hasWebAuthn || hasActiveMtls)
        {
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, HttpContext, mfaToken, StepUpOps.TotpSetup))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });
        }

        // Remove any unverified secrets (abandoned setup attempts)
        var unverified = await _db.TotpSecrets.Where(t => t.UserId == userId.Value && !t.IsVerified).ToListAsync();
        if (unverified.Count > 0)
        {
            _db.TotpSecrets.RemoveRange(unverified);
        }

        // Generate a new 160-bit (20-byte) secret
        var secretBytes = RandomNumberGenerator.GetBytes(20);
        var base32Secret = Base32Encode(secretBytes);

        var totpSecret = new TotpSecretEntity
        {
            UserId = userId.Value,
            EncryptedSecretKey = _protector.Protect(base32Secret),
            DeviceName = request?.DeviceName,
            IsVerified = false,
            RegisteredAt = DateTime.UtcNow
        };

        _db.TotpSecrets.Add(totpSecret);
        await _db.SaveChangesAsync();

        // Build provisioning URI per RFC 6238. algorithm=SHA1 is required for broad authenticator
        // app compatibility (Google Authenticator, Authy, etc.).
        var provisioningUri = $"otpauth://totp/ModularCA:{Uri.EscapeDataString(user.Username)}?secret={base32Secret}&issuer=ModularCA&algorithm=SHA1&digits=6&period=30";

        return Ok(new
        {
            secret = base32Secret,
            provisioningUri,
            message = "Scan the QR code with your authenticator app, then verify with a code from the app."
        });
    }

    /// <summary>
    /// Verifies the first TOTP code after setup to confirm the user has successfully
    /// enrolled their authenticator app. Marks the secret as verified on success and returns ten
    /// one-time recovery codes, stored only as per-user salted PBKDF2 hashes (<see cref="RecoveryCodeHash"/>).
    /// The code's time step is claimed through <see cref="MfaSingleUse.TryClaimTotpStepAsync"/>, so
    /// one code cannot complete two concurrent enrolments.
    /// </summary>
    [Authorize]
    [HttpPost("verify-setup")]
    public async Task<IActionResult> VerifySetup([FromBody] TotpCodeRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (string.IsNullOrWhiteSpace(request.Code))
            return BadRequest(new { error = "TOTP code is required" });

        // Same rule as Setup — if the user already has
        // another verified factor, VerifySetup requires step-up. Bootstrap users
        // without any factor can still complete first-time enrollment.
        var hasWebAuthnPrecheck = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var hasMtlsPrecheck = await _db.MtlsCredentials.Where(await ModularCA.Core.Helpers.MtlsCredentialStatus.UsableAsync(_db, DateTime.UtcNow)).AnyAsync(c => c.UserId == userId.Value);
        if (hasWebAuthnPrecheck || hasMtlsPrecheck)
        {
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, HttpContext, mfaToken, StepUpOps.TotpVerifySetup))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });
        }

        var totpSecret = await _db.TotpSecrets
            .FirstOrDefaultAsync(t => t.UserId == userId.Value && !t.IsVerified);

        if (totpSecret == null)
            return BadRequest(new { error = "No pending TOTP setup found. Call /setup first." });

        var secret = GetDecryptedSecret(totpSecret);
        var (valid, timeStep) = VerifyTotpCode(secret, request.Code, 0);
        // 400, not 401: the session is fine, the code the user typed is wrong. The console's API
        // client treats every 401 as the end of the session, so a typo here used to sign the user
        // out in the middle of enrolment (and, on the security page, throw away the step-up).
        if (!valid || !await MfaSingleUse.TryClaimTotpStepAsync(_replayGuard, userId.Value, timeStep))
            return BadRequest(new { error = "Invalid TOTP code. Check your authenticator app and try again." });

        totpSecret.IsVerified = true;
        totpSecret.LastUsedTimeStep = timeStep;
        totpSecret.LastUsedAt = DateTime.UtcNow;

        // Mark MFA enrollment timestamp if this is the user's first MFA method
        var userEntity = await _db.Users.FindAsync(userId.Value);
        if (userEntity != null && userEntity.MfaEnrolledAt == null)
        {
            userEntity.MfaEnrolledAt = DateTime.UtcNow;
        }

        // Generate 10 one-time recovery codes, hash them at rest,
        // and return the plaintext to the user exactly once so they can print/save them.
        // Losing the authenticator without saving these codes is a support ticket, by design.
        var plaintextCodes = new List<string>(capacity: 10);
        // Drop any stale codes from a previous enrollment attempt
        var staleCodes = await _db.TotpRecoveryCodes.Where(r => r.UserId == userId.Value).ToListAsync();
        if (staleCodes.Count > 0) _db.TotpRecoveryCodes.RemoveRange(staleCodes);
        for (int i = 0; i < 10; i++)
        {
            var raw = RandomNumberGenerator.GetBytes(10);
            // Base32-style 5-char groups separated by a dash for human legibility: "XXXXX-XXXXX".
            var code = Base32Encode(raw).Substring(0, 10);
            code = code.Substring(0, 5) + "-" + code.Substring(5, 5);
            plaintextCodes.Add(code);

            _db.TotpRecoveryCodes.Add(new TotpRecoveryCodeEntity
            {
                UserId = userId.Value,
                CodeHash = RecoveryCodeHash.Compute(userId.Value, code),
                CreatedAt = DateTime.UtcNow
            });
        }

        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserUpdated,
            userId.Value,
            _currentUser.User?.Username,
            details: new { Action = "TotpEnrolled", DeviceName = totpSecret.DeviceName, RecoveryCodeCount = plaintextCodes.Count });

        return Ok(new
        {
            message = "TOTP setup verified successfully. Authenticator app is now active.",
            recoveryCodes = plaintextCodes,
            recoveryNotice = "Store these recovery codes in a safe place. Each code can be used only once and they will not be shown again."
        });
    }

    /// <summary>
    /// Exchange a one-time recovery code for a TOTP reset. The caller
    /// provides their username + a recovery code; on success, the user's TOTP secret is
    /// removed and they must re-enroll via <c>/setup</c>. The recovery code is consumed
    /// (marked <c>UsedAt</c>) to prevent replay, the security stamp rotates (old JWTs stop at once)
    /// and every refresh token is revoked, in the transaction that consumes the code. Codes match in either stored form
    /// (<see cref="RecoveryCodeHash"/>). A wrong code counts as a failed sign-in (counted
    /// atomically), locks the account at the security policy's threshold and then notifies
    /// administrators, as a wrong password does. An unknown, disabled or locked account costs the
    /// same hashing and the same <see cref="SecurityPolicyEntity.LoginResponseDelayMs"/> budget as a
    /// wrong code, so the response time does not tell them apart.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("recovery")]
    public async Task<IActionResult> TotpRecovery([FromBody] TotpRecoveryRequest request)
    {
        var sw = Stopwatch.StartNew();
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.RecoveryCode))
            return BadRequest(new { error = "Username and recovery code are required" });

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            _ = RecoveryCodeHash.Candidates(Guid.Empty, request.RecoveryCode);
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTotpFailed,
                null, request.Username,
                sourceIp: sourceIp, success: false,
                details: new { reason = "totp_recovery_user_not_found" },
                errorMessage: "RecoveryFailed");
            await DelayToBudgetAsync(sw);
            return Unauthorized(new { error = "Invalid recovery code" });
        }

        // Recovery is a credential exchange, so the account-state checks that gate every other
        // login path apply here too. Without them a disabled or locked account could still
        // trade a recovery code for a cleared MFA enrolment and a rotated security stamp.
        await ModularCA.Core.Helpers.AccountLockout.ClearElapsedAsync(_db, user, DateTime.UtcNow);
        if (!user.IsActive || user.IsLocked || (user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow))
        {
            _ = RecoveryCodeHash.Candidates(user.Id, request.RecoveryCode);
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTotpFailed,
                user.Id, user.Username,
                sourceIp: sourceIp, success: false,
                details: new { reason = "totp_recovery_account_not_eligible" },
                errorMessage: "RecoveryFailed");
            await DelayToBudgetAsync(sw);
            return Unauthorized(new { error = "Invalid recovery code" });
        }

        var (currentHash, legacyHash) = RecoveryCodeHash.Candidates(user.Id, request.RecoveryCode);
        var code = await _db.TotpRecoveryCodes
            .FirstOrDefaultAsync(r => r.UserId == user.Id && (r.CodeHash == currentHash || r.CodeHash == legacyHash) && r.UsedAt == null);

        if (code == null)
        {
            // Count the failure against the account and lock it at the shared threshold, as the
            // password and certificate paths do, so guessing here runs into the same lockout.
            // Incremented in the database, so concurrent guesses cannot overwrite each other's count.
            await _db.Users
                .Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
            await _db.Entry(user).ReloadAsync();

            var policy = await _securityPolicy.GetAsync();
            var lockedOut = policy.MaxFailedLoginAttempts > 0 && user.FailedLoginAttempts >= policy.MaxFailedLoginAttempts;
            if (lockedOut)
            {
                if (policy.LockoutMinutes > 0)
                    user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(policy.LockoutMinutes);
                else
                    user.IsLocked = true;
                _db.Users.Update(user);
                await _db.SaveChangesAsync();
            }

            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTotpFailed,
                user.Id, user.Username,
                sourceIp: sourceIp, success: false,
                details: new { reason = "totp_recovery_code_invalid", user.FailedLoginAttempts, lockedOut },
                errorMessage: "RecoveryFailed");
            if (lockedOut)
            {
                await _notifications.NotifyAccountLockedAsync(user.Username, policy.LockoutMinutes > 0
                    ? $"Temporarily locked for {policy.LockoutMinutes} minutes after {user.FailedLoginAttempts} failed attempts (TOTP recovery code) from {sourceIp}"
                    : $"Permanently locked after {user.FailedLoginAttempts} failed attempts (TOTP recovery code) from {sourceIp}");
            }
            await DelayToBudgetAsync(sw);
            return Unauthorized(new { error = "Invalid recovery code" });
        }

        // Consume the code
        code.UsedAt = DateTime.UtcNow;

        // Clear the existing TOTP secret so the user must re-enroll.
        var secrets = await _db.TotpSecrets.Where(t => t.UserId == user.Id).ToListAsync();
        if (secrets.Count > 0) _db.TotpSecrets.RemoveRange(secrets);

        user.MfaEnrolledAt = null;
        _db.Users.Update(user);

        // The stamp invalidates JWTs; it does not touch refresh tokens, and refresh does not
        // check the stamp. A recovery code is used on a bad day, possibly because a device is
        // gone; the sessions on that device must go with it. This saves the consumed code and the
        // removed secret with the rotated stamp, and revokes the refresh tokens, in one transaction.
        await ModularCA.Core.Helpers.UserSessionTermination.EndAllSessionsSetBasedAsync(_db, user, DateTime.UtcNow);
        await ModularCA.API.Middleware.TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, user.Id);

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserUpdated,
            user.Id, user.Username,
            sourceIp: sourceIp,
            details: new { Action = "TotpRecoveryCodeUsed" });

        return Ok(new
        {
            message = "Recovery code accepted. TOTP has been reset. Please log in and call /auth/totp/setup to re-enroll your authenticator.",
            requiresReenrollment = true
        });
    }

    /// <summary>
    /// Waits until the security policy's <see cref="SecurityPolicyEntity.LoginResponseDelayMs"/>
    /// budget has elapsed since <paramref name="sw"/> started, so every refusal of a recovery takes
    /// about the same wall-clock time. As <c>AuthController</c> does for password sign-in.
    /// </summary>
    private async Task DelayToBudgetAsync(Stopwatch sw)
    {
        var budgetMs = (await _securityPolicy.GetAsync()).LoginResponseDelayMs;
        if (budgetMs <= 0) return;
        var elapsed = (int)sw.ElapsedMilliseconds;
        if (elapsed >= budgetMs) return;
        try
        {
            await Task.Delay(budgetMs - elapsed, HttpContext.RequestAborted);
        }
        catch (TaskCanceledException)
        {
            // Client disconnected.
        }
    }

    // ── Login verification ──────────────────────────────────────────

    /// <summary>
    /// Verifies a TOTP code during the login MFA flow. Accepts the temporary MFA token
    /// issued by the login endpoint (no JWT required), whether the first factor was a password or
    /// a client certificate. On success, issues a full JWT token, wearing the user's default
    /// access badge when they have one.
    /// <para>
    /// Single-use under concurrency: the code's time step is claimed through
    /// <see cref="MfaSingleUse.TryClaimTotpStepAsync"/> (a code already used, here or for step-up,
    /// is refused as invalid), and the pending-MFA token is consumed with
    /// <see cref="PendingMfaToken.ConsumeAsync"/>. Of concurrent verifications of one token, or of
    /// one code, exactly one issues a session. The token is read without consuming it first, so a
    /// mistyped code can be retried.
    /// </para>
    /// </summary>
    /// <param name="request">The pending-MFA token and the TOTP code.</param>
    [AllowAnonymous]
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] TotpMfaVerifyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.MfaToken))
            return BadRequest(new { error = "MFA token is required" });

        if (string.IsNullOrWhiteSpace(request.Code))
            return BadRequest(new { error = "TOTP code is required" });

        // Read the MFA token but do NOT remove it yet — removal happens on success or
        // when the failure threshold is reached. This allows the user to retry with a
        // correct code after a typo without being kicked back to login.
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var pending = await ModularCA.Auth.Utils.PendingMfaToken.PeekAsync(_cache, request.MfaToken);
        var userId = pending?.UserId ?? Guid.Empty;
        if (pending == null)
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTokenInvalid,
                actorUserId: null,
                actorUsername: null,
                targetEntityType: "User",
                sourceIp: sourceIp,
                success: false,
                errorMessage: "MFA token not found in cache or expired");
            return Unauthorized(new { error = "MFA token is invalid or expired" });
        }

        // Brute-force failure counter is scoped by userId (not
        // by MFA token), so attackers can't trivially reset it by reissuing a
        // fresh MFA token via a new /auth/login call. If the counter trips we
        // also nuke the MFA-token cache entry so re-login is still required.
        var failKey = $"mfa-fail:{userId}";
        var failCountStr = await _cache.GetStringAsync(failKey);
        var failCount = int.TryParse(failCountStr, out var fc) ? fc : 0;

        if (failCount >= 5)
        {
            await _cache.RemoveAsync($"mfa:{request.MfaToken}");
            await _cache.RemoveAsync(failKey);
            return StatusCode(429, new { error = "Too many failed MFA attempts. Please log in again." });
        }

        var user = await _db.Users.FindAsync(userId);
        if (user == null)
            return Unauthorized(new { error = "User not found" });

        // Find the user's verified TOTP secret
        var totpSecret = await _db.TotpSecrets
            .FirstOrDefaultAsync(t => t.UserId == userId && t.IsVerified);

        if (totpSecret == null)
            return BadRequest(new { error = "No TOTP secret configured for this user" });

        var secret = GetDecryptedSecret(totpSecret);
        var (valid, timeStep) = VerifyTotpCode(secret, request.Code, totpSecret.LastUsedTimeStep);
        // A code that matched is accepted once: the claim, not the LastUsedTimeStep read above,
        // decides between concurrent requests carrying it. A replay counts as a failure.
        var replayed = valid && !await MfaSingleUse.TryClaimTotpStepAsync(_replayGuard, userId, timeStep);
        if (!valid || replayed)
        {
            failCount++;
            await _cache.SetStringAsync(failKey, failCount.ToString(),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });

            Log.Warning("TOTP verification failed for {Username} (attempt {FailCount}/5, serverUtc={ServerUtc})",
                user.Username, failCount, DateTimeOffset.UtcNow.ToString("O"));

            // Increment the Prometheus failure counter so
            // operators can alert on brute-force in progress without SIEM.
            MetricsService.AuthMfaVerificationFailuresTotal.WithLabels("totp", replayed ? "replayed_code" : "invalid_code").Inc();

            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTotpFailed,
                actorUserId: userId,
                actorUsername: user.Username,
                targetEntityType: "User",
                targetEntityId: userId.ToString(),
                sourceIp: sourceIp,
                success: false,
                errorMessage: replayed ? "TOTP code already used" : "Invalid TOTP code");
            return Unauthorized(new { error = "Invalid TOTP code" });
        }

        // Consume the MFA token. Every concurrent request for it has read it above; the atomic
        // claim inside ConsumeAsync lets exactly one of them go on to issue a session.
        if (await ModularCA.Auth.Utils.PendingMfaToken.ConsumeAsync(_cache, _replayGuard, request.MfaToken) == null)
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.MfaTokenInvalid,
                actorUserId: userId,
                actorUsername: user.Username,
                targetEntityType: "User",
                targetEntityId: userId.ToString(),
                sourceIp: sourceIp,
                success: false,
                errorMessage: "MFA token already consumed or expired");
            return Unauthorized(new { error = "MFA token is invalid or expired" });
        }

        // TOTP verified — update last used timestamp and time step for replay prevention
        totpSecret.LastUsedTimeStep = timeStep;
        totpSecret.LastUsedAt = DateTime.UtcNow;
        MetricsService.AuthMfaVerificationsTotal.WithLabels("totp").Inc();

        // Clear the failure counter.
        await _cache.RemoveAsync(failKey);

        // MFA is complete; issue the JWT.
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
                details: new { Reason = blockedAtIssue, Flow = "totp-verify" },
                success: false);
            return StatusCode(403, new { error = AccountStateGate.ClientMessage });
        }

        var groups = await _db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group)
            .Select(gm => gm.Group)
            .ToListAsync();
        // A default access badge starts the session narrowed, as on every sign-in path.
        var defaultBadge = await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Authorization.AccessBadgeService>().GetDefaultClaimAsync(user.Id);
        var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, badge: defaultBadge);
        var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
        var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash,
            await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Services.IDpopProofService>().GetValidatedJktAsync(HttpContext));
        refreshToken.AccessBadgeId = defaultBadge?.Id;
        // Hand the plaintext back to the client; the DB stores the hash.
        var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

        user.LastLoginAt = DateTime.UtcNow;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;

        _db.RefreshTokens.Add(refreshToken);
        _db.Users.Update(user);
        await _db.SaveChangesAsync();

        // Enforce concurrent session limit
        var secPolicy = await _securityPolicy.GetAsync();
        if (secPolicy.MaxConcurrentSessions > 0)
        {
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            if (activeTokens.Count > secPolicy.MaxConcurrentSessions)
            {
                var tokensToRevoke = activeTokens.Skip(secPolicy.MaxConcurrentSessions);
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
            details: new { TwoFactor = "TOTP" });

        return Ok(new LoginResponse
        {
            Token = Token,
            ExpiresAt = ExpiresAt,
            RefreshToken = refreshPlaintext
        });
    }

    // ── Removal ─────────────────────────────────────────────────────

    /// <summary>
    /// Removes the TOTP secret from the authenticated user's account, disabling
    /// authenticator-app-based MFA. Requires a valid step-up MFA token via X-MFA-Token header.
    /// Blocks removal if TOTP is the user's only remaining MFA method. Removes the secret and ends
    /// every session of the account (the current one included) in one save, as removing a WebAuthn
    /// or mTLS credential does, since a session does not record which factor opened it; the ending
    /// is audited as <see cref="AuditActionType.UserSessionsEnded"/>.
    /// </summary>
    [Authorize]
    [HttpDelete]
    [RequireStepUp(StepUpOps.TotpRemove)]
    public async Task<IActionResult> Remove()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var secrets = await _db.TotpSecrets.Where(t => t.UserId == userId.Value).ToListAsync();
        if (secrets.Count == 0)
            return NotFound(new { error = "No TOTP secret found for this user" });

        // Prevent removal of last MFA method
        var hasWebAuthn = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var hasActiveMtls = await _db.MtlsCredentials.Where(await ModularCA.Core.Helpers.MtlsCredentialStatus.UsableAsync(_db, DateTime.UtcNow)).AnyAsync(c => c.UserId == userId.Value);
        if (!hasWebAuthn && !hasActiveMtls)
            return StatusCode(409, new { error = "Cannot remove your only MFA method. Register a security key or enroll an mTLS certificate before removing TOTP." });

        _db.TotpSecrets.RemoveRange(secrets);

        // Refresh tokens do not record the factor that opened them, so every session ends, as it
        // does when a WebAuthn or mTLS credential is removed.
        var ended = await ModularCA.Core.Helpers.UserSessionTermination.EndAllSessionsAsync(_db, [userId.Value], DateTime.UtcNow);
        await _db.SaveChangesAsync();
        await ModularCA.Core.Helpers.UserSessionTermination.InvalidateStampCacheAsync(_cache, [userId.Value]);

        // Emit the dedicated MfaTotpRemoved action type (not the
        // generic UserUpdated) and capture the source IP so detection rules like
        // "alert on >N MFA removals from same IP" can actually fire.
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaTotpRemoved,
            userId.Value,
            _currentUser.User?.Username,
            targetEntityType: "User",
            targetEntityId: userId.Value.ToString(),
            details: new { Action = "TotpRemoved" },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        foreach (var e in ended)
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserSessionsEnded,
                userId.Value,
                _currentUser.User?.Username,
                targetEntityType: "User",
                targetEntityId: e.UserId.ToString(),
                details: new { reason = "totp_removed", refreshTokensRevoked = e.RefreshTokensRevoked },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        }

        return Ok(new { message = "TOTP has been removed from your account. Every session of this account has been signed out; sign in again." });
    }

    // ── Decryption / lazy migration ──────────────────────────────────

    /// <summary>
    /// Returns the plaintext TOTP secret by decrypting <see cref="TotpSecretEntity.EncryptedSecretKey"/>.
    /// </summary>
    private string GetDecryptedSecret(TotpSecretEntity entity)
    {
        if (string.IsNullOrEmpty(entity.EncryptedSecretKey))
            throw new InvalidOperationException("No TOTP secret found");
        return _protector.Unprotect(entity.EncryptedSecretKey);
    }

    // ── TOTP RFC 6238 implementation ────────────────────────────────

    /// <summary>
    /// Generates a 6-digit TOTP code for the given key and time step per RFC 6238.
    /// </summary>
    private static string GenerateTotp(byte[] key, long timeStep)
    {
        // TOTP uses HMAC-SHA1 per RFC 6238 default. While SHA-1 has known collision weaknesses,
        // HMAC-SHA1 remains secure for TOTP (no collision attacks apply to HMAC construction).
        // Changing to SHA-256 would break compatibility with most authenticator apps.
        using var hmac = new HMACSHA1(key);
        var timeBytes = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian) Array.Reverse(timeBytes);
        var hash = hmac.ComputeHash(timeBytes);
        var offset = hash[^1] & 0x0F;
        var code = ((hash[offset] & 0x7F) << 24
                  | hash[offset + 1] << 16
                  | hash[offset + 2] << 8
                  | hash[offset + 3]) % 1_000_000;
        return code.ToString("D6");
    }

    /// <summary>
    /// Verifies a TOTP code against the given base32-encoded secret, allowing
    /// a configurable time-step window to account for clock drift.
    /// Rejects any time step at or before <paramref name="lastUsedTimeStep"/> to prevent replay attacks.
    /// Exposed as internal static so <see cref="MfaStepUpController"/> can reuse it.
    /// </summary>
    /// <param name="secret">Base32-encoded shared secret.</param>
    /// <param name="code">The 6-digit TOTP code to verify.</param>
    /// <param name="lastUsedTimeStep">The last successfully verified time step. Codes at or before this step are rejected.</param>
    /// <param name="windowSize">Number of time steps to check before and after the current step (default 1).</param>
    /// <returns>A tuple indicating whether the code is valid and, if so, the matched time step.</returns>
    internal static (bool valid, long timeStep) VerifyTotpCode(string secret, string code, long lastUsedTimeStep = 0, int windowSize = 1)
    {
        var key = Base32Decode(secret);
        var currentTimeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        for (int i = -windowSize; i <= windowSize; i++)
        {
            var step = currentTimeStep + i;
            if (step <= lastUsedTimeStep) continue; // Reject replayed time steps
            if (GenerateTotp(key, step) == code)
                return (true, step);
        }
        return (false, 0);
    }

    /// <summary>
    /// Verifies a TOTP code against the given base32-encoded secret, accepting the code of every
    /// 30-second step that overlaps the span from <paramref name="tolerance"/> before
    /// <paramref name="now"/> to <paramref name="tolerance"/> after it. With a tolerance under one
    /// step that is the current code, plus the previous one early in a step or the next one late
    /// in it: never more than two codes at once, where <see cref="VerifyTotpCode"/> with a window
    /// of one accepts three. Rejects any time step at or before
    /// <paramref name="lastUsedTimeStep"/> to prevent replay attacks.
    /// </summary>
    /// <param name="secret">Base32-encoded shared secret.</param>
    /// <param name="code">The 6-digit TOTP code to verify.</param>
    /// <param name="lastUsedTimeStep">The last successfully verified time step. Codes at or before this step are rejected.</param>
    /// <param name="tolerance">How far the caller's clock may differ from this host's, in either direction.</param>
    /// <param name="now">The time to verify at.</param>
    /// <returns>A tuple indicating whether the code is valid and, if so, the matched time step.</returns>
    internal static (bool valid, long timeStep) VerifyTotpCodeWithin(string secret, string code, long lastUsedTimeStep, TimeSpan tolerance, DateTimeOffset now)
    {
        var key = Base32Decode(secret);
        var seconds = now.ToUnixTimeSeconds();
        var slack = (long)tolerance.TotalSeconds;
        var current = seconds / 30;
        var first = (seconds - slack) / 30;
        var last = (seconds + slack) / 30;

        // The current step first, so a code that is right by this host's clock is matched to it.
        if (current > lastUsedTimeStep && GenerateTotp(key, current) == code)
            return (true, current);
        for (var step = first; step <= last; step++)
        {
            if (step == current || step <= lastUsedTimeStep) continue; // Reject replayed time steps
            if (GenerateTotp(key, step) == code)
                return (true, step);
        }
        return (false, 0);
    }

    // ── Base32 helpers ──────────────────────────────────────────────

    private static readonly char[] Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

    /// <summary>
    /// Encodes a byte array to a base32 string (RFC 4648) without padding.
    /// </summary>
    internal static string Base32Encode(byte[] data)
    {
        var result = new System.Text.StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                result.Append(Base32Alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }
        if (bitsLeft > 0)
        {
            result.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }
        return result.ToString();
    }

    /// <summary>
    /// Decodes a base32-encoded string (RFC 4648) to a byte array. Ignores padding characters.
    /// </summary>
    internal static byte[] Base32Decode(string base32)
    {
        base32 = base32.TrimEnd('=').ToUpperInvariant();
        var output = new byte[base32.Length * 5 / 8];
        int buffer = 0, bitsLeft = 0, index = 0;
        foreach (var c in base32)
        {
            int value;
            if (c >= 'A' && c <= 'Z')
                value = c - 'A';
            else if (c >= '2' && c <= '7')
                value = c - '2' + 26;
            else
                throw new FormatException($"Invalid base32 character: {c}");

            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output[index++] = (byte)(buffer >> bitsLeft);
            }
        }
        return output;
    }
}

// ── Request models ──────────────────────────────────────────────────

/// <summary>
/// Request body for the TOTP setup endpoint.
/// </summary>
public class TotpSetupRequest
{
    /// <summary>Optional friendly name for the authenticator device.</summary>
    public string? DeviceName { get; set; }
}

/// <summary>
/// Request body for TOTP code verification during setup (requires JWT).
/// </summary>
public class TotpCodeRequest
{
    /// <summary>The 6-digit TOTP code from the authenticator app.</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Request body for TOTP verification during the login MFA flow (uses MFA token, no JWT required).
/// </summary>
public class TotpMfaVerifyRequest
{
    /// <summary>The temporary MFA token issued by the login endpoint after successful password verification.</summary>
    public string MfaToken { get; set; } = string.Empty;

    /// <summary>The 6-digit TOTP code from the authenticator app.</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Request body for the one-time TOTP recovery code exchange.
/// </summary>
public class TotpRecoveryRequest
{
    /// <summary>Username of the account whose TOTP is being recovered.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Plaintext recovery code issued at TOTP enrollment. Case- and dash-insensitive.</summary>
    public string RecoveryCode { get; set; } = string.Empty;
}
