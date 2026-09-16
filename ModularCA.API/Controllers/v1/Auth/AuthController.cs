using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Fido2NetLib;
using Fido2NetLib.Objects;
using ModularCA.API.Middleware;
using ModularCA.API.Services;
using ModularCA.API.Validation.Users;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Models;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Controllers.v1.Auth
{
    /// <summary>
    /// Authentication endpoints for JWT login, token refresh, certificate-based authentication,
    /// and pre-JWT password change for forced password reset on first login.
    /// Exposed at both <c>/auth/*</c> (canonical public short URL) and <c>/api/v1/auth/*</c>
    /// (legacy path, kept active during the frontend migration).
    /// </summary>
    [ApiController]
    [Route("api/v1/auth")]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        private readonly ModularCADbContext _db;
        private readonly IJwtTokenService _jwt;
        private readonly ICurrentUserService _currentUser;
        private readonly IAuditService _audit;
        private readonly SystemConfig _config;
        private readonly ILdapAuthService _ldapAuth;
        private readonly ModularCA.Core.Services.ILdapGroupSyncService _groupSync;
        private readonly ModularCA.Core.Services.INotificationService _notifications;
        private readonly IPasswordPolicyService _passwordPolicy;
        private readonly ISecurityPolicyService _securityPolicy;
        private readonly IFido2? _fido2;
        // SECURITY: IDistributedCache is required — AddDistributedMemoryCache() is registered
        // unconditionally in StartModularCA.cs as a fail-closed fallback when Redis isn't
        // configured, and a post-build sanity check refuses to boot if it can't be resolved.
        // The MFA step-up path (availableMfaMethods.Count > 0) depends on this cache to issue
        // short-lived MFA tokens; if cache were missing, the branch would previously fall
        // through to full JWT issuance and silently bypass MFA. Do not mark this nullable.
        private readonly IDistributedCache _cache;
        private readonly IValidator<ModularCA.Auth.Models.LoginRequest> _loginValidator;
        private readonly IValidator<PreJwtChangePasswordRequest> _changePasswordValidator;

        /// <summary>
        /// Initializes the authentication controller with required services.
        /// IFido2 is only injected when WebAuthn is enabled.
        /// IDistributedCache is always required: a concrete implementation
        /// (Redis or in-process memory) is registered unconditionally at startup
        /// and validated post-build so the MFA step-up branch cannot silently
        /// fall through to full JWT issuance when TOTP/WebAuthn methods exist.
        /// <see cref="IValidator{LoginRequest}"/> and
        /// <see cref="IValidator{PreJwtChangePasswordRequest}"/> are now injected so shape
        /// validation happens before the auth path touches the DB.
        /// </summary>
        public AuthController(ModularCADbContext db, IJwtTokenService jwt, ICurrentUserService currentUser,
            IAuditService audit, SystemConfig config, ILdapAuthService ldapAuth,
            ModularCA.Core.Services.ILdapGroupSyncService groupSync,
            ModularCA.Core.Services.INotificationService notifications,
            IPasswordPolicyService passwordPolicy,
            ISecurityPolicyService securityPolicy,
            IValidator<ModularCA.Auth.Models.LoginRequest> loginValidator,
            IValidator<PreJwtChangePasswordRequest> changePasswordValidator,
            IDistributedCache cache,
            IFido2? fido2 = null)
        {
            _db = db;
            _jwt = jwt;
            _currentUser = currentUser;
            _audit = audit;
            _config = config;
            _ldapAuth = ldapAuth;
            _groupSync = groupSync;
            _notifications = notifications;
            _passwordPolicy = passwordPolicy;
            _securityPolicy = securityPolicy;
            _loginValidator = loginValidator;
            _changePasswordValidator = changePasswordValidator;
            _cache = cache ?? throw new ArgumentNullException(nameof(cache),
                "IDistributedCache must be registered — MFA step-up tokens cannot be issued without it. " +
                "Check StartModularCA.cs cache registration.");
            _fido2 = fido2;
        }

        /// <summary>
        /// Returns the system use notification banner for display on login pages.
        /// Returns empty when no banner is configured.
        /// </summary>
        [AllowAnonymous]
        [HttpGet("login-banner")]
        public async Task<IActionResult> GetLoginBanner()
        {
            var policy = await _securityPolicy.GetAsync();
            var banner = string.IsNullOrWhiteSpace(policy.LoginBanner) ? null : policy.LoginBanner;
            var title = string.IsNullOrWhiteSpace(policy.LoginBannerTitle) ? null : policy.LoginBannerTitle;
            return Ok(new { banner, title });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] ModularCA.Auth.Models.LoginRequest request)
        {
            // Wall-clock budget so the response always takes the same
            // amount of time regardless of which validation branch fires.
            var sw = Stopwatch.StartNew();
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Shape-validate before we touch the DB. This blocks unicode
            // homoglyph / overlong / control-char username probes before they can seed audit
            // log entries or drive user-enumeration side channels.
            request.Username = UserFieldValidators.NormalizeIdentity(request.Username) ?? request.Username;
            var loginValidation = await _loginValidator.ValidateAsync(request);
            if (!loginValidation.IsValid)
            {
                MetricsService.AuthLoginFailures.WithLabels("invalid_input").Inc();
                MetricsService.AuthLoginTotal.WithLabels("password", "false").Inc();
                // Burn a dummy hash so the timing matches the real-user path — an attacker
                // cannot separate "invalid shape" from "user not found" from "wrong password"
                // by wall-clock.
                PasswordUtil.DummyVerify(request.Password ?? string.Empty);
                await DelayToBudgetAsync(sw);
                return Unauthorized(new { error = "Invalid username or password" });
            }

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

            // Collapse user-not-found and all account-state pre-checks into
            // a single generic 401 so the public login endpoint does not leak account state.
            // Distinguishing errors (disabled/locked/password_change_required/password_expired)
            // only surface AFTER a correct password has been verified.
            if (user == null)
            {
                MetricsService.AuthLoginFailures.WithLabels("user_not_found").Inc();
                MetricsService.AuthLoginTotal.WithLabels("password", "false").Inc();
                await _audit.LogAsync(AuditActionType.UserLoginFailed, null, request.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "user_not_found" },
                    errorMessage: "LoginFailed");
                PasswordUtil.DummyVerify(request.Password ?? string.Empty);
                await DelayToBudgetAsync(sw);
                return Unauthorized(new { error = "Invalid username or password" });
            }

            // Clear expired lockout BEFORE evaluating account state gates so a user whose
            // temporary lockout has elapsed can verify their password normally.
            if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc <= DateTime.UtcNow)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
            }

            // Pre-compute account gating flags — do NOT return yet. These are applied
            // AFTER password verification so an attacker who doesn't have the password
            // cannot enumerate disabled/locked/change-required accounts.
            bool isDisabled = !user.IsActive;
            bool isHardLocked = user.IsLocked;
            bool isTempLocked = user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow;

            // Password verification — try LDAP first if enabled, then fall back to local
            var passwordValid = false;
            var ldapAuthenticated = false;
            if (_config.LdapAuth.Enabled)
            {
                var (ldapSuccess, _) = await _ldapAuth.AuthenticateAsync(request.Username, request.Password);
                passwordValid = ldapSuccess;
                ldapAuthenticated = ldapSuccess;
            }
            if (!passwordValid)
                passwordValid = PasswordUtil.VerifyPassword(request.Password, user.PasswordHash);

            if (!passwordValid)
            {
                MetricsService.AuthLoginTotal.WithLabels(ldapAuthenticated ? "ldap" : "password", "false").Inc();
                MetricsService.AuthLoginFailures.WithLabels("invalid_password").Inc();

                // Atomic increment via provider-agnostic ExecuteUpdateAsync.
                // Replaces an earlier raw-SQL UPDATE that used PostgreSQL-style double-quoted
                // identifiers — those fail on stock MySQL (quotes become string literals unless
                // ANSI_QUOTES is set), silently disabling the failed-login lockout counter.
                await _db.Users
                    .Where(u => u.Id == user.Id)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
                await _db.Entry(user).ReloadAsync();

                var maxAttempts = (await _securityPolicy.GetAsync()).MaxFailedLoginAttempts;
                var lockoutMinutes = (await _securityPolicy.GetAsync()).LockoutMinutes;

                if (maxAttempts > 0 && user.FailedLoginAttempts >= maxAttempts)
                {
                    if (lockoutMinutes > 0)
                    {
                        user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                        // Collapse account-state reason into DetailsJson
                        // so the audit log does not leak enumeration info into the summary
                        // column that auditors/SIEMs ingest unfiltered.
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                            sourceIp: sourceIp, success: false,
                            details: new { reason = "temp_lockout", attempts = user.FailedLoginAttempts, lockoutMinutes },
                            errorMessage: "LoginFailed");
                        await _notifications.NotifyAccountLockedAsync(user.Username,
                            $"Temporarily locked for {lockoutMinutes} minutes after {user.FailedLoginAttempts} failed attempts from {sourceIp}");
                    }
                    else
                    {
                        user.IsLocked = true;
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                            sourceIp: sourceIp, success: false,
                            details: new { reason = "hard_lockout", attempts = user.FailedLoginAttempts },
                            errorMessage: "LoginFailed");
                        await _notifications.NotifyAccountLockedAsync(user.Username,
                            $"Permanently locked after {user.FailedLoginAttempts} failed attempts from {sourceIp}");
                    }
                }
                else
                {
                    await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                        sourceIp: sourceIp, success: false,
                        details: new { reason = "invalid_password" },
                        errorMessage: "LoginFailed");
                }

                _db.Users.Update(user);
                await _db.SaveChangesAsync();
                await DelayToBudgetAsync(sw);
                return Unauthorized(new { error = "Invalid username or password" });
            }

            // --- Password verified. Now apply the gates that were deferred above so an
            // attacker cannot enumerate account state without a correct password. ---

            if (isDisabled)
            {
                MetricsService.AuthLoginFailures.WithLabels("account_disabled").Inc();
                MetricsService.AuthLoginTotal.WithLabels("password", "false").Inc();
                await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "account_disabled" },
                    errorMessage: "LoginFailed");
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is disabled" });
            }
            if (isHardLocked)
            {
                MetricsService.AuthLoginFailures.WithLabels("account_locked").Inc();
                MetricsService.AuthLoginTotal.WithLabels("password", "false").Inc();
                await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "account_locked" },
                    errorMessage: "LoginFailed");
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is locked. Contact an administrator." });
            }
            if (isTempLocked)
            {
                MetricsService.AuthLoginFailures.WithLabels("account_temporarily_locked").Inc();
                MetricsService.AuthLoginTotal.WithLabels("password", "false").Inc();
                await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "account_temporarily_locked" },
                    errorMessage: "LoginFailed");
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is temporarily locked. Try again later." });
            }

            // Rehash-on-verify. If the stored hash is below the current
            // minimum iteration count (legacy 100k or anything pre-600k), transparently
            // rehash with the modern parameters and save. LDAP-authenticated logins skip
            // this — they don't use the local hash at all.
            if (!ldapAuthenticated && PasswordUtil.NeedsRehash(user.PasswordHash))
            {
                user.PasswordHash = PasswordUtil.HashPassword(request.Password);
            }

            // Password policy checks (after successful password verification)
            if (user.PasswordChangeOnNextLogon)
            {
                MetricsService.AuthLoginFailures.WithLabels("password_change_required").Inc();
                // Reset failed attempts on correct password even if forced to change
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
                _db.Users.Update(user);
                await _db.SaveChangesAsync();
                return StatusCode(403, new { error = "Password change required", requirePasswordChange = true });
            }

            if (!user.PasswordNeverExpires && user.PasswordExpirationDate.HasValue && user.PasswordExpirationDate < DateTime.UtcNow)
            {
                MetricsService.AuthLoginFailures.WithLabels("password_expired").Inc();
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
                _db.Users.Update(user);
                await _db.SaveChangesAsync();
                return StatusCode(403, new { error = "Password has expired", passwordExpired = true });
            }

            // LDAP group sync (if LDAP authenticated and group sync enabled)
            if (ldapAuthenticated && _config.LdapAuth.GroupSyncEnabled)
            {
                var ldapGroups = await _ldapAuth.GetUserGroupsAsync(request.Username);
                await _groupSync.SyncUserGroupsAsync(user.Id, ldapGroups);
            }

            // === MFA Check ===
            // After successful password verification, determine available MFA methods
            var availableMfaMethods = new List<string>();

            // Check TOTP
            var hasTotpSecret = await _db.TotpSecrets.AnyAsync(t => t.UserId == user.Id && t.IsVerified);
            if (hasTotpSecret) availableMfaMethods.Add("totp");

            // Check WebAuthn
            bool hasWebAuthnCredentials = false;
            if (_config.WebAuthn.Enabled && _fido2 != null)
            {
                hasWebAuthnCredentials = await _db.Fido2Credentials.AnyAsync(c => c.UserId == user.Id);
                if (hasWebAuthnCredentials) availableMfaMethods.Add("webauthn");
            }

            // Check mTLS credentials
            var hasMtls = await _db.MtlsCredentials.AnyAsync(c => c.UserId == user.Id && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);
            if (hasMtls) availableMfaMethods.Add("mtls");

            // Check if MFA is enforced for any of the user's groups
            var userGroups = await _db.CaGroupMembers
                .Where(gm => gm.UserId == user.Id)
                .Include(gm => gm.Group)
                    .ThenInclude(g => g.Grants)
                .Select(gm => gm.Group)
                .ToListAsync();
            var mfaEnforced = _config.WebAuthn.EnforceForGroups.Count > 0
                && userGroups.Any(g => _config.WebAuthn.EnforceForGroups.Contains(g.TemplateName ?? "Custom", StringComparer.OrdinalIgnoreCase));

            if (availableMfaMethods.Count == 0 && mfaEnforced)
            {
                MetricsService.AuthLoginFailures.WithLabels("mfa_required_not_enrolled").Inc();
                // MFA required but no methods configured
                user.FailedLoginAttempts = 0;
                _db.Users.Update(user);
                await _db.SaveChangesAsync();
                return StatusCode(403, new
                {
                    error = "Multi-factor authentication is required for your role but no MFA methods are configured. Set up TOTP or a security key.",
                    requiresMfaEnrollment = true
                });
            }

            // SECURITY: do NOT add a `_cache != null` guard here. _cache is non-nullable and is
            // validated at startup. If MFA methods are enrolled we MUST take the MFA step-up
            // branch; falling through to JWT issuance would silently bypass MFA.
            if (availableMfaMethods.Count > 0)
            {
                // Issue a temporary MFA token (not a full JWT — short-lived, only valid for MFA verification)
                // TTL is now driven by SecurityPolicyEntity.MfaSessionTtlSeconds (default 300 s, DB-backed)
                // and clamped to a sane operator range. Centralized so all six call sites that
                // hard-coded TimeSpan.FromMinutes(5) read from a single knob.
                var mfaToken = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
                var mfaSessionTtl = Math.Clamp((await _securityPolicy.GetAsync()).MfaSessionTtlSeconds, 60, 900);
                await _cache.SetStringAsync($"mfa:{mfaToken}", user.Id.ToString(), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(mfaSessionTtl)
                });

                // Reset failed attempts
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
                _db.Users.Update(user);
                await _db.SaveChangesAsync();

                if (availableMfaMethods.Count == 1)
                {
                    // Only one method — prompt for it directly
                    var method = availableMfaMethods[0];
                    var response = new Dictionary<string, object>
                    {
                        { "requiresMfa", true },
                        { "mfaToken", mfaToken },
                        { "method", method },
                        { "availableMethods", availableMfaMethods }
                    };

                    // If WebAuthn, include assertion options
                    if (method == "webauthn" && _fido2 != null)
                    {
                        var existingKeys = await _db.Fido2Credentials
                            .Where(c => c.UserId == user.Id)
                            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                            .ToListAsync();
                        var assertionOptions = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
                        {
                            AllowedCredentials = existingKeys,
                            UserVerification = UserVerificationRequirement.Preferred
                        });
                        await _cache.SetStringAsync($"webauthn:assert:{user.Id}", assertionOptions.ToJson(),
                            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
                        // Embed as a parsed JsonNode so the global JsonStringEnumConverter does
                        // not stringify the WebAuthn enums (alg/type) into values the browser
                        // rejects. ToJson() is the library's spec-correct serializer.
                        response["assertionOptions"] = System.Text.Json.Nodes.JsonNode.Parse(assertionOptions.ToJson())!;
                    }

                    return Ok(response);
                }
                else
                {
                    // Multiple methods — let client choose
                    return Ok(new
                    {
                        requiresMfa = true,
                        mfaToken,
                        availableMethods = availableMfaMethods,
                        message = "Select an MFA method to continue"
                    });
                }
            }

            // Successful login — issue tokens (roles refreshed after sync)
            // Determine whether MFA enrollment is required.
            // For admin/operator roles (system-wide groups), TOTP or WebAuthn is mandatory;
            // mTLS alone is not sufficient because those roles can perform privileged operations.
            // Any user in a system group (admin, operator, auditor) must have TOTP or WebAuthn.
            // mTLS alone is not sufficient for admin roles — TOTP/WebAuthn provides a second
            // factor that doesn't depend on the CA infrastructure being operational.
            var isAdminRole = userGroups.Any(g => g.IsSystemGroup);
            var mfaSetupRequired = isAdminRole
                ? !hasTotpSecret && !hasWebAuthnCredentials
                : !hasTotpSecret && !hasWebAuthnCredentials && !hasMtls;
            var mtlsOnlyWarning = hasMtls && !hasTotpSecret && !hasWebAuthnCredentials;

            // Reuse userGroups (already queried above) instead of a duplicate DB round-trip
            var groups = userGroups;
            // A default access badge starts the session narrowed; badgeless otherwise.
            var defaultBadge = await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Authorization.AccessBadgeService>().GetDefaultAsync(user.Id);
            var badgeClaim = defaultBadge == null ? null : new ModularCA.Auth.Interfaces.AccessBadgeClaim(defaultBadge.Id, defaultBadge.Name);
            var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupRequired, badge: badgeClaim);
            var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
            var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash,
                await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Services.IDpopProofService>().GetValidatedJktAsync(HttpContext));
            refreshToken.AccessBadgeId = defaultBadge?.Id;
            var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            user.LastLoginAt = DateTime.UtcNow;

            _db.RefreshTokens.Add(refreshToken);
            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            // Enforce concurrent session limit
            if ((await _securityPolicy.GetAsync()).MaxConcurrentSessions > 0)
            {
                var activeTokens = await _db.RefreshTokens
                    .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(t => t.CreatedAt)
                    .ToListAsync();

                if (activeTokens.Count > (await _securityPolicy.GetAsync()).MaxConcurrentSessions)
                {
                    var tokensToRevoke = activeTokens.Skip((await _securityPolicy.GetAsync()).MaxConcurrentSessions);
                    foreach (var old in tokensToRevoke)
                    {
                        old.IsRevoked = true;
                        old.RevokedAt = DateTime.UtcNow;
                    }
                    await _db.SaveChangesAsync();
                }
            }

            await _audit.LogAsync(AuditActionType.UserLogin, user.Id, user.Username, sourceIp: sourceIp);
            MetricsService.AuthLoginTotal.WithLabels(ldapAuthenticated ? "ldap" : "password", "true").Inc();

            return Ok(new LoginResponse
            {
                Token = Token,
                ExpiresAt = ExpiresAt,
                RefreshToken = refreshPlaintext,
                MfaSetupRequired = mfaSetupRequired ? true : null,
                MtlsOnlyWarning = mtlsOnlyWarning ? true : null
            });
        }

        /// <summary>
        /// Waits until the configured <see cref="ModularCA.Shared.Entities.SecurityPolicyEntity.LoginResponseDelayMs"/>
        /// budget has elapsed so the endpoint always takes roughly the same wall-clock time
        /// regardless of which validation branch fired. Called on every failure path.
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
                // Client disconnected — no-op.
            }
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
                return Unauthorized(new { error = "Invalid or expired refresh token" });

            // Refresh tokens are stored SHA-256 hashed — hash before lookup.
            var hashedIncoming = JwtTokenService.HashRefreshToken(request.RefreshToken);

            // Look up regardless of revoked status so genuine reuse (a replayed, already-rotated
            // token) can be told apart from an unknown token, just below.
            var stored = await _db.RefreshTokens
                .Include(x => x.User)
                .FirstOrDefaultAsync(x => x.Token == hashedIncoming);

            if (stored == null || stored.ExpiresAt < DateTime.UtcNow)
                return Unauthorized(new { error = "Invalid or expired refresh token" });

            // Refresh-token reuse detection (rotation). A token that is already REVOKED is being
            // replayed — the client already rotated it, or a stolen copy is in use. If it belonged to
            // a rotation family, revoke the whole family (fail safe). This fires only on genuine replay
            // of a spent token — NOT on every post-rotation refresh. (Previously a normally-revoked
            // predecessor tripped a "any revoked sibling" check, breaking the 2nd refresh of every
            // session; that check is removed below.)
            if (stored.IsRevoked)
            {
                if (stored.FamilyId.HasValue)
                {
                    var familyTokens = await _db.RefreshTokens
                        .Where(t => t.FamilyId == stored.FamilyId && !t.IsRevoked)
                        .ToListAsync();
                    foreach (var t in familyTokens)
                    {
                        t.IsRevoked = true;
                        t.RevokedAt = DateTime.UtcNow;
                    }
                    await _db.SaveChangesAsync();
                    await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, stored.User?.Username,
                        sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(), success: false,
                        errorMessage: $"Refresh token reuse detected in family {stored.FamilyId} — all tokens revoked");
                    return Unauthorized(new { error = "Token family compromised. Please log in again." });
                }
                return Unauthorized(new { error = "Invalid or expired refresh token" });
            }

            // Absolute session lifetime cap based on the original family's
            // CreatedAt. Refresh rotation must not extend a session beyond this horizon.
            var maxSessionDays = (await _securityPolicy.GetAsync()).MaxSessionLifetimeDays;
            if (maxSessionDays > 0 && stored.FamilyCreatedAt.HasValue)
            {
                var sessionHorizon = stored.FamilyCreatedAt.Value.AddDays(maxSessionDays);
                if (DateTime.UtcNow > sessionHorizon)
                {
                    stored.IsRevoked = true;
                    stored.RevokedAt = DateTime.UtcNow;
                    await _db.SaveChangesAsync();
                    return Unauthorized(new { error = "Session lifetime exceeded. Please log in again." });
                }
            }

            var user = stored.User;
            if (user == null)
                return Unauthorized(new { error = "User associated with refresh token not found" });

            // Idle timeout check — reject if the session has been inactive too long
            if ((await _securityPolicy.GetAsync()).SessionIdleTimeoutMinutes > 0 &&
                stored.LastActivityAt.AddMinutes((await _securityPolicy.GetAsync()).SessionIdleTimeoutMinutes) < DateTime.UtcNow)
            {
                stored.IsRevoked = true;
                stored.RevokedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync();
                return Unauthorized(new { error = "Session expired due to inactivity" });
            }

            // Enforce account status on refresh — locked/disabled users can't refresh
            if (!user.IsActive || user.IsLocked || (user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow))
            {
                stored.IsRevoked = true;
                stored.RevokedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync();
                return StatusCode(403, new { error = "Account is locked or disabled" });
            }

            var groups = await _db.CaGroupMembers
                .Where(gm => gm.UserId == user.Id)
                .Include(gm => gm.Group)
                    .ThenInclude(g => g.Grants)
                .Select(gm => gm.Group)
                .ToListAsync();
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Refresh token binding checks
            var currentIp = HttpContext.Connection.RemoteIpAddress;
            var currentIpStr = currentIp != null
                ? (currentIp.IsIPv4MappedToIPv6 ? currentIp.MapToIPv4().ToString() : currentIp.ToString())
                : null;

            if (_config.Security.BindRefreshTokenToIp && stored.CreatedByIp != null && currentIpStr != stored.CreatedByIp)
            {
                // IP is an audit signal only — refresh-token theft is defended by DPoP proof-of-
                // possession (CnfJkt below) plus rotation/family-reuse detection, NOT by IP pinning,
                // which breaks legitimate dual-stack (IPv4/IPv6) and roaming clients. Never revoke here.
                await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, user.Username,
                    sourceIp: currentIpStr, success: true, errorMessage: $"Refresh token IP changed (allowed): expected {stored.CreatedByIp}, got {currentIpStr}");
            }

            if (_config.Security.BindRefreshTokenToFingerprint && stored.UserAgentHash != null)
            {
                var currentUaHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
                if (currentUaHash != stored.UserAgentHash)
                {
                    if (!_config.Security.AllowRefreshTokenMismatch)
                    {
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, user.Username,
                            sourceIp: currentIpStr, success: false, errorMessage: "Refresh token fingerprint mismatch");
                        stored.IsRevoked = true;
                        stored.RevokedAt = DateTime.UtcNow;
                        await _db.SaveChangesAsync();
                        return Unauthorized(new { error = "Session invalid: client fingerprint changed", code = "REFRESH_FINGERPRINT_MISMATCH" });
                    }
                    await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, user.Username,
                        sourceIp: currentIpStr, success: true, errorMessage: "Refresh token fingerprint mismatch (allowed)");
                }
            }

            // DPoP proof-of-possession enforcement (refresh-only). When this session was bound to a
            // client key at issuance (CnfJkt set), rotation requires a valid proof signed by that
            // non-extractable key — so a stolen refresh token alone cannot be used to keep the session
            // alive. Soft rollout: unbound (legacy/non-PoP) sessions skip the check until they expire.
            var dpopSvc = HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Services.IDpopProofService>();
            var proofJkt = await dpopSvc.GetValidatedJktAsync(HttpContext, HttpContext.RequestAborted);
            if (!string.IsNullOrEmpty(stored.CnfJkt))
            {
                var popOk = proofJkt != null && string.Equals(proofJkt, stored.CnfJkt, StringComparison.Ordinal);
                if (!popOk)
                {
                    // Short prefixes only — thumbprints aren't secret but keep the audit log terse.
                    var got = proofJkt == null ? "none" : proofJkt[..Math.Min(12, proofJkt.Length)];
                    var exp = stored.CnfJkt[..Math.Min(12, stored.CnfJkt.Length)];
                    var kind = proofJkt == null ? "missing" : "mismatch";
                    if (_config.Security.EnforceRefreshTokenPoP)
                    {
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, user.Username,
                            sourceIp: currentIpStr, success: false,
                            errorMessage: $"Refresh PoP {kind} (enforced): expected {exp}, got {got}");
                        return Unauthorized(new { error = "Proof of possession required for this session", code = "REFRESH_POP_INVALID" });
                    }
                    // Observe mode: log and allow; the binding follows the presented key below.
                    await _audit.LogAsync(AuditActionType.UserLoginFailed, stored.UserId, user.Username,
                        sourceIp: currentIpStr, success: true,
                        errorMessage: $"Refresh PoP {kind} (observe — allowed): expected {exp}, got {got}");
                }
            }

            // Preserve MFA setup requirement on refreshed tokens
            var hasTotp = await _db.TotpSecrets.AnyAsync(t => t.UserId == user.Id && t.IsVerified);
            var hasWebAuthn = await _db.Fido2Credentials.AnyAsync(c => c.UserId == user.Id);
            var hasMtlsCreds = await _db.MtlsCredentials.AnyAsync(c => c.UserId == user.Id && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);

            // All system group members must have TOTP or WebAuthn — mTLS alone is insufficient
            var isAdminOnRefresh = groups.Any(g => g.IsSystemGroup);
            var mfaSetupNeeded = isAdminOnRefresh
                ? !hasTotp && !hasWebAuthn
                : !hasTotp && !hasWebAuthn && !hasMtlsCreds;

            // Keep the session's access badge across rotation; a deleted badge was already
            // cleared from the row, so the session comes back badgeless.
            ModularCA.Auth.Interfaces.AccessBadgeClaim? carriedBadge = null;
            if (stored.AccessBadgeId is Guid carriedBadgeId)
            {
                var carried = await _db.AccessBadges.AsNoTracking().FirstOrDefaultAsync(b => b.Id == carriedBadgeId && b.UserId == user.Id);
                carriedBadge = carried == null ? null : new ModularCA.Auth.Interfaces.AccessBadgeClaim(carried.Id, carried.Name);
            }
            var newAccessToken = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupNeeded, badge: carriedBadge);
            var currentUaHashForNew = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
            // Bind the rotated token to the key the client just proved possession of (or keep the
            // existing binding when this refresh carried no proof). This also upgrades legacy unbound
            // sessions, and — in observe mode — lets the binding settle on the client's actual key.
            var newRefreshToken = _jwt.GenerateRefreshToken(stored.UserId, sourceIp, currentUaHashForNew, proofJkt ?? stored.CnfJkt);
            newRefreshToken.FamilyId = stored.FamilyId;
            newRefreshToken.AccessBadgeId = carriedBadge?.Id;
            // Propagate the ORIGINAL family creation timestamp so the
            // absolute session cap is measured from the first login, not from each rotation.
            newRefreshToken.FamilyCreatedAt = stored.FamilyCreatedAt ?? stored.CreatedAt;
            newRefreshToken.LastActivityAt = DateTime.UtcNow;

            // The returned plaintext goes to the client; the entity's Token column stores
            // the SHA-256 hash of the same plaintext.
            var newRefreshPlaintext = newRefreshToken.PlaintextTokenForClient ?? newRefreshToken.Token;

            // Revoke old token
            stored.IsRevoked = true;
            stored.RevokedAt = DateTime.UtcNow;
            stored.ReplacedByToken = newRefreshToken.Token;

            _db.RefreshTokens.Add(newRefreshToken);
            await _db.SaveChangesAsync();

            return Ok(new LoginResponse
            {
                Token = newAccessToken.Token,
                ExpiresAt = newAccessToken.ExpiresAt,
                RefreshToken = newRefreshPlaintext,
                MfaSetupRequired = mfaSetupNeeded ? true : null
            });
        }
        /// <summary>
        /// Pre-JWT password change endpoint for users who are forced to change their password
        /// on next login (e.g., first login or admin-initiated reset). Does not require a JWT
        /// because the user has not yet been issued one. Verifies the old password, validates
        /// the new password against the configured password policy, updates the hash, clears
        /// the <see cref="Shared.Entities.UserEntity.PasswordChangeOnNextLogon"/> flag, and
        /// requires the user to re-login with the new password.
        /// </summary>
        [AllowAnonymous]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] PreJwtChangePasswordRequest request)
        {
            // Same wall-clock budget as the login path.
            var sw = Stopwatch.StartNew();
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Shape-validate username + field-presence in one pass.
            request.Username = UserFieldValidators.NormalizeIdentity(request.Username) ?? request.Username;
            var changePwdValidation = await _changePasswordValidator.ValidateAsync(request);
            if (!changePwdValidation.IsValid)
            {
                PasswordUtil.DummyVerify(request.OldPassword ?? string.Empty);
                await DelayToBudgetAsync(sw);
                return BadRequest(new { error = string.Join("; ", changePwdValidation.Errors.Select(e => e.ErrorMessage)) });
            }

            if (request.NewPassword != request.ConfirmNewPassword)
                return BadRequest(new { error = "New password and confirmation do not match" });

            if (request.NewPassword == request.OldPassword)
                return BadRequest(new { error = "New password must be different from the old password" });

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
            {
                // Dummy verify so timing is constant, plus generic 401.
                PasswordUtil.DummyVerify(request.OldPassword ?? string.Empty);
                await DelayToBudgetAsync(sw);
                return Unauthorized(new { error = "Invalid username or password" });
            }

            // Clear expired lockout
            if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc <= DateTime.UtcNow)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
            }

            // Defer account-state gates until AFTER password verification.
            bool isDisabled = !user.IsActive;
            bool isHardLocked = user.IsLocked;
            bool isTempLocked = user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow;

            // Verify old password
            if (!PasswordUtil.VerifyPassword(request.OldPassword, user.PasswordHash))
            {
                // Atomic increment via provider-agnostic ExecuteUpdateAsync
                // (replaces a PG-style double-quoted raw SQL that silently failed on MySQL).
                await _db.Users
                    .Where(u => u.Id == user.Id)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
                await _db.Entry(user).ReloadAsync();

                var maxAttempts = (await _securityPolicy.GetAsync()).MaxFailedLoginAttempts;
                var lockoutMinutes = (await _securityPolicy.GetAsync()).LockoutMinutes;
                if (maxAttempts > 0 && user.FailedLoginAttempts >= maxAttempts)
                {
                    if (lockoutMinutes > 0)
                    {
                        user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                            sourceIp: sourceIp, success: false,
                            details: new { reason = "temp_lockout", source = "pre_jwt_change_password", attempts = user.FailedLoginAttempts, lockoutMinutes },
                            errorMessage: "LoginFailed");
                    }
                    else
                    {
                        user.IsLocked = true;
                        await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                            sourceIp: sourceIp, success: false,
                            details: new { reason = "hard_lockout", source = "pre_jwt_change_password", attempts = user.FailedLoginAttempts },
                            errorMessage: "LoginFailed");
                    }
                }
                else
                {
                    await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                        sourceIp: sourceIp, success: false,
                        details: new { reason = "invalid_password", source = "pre_jwt_change_password" },
                        errorMessage: "LoginFailed");
                }
                _db.Users.Update(user);
                await _db.SaveChangesAsync();
                await DelayToBudgetAsync(sw);
                return Unauthorized(new { error = "Invalid username or password" });
            }

            // Password verified — NOW apply the deferred account-state gates.
            if (isDisabled)
            {
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is disabled" });
            }
            if (isHardLocked)
            {
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is locked. Contact an administrator." });
            }
            if (isTempLocked)
            {
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new { error = "Account is temporarily locked. Try again later." });
            }

            // Reset failed attempts on successful password verification
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;

            // Validate new password against policy and reuse check.
            // This endpoint exists for one situation: the account cannot log in until its
            // password is replaced (an administrator's temporary password, or an expired one).
            // It is not a general password-change path; that one lives behind a session and
            // step-up MFA. Without this gate, a phished password alone rotated the password and
            // locked the real owner out of an MFA-protected account. Evaluated after the old
            // password verified, so it reveals nothing to a caller who has not proved it.
            var passwordExpired = !user.PasswordNeverExpires
                && user.PasswordExpirationDate.HasValue
                && user.PasswordExpirationDate < DateTime.UtcNow;
            if (!user.PasswordChangeOnNextLogon && !passwordExpired)
            {
                await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "change_not_required", source = "pre_jwt_change_password" },
                    errorMessage: "LoginFailed");
                await DelayToBudgetAsync(sw);
                return StatusCode(403, new
                {
                    error = "This account's password does not need to be changed before signing in. "
                          + "Sign in and change it from your account settings."
                });
            }

            var (isValid, errors) = await _passwordPolicy.ValidateAsync(user.Id, request.NewPassword);
            if (!isValid)
            {
                return BadRequest(new { error = "Password does not meet policy requirements", details = errors });
            }

            // Update password — store with modern parameters.
            var newHash = PasswordUtil.HashPassword(request.NewPassword);
            user.PasswordHash = newHash;
            // SP 800-63B §5.1.1.2: record the rotation in PasswordHistory
            // (and prune oldest rows beyond HistoryCount) so subsequent changes can
            // reject reuse. No-op when HistoryCount <= 0.
            await _passwordPolicy.RecordPasswordHistoryAsync(user.Id, newHash);
            user.PasswordChangeOnNextLogon = false;
            // Rotate the security stamp so outstanding JWTs (if any)
            // invalidate immediately and all refresh tokens get revoked below.
            user.SecurityStamp = Guid.NewGuid().ToString();

            // Reset password expiration based on policy
            var policy = await _passwordPolicy.GetPolicyAsync();
            if (!user.PasswordNeverExpires && policy.MaxAgeDays > 0)
                user.PasswordExpirationDate = DateTime.UtcNow.AddDays(policy.MaxAgeDays);

            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            // Blow the per-user stamp cache so admin or user-forced
            // changes take effect on the next request, not 30 s later.
            // _cache is guaranteed non-null — registered unconditionally in StartModularCA.cs.
            await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, user.Id);

            // The comment on the stamp rotation above has promised this since it was written;
            // nothing performed it. A refresh token stolen before the change re-minted a session
            // carrying the new stamp, because refresh checks account state, not credentials.
            await RevokeAllRefreshTokensAsync(user.Id);

            await _audit.LogAsync(AuditActionType.UserPasswordChanged, user.Id, user.Username,
                sourceIp: sourceIp, details: new { reason = "Forced password change on login" });

            return Ok(new { message = "Password changed successfully. Please log in again." });
        }

        /// <summary>
        /// Revokes every live refresh token an account holds. Called wherever a credential
        /// changes, so a session that predates the change cannot outlive it.
        /// </summary>
        private async Task RevokeAllRefreshTokensAsync(Guid userId)
        {
            await _db.RefreshTokens
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.RevokedAt, DateTime.UtcNow));
        }

        /// <summary>
        /// Logs out the current user by revoking their JWT and all active refresh tokens.
        /// The JWT's <c>jti</c> claim is stored in the distributed cache so the
        /// <see cref="Middleware.TokenRevocationMiddleware"/> rejects subsequent requests
        /// using the same token.
        /// </summary>
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                              ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { error = "Invalid token" });

            // Revoke the JWT by caching its jti until expiry
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value
                      ?? User.FindFirst("jti")?.Value;

            // _cache is guaranteed non-null — registered unconditionally in StartModularCA.cs.
            if (!string.IsNullOrEmpty(jti))
            {
                var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value
                               ?? User.FindFirst("exp")?.Value;

                TimeSpan ttl;
                if (expClaim != null && long.TryParse(expClaim, out var expUnix))
                {
                    var expDate = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                    ttl = expDate - DateTimeOffset.UtcNow;
                    if (ttl <= TimeSpan.Zero)
                        ttl = TimeSpan.FromSeconds(1);
                }
                else
                {
                    // Fallback: use the configured JWT lifetime
                    ttl = TimeSpan.FromMinutes(_config.JWT.ExpirationMinutes);
                }

                await _cache.SetStringAsync($"revoked-jwt:{jti}", "1", new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                });
            }

            // Revoke all active refresh tokens for this user
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ToListAsync();

            foreach (var token in activeTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }

            await _db.SaveChangesAsync();

            var username = User.FindFirst("username")?.Value ?? userIdClaim;
            await _audit.LogAsync(AuditActionType.UserLogout, userId, username, sourceIp: sourceIp);
            MetricsService.AuthTokenRevocationsTotal.Inc();

            return Ok(new { message = "Logged out successfully" });
        }

        [AllowAnonymous]
        [HttpPost("cert-login")]
        public async Task<IActionResult> CertLogin()
        {
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
            if (clientCert == null)
            {
                await _audit.LogAsync(AuditActionType.UserLoginFailed, null, null,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "no_client_certificate" },
                    errorMessage: "LoginFailed");
                return Unauthorized(new { error = "Client certificate required" });
            }

            var thumbprint = clientCert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            var credential = await _db.MtlsCredentials.Include(m => m.User).FirstOrDefaultAsync(m => m.Thumbprint == thumbprint && !m.IsRevoked && m.ExpiresAt > DateTime.UtcNow);
            var user = credential?.User;
            if (user == null)
            {
                await _audit.LogAsync(AuditActionType.UserLoginFailed, null, null,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "cert_thumbprint_unknown", thumbprint },
                    errorMessage: "LoginFailed");
                return Unauthorized(new { error = "No user associated with this certificate" });
            }

            // Full chain validation against the credential's enrolled
            // signing CA. Thumbprint equality alone is not proof of issuer binding —
            // require the cert to chain to the exact CA it was enrolled under.
            var chainOk = await MtlsChainValidator.ValidateAgainstCredentialCaAsync(
                _db, credential!.SigningCaId, clientCert,
                requireRevocationCheck: (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck);

            if (!chainOk)
            {
                // Treat as a failed login for the identified user and
                // apply the same FailedLoginAttempts / lockout flow as password logins.
                await _db.Users
                    .Where(u => u.Id == user.Id)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
                await _db.Entry(user).ReloadAsync();

                var maxAttempts = (await _securityPolicy.GetAsync()).MaxFailedLoginAttempts;
                var lockoutMinutes = (await _securityPolicy.GetAsync()).LockoutMinutes;
                if (maxAttempts > 0 && user.FailedLoginAttempts >= maxAttempts)
                {
                    if (lockoutMinutes > 0)
                        user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                    else
                        user.IsLocked = true;
                }
                _db.Users.Update(user);
                await _db.SaveChangesAsync();

                await _audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                    sourceIp: sourceIp, success: false,
                    details: new { reason = "cert_chain_validation_failed", thumbprint, signingCaId = credential.SigningCaId },
                    errorMessage: "LoginFailed");
                MetricsService.AuthLoginFailures.WithLabels("cert_chain_invalid").Inc();
                return Unauthorized(new { error = "Client certificate failed chain validation" });
            }

            // Account status checks (same as password login)
            if (!user.IsActive)
                return StatusCode(403, new { error = "Account is disabled" });
            if (user.IsLocked)
                return StatusCode(403, new { error = "Account is locked" });
            if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow)
                return StatusCode(403, new { error = "Account is temporarily locked" });

            // A client certificate is ONE factor. If the account has a second enrolled, require
            // it — exactly as MtlsController does for the same certificate on the same listener,
            // and as /auth/login does after a correct password.
            //
            // This endpoint went straight from chain validation to GenerateToken, so a user with
            // TOTP or a security key enrolled — for whom /auth/login enforces MFA — could bypass
            // it entirely by presenting their enrolled .p12 here instead. Anyone holding that
            // file had single-factor admin, and the file is written to disk by MtlsController's
            // enrolment flow.
            var certMfaMethods = new List<string>();
            if (await _db.TotpSecrets.AnyAsync(t => t.UserId == user.Id && t.IsVerified))
                certMfaMethods.Add("totp");
            if (_config.WebAuthn.Enabled && _fido2 != null
                && await _db.Fido2Credentials.AnyAsync(c => c.UserId == user.Id))
                certMfaMethods.Add("webauthn");

            if (certMfaMethods.Count > 0)
            {
                var certMfaToken = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
                var certMfaTtl = Math.Clamp((await _securityPolicy.GetAsync()).MfaSessionTtlSeconds, 60, 900);
                await _cache.SetStringAsync($"mfa:{certMfaToken}", user.Id.ToString(),
                    new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(certMfaTtl)
                    });

                return Ok(new
                {
                    requiresMfa = true,
                    mfaToken = certMfaToken,
                    method = certMfaMethods.Count == 1 ? certMfaMethods[0] : null,
                    availableMethods = certMfaMethods,
                    message = "Client certificate accepted. Complete multi-factor authentication to continue."
                });
            }

            var groups = await _db.CaGroupMembers
                .Where(gm => gm.UserId == user.Id)
                .Include(gm => gm.Group)
                .Select(gm => gm.Group)
                .ToListAsync();
            // mTLS is the only factor here. For a member of a system group that is not enough:
            // Login computes the same flag and MfaEnrollmentMiddleware confines a token that
            // carries it to enrollment until a second factor exists. These certificate-primary
            // paths minted an unrestricted token instead, so an admin whose only factor was a
            // .p12 had full API access on one possession factor, and a restricted admin could
            // enrol a .p12 and certificate-login around the restriction.
            var mfaSetupRequired = groups.Any(g => g.IsSystemGroup);
            var mfaEnforcedForGroup = _config.WebAuthn.EnforceForGroups.Count > 0
                && groups.Any(g => _config.WebAuthn.EnforceForGroups.Contains(g.TemplateName ?? "Custom", StringComparer.OrdinalIgnoreCase));
            if (mfaEnforcedForGroup)
            {
                return StatusCode(403, new
                {
                    error = "Multi-factor authentication is required for your group. Sign in with your password to enrol a second factor.",
                    requiresMfaEnrollment = true
                });
            }
            var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupRequired);
            var certUserAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
            var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, certUserAgentHash,
                await HttpContext.RequestServices.GetRequiredService<ModularCA.Auth.Services.IDpopProofService>().GetValidatedJktAsync(HttpContext));
            var certRefreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

            user.LastLoginAt = DateTime.UtcNow;
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;

            _db.RefreshTokens.Add(refreshToken);
            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            // Enforce concurrent session limit
            if ((await _securityPolicy.GetAsync()).MaxConcurrentSessions > 0)
            {
                var activeTokens = await _db.RefreshTokens
                    .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(t => t.CreatedAt)
                    .ToListAsync();

                if (activeTokens.Count > (await _securityPolicy.GetAsync()).MaxConcurrentSessions)
                {
                    var tokensToRevoke = activeTokens.Skip((await _securityPolicy.GetAsync()).MaxConcurrentSessions);
                    foreach (var old in tokensToRevoke)
                    {
                        old.IsRevoked = true;
                        old.RevokedAt = DateTime.UtcNow;
                    }
                    await _db.SaveChangesAsync();
                }
            }

            await _audit.LogAsync(AuditActionType.UserCertLogin, user.Id, user.Username,
                sourceIp: sourceIp, details: new { CertThumbprint = thumbprint });
            MetricsService.AuthLoginTotal.WithLabels("certificate", "true").Inc();

            return Ok(new LoginResponse
            {
                Token = Token,
                ExpiresAt = ExpiresAt,
                RefreshToken = certRefreshPlaintext
            });
        }
    }
}
