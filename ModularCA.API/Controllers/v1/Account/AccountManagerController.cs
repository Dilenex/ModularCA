using System.Net.Mail;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Management;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Account
{
    /// <summary>
    /// User account self-service endpoints for profile updates and password changes.
    /// </summary>
    [ApiController]
    [Route("api/v1/account")]
    [Authorize]
    [NodeRole(ProcessRole.Control)]
    public class AccountManagerController(
        IUserManagementService userManager,
        ICurrentUserService currentUser,
        IAuditService auditService,
        IDistributedCache cache,
        ModularCADbContext db) : ControllerBase
    {
        private readonly IUserManagementService _userManager = userManager;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly IAuditService _audit = auditService;
        private readonly IDistributedCache _cache = cache;
        private readonly ModularCADbContext _db = db;

        /// <summary>
        /// Returns the authenticated caller's own profile. This is the read side of this
        /// controller's <c>PUT</c>, and the endpoint both self-service account pages use.
        /// </summary>
        /// <remarks>
        /// <c>GetUserById</c> throws when the user is missing rather than returning null, so the
        /// old <c>if (user == null) return NotFound()</c> was unreachable and a caller whose row had
        /// been deleted mid-session got a 500 instead. Catching the miss keeps that case a 404.
        /// </remarks>
        [HttpGet]
        public async Task<IActionResult> GetUserInfo()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            try
            {
                return Ok(await _userManager.GetUserById(_currentUser.User.Id));
            }
            catch (Exception)
            {
                return NotFound();
            }
        }

        /// <summary>
        /// Updates the authenticated user's OWN profile. Display name, first name and last name are
        /// updated freely. Changing the email address additionally requires a step-up MFA token
        /// (<see cref="StepUpOps.ChangeEmail"/>) because email is an identity/recovery field. Username
        /// is immutable here — it is the login identity and is managed by administrators only. A null
        /// field is left unchanged; only fields that actually differ are written.
        /// </summary>
        [HttpPut]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateAccountProfileRequest request,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == _currentUser.User.Id);
            if (user == null)
                return NotFound();

            var changes = new List<string>();
            var emailChanged = false;

            // Email change — sensitive: require step-up MFA, then validate format + uniqueness.
            var newEmail = request.Email?.Trim();
            if (!string.IsNullOrEmpty(newEmail) && !string.Equals(newEmail, user.Email, StringComparison.OrdinalIgnoreCase))
            {
                if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ChangeEmail, user.Id.ToString()))
                    return StatusCode(403, new { error = "MFA re-verification required to change your email address. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

                if (!MailAddress.TryCreate(newEmail, out _))
                    return BadRequest(new { error = "That email address is not valid." });

                var inUse = await _db.Users.AnyAsync(u => u.Id != user.Id && u.Email == newEmail);
                if (inUse)
                    return BadRequest(new { error = "That email address is already in use." });

                user.Email = newEmail;
                changes.Add("Email");
                emailChanged = true;
            }

            // Low-risk profile fields — applied freely. Only a provided, actually-different value counts.
            var newDisplay = request.DisplayName?.Trim();
            if (request.DisplayName != null && newDisplay != user.DisplayName)
            {
                user.DisplayName = string.IsNullOrEmpty(newDisplay) ? null : newDisplay;
                changes.Add("DisplayName");
            }
            var newFirst = request.FirstName?.Trim();
            if (request.FirstName != null && newFirst != user.FirstName)
            {
                user.FirstName = newFirst ?? string.Empty;
                changes.Add("FirstName");
            }
            var newLast = request.LastName?.Trim();
            if (request.LastName != null && newLast != user.LastName)
            {
                user.LastName = newLast ?? string.Empty;
                changes.Add("LastName");
            }

            if (changes.Count == 0)
                return Ok(new { message = "No changes.", changes });

            await _db.SaveChangesAsync();

            await _audit.LogAsync(AuditActionType.UserUpdated, user.Id, user.Username,
                "User", user.Id.ToString(),
                new { Self = true, Changes = changes, EmailChanged = emailChanged },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(new
            {
                message = "Account updated.",
                changes,
                // Echo saved values so the SPA can refresh without a second round-trip.
                user.Username,
                user.Email,
                user.DisplayName,
                user.FirstName,
                user.LastName,
            });
        }

        /// <summary>
        /// Changes the authenticated user's password. Requires a valid step-up MFA token
        /// via the X-MFA-Token header to prevent unauthorized password changes from hijacked sessions.
        /// Audit findings #32: emits <see cref="AuditActionType.UserPasswordChanged"/> with
        /// <c>success=false</c> when the underlying call returns false or throws — restoring the
        /// credential-stuffing signal that previously only fired on successful changes.
        /// </summary>
        [HttpPut("password")]
        public async Task<IActionResult> ChangePassword([FromBody] UpdatePasswordRequest request,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Require step-up MFA verification
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ChangePassword))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            bool result;
            try
            {
                result = await _userManager.UpdateUserPassword(_currentUser.User.Id, request);
            }
            catch (Exception ex)
            {
                // Audit findings #32: capture exception-path failures so brute-force / credential
                // stuffing attempts produce a SIEM-visible signal even when the underlying service
                // throws (e.g. user lookup failure, DB write timeout). Wrapped so audit-store
                // failure cannot shadow the original error rethrow.
                try
                {
                    await _audit.LogAsync(AuditActionType.UserPasswordChanged, _currentUser.User.Id, _currentUser.User.Username,
                        "User", _currentUser.User.Id.ToString(),
                        sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                        success: false,
                        errorMessage: ex.Message);
                }
                catch
                {
                    // Swallow — surface the original exception.
                }
                throw;
            }

            if (result)
            {
                await _audit.LogAsync(AuditActionType.UserPasswordChanged, _currentUser.User.Id, _currentUser.User.Username,
                    "User", _currentUser.User.Id.ToString(),
                    sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = "Password changed successfully" });
            }

            // Audit findings #32: also emit failure record on the false-returning path so SIEM
            // sees both wrong-current-password and policy-rejection failures.
            try
            {
                await _audit.LogAsync(AuditActionType.UserPasswordChanged, _currentUser.User.Id, _currentUser.User.Username,
                    "User", _currentUser.User.Id.ToString(),
                    sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: "Password change rejected (wrong current password or policy violation).");
            }
            catch
            {
                // Swallow — keep the original 400 to the user.
            }
            return BadRequest(new { error = "Failed to change password" });
        }

        /// <summary>
        /// Returns the authenticated user's MFA enrollment status, including
        /// which methods are configured and their details.
        /// </summary>
        [HttpGet("mfa")]
        public async Task<IActionResult> GetMfaStatus()
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            var userId = _currentUser.User.Id;

            var totp = await _db.TotpSecrets
                .Where(t => t.UserId == userId && t.IsVerified)
                .Select(t => new { t.DeviceName, t.RegisteredAt, t.LastUsedAt })
                .FirstOrDefaultAsync();

            var webauthnCreds = await _db.Fido2Credentials
                .Where(c => c.UserId == userId)
                .Select(c => new { c.Id, c.DeviceName, c.RegisteredAt, c.LastUsedAt })
                .OrderByDescending(c => c.RegisteredAt)
                .ToListAsync();

            var mtlsCreds = await _db.MtlsCredentials
                .Where(c => c.UserId == userId && !c.IsRevoked)
                .Select(c => new { c.Id, c.DeviceName, c.SerialNumber, c.IssuedAt, c.ExpiresAt, c.SigningCaId })
                .OrderByDescending(c => c.IssuedAt)
                .ToListAsync();

            return Ok(new
            {
                totp = new { enrolled = totp != null, deviceName = totp?.DeviceName, registeredAt = (DateTime?)totp?.RegisteredAt, lastUsedAt = totp?.LastUsedAt },
                webauthn = new { enrolled = webauthnCreds.Count > 0, credentials = webauthnCreds },
                mtls = new { enrolled = mtlsCreds.Count > 0, credentials = mtlsCreds },
                hasStepUpCapability = totp != null || webauthnCreds.Count > 0
            });
        }

    }

    /// <summary>
    /// Request body for self-service account profile updates (<c>PUT /api/v1/account</c>). Every field
    /// is optional; a null field is left unchanged. Changing <see cref="Email"/> requires a step-up MFA
    /// token. Username is intentionally absent — it is not self-editable.
    /// </summary>
    public class UpdateAccountProfileRequest
    {
        public string? DisplayName { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
    }
}
