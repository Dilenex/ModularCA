using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Auth.Utils;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Auth.Services;

/// <summary>
/// Verifies a username and password for a machine protocol that carries no session.
/// </summary>
/// <remarks>
/// <para>
/// EST (RFC 7030 section 3.2.3) authenticates enrollment with HTTP Basic, which means a password
/// check with none of the apparatus a browser login has — no MFA, no step-up, no refresh token,
/// no cookie. What it must keep is everything that makes a password check safe: lockout,
/// account-state gating, and an audit record. This exists so the EST handler cannot quietly get a
/// weaker version of those.
/// </para>
/// <para>
/// It is a deliberate extraction of the rules in <c>AuthController.Login</c> rather than a second
/// implementation of them, and the ordering below is copied from there on purpose:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Account state is evaluated before the password but applied after it.</b> Returning
///     "disabled" or "locked" to a caller who has not proved they know the password turns this
///     endpoint into an account enumerator.
///   </description></item>
///   <item><description>
///     <b>LDAP first, local second</b>, matching interactive login, so an environment that moved
///     authentication to a directory does not find EST still accepting a stale local hash.
///   </description></item>
///   <item><description>
///     <b>Failed attempts increment and lock.</b> Basic auth over a protocol endpoint is the most
///     brute-forceable surface this product has: no CAPTCHA, no interactive delay, and a client
///     that retries by design. Sharing the counter with interactive login means an attacker cannot
///     use EST to grind passwords that the login page would have locked.
///   </description></item>
/// </list>
/// <para>
/// Every outcome is audited as a login event, so EST credential use appears in the same trail an
/// auditor already reads rather than in a protocol-specific corner.
/// </para>
/// </remarks>
public interface IProtocolCredentialService
{
    /// <summary>
    /// Verifies credentials presented by a protocol client.
    /// </summary>
    /// <param name="username">Username from the Authorization header.</param>
    /// <param name="password">Password from the Authorization header.</param>
    /// <param name="protocol">Protocol name for the audit record, e.g. "EST".</param>
    /// <param name="sourceIp">Caller address for the audit record and lockout notifications.</param>
    /// <returns>The verified username, or null when verification failed for any reason.</returns>
    Task<string?> VerifyAsync(string username, string password, string protocol, string? sourceIp);
}

/// <inheritdoc />
public class ProtocolCredentialService(
    ModularCADbContext db,
    IAuditService audit,
    SystemConfig config,
    ILdapAuthService ldapAuth,
    ISecurityPolicyService securityPolicy) : IProtocolCredentialService
{
    /// <inheritdoc />
    public async Task<string?> VerifyAsync(string username, string password, string protocol, string? sourceIp)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
            return null;

        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            // Same constant-time dummy verify the login path performs, so an unknown username
            // cannot be told from a wrong password by how long the answer takes. EST clients
            // retry mechanically, which makes a timing oracle here cheaper to exploit than one
            // behind a login form.
            PasswordUtil.DummyVerify(password);

            // Audited without a user id so a spray against invented names is still visible, and
            // answered identically to a wrong password.
            await audit.LogAsync(AuditActionType.UserLoginFailed, null, username,
                sourceIp: sourceIp, success: false,
                details: new { reason = "unknown_user", protocol },
                errorMessage: "LoginFailed");
            return null;
        }

        // An elapsed temporary lockout clears itself on the next attempt, exactly as at login.
        var lockoutExpired = false;
        if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc <= DateTime.UtcNow)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            lockoutExpired = true;
        }

        // Computed now, applied after the password check. See the remarks.
        var isDisabled = !user.IsActive;
        var isHardLocked = user.IsLocked;
        var isTempLocked = user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow;

        // A password the account is required to replace is not a credential for unattended
        // enrollment. Interactive login catches both of these and forces the change; a protocol
        // client has no way to complete that, so it is refused. Without this, the temporary
        // password an administrator hands out at reset time was a working EST credential until
        // the user got around to changing it.
        var mustChangePassword = user.PasswordChangeOnNextLogon;
        var passwordExpired = !user.PasswordNeverExpires
            && user.PasswordExpirationDate.HasValue
            && user.PasswordExpirationDate < DateTime.UtcNow;

        var passwordValid = false;
        var viaLdap = false;
        if (config.LdapAuth.Enabled)
        {
            var (ldapSuccess, _) = await ldapAuth.AuthenticateAsync(username, password);
            passwordValid = ldapSuccess;
            viaLdap = ldapSuccess;
        }
        if (!passwordValid)
            passwordValid = PasswordUtil.VerifyPassword(password, user.PasswordHash);

        if (!passwordValid)
        {
            await db.Users
                .Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
            await db.Entry(user).ReloadAsync();

            var policy = await securityPolicy.GetAsync();
            if (policy.MaxFailedLoginAttempts > 0 && user.FailedLoginAttempts >= policy.MaxFailedLoginAttempts)
            {
                if (policy.LockoutMinutes > 0)
                    user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(policy.LockoutMinutes);
                else
                    user.IsLocked = true;

                await db.SaveChangesAsync();
            }

            await audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                sourceIp: sourceIp, success: false,
                details: new { reason = "invalid_password", protocol, attempts = user.FailedLoginAttempts },
                errorMessage: "LoginFailed");
            return null;
        }

        // Password was correct — now the account state may be revealed, because the caller has
        // already demonstrated they hold the credential.
        if (isDisabled || isHardLocked || isTempLocked || mustChangePassword || passwordExpired)
        {
            await audit.LogAsync(AuditActionType.UserLoginFailed, user.Id, user.Username,
                sourceIp: sourceIp, success: false,
                details: new
                {
                    reason = isDisabled ? "account_disabled"
                        : isHardLocked ? "hard_lockout"
                        : isTempLocked ? "temp_lockout"
                        : mustChangePassword ? "password_change_required"
                        : "password_expired",
                    protocol,
                },
                errorMessage: "LoginFailed");
            return null;
        }

        // lockoutExpired matters here: clearing an elapsed lockout above only touched the tracked
        // entity, which leaves this condition already false and the stale count unsaved. The
        // account would then carry its old failure total into the next window and lock again after
        // a single mistake. The interactive login path never showed this because it writes
        // LastLoginUtc on the way out and saves regardless.
        if (lockoutExpired || user.FailedLoginAttempts != 0 || user.LockoutEndUtc != null)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            await db.SaveChangesAsync();
        }

        await audit.LogAsync(AuditActionType.UserLogin, user.Id, user.Username,
            sourceIp: sourceIp, success: true,
            details: new { protocol, method = viaLdap ? "ldap" : "password" });

        return user.Username;
    }
}
