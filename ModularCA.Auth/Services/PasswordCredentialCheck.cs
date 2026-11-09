using ModularCA.Auth.Utils;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Auth.Services;

/// <summary>The answer to "is this the account's password?", with where it was answered.</summary>
public enum PasswordCheckResult
{
    /// <summary>The directory accepted the bind.</summary>
    ValidViaLdap,

    /// <summary>The local password hash matched.</summary>
    ValidLocal,

    /// <summary>The password is wrong: the directory refused it, or the local hash did not match.</summary>
    Invalid,

    /// <summary>
    /// LDAP sign-in is on and the directory gave no answer about the user, so the password was not
    /// checked at all. Not a wrong password: callers refuse the sign-in without counting a failure.
    /// </summary>
    DirectoryUnavailable,
}

/// <summary>
/// The single rule for checking a sign-in password, shared by interactive login
/// (<c>AuthController.Login</c>) and protocol Basic authentication
/// (<see cref="ProtocolCredentialService"/>).
/// </summary>
/// <remarks>
/// <para>
/// With LDAP sign-in off, the local hash decides. With it on (<see cref="LdapAuthConfig.Enabled"/>,
/// an instance-wide setting; accounts carry no per-user source), the directory is asked first:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Bind accepted:</b> valid.
///   </description></item>
///   <item><description>
///     <b>Bind refused:</b> invalid, and the local hash is not consulted. The directory is
///     authoritative for an account it knows. Falling back let a stale local password (the one
///     handed out at account creation, say) keep working after the directory rotated, disabled or
///     expired the account.
///   </description></item>
///   <item><description>
///     <b>No directory entry</b> (service-account search found nobody): the account is local-only,
///     such as the bootstrap administrator, so the local hash decides. Every account is created
///     locally and a directory bind only ever signs in as an existing local account, so a local-only
///     account is a normal part of the model and its sign-in is kept when LDAP is turned on.
///   </description></item>
///   <item><description>
///     <b>Directory unavailable</b> (unreachable, service-account bind failed, unexpected error):
///     fail closed. The local hash is not consulted, because without an answer there is no telling
///     whether the account is a directory account with a stale local password. The sign-in is
///     refused without counting a failed attempt, so an outage does not lock accounts. Passwordless
///     sign-in (WebAuthn, mTLS) does not depend on the directory and still works.
///   </description></item>
/// </list>
/// <para>
/// On every path that does not verify the local hash, a dummy verification runs instead, so the
/// time taken does not reveal which branch answered.
/// </para>
/// </remarks>
public static class PasswordCredentialCheck
{
    /// <summary>
    /// Checks <paramref name="password"/> for the account by the rules in the remarks.
    /// </summary>
    /// <param name="config">System configuration; <see cref="SystemConfig.LdapAuth"/> decides whether the directory is asked.</param>
    /// <param name="ldap">The directory client.</param>
    /// <param name="username">The sign-in name.</param>
    /// <param name="password">The submitted password.</param>
    /// <param name="localPasswordHash">The account's stored local hash.</param>
    /// <returns>The result and where it was decided.</returns>
    public static async Task<PasswordCheckResult> VerifyAsync(
        SystemConfig config, ILdapAuthService ldap, string username, string password, string localPasswordHash)
    {
        if (config.LdapAuth.Enabled)
        {
            switch (await ldap.AuthenticateAsync(username, password))
            {
                case LdapBindOutcome.Succeeded:
                    return PasswordCheckResult.ValidViaLdap;
                case LdapBindOutcome.UserNotFound:
                    break;
                case LdapBindOutcome.Refused:
                    PasswordUtil.DummyVerify(password);
                    return PasswordCheckResult.Invalid;
                default:
                    PasswordUtil.DummyVerify(password);
                    return PasswordCheckResult.DirectoryUnavailable;
            }
        }

        return PasswordUtil.VerifyPassword(password, localPasswordHash)
            ? PasswordCheckResult.ValidLocal
            : PasswordCheckResult.Invalid;
    }
}
