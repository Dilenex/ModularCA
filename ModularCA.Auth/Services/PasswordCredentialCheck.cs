using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
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
    /// A <see cref="PasswordSource.Directory"/> account the directory has no entry for (its entry
    /// was deleted, say). The local hash is not consulted. Callers treat it as a wrong password,
    /// failed attempt included, and audit it under its own reason.
    /// </summary>
    NotInDirectory,

    /// <summary>
    /// The directory had to answer and gave no answer about the user (unreachable, or LDAP sign-in
    /// is off for a <see cref="PasswordSource.Directory"/> account), so the password was not checked
    /// at all. Not a wrong password: callers refuse the sign-in without counting a failure.
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
/// The account's <see cref="PasswordSource"/> picks the rule:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b><see cref="PasswordSource.Local"/>:</b> the local hash decides, and the directory is never
///     asked, even with LDAP sign-in on. A local account (the bootstrap administrator, a break-glass
///     account) signs in through a directory outage and in direct-bind mode, where an unknown user
///     and a refused bind look the same.
///   </description></item>
///   <item><description>
///     <b><see cref="PasswordSource.Directory"/>:</b> the directory decides, and the local hash is
///     never consulted. A refused bind and a missing entry are wrong passwords (counted); an
///     unreachable directory, or LDAP sign-in turned off, is
///     <see cref="PasswordCheckResult.DirectoryUnavailable"/> (not counted). Deleting the
///     directory entry, or turning LDAP off, therefore never brings a stale local password back.
///   </description></item>
///   <item><description>
///     <b><see cref="PasswordSource.Inherit"/>:</b> the instance rule. With LDAP sign-in off
///     (<see cref="LdapAuthConfig.Enabled"/>), the local hash decides. With it on, the directory is
///     asked first: an accepted bind is valid, and the caller then learns the account as
///     <see cref="PasswordSource.Directory"/> (<see cref="LearnDirectorySourceAsync"/>); a refused
///     bind is final, because falling back let a
///     stale local password keep working after the directory rotated, disabled or expired the
///     account; no directory entry (only a service-account search can tell) lets the local hash
///     decide; and an unreachable directory fails closed without counting a failed attempt,
///     because without an answer there is no telling whether the account is a directory account
///     with a stale local password.
///   </description></item>
/// </list>
/// <para>
/// Passwordless sign-in (WebAuthn, mTLS) does not depend on the directory. On every path that does
/// not verify the local hash, a dummy verification runs instead, so the time taken does not reveal
/// which branch answered.
/// </para>
/// </remarks>
public static class PasswordCredentialCheck
{
    /// <summary>
    /// Checks <paramref name="password"/> for the account by the rules in the remarks.
    /// </summary>
    /// <param name="config">System configuration; <see cref="SystemConfig.LdapAuth"/> decides whether an <see cref="PasswordSource.Inherit"/> account asks the directory.</param>
    /// <param name="ldap">The directory client.</param>
    /// <param name="username">The sign-in name.</param>
    /// <param name="password">The submitted password.</param>
    /// <param name="localPasswordHash">The account's stored local hash.</param>
    /// <param name="source">The account's password source.</param>
    /// <returns>The result and where it was decided.</returns>
    public static async Task<PasswordCheckResult> VerifyAsync(
        SystemConfig config, ILdapAuthService ldap, string username, string password, string localPasswordHash,
        PasswordSource source)
    {
        var askDirectory = source switch
        {
            PasswordSource.Local => false,
            PasswordSource.Directory => true,
            _ => config.LdapAuth.Enabled,
        };

        if (askDirectory)
        {
            if (!config.LdapAuth.Enabled)
            {
                // Only a Directory account gets here: LDAP sign-in is off, so there is no one to ask,
                // and the local hash is not this account's password.
                PasswordUtil.DummyVerify(password);
                return PasswordCheckResult.DirectoryUnavailable;
            }

            switch (await ldap.AuthenticateAsync(username, password))
            {
                case LdapBindOutcome.Succeeded:
                    return PasswordCheckResult.ValidViaLdap;
                case LdapBindOutcome.UserNotFound when source == PasswordSource.Directory:
                    PasswordUtil.DummyVerify(password);
                    return PasswordCheckResult.NotInDirectory;
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

    /// <summary>
    /// After <see cref="VerifyAsync"/> returned <see cref="PasswordCheckResult.ValidViaLdap"/>:
    /// turns an <see cref="PasswordSource.Inherit"/> account into a
    /// <see cref="PasswordSource.Directory"/> one and audits
    /// <see cref="AuditActionType.UserPasswordSourceLearned"/>. The directory has just shown that it
    /// holds this account's password, so from now on deleting its directory entry (rather than
    /// disabling it) or turning LDAP sign-in off cannot bring a stale local password back.
    /// </summary>
    /// <remarks>
    /// Runs before the account-state gates, since the bind alone proves where the password lives. A
    /// service identity, which never signs in, is left alone, and so is an account whose source is
    /// already set. The write is a conditional update, so an administrator's concurrent change of
    /// the source wins; the tracked entity is then given the stored value, so a later save of it
    /// does not write the old one back.
    /// </remarks>
    /// <param name="db">The application database.</param>
    /// <param name="audit">Where the change is audited.</param>
    /// <param name="user">The account that just signed in; tracked by <paramref name="db"/> or detached.</param>
    /// <param name="sourceIp">The caller's address, for the audit record.</param>
    /// <param name="via">The sign-in path, for the audit record: <c>login</c>, or the protocol name such as <c>EST</c>.</param>
    /// <returns>True when this call changed the source.</returns>
    public static async Task<bool> LearnDirectorySourceAsync(
        ModularCADbContext db, IAuditService audit, UserEntity user, string? sourceIp, string via)
    {
        if (user.PasswordSource != PasswordSource.Inherit || user.IsServiceIdentity)
            return false;

        var changed = await db.Users
            .Where(u => u.Id == user.Id && u.PasswordSource == PasswordSource.Inherit)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordSource, PasswordSource.Directory));
        var stored = changed == 1
            ? PasswordSource.Directory
            : await db.Users.Where(u => u.Id == user.Id).Select(u => u.PasswordSource).FirstOrDefaultAsync();

        var entry = db.Entry(user);
        if (entry.State == EntityState.Detached)
        {
            user.PasswordSource = stored;
        }
        else
        {
            entry.Property(u => u.PasswordSource).CurrentValue = stored;
            entry.Property(u => u.PasswordSource).OriginalValue = stored;
        }

        if (changed != 1)
            return false;

        await audit.LogAsync(AuditActionType.UserPasswordSourceLearned, user.Id, user.Username,
            "User", user.Id.ToString(),
            new { From = nameof(PasswordSource.Inherit), To = nameof(PasswordSource.Directory), Via = via },
            sourceIp);
        return true;
    }
}
