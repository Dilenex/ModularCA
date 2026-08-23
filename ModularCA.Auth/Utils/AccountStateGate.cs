using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Utils;

/// <summary>
/// The single decision on whether an account may be issued a session right now.
/// <para>
/// Three flags disqualify a user — <see cref="UserEntity.IsActive"/> false (disabled),
/// <see cref="UserEntity.IsLocked"/> true (hard lock by an administrator), and
/// <see cref="UserEntity.LockoutEndUtc"/> in the future (temporary lockout from failed
/// logins). Every path that mints a JWT has to consult all three, and before this type
/// existed each path decided for itself.
/// </para>
/// <para>
/// The result was uneven. <c>AuthController.Login</c> and the refresh path checked all three.
/// Every MFA-completion path — TOTP verify, WebAuthn verify, mTLS verify, mTLS verify-redirect —
/// checked none, relying on the gate having run upstream when the temporary MFA token was
/// issued. That reasoning holds only for the length of the MFA window (up to
/// <c>MfaSessionTtlSeconds</c>, clamped to 900s): an administrator who disables an account
/// while its owner is part-way through MFA watches them complete it and receive a full session.
/// </para>
/// <para>
/// And it did not hold at all for <c>MtlsController.LoginRedirect</c>, which is a PRIMARY login
/// path with no upstream gate whatsoever. A disabled user holding a valid mTLS credential could
/// log in — and the same method then cleared their <c>LockoutEndUtc</c> and reset their failed
/// login counter, so the login also undid the lockout.
/// </para>
/// </summary>
public static class AccountStateGate
{
    /// <summary>
    /// True when the account must not receive a session. <paramref name="reason"/> carries an
    /// operator-facing description for the audit trail — it deliberately distinguishes the three
    /// cases, which the message returned to the CALLER must not.
    /// </summary>
    /// <remarks>
    /// Callers should return a single undifferentiated error to the client. Telling an
    /// unauthenticated caller whether an account is disabled, hard-locked, or temporarily locked
    /// is an enumeration oracle; the distinction belongs in the audit log, not the response.
    /// </remarks>
    public static bool IsBlocked(UserEntity user, out string reason)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (!user.IsActive)
        {
            reason = "account is disabled";
            return true;
        }

        if (user.IsLocked)
        {
            reason = "account is locked by an administrator";
            return true;
        }

        if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc > DateTime.UtcNow)
        {
            reason = $"account is temporarily locked until {user.LockoutEndUtc:O}";
            return true;
        }

        reason = string.Empty;
        return false;
    }

    /// <summary>
    /// The message to return to the caller when <see cref="IsBlocked"/> is true. Identical for
    /// all three causes on purpose — see the remarks there.
    /// </summary>
    public const string ClientMessage = "Account is locked or disabled";
}
