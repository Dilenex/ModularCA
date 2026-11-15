using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The one rule for password expiry, used wherever an account's expiry is read or stamped.
/// <c>PasswordPolicy.MaxAgeDays</c> of 0 (or less) means passwords never expire: no account is
/// expired while it stands, even one carrying an expiry date from an earlier policy, and a
/// password change clears the date instead of stamping one.
/// </summary>
public static class PasswordExpiry
{
    /// <summary>
    /// Whether <paramref name="user"/>'s local password has expired under <paramref name="policy"/>
    /// at <paramref name="nowUtc"/>: the policy sets a maximum age, the account is not marked
    /// "never expires", and its stamped expiry date has passed.
    /// </summary>
    public static bool IsExpired(UserEntity user, PasswordPolicyEntity policy, DateTime nowUtc)
        => ExpiresAt(user, policy) is { } at && at < nowUtc;

    /// <summary>
    /// Whether the expiry date stamped on <paramref name="user"/> has passed, before the policy is
    /// asked whether dates count at all. False for most sign-ins, which lets a caller skip reading
    /// the policy; true is not yet "expired", only <see cref="IsExpired"/> says that.
    /// </summary>
    public static bool StampedDatePassed(UserEntity user, DateTime nowUtc)
        => !user.PasswordNeverExpires && user.PasswordExpirationDate is { } at && at < nowUtc;

    /// <summary>
    /// When <paramref name="user"/>'s password expires under <paramref name="policy"/>, or null
    /// when it does not: the policy sets no maximum age, the account is marked "never expires", or
    /// no date was stamped.
    /// </summary>
    public static DateTime? ExpiresAt(UserEntity user, PasswordPolicyEntity policy)
        => policy.MaxAgeDays > 0 && !user.PasswordNeverExpires ? user.PasswordExpirationDate : null;

    /// <summary>
    /// Sets <paramref name="user"/>'s expiry date for a password set at <paramref name="nowUtc"/>:
    /// <c>MaxAgeDays</c> later, or none when the policy sets no maximum age or the account is
    /// marked "never expires".
    /// </summary>
    public static void Stamp(UserEntity user, PasswordPolicyEntity policy, DateTime nowUtc)
        => user.PasswordExpirationDate = policy.MaxAgeDays > 0 && !user.PasswordNeverExpires
            ? nowUtc.AddDays(policy.MaxAgeDays)
            : null;
}
