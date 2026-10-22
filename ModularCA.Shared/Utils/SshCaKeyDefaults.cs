namespace ModularCA.Shared.Utils;

/// <summary>
/// The defaults of a new SSH CA key and of the signing profiles created with it
/// (<c>docs/architecture/ssh-defaults.md</c>; owner, 2026-10-08). The key holds the hard ceiling
/// on a certificate's lifetime; these are what that ceiling is when a request does not say, and
/// when an administrator is reminded to review the key.
/// </summary>
/// <remarks>
/// A key that signs user certificates, including one that signs both types, takes the user
/// values. Only a key that signs host certificates and no user certificates takes the host values.
/// </remarks>
public static class SshCaKeyDefaults
{
    /// <summary>The longest certificate, in hours, of a key that signs user certificates, when a request names none.</summary>
    public const int UserMaxValidityHours = 24;

    /// <summary>The longest certificate, in hours, of a host-only key, when a request names none: one year.</summary>
    public const int HostMaxValidityHours = 8760;

    /// <summary>How many years after its creation a key that signs user certificates is due for review.</summary>
    public const int UserReviewYears = 2;

    /// <summary>How many years after its creation a host-only key is due for review.</summary>
    public const int HostReviewYears = 5;

    /// <summary>How many days before its review date a key is shown, and notified, as due for review.</summary>
    public const int ReviewWarningDays = 90;

    /// <summary>How many years ahead, at most, a review date may be set.</summary>
    public const int MaxReviewYearsAhead = 10;

    /// <summary>
    /// The default extensions of the user signing profile created with a key: a terminal and
    /// nothing else. Agent forwarding lets a compromised server use the holder's access
    /// elsewhere, so forwarding is asked for through a certificate profile that requires it.
    /// </summary>
    public static readonly IReadOnlyList<string> UserSigningDefaultExtensions = ["permit-pty"];

    /// <summary>Whether a key signs host certificates and no user certificates.</summary>
    public static bool IsHostOnly(bool isUserCa, bool isHostCa) => isHostCa && !isUserCa;

    /// <summary>The longest certificate, in hours, of a new key whose request names none.</summary>
    public static int MaxValidityHours(bool isUserCa, bool isHostCa)
        => IsHostOnly(isUserCa, isHostCa) ? HostMaxValidityHours : UserMaxValidityHours;

    /// <summary>
    /// The review date of a key created at <paramref name="createdAt"/>, in UTC:
    /// <see cref="UserReviewYears"/> later for a key that signs user certificates,
    /// <see cref="HostReviewYears"/> later for a host-only key.
    /// </summary>
    public static DateTime ReviewBy(DateTime createdAt, bool isUserCa, bool isHostCa)
        => Utc(createdAt).AddYears(IsHostOnly(isUserCa, isHostCa) ? HostReviewYears : UserReviewYears);

    /// <summary>
    /// Null when <paramref name="reviewBy"/> may be set as a key's review date at
    /// <paramref name="now"/>: it is in the future and at most <see cref="MaxReviewYearsAhead"/>
    /// years ahead. Otherwise a sentence for a 400 answer.
    /// </summary>
    public static string? ReviewByError(DateTime reviewBy, DateTime now)
    {
        var at = Utc(reviewBy);
        var from = Utc(now);
        if (at <= from)
            return "The review date must be in the future.";
        if (at > from.AddYears(MaxReviewYearsAhead))
            return $"The review date can be at most {MaxReviewYearsAhead} years ahead.";
        return null;
    }

    /// <summary>
    /// Whether a key is due for review at <paramref name="now"/>: its review date is within
    /// <see cref="ReviewWarningDays"/> days, or has passed. A key with no review date is never due.
    /// This decides a reminder and nothing else.
    /// </summary>
    public static bool ReviewIsDue(DateTime? reviewBy, DateTime now)
        => reviewBy is { } at && Utc(at) <= Utc(now).AddDays(ReviewWarningDays);

    private static DateTime Utc(DateTime value)
        => value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
