namespace ModularCA.Core.Services;

/// <summary>
/// The steps of a certificate's expiry warning that send a <c>CertExpiring</c> notification, each
/// at most once per certificate: the soft warning starting, a reminder inside the window
/// (<c>CertExpiryNotification.WarningDaysBeforeExpiry</c>), and the alert starting.
/// </summary>
public static class CertExpiryStage
{
    /// <summary>The soft warning started.</summary>
    public const string Warning = "Warning";

    /// <summary>A reminder inside the warning window.</summary>
    public const string Reminder = "Reminder";

    /// <summary>The alert started.</summary>
    public const string Alert = "Alert";

    /// <summary>
    /// The time left before expiry in the largest unit that reads well: days from two days up,
    /// hours from two hours up, minutes below.
    /// </summary>
    public static string TimeLeft(TimeSpan left)
    {
        if (left.TotalDays >= 2) return $"{(int)left.TotalDays} days";
        if (left.TotalHours >= 2) return $"{(int)left.TotalHours} hours";
        var minutes = Math.Max(0, (int)left.TotalMinutes);
        return minutes == 1 ? "1 minute" : $"{minutes} minutes";
    }
}
