namespace ModularCA.Shared.Utils;

/// <summary>
/// The one rule for how long a signed-in session may last. A session is a family of refresh
/// tokens: the first is issued at sign-in and each refresh replaces it with a successor of the
/// same family. Two settings bound it: the maximum session lifetime
/// (<see cref="ModularCA.Shared.Entities.SecurityPolicyEntity.MaxSessionLifetimeHours"/>, counted
/// from the sign-in) and the refresh-token lifetime
/// (<see cref="ModularCA.Shared.Models.Config.TokenConfig.RefreshTokenDays"/>, counted from each
/// refresh). The session maximum wins: no refresh token, and no access token issued from one, is
/// valid past the sign-in time plus the maximum, whatever the refresh-token lifetime says.
/// </summary>
public static class SessionLifetime
{
    /// <summary>
    /// The maximum session lifetime a new install gets, in hours. NIST SP 800-63B asks for
    /// reauthentication at least every 12 hours at AAL2 and AAL3.
    /// </summary>
    public const int RecommendedMaxHours = 12;

    /// <summary>
    /// The idle timeout NIST SP 800-63B asks for at AAL2, in minutes (15 at AAL3). The default of
    /// <see cref="ModularCA.Shared.Entities.SecurityPolicyEntity.SessionIdleTimeoutMinutes"/>.
    /// </summary>
    public const int RecommendedIdleMinutes = 30;

    /// <summary>
    /// The moment a session that began at <paramref name="sessionStartedUtc"/> must end, or null
    /// when <paramref name="maxSessionLifetimeHours"/> is 0 or less (no maximum). A value too
    /// large for the calendar gives <see cref="DateTime.MaxValue"/> instead of an exception.
    /// </summary>
    public static DateTime? Horizon(DateTime sessionStartedUtc, int maxSessionLifetimeHours)
    {
        if (maxSessionLifetimeHours <= 0) return null;
        var room = DateTime.MaxValue - sessionStartedUtc;
        return room.TotalHours <= maxSessionLifetimeHours ? DateTime.MaxValue : sessionStartedUtc.AddHours(maxSessionLifetimeHours);
    }

    /// <summary>
    /// When a refresh token issued at <paramref name="nowUtc"/> for a session that began at
    /// <paramref name="sessionStartedUtc"/> expires: <paramref name="refreshTokenDays"/> from now,
    /// or the session's <see cref="Horizon"/> when that comes first.
    /// </summary>
    public static DateTime RefreshTokenExpiry(DateTime nowUtc, DateTime sessionStartedUtc, int refreshTokenDays, int maxSessionLifetimeHours)
    {
        var byToken = nowUtc.AddDays(refreshTokenDays);
        return Horizon(sessionStartedUtc, maxSessionLifetimeHours) is { } horizon && horizon < byToken ? horizon : byToken;
    }

    /// <summary>
    /// How long a refresh token can really last under the two settings, in hours: the
    /// refresh-token lifetime, or the session maximum when that is shorter and set.
    /// </summary>
    public static int EffectiveRefreshTokenHours(int refreshTokenDays, int maxSessionLifetimeHours)
    {
        var byToken = (long)refreshTokenDays * 24;
        var effective = maxSessionLifetimeHours > 0 ? Math.Min(byToken, maxSessionLifetimeHours) : byToken;
        return (int)Math.Min(effective, int.MaxValue);
    }

    /// <summary>
    /// Whether the session that began at <paramref name="sessionStartedUtc"/> is past its
    /// <see cref="Horizon"/> at <paramref name="nowUtc"/>.
    /// </summary>
    public static bool IsOver(DateTime nowUtc, DateTime sessionStartedUtc, int maxSessionLifetimeHours)
        => Horizon(sessionStartedUtc, maxSessionLifetimeHours) is { } horizon && nowUtc >= horizon;
}
