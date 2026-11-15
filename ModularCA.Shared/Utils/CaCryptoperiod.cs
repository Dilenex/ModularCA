namespace ModularCA.Shared.Utils;

/// <summary>
/// The instance's settings for CA cryptoperiod notices (<c>CaLifecycle</c> in the settings
/// store). Every one of them only decides when a notice is shown; none changes what a CA does.
/// </summary>
/// <param name="RootExpiryNoticeDays">How many days before a root CA certificate expires its notice starts; 0 for no early notice.</param>
/// <param name="IntermediateExpiryNoticeDays">The same for a CA certificate that another CA issued.</param>
/// <param name="KeyUsagePeriodDays">How long a CA key may have been signing before a notice says so; 0 for never.</param>
public sealed record CaCryptoperiodSettings(int RootExpiryNoticeDays, int IntermediateExpiryNoticeDays, int KeyUsagePeriodDays)
{
    /// <summary>What a new install and an upgraded one both start with: two years, one year, and no key-usage notice.</summary>
    public static readonly CaCryptoperiodSettings Defaults = new(DefaultRootExpiryNoticeDays, DefaultIntermediateExpiryNoticeDays, 0);

    /// <summary>The default notice window of a root CA certificate: two years.</summary>
    public const int DefaultRootExpiryNoticeDays = 730;

    /// <summary>The default notice window of an intermediate CA certificate: one year.</summary>
    public const int DefaultIntermediateExpiryNoticeDays = 365;

    /// <summary>The longest window or period a setting accepts, in days: one hundred years.</summary>
    public const int MaxDays = 36500;
}

/// <summary>
/// What is known about a CA's key and certificate over time. Every member is a fact read from
/// the database, with null for what could not be read; nothing here is a judgment.
/// </summary>
/// <param name="IsRoot">Whether the CA's certificate is self-issued.</param>
/// <param name="KeyInUseSince">
/// When the key started signing, as well as the instance knows: the start of validity of the
/// earliest certificate the CA has over its current key. A key made outside the instance, or
/// certified long after it was made, is older than this says.
/// </param>
/// <param name="CertificateCount">How many certificates the CA has had over its current key, the current one included.</param>
/// <param name="CertificateNotBefore">Start of validity of the current CA certificate.</param>
/// <param name="CertificateNotAfter">End of validity of the current CA certificate.</param>
/// <param name="ExpiryWarningAt">When the certificate's own expiry warning starts (<see cref="ExpiryWarningRule"/>), as stored on it.</param>
/// <param name="ExpiryAlertAt">When the certificate's own expiry alert starts, as stored on it.</param>
/// <param name="LatestIssuedNotAfter">The latest end of validity among the unexpired, unrevoked certificates issued under this key; null when there is none.</param>
/// <param name="LongestProfileValidity">The longest validity a certificate profile linked to this CA allows; null when none sets a maximum.</param>
/// <param name="LongestProfileName">The name of that profile.</param>
/// <param name="ParentName">The name of the CA that issued this CA's certificate, when it is a CA of this instance.</param>
/// <param name="ParentCertificateNotAfter">End of validity of that CA's current certificate.</param>
public sealed record CaCryptoperiodFacts(
    bool IsRoot,
    DateTime? KeyInUseSince,
    int CertificateCount,
    DateTime? CertificateNotBefore,
    DateTime? CertificateNotAfter,
    DateTime? ExpiryWarningAt,
    DateTime? ExpiryAlertAt,
    DateTime? LatestIssuedNotAfter,
    TimeSpan? LongestProfileValidity,
    string? LongestProfileName,
    string? ParentName,
    DateTime? ParentCertificateNotAfter)
{
    /// <summary>Where <see cref="KeyInUseSince"/> comes from, for the console to say beside it.</summary>
    public const string KeyInUseSinceSource = "The start of validity of the earliest certificate this CA has had over its current key.";
}

/// <summary>
/// The notices a CA's cryptoperiod raises: its certificate nearing its end, its profiles asking
/// for more time than its certificate has left, a key that has signed longer than the
/// organization's policy says, and a certificate that outlives its issuer's. NIST SP 800-57
/// Part 1 treats a certificate's validity as the bound on the public key's use and suggests an
/// originator-usage period for a private signature key; how long a CA key may sign is the
/// organization's policy, so that period is a setting and is off until someone sets it. A notice
/// is information: no CA stops signing and no node becomes not ready because of one.
/// </summary>
public static class CaCryptoperiod
{
    /// <summary>The CA certificate has expired.</summary>
    public const string CertificateExpired = "CaCertificateExpired";

    /// <summary>The CA certificate expires within its notice window, or is in its own expiry warning or alert.</summary>
    public const string CertificateExpiring = "CaCertificateExpiring";

    /// <summary>A linked certificate profile allows a validity longer than the CA certificate has left, so issuance is shortened.</summary>
    public const string ProfilesOutliveCertificate = "CaProfilesOutliveCertificate";

    /// <summary>The key has been signing longer than the configured usage period.</summary>
    public const string KeyUsagePeriodExceeded = "CaKeyUsagePeriodExceeded";

    /// <summary>The CA certificate ends after the certificate of the CA that issued it.</summary>
    public const string OutlivesParent = "CaCertificateOutlivesParent";

    /// <summary>
    /// The notices for a CA with <paramref name="facts"/> at <paramref name="now"/> under
    /// <paramref name="settings"/>, most pressing first. Empty when there is nothing to say or
    /// the certificate's validity is not known.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Expiry.</b> One notice, three levels. It starts when the certificate has no more than
    /// the notice window left (two years for a root and one for an intermediate by default; a
    /// window of 0 gives no early notice). It becomes a warning when the certificate's own
    /// expiry warning starts and critical when its alert starts: those two instants are the ones
    /// stored on the certificate (<see cref="ExpiryWarningRule"/>: 30 and 7 days for a CA
    /// certificate unless its profile says otherwise), which the certificate list, the lifecycle
    /// summary and the expiry e-mails already use, so the levels cannot disagree with them.
    /// </para>
    /// <para>
    /// <b>Profiles.</b> Issuance shortens a certificate that would end after its issuer
    /// (five minutes before the issuer's end) and refuses one whose profile minimum no longer
    /// fits. The notice says so when a linked profile's maximum is longer than what is left.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<CaKeyAdvisory> Advisories(CaCryptoperiodFacts facts, CaCryptoperiodSettings settings, DateTime now)
    {
        var found = new List<CaKeyAdvisory>();
        if (facts.CertificateNotAfter is not DateTime notAfter)
            return found;

        var left = notAfter - now;
        if (left <= TimeSpan.Zero)
        {
            found.Add(new CaKeyAdvisory(CertificateExpired,
                $"This CA's certificate expired on {Day(notAfter)}. Nothing it issued validates any more, and it issues nothing. "
                + (facts.IsRoot
                    ? "Renew the certificate (same key, new validity) and give the new one to everyone who trusts this root."
                    : "Renew the certificate (same key, new validity); its parent signs the new one."),
                CaKeyAdvisory.Critical, "Certificate expired"));
        }
        else
        {
            var window = facts.IsRoot ? settings.RootExpiryNoticeDays : settings.IntermediateExpiryNoticeDays;
            var inAlert = facts.ExpiryAlertAt is DateTime alertAt && alertAt <= now;
            var inWarning = facts.ExpiryWarningAt is DateTime warningAt && warningAt <= now;
            var inNotice = window > 0 && left <= TimeSpan.FromDays(window);
            if (inAlert || inWarning || inNotice)
            {
                var severity = inAlert ? CaKeyAdvisory.Critical : inWarning ? CaKeyAdvisory.Warning : CaKeyAdvisory.Notice;
                found.Add(new CaKeyAdvisory(CertificateExpiring,
                    $"This CA's certificate expires on {Day(notAfter)}, in {Span(left)}. "
                    + "Every certificate it issues ends before that, so the time it can offer shrinks every day. "
                    + (facts.IsRoot
                        ? "Renew the certificate (same key, new validity) in good time: the new root certificate has to reach everyone who trusts this one before the old one expires."
                        : "Renew the certificate (same key, new validity) before then; its parent signs the new one, and nothing has to be redistributed to those who trust the root."),
                    severity, $"Certificate expires in {Span(left)}"));
            }

            if (facts.LongestProfileValidity is TimeSpan longest && longest > left)
            {
                found.Add(new CaKeyAdvisory(ProfilesOutliveCertificate,
                    $"{(string.IsNullOrWhiteSpace(facts.LongestProfileName) ? "A certificate profile" : $"The certificate profile '{facts.LongestProfileName}'")} "
                    + $"allows certificates valid for {Span(longest)}, and this CA's own certificate has {Span(left)} left. "
                    + "A certificate issued now is shortened to end five minutes before the CA certificate does, with a warning to whoever requested it, "
                    + "and a profile whose minimum validity no longer fits is refused. Renew the CA certificate to issue for the full period again.",
                    CaKeyAdvisory.Notice, "Issued certificates are shortened"));
            }
        }

        if (facts.ParentCertificateNotAfter is DateTime parentEnd && parentEnd < notAfter && left > TimeSpan.Zero)
        {
            found.Add(new CaKeyAdvisory(OutlivesParent,
                $"This CA's certificate is valid until {Day(notAfter)}, and the certificate of {(string.IsNullOrWhiteSpace(facts.ParentName) ? "its parent CA" : $"its parent, '{facts.ParentName}',")} "
                + $"expires first, on {Day(parentEnd)}. A chain ends with its shortest certificate: after that day this CA's certificate validates under no chain that uses the parent's current certificate. "
                + "Renew the parent's certificate before then.",
                parentEnd <= now ? CaKeyAdvisory.Critical : CaKeyAdvisory.Notice, "Outlives its parent's certificate"));
        }

        if (settings.KeyUsagePeriodDays > 0 && facts.KeyInUseSince is DateTime since && now - since > TimeSpan.FromDays(settings.KeyUsagePeriodDays))
        {
            found.Add(new CaKeyAdvisory(KeyUsagePeriodExceeded,
                $"This CA's key has been signing since {Day(since)}, {Span(now - since)}: longer than the {Span(TimeSpan.FromDays(settings.KeyUsagePeriodDays))} this instance sets as a CA key's usage period "
                + "(CA lifecycle in Settings; NIST SP 800-57 Part 1 calls it the originator-usage period). The key keeps working. "
                + "Renewing the certificate does not change the key: a CA gets a new key only by creating a new CA and moving issuance to it.",
                CaKeyAdvisory.Notice, $"Key in use {Span(now - since)}"));
        }

        return found.OrderBy(a => a.Severity switch { CaKeyAdvisory.Critical => 0, CaKeyAdvisory.Warning => 1, _ => 2 }).ToList();
    }

    /// <summary>Why <paramref name="settings"/> cannot be saved, or null: each value from 0 to <see cref="CaCryptoperiodSettings.MaxDays"/>.</summary>
    public static string? Problem(CaCryptoperiodSettings settings)
    {
        if (settings.RootExpiryNoticeDays is < 0 or > CaCryptoperiodSettings.MaxDays)
            return $"The root CA expiry notice must be from 0 to {CaCryptoperiodSettings.MaxDays} days; it is {settings.RootExpiryNoticeDays}.";
        if (settings.IntermediateExpiryNoticeDays is < 0 or > CaCryptoperiodSettings.MaxDays)
            return $"The intermediate CA expiry notice must be from 0 to {CaCryptoperiodSettings.MaxDays} days; it is {settings.IntermediateExpiryNoticeDays}.";
        if (settings.KeyUsagePeriodDays is < 0 or > CaCryptoperiodSettings.MaxDays)
            return $"The CA key usage period must be from 0 to {CaCryptoperiodSettings.MaxDays} days; it is {settings.KeyUsagePeriodDays}.";
        return null;
    }

    private static string Day(DateTime value) => value.ToUniversalTime().ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>A length of time in words: days under two months, months under two years, then years to one decimal.</summary>
    public static string Span(TimeSpan span)
    {
        var days = (int)Math.Floor(Math.Abs(span.TotalDays));
        if (days < 1)
            return "less than a day";
        if (days < 60)
            return days == 1 ? "1 day" : $"{days} days";
        if (days < 730)
            return $"{days / 30} months";
        var years = Math.Round(days / 365.25, 1);
        return years == Math.Floor(years)
            ? $"{years.ToString("0", System.Globalization.CultureInfo.InvariantCulture)} years"
            : $"{years.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture)} years";
    }
}
