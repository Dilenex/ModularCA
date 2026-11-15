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
/// What a reader who may not see a CA's parent is told about the parent's certificate: only how
/// its end stands against the CA's own. Nothing here identifies the parent or dates its certificate.
/// </summary>
public enum CaWithheldParent
{
    /// <summary>The parent's certificate does not end before this CA's, or its end is not known.</summary>
    NoEarlierEnd,

    /// <summary>The parent's certificate ends before this CA's and has not ended yet.</summary>
    EndsFirst,

    /// <summary>The parent's certificate ends before this CA's and has already ended.</summary>
    Expired,
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
/// <param name="LongestProfileValidity">The longest validity an end-entity certificate profile linked to this CA allows, the CA's own infrastructure profiles left out; null when none sets a maximum.</param>
/// <param name="LongestProfileName">The name of that profile.</param>
/// <param name="ParentName">The name of the CA that issued this CA's certificate, when it is a CA of this instance that the reader may see; null for a parent outside the reader's space fence (<see cref="WithheldParent"/>).</param>
/// <param name="ParentCertificateNotAfter">End of validity of that CA's current certificate; null, like the name, for a parent the reader may not see.</param>
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
    /// <summary>
    /// True when the CA has no end-entity profile with a maximum and <see cref="LongestProfileValidity"/>
    /// is that of one of its own infrastructure profiles (OCSP responder, timestamp, CMP signer),
    /// shown so the fact is not empty. Such a profile raises no notice: its certificates are meant
    /// to end with the CA's.
    /// </summary>
    public bool LongestProfileIsInfrastructure { get; init; }

    /// <summary>
    /// Set when the CA has a parent in this instance that the reader may not see (it is outside
    /// their space fence): <see cref="ParentName"/> and <see cref="ParentCertificateNotAfter"/> are
    /// then null, and this says the one thing the "outlives its parent" notice needs. Null for a
    /// root, for a parent the reader may see, and for a parent that no longer exists.
    /// </summary>
    public CaWithheldParent? WithheldParent { get; init; }

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
    /// fits. The notice says so once an end-entity profile's maximum is longer than what is left
    /// by a tenth of that maximum or more (<see cref="ShortensMaterially"/>); the CA's own
    /// infrastructure profiles never raise it.
    /// </para>
    /// <para>
    /// <b>A parent the reader may not see.</b> The "outlives its parent" notice then names no
    /// parent and gives no date of the parent's certificate
    /// (<see cref="CaCryptoperiodFacts.WithheldParent"/>): it says that the parent's certificate
    /// ends earlier, or has expired, and to ask an administrator of the parent CA.
    /// </para>
    /// <para>
    /// <b>Length.</b> Every message is at most 40 words: what is so, and what to do. The
    /// mechanism is in the documentation.
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
                $"This CA's certificate expired on {Day(notAfter)}. It issues nothing, and what it issued no longer validates. Renew the CA certificate.",
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
                    + (facts.IsRoot
                        ? "Renew the CA certificate in good time, then give the new root certificate to everyone who trusts this one."
                        : "Renew the CA certificate; its parent signs the new one."),
                    severity, $"Certificate expires in {Span(left)}"));
            }

            if (!facts.LongestProfileIsInfrastructure && facts.LongestProfileValidity is TimeSpan longest && ShortensMaterially(longest, left))
            {
                found.Add(new CaKeyAdvisory(ProfilesOutliveCertificate,
                    $"{(string.IsNullOrWhiteSpace(facts.LongestProfileName) ? "A certificate profile" : $"'{facts.LongestProfileName}'")} allows {Span(longest)}, "
                    + $"but this CA's certificate ends in {Span(left)}. Certificates are issued shorter until the CA certificate is renewed.",
                    CaKeyAdvisory.Notice, "Issued certificates are shortened"));
            }
        }

        if (facts.ParentCertificateNotAfter is DateTime parentEnd && parentEnd < notAfter && left > TimeSpan.Zero)
        {
            found.Add(new CaKeyAdvisory(OutlivesParent,
                $"This certificate is valid until {Day(notAfter)}, but the certificate of {(string.IsNullOrWhiteSpace(facts.ParentName) ? "its parent CA" : $"its parent '{facts.ParentName}'")} "
                + $"expires on {Day(parentEnd)}. Renew the parent's certificate before then.",
                parentEnd <= now ? CaKeyAdvisory.Critical : CaKeyAdvisory.Notice, "Outlives its parent's certificate"));
        }
        else if (facts.WithheldParent is CaWithheldParent.EndsFirst or CaWithheldParent.Expired && left > TimeSpan.Zero)
        {
            // The reader may not see the parent CA: no name, and no date of its certificate.
            var expired = facts.WithheldParent == CaWithheldParent.Expired;
            found.Add(new CaKeyAdvisory(OutlivesParent,
                $"This certificate is valid until {Day(notAfter)}, but its parent's certificate {(expired ? "has expired" : "expires earlier")}. "
                + "Ask an administrator of the parent CA to renew it.",
                expired ? CaKeyAdvisory.Critical : CaKeyAdvisory.Notice, "Outlives its parent's certificate"));
        }

        if (settings.KeyUsagePeriodDays > 0 && facts.KeyInUseSince is DateTime since && now - since > TimeSpan.FromDays(settings.KeyUsagePeriodDays))
        {
            found.Add(new CaKeyAdvisory(KeyUsagePeriodExceeded,
                $"This CA's key has been signing since {Day(since)}, longer than the {Span(TimeSpan.FromDays(settings.KeyUsagePeriodDays))} this instance sets as a CA key's usage period "
                + "(NIST SP 800-57). A new key means a new CA.",
                CaKeyAdvisory.Notice, $"Key in use {Span(now - since)}"));
        }

        return found.OrderBy(a => a.Severity switch { CaKeyAdvisory.Critical => 0, CaKeyAdvisory.Warning => 1, _ => 2 }).ToList();
    }

    /// <summary>The share of a profile's maximum validity that has to be lost before the shortening is worth a notice: a tenth.</summary>
    public const double MaterialShorteningShare = 0.10;

    /// <summary>
    /// Whether a CA with <paramref name="left"/> on its certificate shortens what a profile with
    /// maximum <paramref name="profileMaximum"/> issues by enough to say so. A certificate profile
    /// has a minimum and a maximum validity and no default of its own: a request that names no
    /// end gets the maximum. So every request is shortened as soon as the CA has less than the
    /// maximum left, which for a CA and a profile of the same length is the CA's first day. The
    /// notice is therefore raised only once a certificate issued now would lose at least a tenth
    /// of the profile's maximum (<see cref="MaterialShorteningShare"/>): a 10-year profile on a
    /// CA with 9 years left, a 397-day profile on a CA with 357 days left.
    /// </summary>
    public static bool ShortensMaterially(TimeSpan profileMaximum, TimeSpan left)
        => profileMaximum > TimeSpan.Zero && left < profileMaximum
           && (profileMaximum - left).Ticks >= (long)(profileMaximum.Ticks * MaterialShorteningShare);

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
