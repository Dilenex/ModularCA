using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Utils;

/// <summary>
/// A certificate profile's expiry warning settings, as stored on <see cref="CertProfileEntity"/>
/// or after inheritance. Null values take the defaults of <see cref="ExpiryWarningRule"/>.
/// </summary>
/// <param name="WarningPercent">Share of the lifetime, 1 to 100, that remains when the soft warning starts; null for the default.</param>
/// <param name="WarningMaxWindow">Longest soft warning window, an ISO 8601 duration such as <c>P30D</c>; null for no cap.</param>
/// <param name="AlertPercent">Share of the lifetime, 1 to 100, that remains when the alert starts; null for the default.</param>
/// <param name="AlertMaxWindow">Longest alert window, an ISO 8601 duration; null for no cap.</param>
/// <param name="NeverWarn">The certificates are renewed automatically: neither warning is ever raised.</param>
public sealed record ExpiryWarningSettings(
    int? WarningPercent = null,
    string? WarningMaxWindow = null,
    int? AlertPercent = null,
    string? AlertMaxWindow = null,
    bool NeverWarn = false)
{
    /// <summary>No settings: the defaults apply.</summary>
    public static readonly ExpiryWarningSettings None = new();

    /// <summary>The settings <paramref name="profile"/> stores itself, without inheritance.</summary>
    public static ExpiryWarningSettings Of(CertProfileEntity profile) => new(
        profile.ExpiryWarningPercent, profile.ExpiryWarningMaxWindow,
        profile.ExpiryAlertPercent, profile.ExpiryAlertMaxWindow, profile.ExpiryNeverWarn);

    /// <summary>Whether the soft level is set at all: a percent or a window.</summary>
    public bool WarningSet => WarningPercent != null || !string.IsNullOrWhiteSpace(WarningMaxWindow);

    /// <summary>Whether the alert level is set at all: a percent or a window.</summary>
    public bool AlertSet => AlertPercent != null || !string.IsNullOrWhiteSpace(AlertMaxWindow);
}

/// <summary>
/// When a certificate's expiry warning starts: the soft warning (amber) and the alert (red). Each
/// certificate stores both instants when it is issued, and every count, list, chart, e-mail and
/// health score reads them.
/// </summary>
/// <remarks>
/// <para>
/// A level starts when <c>percent</c> of the certificate's lifetime remains, capped at the
/// level's maximum window when one is set: 30 % and 10 % by default, with no cap, so a 10-hour
/// certificate warns 3 hours before it expires and alerts 1 hour before, a 90-day one 27 and 9
/// days before, a one-year one about 110 and 37 days before.
/// </para>
/// <para>
/// A CA certificate whose profile does not set a level keeps the fixed windows it always had:
/// 30 days for the soft warning, 7 days for the alert. A profile that never warns (its
/// certificates are renewed automatically) stores both instants at <c>NotAfter</c>, so neither
/// window is ever entered; the certificate still counts as expired, not replaced, if it does
/// expire without a successor.
/// </para>
/// <para>
/// The alert never starts before the soft warning, and neither starts before <c>NotBefore</c>.
/// </para>
/// </remarks>
public static class ExpiryWarningRule
{
    /// <summary>Share of the lifetime that remains when the soft warning starts, unless the profile says otherwise.</summary>
    public const int DefaultWarningPercent = 30;

    /// <summary>Share of the lifetime that remains when the alert starts, unless the profile says otherwise.</summary>
    public const int DefaultAlertPercent = 10;

    /// <summary>Soft warning window of a CA certificate whose profile sets no soft level.</summary>
    public static readonly TimeSpan CaWarningWindow = TimeSpan.FromDays(30);

    /// <summary>Alert window of a CA certificate whose profile sets no alert level.</summary>
    public static readonly TimeSpan CaAlertWindow = TimeSpan.FromDays(7);

    /// <summary>
    /// The soft warning and alert instants of a certificate valid from <paramref name="notBefore"/>
    /// to <paramref name="notAfter"/> under <paramref name="settings"/> (null for none).
    /// </summary>
    /// <param name="notBefore">Start of validity.</param>
    /// <param name="notAfter">End of validity.</param>
    /// <param name="isCa">Whether the certificate is a CA certificate, which has its own defaults.</param>
    /// <param name="settings">The effective profile's settings, or null.</param>
    public static (DateTime WarningAt, DateTime AlertAt) Compute(DateTime notBefore, DateTime notAfter, bool isCa, ExpiryWarningSettings? settings)
    {
        var plan = Plan(settings);
        if (plan.NeverWarn)
            return (notAfter, notAfter);

        var lifetime = notAfter > notBefore ? notAfter - notBefore : TimeSpan.Zero;
        var warning = plan.Warning.Window(lifetime, isCa);
        var alert = plan.Alert.Window(lifetime, isCa);
        if (alert > warning)
            alert = warning;
        return (notAfter - warning, notAfter - alert);
    }

    /// <summary>
    /// How one level's window is found: <see cref="CaWindow"/> for a CA certificate when set,
    /// otherwise <see cref="Percent"/> of the lifetime capped at <see cref="Cap"/>; never longer
    /// than the lifetime. The re-compute after a profile edit hands the same values to SQL.
    /// </summary>
    /// <param name="Percent">Share of the lifetime, 0 to 100.</param>
    /// <param name="Cap">Longest window, or null for none.</param>
    /// <param name="CaWindow">Fixed window of a CA certificate, or null when the profile sets this level.</param>
    public readonly record struct LevelPlan(int Percent, TimeSpan? Cap, TimeSpan? CaWindow)
    {
        /// <summary>The window of a certificate with <paramref name="lifetime"/>.</summary>
        public TimeSpan Window(TimeSpan lifetime, bool isCa)
        {
            TimeSpan window;
            if (isCa && CaWindow is TimeSpan fixedSpan)
                window = fixedSpan;
            else
            {
                window = TimeSpan.FromTicks((long)(lifetime.Ticks * (Percent / 100.0)));
                if (Cap is TimeSpan cap && cap < window)
                    window = cap;
            }
            return window > lifetime ? lifetime : window;
        }
    }

    /// <summary>
    /// The two levels of <paramref name="settings"/> (null for none), defaults filled in. A window
    /// that is not an ISO 8601 duration is read as no cap, so a bad stored value never stops an
    /// issuance; saving one is refused (<see cref="Problem"/>).
    /// </summary>
    public static (bool NeverWarn, LevelPlan Warning, LevelPlan Alert) Plan(ExpiryWarningSettings? settings)
    {
        settings ??= ExpiryWarningSettings.None;
        return (settings.NeverWarn,
            new LevelPlan(Math.Clamp(settings.WarningPercent ?? DefaultWarningPercent, 0, 100), SafeWindow(settings.WarningMaxWindow),
                settings.WarningSet ? null : CaWarningWindow),
            new LevelPlan(Math.Clamp(settings.AlertPercent ?? DefaultAlertPercent, 0, 100), SafeWindow(settings.AlertMaxWindow),
                settings.AlertSet ? null : CaAlertWindow));
    }

    private static TimeSpan? SafeWindow(string? value)
    {
        try { return ParseWindow(value); }
        catch (FormatException) { return null; }
    }

    /// <summary>The window <paramref name="value"/> names, or null when it is blank.</summary>
    /// <exception cref="FormatException"><paramref name="value"/> is not an ISO 8601 duration.</exception>
    public static TimeSpan? ParseWindow(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Iso8601ParserUtil.ParseIso8601(value);

    /// <summary>
    /// Why the settings cannot be saved on one profile, or null: each percent from 1 to 100, the
    /// alert percent no larger than the soft one, each window a positive ISO 8601 duration and the
    /// alert window no longer than the soft one. The two comparisons apply when the profile sets
    /// both values; <see cref="Compute"/> holds the alert to the soft warning in every case.
    /// </summary>
    public static string? Problem(int? warningPercent, string? warningMaxWindow, int? alertPercent, string? alertMaxWindow)
    {
        if (warningPercent is < 1 or > 100)
            return $"The expiry warning percent must be from 1 to 100; it is {warningPercent}.";
        if (alertPercent is < 1 or > 100)
            return $"The expiry alert percent must be from 1 to 100; it is {alertPercent}.";
        if (alertPercent != null && warningPercent != null && alertPercent > warningPercent)
            return $"The expiry alert percent ({alertPercent}) cannot be larger than the warning percent ({warningPercent}): the alert comes after the warning.";

        TimeSpan? warning, alert;
        try { warning = ParseWindow(warningMaxWindow); }
        catch (FormatException) { return $"The expiry warning window '{warningMaxWindow}' is not an ISO 8601 duration such as P30D or PT6H."; }
        try { alert = ParseWindow(alertMaxWindow); }
        catch (FormatException) { return $"The expiry alert window '{alertMaxWindow}' is not an ISO 8601 duration such as P7D or PT1H."; }
        if (warning <= TimeSpan.Zero)
            return "The expiry warning window must be longer than zero.";
        if (alert <= TimeSpan.Zero)
            return "The expiry alert window must be longer than zero.";
        if (warning != null && alert != null && alert > warning)
            return $"The expiry alert window ({alertMaxWindow}) cannot be longer than the warning window ({warningMaxWindow}).";
        return null;
    }

    /// <summary>
    /// The expiry warning settings of <paramref name="child"/> merged with those of
    /// <paramref name="parent"/>, with each field's source written to <paramref name="sources"/>
    /// (<c>inherited</c>, <c>overridden</c> or <c>clamped</c>) under the
    /// <see cref="CertProfileEntity"/> property name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By default a child may only warn earlier than its parent, as with the other CLM-002 clamps,
    /// judged by what the parent's settings do rather than by what it stores: a percent at least
    /// the parent's (the default when the parent sets none), a window at least the parent's (none
    /// when the parent has no cap, since a cap only makes the warning later), and never-warn only
    /// when the parent never warns too. When both profiles issue CA certificates and the parent
    /// sets nothing for a level, the parent's window for that level is the CA default
    /// (<see cref="CaWarningWindow"/>, <see cref="CaAlertWindow"/>), so a longer window on the
    /// child is kept. A value outside that is replaced by the parent's and marked <c>clamped</c>;
    /// <paramref name="onClamp"/> hears of each.
    /// </para>
    /// <para>
    /// A child that declares <see cref="CertProfileEntity.ExpiryWarningOverridesParent"/> keeps
    /// every value it sets, unclamped, and inherits only the ones it leaves empty.
    /// </para>
    /// </remarks>
    /// <param name="child">The inheriting profile.</param>
    /// <param name="parent">The profile it inherits from.</param>
    /// <param name="sources">Receives each field's source.</param>
    /// <param name="onClamp">Called with the field name, the child's value and the parent's value (for a CA default, the window it
    /// amounts to, such as <c>P30D (CA default)</c>), for each clamp; may be null.</param>
    public static ExpiryWarningSettings Merge(CertProfileEntity child, CertProfileEntity parent,
        IDictionary<string, string> sources, Action<string, string?, string?>? onClamp = null)
    {
        const string inherited = "inherited", overridden = "overridden", clamped = "clamped";

        if (child.ExpiryWarningOverridesParent)
        {
            int? Pick(int? own, int? theirs, string field)
            {
                sources[field] = own != null ? overridden : inherited;
                return own ?? theirs;
            }
            string? PickWindow(string? own, string? theirs, string field)
            {
                var set = !string.IsNullOrWhiteSpace(own);
                sources[field] = set ? overridden : inherited;
                return set ? own : theirs;
            }
            sources[nameof(CertProfileEntity.ExpiryNeverWarn)] = overridden;
            sources[nameof(CertProfileEntity.ExpiryWarningOverridesParent)] = overridden;
            return new ExpiryWarningSettings(
                Pick(child.ExpiryWarningPercent, parent.ExpiryWarningPercent, nameof(CertProfileEntity.ExpiryWarningPercent)),
                PickWindow(child.ExpiryWarningMaxWindow, parent.ExpiryWarningMaxWindow, nameof(CertProfileEntity.ExpiryWarningMaxWindow)),
                Pick(child.ExpiryAlertPercent, parent.ExpiryAlertPercent, nameof(CertProfileEntity.ExpiryAlertPercent)),
                PickWindow(child.ExpiryAlertMaxWindow, parent.ExpiryAlertMaxWindow, nameof(CertProfileEntity.ExpiryAlertMaxWindow)),
                child.ExpiryNeverWarn);
        }

        int? Percent(int? own, int? theirs, int fallback, string field)
        {
            if (own == null)
            {
                sources[field] = inherited;
                return theirs;
            }
            if (own < (theirs ?? fallback))
            {
                sources[field] = clamped;
                onClamp?.Invoke(field, own.ToString(), (theirs ?? fallback).ToString());
                return theirs;
            }
            sources[field] = overridden;
            return own;
        }
        string? Window(string? own, string? theirs, TimeSpan? caDefault, string field)
        {
            if (string.IsNullOrWhiteSpace(own))
            {
                sources[field] = inherited;
                return theirs;
            }
            var theirsShown = theirs ?? (caDefault is TimeSpan d ? $"P{(int)d.TotalDays}D (CA default)" : null);
            TimeSpan? ownSpan, theirSpan;
            try
            {
                ownSpan = ParseWindow(own);
                theirSpan = ParseWindow(theirs) ?? caDefault;
            }
            catch (FormatException)
            {
                sources[field] = clamped;
                onClamp?.Invoke(field, own, theirsShown);
                return theirs;
            }
            if (theirSpan == null || ownSpan < theirSpan)
            {
                sources[field] = clamped;
                onClamp?.Invoke(field, own, theirsShown);
                return theirs;
            }
            sources[field] = overridden;
            return own;
        }

        var parentOwn = ExpiryWarningSettings.Of(parent);
        var caCertificates = child.IsCaProfile && parent.IsCaProfile;
        TimeSpan? caWarning = caCertificates && !parentOwn.WarningSet ? CaWarningWindow : null;
        TimeSpan? caAlert = caCertificates && !parentOwn.AlertSet ? CaAlertWindow : null;

        var neverWarn = child.ExpiryNeverWarn && parent.ExpiryNeverWarn;
        if (child.ExpiryNeverWarn && !parent.ExpiryNeverWarn)
        {
            sources[nameof(CertProfileEntity.ExpiryNeverWarn)] = clamped;
            onClamp?.Invoke(nameof(CertProfileEntity.ExpiryNeverWarn), "true", "false");
        }
        else
            sources[nameof(CertProfileEntity.ExpiryNeverWarn)] = overridden;
        sources[nameof(CertProfileEntity.ExpiryWarningOverridesParent)] = overridden;

        return new ExpiryWarningSettings(
            Percent(child.ExpiryWarningPercent, parent.ExpiryWarningPercent, DefaultWarningPercent, nameof(CertProfileEntity.ExpiryWarningPercent)),
            Window(child.ExpiryWarningMaxWindow, parent.ExpiryWarningMaxWindow, caWarning, nameof(CertProfileEntity.ExpiryWarningMaxWindow)),
            Percent(child.ExpiryAlertPercent, parent.ExpiryAlertPercent, DefaultAlertPercent, nameof(CertProfileEntity.ExpiryAlertPercent)),
            Window(child.ExpiryAlertMaxWindow, parent.ExpiryAlertMaxWindow, caAlert, nameof(CertProfileEntity.ExpiryAlertMaxWindow)),
            neverWarn);
    }
}
