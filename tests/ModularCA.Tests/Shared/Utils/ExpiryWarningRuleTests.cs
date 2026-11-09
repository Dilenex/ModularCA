using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// <see cref="ExpiryWarningRule"/>: when the soft warning and the alert start for a certificate,
/// what a profile may save, and how a child profile's settings merge with its parent's.
/// </summary>
public sealed class ExpiryWarningRuleTests
{
    private static readonly DateTime Start = new(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);

    private static (TimeSpan Warning, TimeSpan Alert) Before(TimeSpan lifetime, bool isCa = false, ExpiryWarningSettings? settings = null)
    {
        var (warningAt, alertAt) = ExpiryWarningRule.Compute(Start, Start + lifetime, isCa, settings);
        return (Start + lifetime - warningAt, Start + lifetime - alertAt);
    }

    [Theory]
    [InlineData(10.0 / 24, 3.0 / 24, 1.0 / 24)]
    [InlineData(20, 6, 2)]
    [InlineData(90, 27, 9)]
    [InlineData(365, 109.5, 36.5)]
    public void A_leaf_warns_at_30_percent_and_alerts_at_10_percent_of_its_lifetime(double days, double warningDays, double alertDays)
    {
        var (warning, alert) = Before(TimeSpan.FromDays(days));
        Assert.Equal(TimeSpan.FromDays(warningDays).TotalSeconds, warning.TotalSeconds, 3);
        Assert.Equal(TimeSpan.FromDays(alertDays).TotalSeconds, alert.TotalSeconds, 3);
    }

    [Fact]
    public void A_window_caps_a_level_and_the_alert_never_starts_before_the_warning()
    {
        var capped = Before(TimeSpan.FromDays(365), settings: new ExpiryWarningSettings(WarningMaxWindow: "P30D", AlertMaxWindow: "P7D"));
        Assert.Equal((TimeSpan.FromDays(30), TimeSpan.FromDays(7)), capped);

        // A cap shorter than the default alert window pulls the alert to the warning.
        var pulled = Before(TimeSpan.FromDays(365), settings: new ExpiryWarningSettings(WarningMaxWindow: "PT6H"));
        Assert.Equal((TimeSpan.FromHours(6), TimeSpan.FromHours(6)), pulled);

        var percents = Before(TimeSpan.FromDays(100), settings: new ExpiryWarningSettings(WarningPercent: 50, AlertPercent: 20));
        Assert.Equal((TimeSpan.FromDays(50), TimeSpan.FromDays(20)), percents);
    }

    [Fact]
    public void A_never_warn_profile_puts_both_instants_at_expiry()
    {
        var notAfter = Start.AddDays(90);
        Assert.Equal((notAfter, notAfter), ExpiryWarningRule.Compute(Start, notAfter, false, new ExpiryWarningSettings(NeverWarn: true)));
        Assert.Equal((notAfter, notAfter), ExpiryWarningRule.Compute(Start, notAfter, true, new ExpiryWarningSettings(WarningPercent: 50, NeverWarn: true)));
    }

    [Fact]
    public void A_ca_certificate_keeps_30_and_7_days_unless_its_profile_sets_a_level()
    {
        Assert.Equal((TimeSpan.FromDays(30), TimeSpan.FromDays(7)), Before(TimeSpan.FromDays(3650), isCa: true));
        Assert.Equal((TimeSpan.FromDays(10), TimeSpan.FromDays(7)), Before(TimeSpan.FromDays(10), isCa: true));

        // A level the profile sets follows the percent rule; the other keeps its fixed window.
        var set = Before(TimeSpan.FromDays(1000), isCa: true, new ExpiryWarningSettings(WarningPercent: 10));
        Assert.Equal((TimeSpan.FromDays(100), TimeSpan.FromDays(7)), set);
        var window = Before(TimeSpan.FromDays(1000), isCa: true, new ExpiryWarningSettings(AlertMaxWindow: "P60D"));
        Assert.Equal((TimeSpan.FromDays(30), TimeSpan.FromDays(30)), window);
    }

    [Fact]
    public void A_zero_or_negative_lifetime_warns_and_alerts_at_expiry()
    {
        Assert.Equal((Start, Start), ExpiryWarningRule.Compute(Start, Start, false, null));
        var earlier = Start.AddDays(-1);
        Assert.Equal((earlier, earlier), ExpiryWarningRule.Compute(Start, earlier, true, null));
    }

    [Fact]
    public void A_bad_stored_window_is_read_as_no_cap()
    {
        Assert.Equal((TimeSpan.FromDays(30), TimeSpan.FromDays(10)),
            Before(TimeSpan.FromDays(100), settings: new ExpiryWarningSettings(WarningMaxWindow: "thirty days")));
    }

    [Theory]
    [InlineData(null, null, null, null, null)]
    [InlineData(30, "P30D", 10, "P7D", null)]
    [InlineData(100, null, 100, null, null)]
    [InlineData(0, null, null, null, "warning percent")]
    [InlineData(101, null, null, null, "warning percent")]
    [InlineData(null, null, 0, null, "alert percent")]
    [InlineData(20, null, 30, null, "cannot be larger")]
    [InlineData(null, "30 days", null, null, "not an ISO 8601")]
    [InlineData(null, "P0D", null, null, "longer than zero")]
    [InlineData(null, null, null, "PT0S", "longer than zero")]
    [InlineData(null, "P7D", null, "P30D", "cannot be longer")]
    public void A_profile_saves_percents_from_1_to_100_and_positive_windows_with_the_alert_inside_the_warning(
        int? warningPercent, string? warningWindow, int? alertPercent, string? alertWindow, string? problem)
    {
        var found = ExpiryWarningRule.Problem(warningPercent, warningWindow, alertPercent, alertWindow);
        if (problem == null)
            Assert.Null(found);
        else
            Assert.Contains(problem, found);
    }

    private static CertProfileEntity Profile(int? warning = null, string? warningWindow = null, int? alert = null, string? alertWindow = null,
        bool neverWarn = false, bool overrides = false, bool isCa = false) => new()
    {
        Name = Guid.NewGuid().ToString("N"), IsCaProfile = isCa,
        ExpiryWarningPercent = warning, ExpiryWarningMaxWindow = warningWindow,
        ExpiryAlertPercent = alert, ExpiryAlertMaxWindow = alertWindow,
        ExpiryNeverWarn = neverWarn, ExpiryWarningOverridesParent = overrides,
    };

    [Fact]
    public void A_child_that_sets_nothing_inherits_every_value()
    {
        var sources = new Dictionary<string, string>();
        var merged = ExpiryWarningRule.Merge(Profile(), Profile(40, "P60D", 15, "P10D"), sources);

        Assert.Equal(new ExpiryWarningSettings(40, "P60D", 15, "P10D"), merged);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryAlertPercent)]);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);
    }

    [Fact]
    public void A_child_may_warn_earlier_but_a_later_warning_is_clamped_to_the_parent()
    {
        var clamps = new List<string>();
        var sources = new Dictionary<string, string>();
        var merged = ExpiryWarningRule.Merge(
            Profile(warning: 50, warningWindow: "P10D", alert: 5, alertWindow: "P20D", neverWarn: true),
            Profile(warning: 40, warningWindow: "P30D", alertWindow: "P5D"),
            sources, (field, _, _) => clamps.Add(field));

        Assert.Equal(new ExpiryWarningSettings(50, "P30D", null, "P20D", false), merged);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryAlertPercent)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryNeverWarn)]);
        Assert.Equal(
            new[] { nameof(CertProfileEntity.ExpiryAlertPercent), nameof(CertProfileEntity.ExpiryNeverWarn), nameof(CertProfileEntity.ExpiryWarningMaxWindow) },
            clamps.Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void Against_a_parent_with_no_settings_the_defaults_bind_and_a_cap_is_clamped_away()
    {
        var sources = new Dictionary<string, string>();
        var merged = ExpiryWarningRule.Merge(Profile(warning: 20, warningWindow: "P90D", alert: 10), Profile(), sources);

        Assert.Equal(new ExpiryWarningSettings(null, null, 10, null), merged);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryAlertPercent)]);
    }

    [Fact]
    public void Never_warn_is_kept_only_when_the_parent_never_warns_too()
    {
        var sources = new Dictionary<string, string>();
        Assert.True(ExpiryWarningRule.Merge(Profile(neverWarn: true), Profile(neverWarn: true), sources).NeverWarn);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryNeverWarn)]);

        // A child of a never-warn parent may warn: that is stricter.
        Assert.False(ExpiryWarningRule.Merge(Profile(), Profile(neverWarn: true), sources).NeverWarn);
    }

    [Fact]
    public void A_child_that_overrides_keeps_its_own_values_unclamped_and_inherits_the_rest()
    {
        var clamps = 0;
        var sources = new Dictionary<string, string>();
        var merged = ExpiryWarningRule.Merge(
            Profile(warning: 5, warningWindow: "PT6H", neverWarn: true, overrides: true),
            Profile(warning: 40, alert: 15, alertWindow: "P3D"),
            sources, (_, _, _) => clamps++);

        Assert.Equal(new ExpiryWarningSettings(5, "PT6H", 15, "P3D", true), merged);
        Assert.Equal(0, clamps);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryWarningPercent)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryAlertPercent)]);
        Assert.Equal("inherited", sources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryNeverWarn)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryWarningOverridesParent)]);
    }

    [Fact]
    public void A_ca_child_may_warn_earlier_than_the_ca_default_its_parent_falls_back_to()
    {
        // A CA parent that sets nothing warns 30 days and alerts 7 days before expiry. Longer
        // windows on the child warn earlier and are kept; shorter ones are clamped away.
        var clamps = new List<(string Field, string? Used)>();
        var sources = new Dictionary<string, string>();
        var merged = ExpiryWarningRule.Merge(
            Profile(warningWindow: "P180D", alertWindow: "P14D", isCa: true), Profile(isCa: true),
            sources, (field, _, used) => clamps.Add((field, used)));

        Assert.Equal(new ExpiryWarningSettings(null, "P180D", null, "P14D"), merged);
        Assert.Empty(clamps);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);
        Assert.Equal((TimeSpan.FromDays(180), TimeSpan.FromDays(14)), Before(TimeSpan.FromDays(3650), isCa: true, merged));

        merged = ExpiryWarningRule.Merge(
            Profile(warningWindow: "P20D", alertWindow: "P3D", isCa: true), Profile(isCa: true),
            sources, (field, _, used) => clamps.Add((field, used)));
        Assert.Equal(ExpiryWarningSettings.None, merged);
        Assert.Equal(
            new[] { (nameof(CertProfileEntity.ExpiryWarningMaxWindow), (string?)"P30D (CA default)"), (nameof(CertProfileEntity.ExpiryAlertMaxWindow), "P7D (CA default)") },
            clamps.ToArray());
        Assert.Equal((TimeSpan.FromDays(30), TimeSpan.FromDays(7)), Before(TimeSpan.FromDays(3650), isCa: true, merged));
    }

    [Fact]
    public void The_ca_default_binds_only_a_level_the_parent_leaves_unset_and_only_between_ca_profiles()
    {
        var sources = new Dictionary<string, string>();

        // The parent sets a warning percent with no cap: any cap on the child warns later.
        var capped = ExpiryWarningRule.Merge(Profile(warningWindow: "P180D", alertWindow: "P14D", isCa: true), Profile(warning: 40, isCa: true), sources);
        Assert.Equal(new ExpiryWarningSettings(40, null, null, "P14D"), capped);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
        Assert.Equal("overridden", sources[nameof(CertProfileEntity.ExpiryAlertMaxWindow)]);

        // End-entity profiles have no CA default: a parent with no settings has no cap.
        var leaf = ExpiryWarningRule.Merge(Profile(warningWindow: "P180D"), Profile(), sources);
        Assert.Null(leaf.WarningMaxWindow);
        Assert.Equal("clamped", sources[nameof(CertProfileEntity.ExpiryWarningMaxWindow)]);
    }
}
