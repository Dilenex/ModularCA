using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="ConfigInputRules"/>, the save-time checks on list-valued settings
/// (PUT /admin/config/http, /email, /cert-expiry-notifications and the notification preferences).
/// </summary>
public class ConfigInputRulesTests
{
    [Fact]
    public void Warning_days_must_each_be_from_1_to_3650()
    {
        Assert.Null(ConfigInputRules.WarningDaysError(null));
        Assert.Null(ConfigInputRules.WarningDaysError(new[] { 90, 30, 1, 3650 }));
        Assert.Null(ConfigInputRules.WarningDaysError(Array.Empty<int>()));
        Assert.Contains("0, -5", ConfigInputRules.WarningDaysError(new[] { 30, 0, -5 }));
        Assert.NotNull(ConfigInputRules.WarningDaysError(new[] { 3651 }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ops@example.com")]
    [InlineData("ops@example.com, sec@example.com,")]
    public void Accepts_empty_or_valid_recipient_lists(string? csv)
        => Assert.Null(ConfigInputRules.EmailListError(csv, "AdminRecipients"));

    [Fact]
    public void Names_the_invalid_recipients()
    {
        var error = ConfigInputRules.EmailListError("ops@example.com, not-an-address", "Recipients");
        Assert.NotNull(error);
        Assert.Contains("not-an-address", error);
        Assert.DoesNotContain("ops@example.com", error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://app.example.com")]
    [InlineData("https://app.example.com:8443, http://localhost:5173, http://127.0.0.1:3000, http://[::1]:3000")]
    public void Accepts_bare_https_origins_and_local_http(string? csv)
        => Assert.Null(ConfigInputRules.CorsOriginsError(csv, requireBareOrigin: true));

    [Theory]
    [InlineData("*", "Wildcard")]
    [InlineData("app.example.com", "absolute URL")]
    [InlineData("http://app.example.com", "https")]
    [InlineData("https://app.example.com/", "no path")]
    [InlineData("https://app.example.com/api", "no path")]
    [InlineData("https://ok.example.com, ftp://files.example.com", "https")]
    public void Refuses_origins_the_server_cannot_use(string csv, string expected)
    {
        var error = ConfigInputRules.CorsOriginsError(csv, requireBareOrigin: true);
        Assert.NotNull(error);
        Assert.Contains(expected, error);
    }

    [Fact]
    public void Startup_keeps_accepting_an_origin_with_a_path()
    {
        Assert.Null(ConfigInputRules.CorsOriginsError("https://app.example.com/", requireBareOrigin: false));
        Assert.NotNull(ConfigInputRules.CorsOriginsError("http://app.example.com", requireBareOrigin: false));
    }

    [Fact]
    public void The_allowed_origins_are_the_list_split_as_startup_splits_it()
    {
        Assert.Equal(
            ["https://app.example.com", "http://localhost:5173"],
            ConfigInputRules.CorsOriginsAllowed(" https://app.example.com ,, http://localhost:5173 "));
        Assert.Equal(["https://app.example.com/"], ConfigInputRules.CorsOriginsAllowed("https://app.example.com/"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("*")]
    [InlineData("https://app.example.com, *")]
    [InlineData("https://app.example.com, http://app.example.com")]
    public void A_blank_list_or_one_startup_would_refuse_allows_no_origin(string? csv)
        => Assert.Empty(ConfigInputRules.CorsOriginsAllowed(csv));

    private static IEnumerable<object[]> SunsetCases(string key)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var path = Path.Combine(dir!.FullName, "tests", "modularca.web.tests", "src", "adminui", "sunset-rule-cases.json");
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty(key).EnumerateArray().Select(e => new object[] { e.GetString()! }).ToList();
    }

    public static IEnumerable<object[]> AcceptedSunsetRules => SunsetCases("accept");
    public static IEnumerable<object[]> RefusedSunsetRules => SunsetCases("reject");

    /// <summary>The sunset-rule grammar the console's row editor applies too (sunset-rule-cases.json).</summary>
    [Theory, MemberData(nameof(AcceptedSunsetRules))]
    public void Accepts_the_shared_valid_sunset_rules(string rule) => Assert.Null(ConfigInputRules.AlgorithmSunsetRuleError(rule));

    [Theory, MemberData(nameof(RefusedSunsetRules))]
    public void Refuses_the_shared_invalid_sunset_rules(string rule) => Assert.NotNull(ConfigInputRules.AlgorithmSunsetRuleError(rule));

    [Fact]
    public void A_sunset_rule_list_reports_the_first_bad_rule_and_accepts_null()
    {
        Assert.Null(ConfigInputRules.AlgorithmSunsetRulesError(null));
        Assert.Null(ConfigInputRules.AlgorithmSunsetRulesError(new[] { "RSA-2048:2030-01-01" }));
        Assert.Contains("2030/01/01", ConfigInputRules.AlgorithmSunsetRulesError(new[] { "RSA-2048:2030-01-01", "RSA:2030/01/01" }));
    }
}
