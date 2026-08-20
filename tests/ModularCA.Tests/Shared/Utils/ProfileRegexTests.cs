using System.Diagnostics;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="ProfileRegex"/>, the bounded-time matcher for operator-authored profile
/// patterns. The contract under test is that hostile or broken input can never buy an issuance:
/// anything other than a completed, successful match is a refusal.
/// </summary>
public class ProfileRegexTests
{
    [Theory]
    [InlineData(@"^[a-z]+\.example\.com$", "host.example.com")]
    [InlineData(@"^\d{3}$", "123")]
    public void Reports_Match_for_values_the_pattern_accepts(string pattern, string input)
        => Assert.Equal(ProfileRegexOutcome.Match, ProfileRegex.Evaluate(input, pattern));

    [Theory]
    [InlineData(@"^[a-z]+\.example\.com$", "host.evil.com")]
    [InlineData(@"^\d{3}$", "12")]
    public void Reports_NoMatch_for_values_the_pattern_rejects(string pattern, string input)
        => Assert.Equal(ProfileRegexOutcome.NoMatch, ProfileRegex.Evaluate(input, pattern));

    [Theory]
    [InlineData("(unclosed")]
    [InlineData(@"[z-a]")]
    [InlineData("*invalid")]
    public void Reports_InvalidPattern_for_patterns_that_do_not_compile(string pattern)
        => Assert.Equal(ProfileRegexOutcome.InvalidPattern, ProfileRegex.Evaluate("anything", pattern));

    [Fact]
    public void An_uncompilable_pattern_is_not_a_match()
    {
        // The bug this replaced did `catch { status = "valid"; }` — a profile whose regex did not
        // compile authorised every value put through it.
        Assert.False(ProfileRegex.IsMatch("anything at all", "(unclosed"));
    }

    [Fact]
    public void Catastrophic_backtracking_times_out_instead_of_hanging()
    {
        // The canonical ReDoS shape: nested quantifiers with a failing tail forces the backtracking
        // engine through exponentially many paths. Under the old static Regex.IsMatch overload
        // (InfiniteMatchTimeout) this pins a core indefinitely.
        const string evil = @"^(a+)+$";
        var input = new string('a', 40) + "!";

        var sw = Stopwatch.StartNew();
        var outcome = ProfileRegex.Evaluate(input, evil);
        sw.Stop();

        Assert.Equal(ProfileRegexOutcome.Timeout, outcome);

        // Generous bound: asserts the budget is enforced at all, without being flaky on a loaded
        // CI box. The point is "bounded", not "exactly 100ms".
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
            $"Match should have been abandoned at the timeout, but took {sw.Elapsed}.");
    }

    [Fact]
    public void A_timed_out_match_is_not_a_match()
    {
        // The security-critical assertion: a hostile input must not gain an issuance by making the
        // validator give up.
        Assert.False(ProfileRegex.IsMatch(new string('a', 40) + "!", @"^(a+)+$"));
    }

    [Theory]
    [InlineData(null, @"^\d+$")]
    [InlineData("123", null)]
    [InlineData("123", "")]
    public void Missing_input_or_pattern_never_reports_a_match(string? input, string? pattern)
        => Assert.NotEqual(ProfileRegexOutcome.Match, ProfileRegex.Evaluate(input, pattern));

    [Fact]
    public void The_timeout_budget_is_bounded_and_positive()
    {
        Assert.True(ProfileRegex.MatchTimeout > TimeSpan.Zero);
        Assert.True(ProfileRegex.MatchTimeout <= TimeSpan.FromSeconds(1),
            "A profile-pattern budget above a second would make ReDoS a usable stall even so.");
    }
}
