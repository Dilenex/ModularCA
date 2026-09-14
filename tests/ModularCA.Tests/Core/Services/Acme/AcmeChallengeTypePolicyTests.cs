using ModularCA.Core.Services.Acme;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// Pins how the per-CA allowed-challenge-type setting is read, now that something reads it.
/// </summary>
public class AcmeChallengeTypePolicyTests
{
    [Theory]
    [InlineData("dns-01")]
    [InlineData("DNS-01")]
    [InlineData("[\"dns-01\"]")]
    [InlineData(" dns-01 , ")]
    public void A_single_type_in_any_of_the_accepted_forms_restricts_to_that_type(string raw)
    {
        var allowed = AcmeChallengeTypePolicy.Parse(raw);
        Assert.NotNull(allowed);
        Assert.Equal(["dns-01"], allowed);
    }

    [Fact]
    public void Multiple_types_are_all_kept_once()
    {
        var allowed = AcmeChallengeTypePolicy.Parse("http-01,dns-01,http-01");
        Assert.Equal(["http-01", "dns-01"], allowed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[]")]
    public void An_empty_setting_means_no_restriction(string? raw)
    {
        Assert.Null(AcmeChallengeTypePolicy.Parse(raw));
    }

    [Fact]
    public void Unknown_names_are_dropped_and_do_not_become_a_restriction_to_nothing()
    {
        // A typo must not silently disable enrollment on the CA.
        Assert.Null(AcmeChallengeTypePolicy.Parse("dsn-01"));
        Assert.Equal(["dns-01"], AcmeChallengeTypePolicy.Parse("dns-01,dsn-01"));
    }

    [Fact]
    public void Filtering_removes_only_types_outside_the_policy()
    {
        var offered = new[] { "http-01", "dns-01" };
        Assert.Equal(["dns-01"], AcmeChallengeTypePolicy.Filter(offered, ["dns-01"], t => t));
        Assert.Equal(offered, AcmeChallengeTypePolicy.Filter(offered, null, t => t));
    }
}
