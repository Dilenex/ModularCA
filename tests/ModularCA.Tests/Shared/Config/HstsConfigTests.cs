using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Config;

/// <summary>
/// The header the HSTS settings give, in the spelling ASP.NET Core's HSTS middleware wrote
/// before the header was built from the settings on every request.
/// </summary>
public class HstsConfigTests
{
    [Theory]
    [InlineData(31536000, true, false, "max-age=31536000; includeSubDomains")]
    [InlineData(86400, false, false, "max-age=86400")]
    [InlineData(63072000, true, true, "max-age=63072000; includeSubDomains; preload")]
    [InlineData(300, false, true, "max-age=300; preload")]
    [InlineData(0, true, false, "max-age=0; includeSubDomains")]
    [InlineData(-5, false, false, "max-age=0")]
    public void The_header_carries_the_max_age_and_the_directives_that_are_set(int maxAge, bool subDomains, bool preload, string expected)
    {
        var hsts = new HstsConfig { MaxAgeSeconds = maxAge, IncludeSubDomains = subDomains, Preload = preload };

        Assert.Equal(expected, hsts.HeaderValue());
    }

    [Fact]
    public void The_default_is_a_year_with_subdomains_and_no_preload()
        => Assert.Equal("max-age=31536000; includeSubDomains", new HstsConfig().HeaderValue());
}
