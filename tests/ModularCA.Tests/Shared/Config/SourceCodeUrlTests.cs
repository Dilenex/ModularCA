using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Config;

/// <summary>
/// Pins how the AGPL section 13 source offer resolves, including for installs carrying a URL from
/// an older build.
/// </summary>
/// <remarks>
/// <para>
/// The GitHub organisation was renamed. Changing <see cref="SourceCodeConfig.UpstreamUrl"/> fixed
/// new installs and reached no existing one: <c>Url</c> is written into <c>config.yaml</c> at
/// bootstrap and the persisted value wins over the compiled default, so a deployed CA kept
/// publishing the old repository name — resolving only because the forge still redirects it.
/// Section 13 obliges an accurate offer, not one that happens to work today.
/// </para>
/// <para>
/// The risk in repairing that is overreach. An operator who modified ModularCA and pointed the
/// offer at their own published fork is the one person whose compliance depends on this field, and
/// silently rewriting it would break exactly them. Matching only the exact strings this project has
/// shipped is what separates "a default nobody chose" from "a decision somebody made".
/// </para>
/// </remarks>
public class SourceCodeUrlTests
{
    [Fact]
    public void An_unset_url_falls_back_to_upstream()
    {
        Assert.Equal(SourceCodeConfig.UpstreamUrl, new SourceCodeConfig { Url = "" }.EffectiveUrl);
        Assert.Equal(SourceCodeConfig.UpstreamUrl, new SourceCodeConfig { Url = "   " }.EffectiveUrl);
    }

    [Fact]
    public void The_default_is_the_current_upstream()
    {
        Assert.Equal(SourceCodeConfig.UpstreamUrl, new SourceCodeConfig().EffectiveUrl);
        Assert.Contains("Dilenex", SourceCodeConfig.UpstreamUrl, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://github.com/Ephemeral-Intel/ModularCA")]
    [InlineData("https://github.com/Ephemeral-Intel/ModularCA/")]
    [InlineData("https://github.com/ephemeral-intel/modularca")]
    [InlineData("  https://github.com/Ephemeral-Intel/ModularCA  ")]
    public void A_superseded_default_resolves_to_the_current_upstream(string persisted)
    {
        // The exact value found on a live deployment, plus the spellings a hand-edit or a
        // round-trip through YAML can produce. None of them was chosen by anyone.
        Assert.Equal(SourceCodeConfig.UpstreamUrl, new SourceCodeConfig { Url = persisted }.EffectiveUrl);
    }

    [Theory]
    [InlineData("https://github.com/acme-corp/ModularCA")]
    [InlineData("https://git.example.internal/pki/modularca")]
    [InlineData("https://github.com/Ephemeral-Intel/ModularCA-fork")]
    [InlineData("https://github.com/Ephemeral-Intel/SomethingElse")]
    public void An_operator_chosen_url_is_left_alone(string chosen)
    {
        // Including two near-misses on the superseded name. A prefix or substring match here would
        // hijack the source offer of a fork whose owner did everything right.
        Assert.Equal(chosen, new SourceCodeConfig { Url = chosen }.EffectiveUrl);
    }

    [Fact]
    public void Whitespace_around_a_chosen_url_is_trimmed_but_the_value_is_kept()
    {
        Assert.Equal("https://example.test/src", new SourceCodeConfig { Url = "  https://example.test/src  " }.EffectiveUrl);
    }

    [Fact]
    public void The_current_upstream_is_not_listed_as_superseded()
    {
        // Adding the live default to that list would make EffectiveUrl rewrite it to itself
        // forever — harmless today, and a trap the moment the name changes again.
        Assert.DoesNotContain(SourceCodeConfig.UpstreamUrl, SourceCodeConfig.SupersededUpstreamUrls);
    }

    [Fact]
    public void The_offer_is_never_empty()
    {
        // A blank source URL renders a footer that silently offers nothing, which is the one
        // failure mode nobody notices by looking at the page.
        foreach (var candidate in new[] { "", "   ", SourceCodeConfig.UpstreamUrl, "https://x.test/s" })
            Assert.False(string.IsNullOrWhiteSpace(new SourceCodeConfig { Url = candidate }.EffectiveUrl));
    }
}
