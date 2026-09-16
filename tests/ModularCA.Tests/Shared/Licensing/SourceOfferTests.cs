using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Licensing;

/// <summary>
/// Guards the AGPL section 13 source-code offer.
/// </summary>
/// <remarks>
/// Section 13 obliges anyone who modifies ModularCA and serves it over a network to offer those
/// users the Corresponding Source of their version. The product's part is to make that offer easy
/// to render and easy to point somewhere correct. The failure mode worth testing for is not a
/// crash — it is a notice that renders but silently offers nothing, which looks fine on the page
/// and satisfies nobody.
/// </remarks>
public class SourceOfferTests
{
    [Fact]
    public void The_default_source_url_is_not_blank()
    {
        // A blank URL renders a footer whose link goes nowhere. Nobody reviewing the page would
        // notice, because the words are still there.
        Assert.False(string.IsNullOrWhiteSpace(SourceCodeConfig.UpstreamUrl));
        Assert.False(string.IsNullOrWhiteSpace(new SourceCodeConfig().Url));
        Assert.StartsWith("https://", new SourceCodeConfig().EffectiveUrl, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Clearing_the_url_falls_back_to_upstream_rather_than_nothing(string? configured)
    {
        // Wrong for a modified build, but a visible statement someone can correct. An empty
        // string is not correctable, because it is not visible.
        var config = new SourceCodeConfig { Url = configured! };

        Assert.Equal(SourceCodeConfig.UpstreamUrl, config.EffectiveUrl);
    }

    [Fact]
    public void An_operator_supplied_url_is_used_and_trimmed()
    {
        // The point of the whole feature: an operator who modified the software points this at
        // their own published source, and that is their compliance step.
        var config = new SourceCodeConfig { Url = "  https://git.example.test/msp/modularca  " };

        Assert.Equal("https://git.example.test/msp/modularca", config.EffectiveUrl);
    }

    [Fact]
    public void The_declared_licence_matches_the_repository_licence_file()
    {
        // If the LICENSE file is ever swapped again, the default SPDX identifier rendered in
        // every SPA's footer must not be left describing the previous licence.
        var licenseText = File.ReadAllText(Path.Combine(RepoRoot(), "LICENSE"));

        Assert.Equal("AGPL-3.0-only", new SourceCodeConfig().License);
        Assert.Contains("GNU AFFERO GENERAL PUBLIC LICENSE", licenseText, StringComparison.Ordinal);
        Assert.Contains("Version 3, 19 November 2007", licenseText, StringComparison.Ordinal);
    }

    [Fact]
    public void The_shared_notice_is_rendered_by_every_spa()
    {
        // Section 13 says "all users interacting with it remotely". publicui is the load-bearing
        // one — it is the only surface an unauthenticated remote user reaches — but a later
        // refactor that drops the component from a layout would remove the offer silently, and
        // nothing else in the build would complain.
        var root = RepoRoot();
        var layouts = new[]
        {
            Path.Combine("modularca.publicui", "src", "components", "Layout.tsx"),
            Path.Combine("modularca.adminui", "src", "components", "Layout.tsx"),
            Path.Combine("modularca.docsui", "src", "App.tsx"),
            Path.Combine("modularca.setupui", "src", "App.tsx"),
        };

        foreach (var relative in layouts)
        {
            var path = Path.Combine(root, relative);
            Assert.True(File.Exists(path), $"expected {relative} to exist");

            var source = File.ReadAllText(path);
            Assert.Contains("<SourceNotice", source, StringComparison.Ordinal);
            Assert.Contains("@shared/components/SourceNotice", source, StringComparison.Ordinal);
        }
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
