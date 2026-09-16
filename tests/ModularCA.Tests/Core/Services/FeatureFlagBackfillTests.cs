using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins what an upgraded instance receives for flags it was bootstrapped without: the row appears,
/// disabled, and nothing the operator already set is touched.
/// </summary>
/// <remarks>
/// The defect this guards: a staging host upgraded to the first MSAE build showed MSAE on the
/// per-CA protocol page but had no flag on the settings page, so the path gate refused every
/// request and there was no supported way to change that.
/// </remarks>
public class FeatureFlagBackfillTests
{
    [Fact]
    public async Task A_missing_flag_is_added_disabled()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.FeatureFlags.Add(new FeatureFlagEntity { Name = "EST.Enabled", Enabled = true });
        await db.SaveChangesAsync();

        var added = await FeatureFlagBackfill.EnsureAsync(db);

        Assert.Equal(["MSAE.Enabled"], added);
        var msae = Assert.Single(db.FeatureFlags, f => f.Name == "MSAE.Enabled");
        Assert.False(msae.Enabled);
        Assert.False(string.IsNullOrWhiteSpace(msae.Description));
    }

    [Fact]
    public async Task An_existing_flag_keeps_the_operators_setting()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.FeatureFlags.Add(new FeatureFlagEntity { Name = "MSAE.Enabled", Enabled = true, Description = "operator wrote this" });
        await db.SaveChangesAsync();

        var added = await FeatureFlagBackfill.EnsureAsync(db);

        Assert.Empty(added);
        var msae = Assert.Single(db.FeatureFlags);
        Assert.True(msae.Enabled);
        Assert.Equal("operator wrote this", msae.Description);
    }

    [Fact]
    public async Task Running_twice_adds_nothing_the_second_time()
    {
        using var db = InMemoryDbContextFactory.Create();
        Assert.NotEmpty(await FeatureFlagBackfill.EnsureAsync(db));
        Assert.Empty(await FeatureFlagBackfill.EnsureAsync(db));
        Assert.Equal(FeatureFlagBackfill.IntroducedFlags.Count, db.FeatureFlags.Count());
    }

    [Fact]
    public void No_introduced_flag_is_enabled_by_default()
    {
        // An upgrade makes a capability available; it never switches one on.
        Assert.All(FeatureFlagBackfill.IntroducedFlags, f => Assert.False(f.Enabled, $"{f.Name} would be enabled by upgrade"));
    }
}
