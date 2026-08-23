using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Holds the two bootstrap paths to the same seeding.
/// <para>
/// ModularCA can be installed two ways — the CLI (<c>BootstrapModularCA</c>) and the setup
/// wizard (<c>BootstrapService</c>) — and they seed the database independently. They had drifted
/// by exactly one call: the wizard seeded IP whitelists and the CLI did not. That is not a
/// cosmetic difference. With no whitelist rows, <c>WhitelistService</c> finds no rule for any
/// bucket and every request resolves to <c>NotCovered</c>, which passes through, so a
/// CLI-installed instance exposed its admin surface to every source address while a
/// wizard-installed one restricted it to internal networks. Same product, same version,
/// different security posture depending on how it was installed.
/// </para>
/// <para>
/// A one-call divergence is invisible in review — the lists are long and nearly identical — so
/// it is checked mechanically here instead. This is a source-text test, in the same spirit as
/// <c>scripts/wire_contract.py</c>: the property worth protecting is a relationship between two
/// files, which no runtime assertion can see.
/// </para>
/// </summary>
public class BootstrapSeedingParityTests
{
    private static readonly Regex SeedCall =
        new(@"BootstrapProfileSeeder\.(Seed\w+)", RegexOptions.Compiled);

    /// <summary>
    /// Walks up from the test assembly to the directory holding the solution file, so the test
    /// does not depend on the build output layout.
    /// </summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static HashSet<string> SeedCallsIn(string relativePath)
    {
        var path = Path.Combine(RepoRoot(), relativePath);
        Assert.True(File.Exists(path), $"expected source file at {path}");
        var text = File.ReadAllText(path);

        return SeedCall.Matches(text)
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);
    }

    [Fact]
    public void Cli_and_wizard_bootstrap_seed_the_same_set()
    {
        var cli = SeedCallsIn(Path.Combine("ModularCA.Bootstrap", "BootstrapModularCA.cs"));
        var wizard = SeedCallsIn(Path.Combine("ModularCA.Bootstrap", "BootstrapService.cs"));

        // Sanity: if the extraction stops matching, this test would pass vacuously.
        Assert.True(cli.Count >= 10, $"only found {cli.Count} seeder calls in the CLI path — extraction is broken");
        Assert.True(wizard.Count >= 10, $"only found {wizard.Count} seeder calls in the wizard path — extraction is broken");

        var missingFromCli = wizard.Except(cli).OrderBy(x => x).ToList();
        var missingFromWizard = cli.Except(wizard).OrderBy(x => x).ToList();

        Assert.True(
            missingFromCli.Count == 0 && missingFromWizard.Count == 0,
            $"Bootstrap paths have drifted.{Environment.NewLine}" +
            $"  Seeded by the wizard but not the CLI: {Format(missingFromCli)}{Environment.NewLine}" +
            $"  Seeded by the CLI but not the wizard: {Format(missingFromWizard)}{Environment.NewLine}" +
            "If the difference is deliberate, say so here rather than deleting the test — the " +
            "whole point is that a one-call gap is invisible in review.");
    }

    [Fact]
    public void Both_paths_seed_ip_whitelists()
    {
        // Named explicitly because this is the one that was missing, and because its absence
        // fails open rather than closed.
        Assert.Contains("SeedWhitelists", SeedCallsIn(Path.Combine("ModularCA.Bootstrap", "BootstrapModularCA.cs")));
        Assert.Contains("SeedWhitelists", SeedCallsIn(Path.Combine("ModularCA.Bootstrap", "BootstrapService.cs")));
    }

    private static string Format(IReadOnlyCollection<string> items)
        => items.Count == 0 ? "(none)" : string.Join(", ", items);
}
