using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// <see cref="MigrationCheckLabels"/> matches the migration sources: for every migration of both
/// contexts, each <c>FailIf</c> or <c>RAISE EXCEPTION</c> in its <c>Up</c> takes the label of the
/// <c>// P1</c> or <c>// 7</c> comment before it, the table holds exactly those labels, and the
/// migration generates one raising command per raising site, so the dry run names the right check.
/// </summary>
public class MigrationCheckLabelsTests
{
    private static readonly Regex Site = new(
        @"^\s*//\s*(?<label>P\d+|\d+)\s*$|(?<raise>\.FailIf\(|RAISE EXCEPTION)", RegexOptions.Multiline | RegexOptions.CultureInvariant);

    [Theory]
    [InlineData("application")]
    [InlineData("audit")]
    public void The_table_holds_each_migrations_check_labels_as_its_source_gives_them(string context)
    {
        using var db = context == "application"
            ? (DbContext)new ModularCADbContextFactory().CreateDbContext([])
            : new AuditDbContextFactory().CreateDbContext([]);
        var folder = Path.Combine(RepoRoot(), "ModularCA.Database", "Migrations");
        if (context == "audit")
            folder = Path.Combine(folder, "Audit");

        var problems = new List<string>();
        foreach (var id in db.GetService<IMigrationsAssembly>().Migrations.Keys)
        {
            var path = Path.Combine(folder, id + ".cs");
            Assert.True(File.Exists(path), $"{path} is missing");
            var source = File.ReadAllText(path);
            var up = source.IndexOf("protected override void Up(", StringComparison.Ordinal);
            var down = source.IndexOf("protected override void Down(", up, StringComparison.Ordinal);
            var labels = new List<string?>();
            string? label = null;
            foreach (Match m in Site.Matches(source[up..(down < 0 ? source.Length : down)]))
            {
                if (m.Groups["label"].Success)
                    label = m.Groups["label"].Value;
                else
                    labels.Add(label);
            }

            var raising = SchemaVersionGate.UpCommands(db, id).Count(c => MigrationCheckLabels.Raises(c.CommandText));
            if (raising != labels.Count)
                problems.Add($"{id}: {labels.Count} raising site(s) in the source, {raising} raising command(s) generated");

            var expected = labels.Any(l => l is not null) ? labels : null;
            var actual = MigrationCheckLabels.Labels.TryGetValue(id, out var held) ? held.ToList() : null;
            if (expected is null != actual is null || (expected is not null && !expected.SequenceEqual(actual!)))
                problems.Add($"{id}: the source labels its checks [{Show(expected)}]; MigrationCheckLabels holds [{Show(actual)}]");
        }
        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void Every_labelled_migration_exists()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var migrations = db.GetService<IMigrationsAssembly>().Migrations.Keys.ToHashSet(StringComparer.Ordinal);
        Assert.All(MigrationCheckLabels.Labels.Keys, id => Assert.Contains(id, migrations));
    }

    /// <summary>The labels, or "none".</summary>
    private static string Show(IEnumerable<string?>? labels) =>
        labels is null ? "none" : string.Join(", ", labels.Select(l => l ?? "(unlabelled)"));

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
