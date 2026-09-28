using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Where <c>StartModularCA</c> runs the startup schema check: before the first read of either
/// database, for every role that reads one, the ingress included.
/// </summary>
public class SchemaStartupOrderTests
{
    private static readonly string Startup = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "StartModularCA.cs"));

    private static int Gate => Startup.IndexOf("SchemaStartup.EnforceAllAsync(", StringComparison.Ordinal);

    [Theory]
    [InlineData("\"FeatureFlags\"")]
    [InlineData("SignerBootstrap.Unlock(")]
    [InlineData("signerBootstrap.AddHsmSigners(")]
    [InlineData("using var anchorDb = new ModularCADbContext(")]
    [InlineData("estTrustAnchors.LoadNow()")]
    [InlineData("using var cmpDb = new ModularCADbContext(")]
    [InlineData("var app = builder.Build();")]
    public void The_schema_check_runs_before_this_read_of_the_database(string read)
    {
        Assert.True(Gate > 0, "StartModularCA no longer calls SchemaStartup.EnforceAllAsync.");
        Assert.Single(AllIndexes("SchemaStartup.EnforceAllAsync("));
        var at = Startup.IndexOf(read, StringComparison.Ordinal);
        Assert.True(at > 0, $"'{read}' is no longer in StartModularCA.");
        Assert.True(Gate < at, $"'{read}' runs before the schema check.");
    }

    [Fact]
    public void The_schema_check_runs_after_the_process_roles_are_resolved_and_the_signer_role_has_left()
    {
        Assert.True(Startup.IndexOf("var ingressOnly =", StringComparison.Ordinal) < Gate);
        Assert.True(Startup.IndexOf("SignerRole.RunAsync(", StringComparison.Ordinal) < Gate);
    }

    [Fact]
    public void An_ingress_only_process_is_checked_against_the_application_database_and_applies_nothing()
    {
        var block = Startup[Startup.LastIndexOf("if (!isSetupMode)", Gate, StringComparison.Ordinal)..Gate];

        Assert.Contains("new(\"application\", DatabaseKind.Application, config.DB.App)", block);
        Assert.Contains("if (!ingressOnly && !string.IsNullOrWhiteSpace(config.DB.Audit.Database))", block);
        Assert.DoesNotContain("!isSetupMode && !ingressOnly)", block);
        Assert.Contains("schemaTargets, controlActive, config.Schema,", Startup[Gate..(Gate + 200)]);
        Assert.DoesNotContain("reads no database", Startup);
    }

    /// <summary>Every index of <paramref name="text"/> in the startup source.</summary>
    private static List<int> AllIndexes(string text)
    {
        var found = new List<int>();
        for (var i = Startup.IndexOf(text, StringComparison.Ordinal); i >= 0; i = Startup.IndexOf(text, i + 1, StringComparison.Ordinal))
            found.Add(i);
        return found;
    }

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
