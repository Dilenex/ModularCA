using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Setup asks whether more than one person will administer the CA. "Just me" starts key
/// ceremonies off for the instance policy and the first space, "several" starts them on, and an
/// unattended bootstrap whose bootstrap.yaml does not say keeps them on. The answer is audited.
/// </summary>
public class BootstrapAdministratorChoiceTests : IDisposable
{
    private readonly string _logs = Path.Combine(Path.GetTempPath(), $"mca-bootstrap-audit-{Guid.NewGuid():N}");

    public BootstrapAdministratorChoiceTests() => BootstrapAuditLog.LogDirectory = _logs;

    public void Dispose()
    {
        BootstrapAuditLog.LogDirectory = null;
        if (Directory.Exists(_logs))
            Directory.Delete(_logs, recursive: true);
    }

    private static (ModularCADbContext Db, SpaceEntity Space) Seeded()
    {
        var db = InMemoryDbContextFactory.Create();
        var space = BootstrapModularCA.EnsureBootstrapSpaces(db, "Acme Corp", null);
        BootstrapProfileSeeder.SeedSecurityPolicy(db);
        return (db, space);
    }

    private string[] AuditLines()
        => Directory.Exists(_logs)
            ? Directory.GetFiles(_logs, "bootstrap-audit-*.jsonl").SelectMany(File.ReadAllLines).Where(l => l.Contains("MultipleAdministrators")).ToArray()
            : [];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_answer_sets_the_requirement_for_the_instance_and_the_first_space(bool severalAdministrators)
    {
        var (db, space) = Seeded();
        using (db)
        {
            Assert.Equal(severalAdministrators, BootstrapModularCA.ApplyAdministratorChoice(db, space, severalAdministrators));

            db.ChangeTracker.Clear();
            Assert.Equal(severalAdministrators, db.SecurityPolicies.Single().RequireKeyCeremony);
            Assert.Equal(severalAdministrators, db.Spaces.Single().RequireKeyCeremony);
        }

        using var line = JsonDocument.Parse(Assert.Single(AuditLines()));
        Assert.Equal(AuditActionType.SecurityPolicyUpdated, line.RootElement.GetProperty("action").GetString());
        Assert.Equal("SecurityPolicy", line.RootElement.GetProperty("targetEntityType").GetString());
        var details = line.RootElement.GetProperty("details");
        Assert.Equal(severalAdministrators, details.GetProperty("MultipleAdministrators").GetBoolean());
        Assert.Equal(severalAdministrators, details.GetProperty("CeremoniesRequired").GetBoolean());
        Assert.Equal(!severalAdministrators, details.GetProperty("CeremonyRequirementDisabled").GetBoolean());
        Assert.Equal(space.Id, details.GetProperty("SpaceId").GetGuid());
    }

    [Fact]
    public void No_answer_keeps_key_ceremonies_on_and_audits_nothing()
    {
        var (db, space) = Seeded();
        using (db)
        {
            Assert.True(BootstrapModularCA.ApplyAdministratorChoice(db, space, null));

            db.ChangeTracker.Clear();
            Assert.True(db.SecurityPolicies.Single().RequireKeyCeremony);
            Assert.True(db.Spaces.Single().RequireKeyCeremony);
        }
        Assert.Empty(AuditLines());
    }

    /// <summary>
    /// The choice reaches the audit database: the line bootstrap writes is replayed on first start
    /// with its own target and details, none of which the audit scrubber blanks.
    /// </summary>
    [Fact]
    public async Task The_choice_is_replayed_into_the_audit_trail()
    {
        var (db, space) = Seeded();
        using (db)
            BootstrapModularCA.ApplyAdministratorChoice(db, space, false);
        var keystoreName = $"probe-{Guid.NewGuid():N}.keystore";
        BootstrapAuditLog.LogKeystoreWrite(keystoreName, AuditActionType.KeystoreKeyAdded, "CN=System Signing CA", "abcd");

        var audit = new RecordingAuditService();
        await new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance).ReplayPendingAsync(_logs);

        var choice = Assert.Single(audit.Entries, e => e.Action == AuditActionType.SecurityPolicyUpdated);
        Assert.Equal("instance", choice.TargetId);
        var scrubbed = AuditJsonScrubber.SerializeAndScrub(choice.Details);
        Assert.DoesNotContain("***", scrubbed);
        using var details = JsonDocument.Parse(scrubbed!);
        var decision = details.RootElement.GetProperty("Decision");
        Assert.False(decision.GetProperty("MultipleAdministrators").GetBoolean());
        Assert.True(decision.GetProperty("CeremonyRequirementDisabled").GetBoolean());
        Assert.True(details.RootElement.GetProperty("ReplayedFromBootstrap").GetBoolean());

        Assert.Single(audit.Entries, e => e.Action == AuditActionType.KeystoreKeyAdded && e.TargetId == keystoreName);
        Assert.Single(Directory.GetFiles(_logs, "*.replayed"));
    }

    [Theory]
    [InlineData("Administration:\n  MultipleAdministrators: false\n", false)]
    [InlineData("Administration:\n  MultipleAdministrators: true\n", true)]
    [InlineData("", null)]
    [InlineData("Administration: {}\n", null)]
    public void Bootstrap_yaml_carries_the_answer_and_may_leave_it_out(string section, bool? expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, "CA:\n  Subject:\n    CN: \"Test Root\"\n" + section);
        try
        {
            Assert.Equal(expected, YamlBootstrapLoader.Load(path).Administration.MultipleAdministrators);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("config/bootstrap.yaml.example")]
    [InlineData("ModularCA.Bootstrap/bootstrap.yaml.example")]
    public void The_example_states_the_key_and_keeps_the_default(string relative)
    {
        var path = Path.Combine(RepoRoot(), relative.Replace('/', Path.DirectorySeparatorChar));
        Assert.Contains("MultipleAdministrators:", File.ReadAllText(path));
        Assert.True(YamlBootstrapLoader.Load(path).Administration.MultipleAdministrators);
    }

    /// <summary>Both bootstrap paths apply the answer, after they seed the security policy.</summary>
    [Theory]
    [InlineData("BootstrapModularCA.cs", "bootstrapConfig.Administration?.MultipleAdministrators")]
    [InlineData("BootstrapService.cs", "request.Admin?.MultipleAdministrators")]
    public void Both_bootstrap_paths_apply_the_answer(string file, string source)
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.Bootstrap", file));
        var seeded = text.IndexOf("BootstrapProfileSeeder.SeedSecurityPolicy(", StringComparison.Ordinal);
        var applied = text.IndexOf("ApplyAdministratorChoice(dbContext, orgSpace, " + source + ")", StringComparison.Ordinal);
        Assert.True(seeded > 0 && applied > seeded, $"{file} must call ApplyAdministratorChoice with {source} after seeding the security policy.");
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
