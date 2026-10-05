using System.Text.Json;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Setup asks whether ACME clients will be on a private network. "Yes" lets the first CA's http-01
/// validator reach private addresses and is audited; "No", and an unattended bootstrap whose
/// bootstrap.yaml does not say, leave it refusing them.
/// </summary>
[Collection(BootstrapAuditLogCollection.Name)]
public class BootstrapAcmePrivateNetworkTests : IDisposable
{
    private readonly string _logs = Path.Combine(Path.GetTempPath(), $"mca-bootstrap-audit-{Guid.NewGuid():N}");

    public BootstrapAcmePrivateNetworkTests() => BootstrapAuditLog.LogDirectory = _logs;

    public void Dispose()
    {
        BootstrapAuditLog.LogDirectory = null;
        if (Directory.Exists(_logs))
            Directory.Delete(_logs, recursive: true);
    }

    private static (ModularCADbContext Db, CertificateAuthorityEntity Ca) Seeded(bool allowPrivate)
    {
        var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Test Root", Label = "test-root" };
        BootstrapProfileSeeder.SeedProtocolConfigs(
            db, ca,
            new SigningProfileEntity { Id = Guid.NewGuid() },
            new CertProfileEntity { Id = Guid.NewGuid() },
            requestProfiles: null,
            acmeAllowPrivateAddressValidation: allowPrivate);
        db.ChangeTracker.Clear();
        return (db, ca);
    }

    private string[] AuditLines()
        => Directory.Exists(_logs)
            ? Directory.GetFiles(_logs, "bootstrap-audit-*.jsonl").SelectMany(File.ReadAllLines).Where(l => l.Contains("AcmeAllowPrivateAddressValidation")).ToArray()
            : [];

    [Fact]
    public void Yes_turns_it_on_for_ACME_only_and_is_audited()
    {
        var (db, ca) = Seeded(allowPrivate: true);
        using (db)
        {
            var configs = db.CaProtocolConfigs.Where(c => c.CaId == ca.Id).ToList();
            Assert.Equal(6, configs.Count);
            Assert.True(configs.Single(c => c.Protocol == "ACME").AcmeAllowPrivateAddressValidation);
            Assert.All(configs.Where(c => c.Protocol != "ACME"), c => Assert.False(c.AcmeAllowPrivateAddressValidation));
        }

        using var line = JsonDocument.Parse(Assert.Single(AuditLines()));
        Assert.Equal(AuditActionType.ProtocolConfigUpdated, line.RootElement.GetProperty("action").GetString());
        Assert.Equal("ProtocolConfig", line.RootElement.GetProperty("targetEntityType").GetString());
        Assert.Equal($"{ca.Id}/ACME", line.RootElement.GetProperty("targetEntityId").GetString());
        var details = line.RootElement.GetProperty("details");
        Assert.True(details.GetProperty("AcmeAllowPrivateAddressValidation").GetBoolean());
        Assert.Equal(ca.Id, details.GetProperty("CaId").GetGuid());
    }

    [Fact]
    public void No_leaves_it_off_and_audits_nothing()
    {
        var (db, ca) = Seeded(allowPrivate: false);
        using (db)
            Assert.All(db.CaProtocolConfigs.Where(c => c.CaId == ca.Id), c => Assert.False(c.AcmeAllowPrivateAddressValidation));
        Assert.Empty(AuditLines());
    }

    [Theory]
    [InlineData("Acme:\n  AllowPrivateAddressValidation: true\n", true)]
    [InlineData("Acme:\n  AllowPrivateAddressValidation: false\n", false)]
    [InlineData("", false)]
    [InlineData("Acme: {}\n", false)]
    public void Bootstrap_yaml_carries_the_answer_and_may_leave_it_out(string section, bool expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, "CA:\n  Subject:\n    CN: \"Test Root\"\n" + section);
        try
        {
            Assert.Equal(expected, YamlBootstrapLoader.Load(path).Acme.AllowPrivateAddressValidation);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("config/bootstrap.yaml.example")]
    [InlineData("ModularCA.Bootstrap/bootstrap.yaml.example")]
    public void The_example_states_the_key_and_keeps_it_off(string relative)
    {
        var path = Path.Combine(RepoRoot(), relative.Replace('/', Path.DirectorySeparatorChar));
        Assert.Contains("AllowPrivateAddressValidation:", File.ReadAllText(path));
        Assert.False(YamlBootstrapLoader.Load(path).Acme.AllowPrivateAddressValidation);
    }

    [Fact]
    public void The_setup_request_carries_the_answer_and_defaults_to_no()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        Assert.False(JsonSerializer.Deserialize<SetupRequest>("{\"features\":{\"enableAcme\":true}}", options)!.Features.AcmeAllowPrivateAddressValidation);
        Assert.True(JsonSerializer.Deserialize<SetupRequest>("{\"features\":{\"enableAcme\":true,\"acmeAllowPrivateAddressValidation\":true}}", options)!.Features.AcmeAllowPrivateAddressValidation);
    }

    /// <summary>Both bootstrap paths pass the answer, and neither does unless ACME is on.</summary>
    [Theory]
    [InlineData("BootstrapModularCA.cs", "features.ACME && (bootstrapConfig.Acme?.AllowPrivateAddressValidation ?? false)")]
    [InlineData("BootstrapService.cs", "request.Features.Acme && request.Features.AcmeAllowPrivateAddressValidation")]
    public void Both_bootstrap_paths_pass_the_answer_only_when_ACME_is_on(string file, string source)
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.Bootstrap", file));
        var call = text.IndexOf("SeedProtocolConfigs(dbContext, caCertCaEntity,", StringComparison.Ordinal);
        Assert.True(call > 0, $"{file} must seed the first CA's protocol configs.");
        var end = text.IndexOf(");", call, StringComparison.Ordinal);
        Assert.Contains(source, text[call..end]);
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
