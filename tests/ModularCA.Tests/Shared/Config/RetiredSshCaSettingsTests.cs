using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Shared.Config;

/// <summary>
/// <c>SshCa.SshKeygenPath</c> and <c>SshCa.KeyStoragePath</c> are gone with the program and the
/// key files they named. An install that upgrades still has them: in the <c>config.yaml</c> every
/// earlier build wrote them into, and conceivably as a row someone put in the settings store.
/// Neither stops a start. The file's section is ignored, with a warning only for a value an
/// operator chose; a stored row is reported and left alone; and the next save of the file leaves
/// the section out.
/// </summary>
public sealed class RetiredSshCaSettingsTests : IDisposable
{
    private static readonly IReadOnlySet<string> NoEnvironment = new HashSet<string>();

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-retired-ssh-{Guid.NewGuid():N}");
    private readonly string _databaseName = $"retired-ssh-{Guid.NewGuid():N}";
    private readonly List<string> _warnings = [];

    public RetiredSshCaSettingsTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string ConfigPath => Path.Combine(_dir, "config.yaml");

    private SystemConfig Load(string yaml)
    {
        File.WriteAllText(ConfigPath, yaml);
        return YamlConfigLoader.Load(ConfigPath, _warnings.Add);
    }

    private ModularCADbContext Db() => InMemoryDbContextFactory.Create(_databaseName);

    private SettingsStore Store() => new(Db(), new RecordingAuditService(), new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);

    [Fact]
    public void The_catalog_has_no_ssh_ca_setting()
    {
        Assert.DoesNotContain(SettingsCatalog.Definitions, d => d.Section == "SshCa");
        Assert.Null(SettingsCatalog.Find("SshCa_SshKeygenPath"));
        Assert.Null(SettingsCatalog.Find("SshCa_KeyStoragePath"));
    }

    /// <summary>Every build before this one wrote the section into the file with these values; nobody chose them.</summary>
    [Fact]
    public void The_section_an_earlier_build_wrote_loads_without_a_word()
    {
        var config = Load("Tokens:\n  RefreshTokenDays: 9\nSshCa:\n  SshKeygenPath: \"ssh-keygen\"\n  KeyStoragePath: config/ssh-ca-keys\nMetrics:\n  Path: /scrape\n");

        Assert.Equal(9, config.Tokens.RefreshTokenDays);
        Assert.Equal("/scrape", config.Metrics.Path);
        Assert.Empty(_warnings);
    }

    [Fact]
    public void A_value_an_operator_chose_is_ignored_with_a_warning_that_names_the_key_and_the_file()
    {
        var config = Load("SshCa:\n  SshKeygenPath: /opt/openssh/bin/ssh-keygen\n  KeyStoragePath: /srv/modularca/ssh-keys\nTokens:\n  RefreshTokenDays: 9\n");

        Assert.Equal(9, config.Tokens.RefreshTokenDays);
        Assert.Equal(2, _warnings.Count);
        Assert.Contains(_warnings, w => w.Contains("SshCa.SshKeygenPath") && w.Contains(ConfigPath) && w.Contains("retired and ignored"));
        Assert.Contains(_warnings, w => w.Contains("SshCa.KeyStoragePath") && w.Contains(ConfigPath) && w.Contains("retired and ignored"));
    }

    [Theory]
    [InlineData("SshCa:\n")]
    [InlineData("SshCa: {}\n")]
    [InlineData("SshCa:\n  SshKeygenPath:\n  KeyStoragePath: ~\n")]
    [InlineData("SshCa:\n  Unheard: of\n")]
    [InlineData("SshCa: ssh-keygen\n")]
    public void An_empty_or_odd_section_does_not_stop_the_load(string section)
    {
        var config = Load(section + "Tokens:\n  RefreshTokenDays: 9\n");

        Assert.Equal(9, config.Tokens.RefreshTokenDays);
        Assert.Empty(_warnings);
    }

    [Fact]
    public void The_file_is_written_back_without_the_section()
    {
        var config = Load("SshCa:\n  SshKeygenPath: /opt/openssh/bin/ssh-keygen\n  KeyStoragePath: /srv/modularca/ssh-keys\nTokens:\n  RefreshTokenDays: 9\n");

        var whole = ConfigYamlWriter.Serialize(config);
        var hostOnly = ConfigYamlWriter.Serialize(config, []);

        Assert.DoesNotContain("SshCa", whole);
        Assert.DoesNotContain("SshKeygenPath", whole);
        Assert.DoesNotContain("KeyStoragePath", whole);
        Assert.DoesNotContain("SshCa", hostOnly);
        Assert.Contains("RefreshTokenDays: 9", whole);
    }

    /// <summary>
    /// The settings were this host's, so the store never held them. A row under one of their keys
    /// is still not a reason to refuse a start: it is reported, and every other setting applies.
    /// </summary>
    [Fact]
    public async Task A_stored_row_under_a_retired_key_is_reported_and_the_start_goes_on()
    {
        File.WriteAllText(ConfigPath, "SshCa:\n  SshKeygenPath: ssh-keygen\n  KeyStoragePath: config/ssh-ca-keys\n");
        await using (var seed = Db())
        {
            seed.Settings.AddRange(
                new SettingEntity { Key = "SshCa_SshKeygenPath", ValueJson = "\"/opt/openssh/bin/ssh-keygen\"", Version = 1, Revision = 1, ActorName = "earlier", Source = "Import" },
                new SettingEntity { Key = "SshCa_KeyStoragePath", ValueJson = "\"/srv/modularca/ssh-keys\"", Version = 1, Revision = 1, ActorName = "earlier", Source = "Import" },
                new SettingEntity { Key = "Acme_Http01_MaxAddresses", ValueJson = "8", Version = 1, Revision = 1, ActorName = "earlier", Source = "Import" });
            seed.SettingsState.Add(new SettingsStateEntity { Id = SettingsStateEntity.SingletonId, Revision = 1, ImportedAt = DateTime.UtcNow.AddDays(-1) });
            await seed.SaveChangesAsync();
        }

        foreach (var mayMove in new[] { false, true })
        {
            var config = YamlConfigLoader.Load(ConfigPath, _warnings.Add);
            var report = await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), ConfigPath), NoEnvironment, mayMove);

            Assert.Equal(8, config.Acme.Http01.MaxAddresses);
            Assert.Equal(1, report.Load.Applied);
            Assert.Equal(
                ["SshCa_KeyStoragePath is not a setting this build knows.", "SshCa_SshKeygenPath is not a setting this build knows."],
                report.Load.Problems);
        }

        Assert.Empty(_warnings);
        await using var check = Db();
        Assert.Equal(3, check.Settings.Count());
        Assert.Equal("\"/srv/modularca/ssh-keys\"", check.Settings.Single(s => s.Key == "SshCa_KeyStoragePath").ValueJson);
    }

    [Fact]
    public async Task The_store_takes_no_new_value_for_a_retired_key()
    {
        var refused = await Assert.ThrowsAsync<SettingsRefusedException>(() => Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, System.Text.Json.Nodes.JsonNode?> { ["SshCa_SshKeygenPath"] = System.Text.Json.Nodes.JsonValue.Create("/tmp/evil") },
            Actor = new SettingsActor(Guid.NewGuid(), "alice"),
            Source = SettingsSource.Api,
        }));

        Assert.Equal(SettingsRefusal.UnknownKey, refused.Reason);
    }
}
