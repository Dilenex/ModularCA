using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Settings;

/// <summary>
/// The instance's identifier as the settings store sees it: a row under a reserved key that no
/// settings change can reach. Not through the store's write, the host command, the move out of
/// <c>config.yaml</c>, a save from the console's endpoints, or a file. What writes and reads
/// the row is SQL of its own, tested on PostgreSQL in <c>PostgresInstanceIdentityTests</c>.
/// </summary>
public sealed class InstanceIdentityTests : IDisposable
{
    private const string Stored = "1111111111111111111111111111111111111111111111111111111111111111";
    private const string Other = "2222222222222222222222222222222222222222222222222222222222222222";
    private static readonly IReadOnlySet<string> NoEnvironment = new HashSet<string>();

    /// <summary>A configuration file that has a section or a key for the identifier.</summary>
    private const string NamesTheIdentifier = @"(?mi)^\s*Instance(Id)?\s*:";
    private static readonly SettingsActor Alice = new(Guid.NewGuid(), "alice");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-instance-id-{Guid.NewGuid():N}");
    private readonly string _databaseName = $"instance-id-{Guid.NewGuid():N}";
    private readonly RecordingAuditService _audit = new();

    public InstanceIdentityTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private ModularCADbContext Db() => InMemoryDbContextFactory.Create(_databaseName);
    private SettingsStore Store() => new(Db(), _audit, new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);

    /// <summary>The row as the first start leaves it.</summary>
    private async Task StoreIdentifierAsync()
    {
        await using var db = Db();
        db.Settings.Add(new SettingEntity
        {
            Key = InstanceIdentity.Key, ValueJson = $"\"{Stored}\"", Version = 1, Revision = 0,
            ActorName = InstanceIdentity.StartActor, Source = SettingsSource.Startup,
        });
        await db.SaveChangesAsync();
    }

    private async Task<SettingEntity> RowAsync()
    {
        await using var db = Db();
        return db.Settings.Single(s => s.Key == InstanceIdentity.Key);
    }

    private async Task AssertUntouchedAsync()
    {
        var row = await RowAsync();
        Assert.Equal($"\"{Stored}\"", row.ValueJson);
        Assert.Equal(1, row.Version);
        Assert.Equal(SettingsSource.Startup, row.Source);
        await using var db = Db();
        Assert.Empty(db.SettingsHistory.Where(h => h.Key == InstanceIdentity.Key));
    }

    // ---- not a setting ---------------------------------------------------------------------------

    [Fact]
    public void The_identifier_is_no_setting_so_no_file_environment_variable_or_console_field_stands_behind_it()
    {
        Assert.Equal("Instance_Id", InstanceIdentity.Key);
        Assert.Null(SettingsCatalog.Find(InstanceIdentity.Key));
        Assert.DoesNotContain(SettingsCatalog.Definitions, d => ReservedSettingKeys.IsReserved(d.Key));
        // No section of the configuration could come to hold it under another spelling.
        Assert.DoesNotContain(SettingsCatalog.Definitions, d => string.Equals(d.Section, "Instance", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(SettingsDescriptions.Describe(null, NoEnvironment), d => ReservedSettingKeys.IsReserved(d.Key));
        Assert.True(ReservedSettingKeys.IsReserved("instance_id"));
        Assert.False(ReservedSettingKeys.IsReserved("Hub_AffiliationTokenSha256"));
    }

    [Fact]
    public void A_whole_configuration_written_to_a_file_does_not_carry_it()
    {
        // What a host writes before the settings have been moved: everything it has.
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, new SystemConfig());

        Assert.DoesNotMatch(NamesTheIdentifier, File.ReadAllText(path));
    }

    // ---- the store refuses it --------------------------------------------------------------------

    [Theory]
    [InlineData("set")]
    [InlineData("clear")]
    [InlineData("expect")]
    [InlineData("set, other case")]
    public async Task The_store_refuses_a_change_that_names_it(string how)
    {
        await StoreIdentifierAsync();
        var change = new SettingsChange
        {
            // A setting of its own in the same change: the whole write is refused, not one key of it.
            Set = how switch
            {
                "set" => new Dictionary<string, JsonNode?> { [InstanceIdentity.Key] = JsonValue.Create(Other), ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8) },
                "set, other case" => new Dictionary<string, JsonNode?> { ["instance_id"] = JsonValue.Create(Other) },
                _ => new Dictionary<string, JsonNode?> { ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8) },
            },
            Clear = how == "clear" ? [InstanceIdentity.Key] : [],
            ExpectedVersions = how == "expect" ? new Dictionary<string, int> { [InstanceIdentity.Key] = 1 } : new Dictionary<string, int>(),
            Actor = Alice, Source = SettingsSource.Api,
        };

        var refusal = await Assert.ThrowsAsync<SettingsRefusedException>(() => Store().WriteAsync(change));

        Assert.Equal(SettingsRefusal.WrittenOnce, refusal.Reason);
        await AssertUntouchedAsync();
        Assert.False((await Store().LoadAsync()).Settings.ContainsKey("Acme_Http01_MaxAddresses"));
        Assert.Empty(_audit.Entries);
    }

    [Fact]
    public async Task The_store_refuses_it_when_nothing_is_stored_too_so_no_settings_change_can_be_the_one_that_stores_it()
    {
        var refusal = await Assert.ThrowsAsync<SettingsRefusedException>(() => Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, JsonNode?> { [InstanceIdentity.Key] = JsonValue.Create(Other) },
            Actor = Alice, Source = SettingsSource.Api,
        }));

        Assert.Equal(SettingsRefusal.WrittenOnce, refusal.Reason);
        Assert.Empty((await Store().LoadAsync()).Settings);
    }

    [Theory]
    [InlineData("set", "Instance_Id")]
    [InlineData("set", "Instance.Id")]
    [InlineData("clear", "Instance_Id")]
    public async Task The_host_command_cannot_set_or_clear_it(string verb, string key)
    {
        await StoreIdentifierAsync();
        var (output, error) = (new StringWriter(), new StringWriter());
        string[] args = verb == "set" ? [verb, key, Other] : [verb, key];

        var exit = await SettingsCommand.RunAsync(Store(), args, output, error);

        Assert.NotEqual(0, exit);
        await AssertUntouchedAsync();
    }

    [Fact]
    public async Task The_host_command_lists_it_with_the_stored_settings()
    {
        await StoreIdentifierAsync();
        var output = new StringWriter();

        Assert.Equal(0, await SettingsCommand.RunAsync(Store(), ["list"], output, new StringWriter()));

        Assert.Contains($"Instance_Id = \"{Stored}\"", output.ToString());
    }

    // ---- the move, a start and a save leave it alone -------------------------------------------

    [Fact]
    public async Task The_move_out_of_the_file_a_start_and_a_save_from_the_console_leave_it_as_it_is()
    {
        // Stored while the settings were still in config.yaml: the row does not wait for the move.
        await StoreIdentifierAsync();
        var path = Path.Combine(_dir, "config.yaml");
        var config = new SystemConfig();
        config.Acme.Http01.MaxAddresses = 8;
        ConfigYamlWriter.Write(path, config);
        var persistence = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);

        var start = await SettingsRuntime.StartAsync(Store(), config, persistence, NoEnvironment, mayMove: true);

        Assert.True(start.Import!.Ran);
        Assert.DoesNotContain(InstanceIdentity.Key, start.Import.ImportedKeys);
        Assert.Empty(start.Load.Problems);
        await AssertUntouchedAsync();

        // What every settings endpoint does: change the configuration in memory, then save it.
        config.Acme.Http01.MaxAddresses = 9;
        config.Hub.AffiliationTokenSha256 = Other;
        await persistence.SaveAsync(Store(), Alice);

        await AssertUntouchedAsync();
        Assert.DoesNotMatch(NamesTheIdentifier, File.ReadAllText(path));
        Assert.DoesNotContain(Stored, File.ReadAllText(path));

        // The next start, and a node that does not move settings.
        var again = new SystemConfig();
        var next = await SettingsRuntime.StartAsync(Store(), again, new SettingsPersistence(again, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: false);
        Assert.Empty(next.Load.Problems);
        Assert.Empty(next.Snapshot.ApplyTo(new SystemConfig()));
        await AssertUntouchedAsync();
    }

    [Fact]
    public async Task A_file_that_names_it_gives_it_no_value()
    {
        await StoreIdentifierAsync();
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, new SystemConfig());
        // Someone types the identifier of another instance into this host's file.
        File.AppendAllText(path, $"\nInstance:\n  Id: \"{Other}\"\n");

        // The loader passes over a section it does not know, so the file is read and the line is nothing.
        var config = YamlConfigLoader.Load(path, _ => { });
        await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);

        await AssertUntouchedAsync();
    }

    // ---- hello's reader --------------------------------------------------------------------------

    private NodeHubOperations Operations(Func<CancellationToken, Task<InstanceIdReading>>? read)
    {
        var services = new ServiceCollection().AddSingleton<IAuditService>(_audit).BuildServiceProvider();
        return new NodeHubOperations(
            InstanceModeStore.Open(Path.Combine(_dir, "hub.sock"), null, Path.Combine(_dir, "config")), new SystemConfig(),
            services.GetRequiredService<IServiceScopeFactory>(),
            _ => Task.FromResult(new HubHealthReport("healthy")), _ => throw new NotSupportedException(), null, "0.4.5-test")
        {
            InstanceId = read,
        };
    }

    [Fact]
    public async Task A_stored_identifier_is_read_once_and_kept_whatever_is_read_later()
    {
        var reads = 0;
        var operations = Operations(_ => Task.FromResult(++reads == 1 ? new InstanceIdReading(Stored, true) : new InstanceIdReading(Other, true)));

        Assert.Equal(Stored, await operations.ReadInstanceIdAsync(default));
        Assert.Equal(Stored, await operations.ReadInstanceIdAsync(default));
        Assert.Equal(1, reads);
    }

    [Fact]
    public async Task A_derived_identifier_is_read_again_until_one_is_stored()
    {
        var readings = new Queue<InstanceIdReading>([new(null, false), new(Other, false), new(Stored, true)]);
        var operations = Operations(_ => Task.FromResult(readings.Dequeue()));

        Assert.Null(await operations.ReadInstanceIdAsync(default));
        Assert.Equal(Other, await operations.ReadInstanceIdAsync(default));
        Assert.Equal(Stored, await operations.ReadInstanceIdAsync(default));
        Assert.Equal(Stored, await operations.ReadInstanceIdAsync(default));
        Assert.Empty(readings);
    }

    [Fact]
    public async Task An_identifier_that_cannot_be_read_is_not_known_and_fails_nothing()
    {
        Assert.Null(await Operations(null).ReadInstanceIdAsync(default));
        Assert.Null(await Operations(_ => throw new InvalidOperationException("no database")).ReadInstanceIdAsync(default));
        // A stored row that holds nothing usable: not known, and not kept as if it were.
        var unusable = Operations(_ => Task.FromResult(new InstanceIdReading(null, true)));
        Assert.Null(await unusable.ReadInstanceIdAsync(default));
    }
}
