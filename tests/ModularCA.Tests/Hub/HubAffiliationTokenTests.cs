using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Hub;

/// <summary>
/// The affiliation token's interim shape: the hub keeps the token, the instance takes its SHA-256
/// from bootstrap.yaml or a host command and keeps it in the settings store with its data, with
/// no schema change. The check itself is in <see cref="HubLocalConnectionTests"/>.
/// </summary>
public sealed class HubAffiliationTokenTests : IDisposable
{
    private const string Token = "kQ3vX0d8m1c5Zr7tYb2Ns9Lw4Hf6Pj0aUe3Gi8Ro1Vk";
    private static readonly string Hash = Convert.ToHexString(HubLocalHost.HashToken(Token)).ToLowerInvariant();

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mca-hubtoken-" + Guid.NewGuid().ToString("N"));
    private readonly string _databaseName = "hub-token-" + Guid.NewGuid().ToString("N");
    private readonly RecordingAuditService _audit = new();

    public HubAffiliationTokenTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private ModularCADbContext Db() => InMemoryDbContextFactory.Create(_databaseName);
    private SettingsStore Store() => new(Db(), _audit, new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);

    private static string RepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "ModularCA.sln"))) dir = Path.GetDirectoryName(dir)!;
        return dir;
    }

    private YamlBootstrapLoader.BootstrapConfig Bootstrap(string hubSection)
    {
        var path = Path.Combine(_dir, "bootstrap.yaml");
        File.WriteAllText(path, "CA:\n  Subject:\n    CN: Test Root\n" + hubSection);
        return YamlBootstrapLoader.Load(path);
    }

    // ---- taking it at bootstrap --------------------------------------------------------------

    [Fact]
    public void Bootstrap_yaml_carries_the_hash_under_Hub()
    {
        var config = Bootstrap($"Hub:\n  AffiliationTokenSha256: \"{Hash.ToUpperInvariant()}\"\n");

        BootstrapInputSections.EnsureHubTokenUsable(config.Hub);
        Assert.Equal(Hash, BootstrapInputSections.HubTokenHash(config.Hub));
    }

    [Fact]
    public void A_bootstrap_yaml_with_no_Hub_section_gives_no_hash()
    {
        var config = Bootstrap("");

        BootstrapInputSections.EnsureHubTokenUsable(config.Hub);
        BootstrapInputSections.EnsureHubTokenUsable(null);
        Assert.Equal("", BootstrapInputSections.HubTokenHash(config.Hub));
        Assert.Equal("", BootstrapInputSections.HubTokenHash(null));
    }

    [Theory]
    [InlineData(Token)]
    [InlineData("abc123")]
    [InlineData("zz8a7d0c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b")]
    public void A_value_that_is_not_a_sha256_is_refused_before_anything_changes(string value)
    {
        var config = Bootstrap($"Hub:\n  AffiliationTokenSha256: \"{value}\"\n");

        var refusal = Assert.Throws<InvalidRequestException>(() => BootstrapInputSections.EnsureHubTokenUsable(config.Hub));

        Assert.Contains("Hub.AffiliationTokenSha256", refusal.Message);
        Assert.Contains("never the token itself", refusal.Remediation);
    }

    [Fact]
    public void The_bootstrap_checks_the_hash_with_its_other_inputs_and_writes_it_to_the_configuration()
    {
        var run = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.Bootstrap", "BootstrapModularCA.cs"));
        var claim = run.IndexOf("BootstrapInputSections.EnsureClaimTokenUsable(bootstrapConfig.Administration);", StringComparison.Ordinal);
        var hub = run.IndexOf("BootstrapInputSections.EnsureHubTokenUsable(bootstrapConfig.Hub);", StringComparison.Ordinal);
        Assert.True(claim > 0 && hub > claim && hub - claim < 200);

        var writer = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.Bootstrap", "BootstrapDatabaseSetup.cs"));
        Assert.Contains("AffiliationTokenSha256 = BootstrapInputSections.HubTokenHash(bootstrapConfig?.Hub)", writer);
    }

    [Theory]
    [InlineData("config/bootstrap.yaml.example")]
    [InlineData("ModularCA.Bootstrap/bootstrap.yaml.example")]
    public void The_examples_describe_the_key_without_setting_it(string relative)
    {
        var path = Path.Combine(RepoRoot(), relative);
        var text = File.ReadAllText(path);

        Assert.Contains("# Hub:", text);
        Assert.Contains("#   AffiliationTokenSha256:", text);
        Assert.Contains("--new-hub-token", text);
        Assert.True(string.IsNullOrEmpty(YamlBootstrapLoader.Load(path).Hub.AffiliationTokenSha256));
    }

    // ---- keeping it with the instance's data ---------------------------------------------------

    [Fact]
    public void The_hash_is_an_instance_wide_setting_so_it_needs_no_table_of_its_own()
    {
        var definition = SettingsCatalog.Find(NodeHubOperations.TokenHashKey);

        Assert.NotNull(definition);
        Assert.Equal(SettingClass.InstanceWide, definition!.Class);
        Assert.True(definition.StoredInDatabase);
        Assert.Equal(SettingSecretKind.None, definition.Secret);
        Assert.Equal("", new SystemConfig().Hub.AffiliationTokenSha256);
    }

    [Fact]
    public async Task The_hash_the_bootstrap_wrote_moves_into_the_store_and_comes_back_at_the_next_start()
    {
        var fromFile = new SystemConfig();
        fromFile.Hub.AffiliationTokenSha256 = Hash;

        await SettingsRuntime.ImportAsync(Store(), fromFile, new HashSet<string>());

        var snapshot = await Store().LoadAsync();
        Assert.Contains(Hash, snapshot.Settings[NodeHubOperations.TokenHashKey].ValueJson);

        var nextStart = new SystemConfig();
        snapshot.ApplyTo(nextStart);
        Assert.Equal(Hash, nextStart.Hub.AffiliationTokenSha256);
        Assert.Equal(HubLocalHost.HashToken(Token), Operations(nextStart).AffiliationTokenHash);
    }

    [Fact]
    public void An_instance_given_no_hash_has_the_check_off()
        => Assert.Null(Operations(new SystemConfig()).AffiliationTokenHash);

    [Fact]
    public async Task A_replacement_that_cannot_be_kept_is_not_in_force()
    {
        var config = new SystemConfig();
        config.Hub.AffiliationTokenSha256 = Hash;
        var operations = Operations(config, (_, _, _, _) => throw new SettingsRefusedException(SettingsRefusal.Busy, "busy"));

        await Assert.ThrowsAsync<SettingsRefusedException>(() => operations.ReplaceAffiliationTokenAsync(new byte[32], null, default));

        Assert.Equal(Hash, config.Hub.AffiliationTokenSha256);
        Assert.Equal(HubLocalHost.HashToken(Token), operations.AffiliationTokenHash);
    }

    private NodeHubOperations Operations(SystemConfig config, Func<ISettingsStore, SettingsActor, string, CancellationToken, Task>? save = null)
    {
        var services = new ServiceCollection().AddSingleton<IAuditService>(_audit).AddSingleton<ISettingsStore>(Store()).BuildServiceProvider();
        return new NodeHubOperations(
            InstanceModeStore.Open(null, null, _dir), config, services.GetRequiredService<IServiceScopeFactory>(),
            _ => throw new NotSupportedException(), _ => throw new NotSupportedException(), save, "test");
    }

    [Fact]
    public void The_console_s_settings_do_not_show_or_edit_the_hash()
    {
        var controllers = Path.Combine(RepoRoot(), "ModularCA.API", "Controllers");
        Assert.All(Directory.EnumerateFiles(controllers, "*.cs", SearchOption.AllDirectories),
            file => Assert.DoesNotContain("AffiliationTokenSha256", File.ReadAllText(file)));
    }

    // ---- the host commands ----------------------------------------------------------------------

    private static Type Command => ApiAssembly.TypeNamed("ModularCA.API.Startup.HubTokenCommand");

    private async Task<(int Exit, string Out, string Error)> SetAsync(string? value)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = await (Task<int>)Command.GetMethod("RunSetAsync")!.Invoke(null, [Store(), _audit, value, output, error])!;
        return (exit, output.ToString(), error.ToString());
    }

    [Fact]
    public void New_hub_token_prints_a_token_its_hash_and_the_bootstrap_line()
    {
        var output = new StringWriter();

        Assert.Equal(0, Command.GetMethod("RunNew")!.Invoke(null, [output]));

        var lines = output.ToString().Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var token = lines[1];
        var hash = Convert.ToHexString(HubLocalHost.HashToken(token)).ToLowerInvariant();
        Assert.True(token.Length >= 40);
        Assert.Contains(hash, lines);
        Assert.Contains("Hub:", lines);
        Assert.Contains($"AffiliationTokenSha256: \"{hash}\"", lines);
        Assert.Contains(lines, l => l.EndsWith($"--set-hub-token-hash {hash}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Set_hub_token_hash_gives_an_existing_instance_its_hash_replaces_it_and_removes_it()
    {
        await SettingsRuntime.ImportAsync(Store(), new SystemConfig(), new HashSet<string>());

        var set = await SetAsync(Hash.ToUpperInvariant());
        Assert.Equal(0, set.Exit);
        Assert.Contains("Restart", set.Out);
        Assert.Contains(Hash, (await Store().LoadAsync()).Settings[NodeHubOperations.TokenHashKey].ValueJson);

        var other = new string('b', 64);
        Assert.Equal(0, (await SetAsync(other)).Exit);
        var config = new SystemConfig();
        (await Store().LoadAsync()).ApplyTo(config);
        Assert.Equal(other, config.Hub.AffiliationTokenSha256);

        var removed = await SetAsync("none");
        Assert.Equal(0, removed.Exit);
        Assert.Contains("off", removed.Out);
        config = new SystemConfig();
        (await Store().LoadAsync()).ApplyTo(config);
        Assert.Equal("", config.Hub.AffiliationTokenSha256);

        Assert.Equal(3, _audit.Entries.Count(e => e.Action == AuditActionType.HubAffiliationTokenReplaced));
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.HubAffiliationTokenReplaced
            && System.Text.Json.JsonSerializer.Serialize(e.Details).Contains(Hash, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(Token)]
    [InlineData("--role")]
    public async Task Set_hub_token_hash_refuses_what_is_not_a_hash_and_changes_nothing(string? value)
    {
        var (exit, _, error) = await SetAsync(value);

        Assert.Equal(1, exit);
        Assert.Contains("never the token itself", error);
        Assert.False((await Store().LoadAsync()).Settings.ContainsKey(NodeHubOperations.TokenHashKey));
        Assert.Empty(_audit.Entries);
    }

    [Fact]
    public void The_host_commands_are_dispatched_before_the_node_starts()
    {
        var startup = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "StartModularCA.cs"));
        var builder = startup.IndexOf("WebApplication.CreateBuilder(args)", StringComparison.Ordinal);

        Assert.InRange(startup.IndexOf("HubTokenCommand.NewFlag", StringComparison.Ordinal), 1, builder);
        Assert.InRange(startup.IndexOf("HubTokenCommand.RunSetAsync(", StringComparison.Ordinal), 1, builder);
        Assert.Equal("--new-hub-token", Command.GetField("NewFlag")!.GetRawConstantValue());
        Assert.Equal("--set-hub-token-hash", Command.GetField("SetFlag")!.GetRawConstantValue());
    }
}
