using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Settings;

/// <summary>
/// The move of the instance-wide settings out of <c>config.yaml</c>, and what the node does with
/// the store from then on: read it at start, write to it when a setting is changed, and keep the
/// file to what belongs to the host. Secrets are not part of the move yet and stay in the file.
/// </summary>
public sealed class SettingsRuntimeTests : IDisposable
{
    private static readonly IReadOnlySet<string> NoEnvironment = new HashSet<string>();
    private static readonly SettingsActor Alice = new(Guid.NewGuid(), "alice");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-settings-runtime-{Guid.NewGuid():N}");
    private readonly string _databaseName = $"settings-runtime-{Guid.NewGuid():N}";
    private readonly RecordingAuditService _audit = new();

    public SettingsRuntimeTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private ModularCADbContext Db() => InMemoryDbContextFactory.Create(_databaseName);
    private SettingsStore Store() => new(Db(), _audit, new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);
    private SettingsStore Store(ModularCA.Shared.Signing.ISigningService signer) => new(Db(), _audit, signer, NullLogger<SettingsStore>.Instance);

    /// <summary>A configuration as an operator's <c>config.yaml</c> gives it: a few settings of every kind changed.</summary>
    private static SystemConfig FromFile()
    {
        var config = new SystemConfig();
        // Instance-wide.
        config.Acme.Http01.MaxAddresses = 8;
        config.IpWhitelist.ExemptPaths = ["/health", "/custom"];
        config.Audit.FailMode = AuditFailMode.FailClosed;
        config.Email.OAuth2ClientId = "client-id-from-the-file";
        // Host-local, bootstrap and signer.
        config.Https.Port = 9443;
        config.Logging.FilePath = "/var/log/modularca/ca.log";
        config.DB.App.Host = "db.internal";
        config.Hsm.ModulePath = "/usr/lib/softhsm/libsofthsm2.so";
        // Secrets.
        config.JWT.Secret = "the-jwt-secret-from-the-file";
        config.IntegrationApi.ApiKey = "the-api-key-from-the-file";
        return config;
    }

    [Fact]
    public void A_configuration_at_its_defaults_needs_nothing_stored()
    {
        // Two fresh configurations have to agree, or every start would look like a change.
        var nothing = new SettingsSnapshot(0, new Dictionary<string, StoredSetting>(), new Dictionary<string, StoredSecret>());

        Assert.Empty(SettingsRuntime.Differences(new SystemConfig(), nothing, NoEnvironment));
    }

    [Fact]
    public async Task The_move_stores_the_instance_wide_settings_the_file_changed_and_nothing_else()
    {
        var report = await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);

        Assert.True(report.Ran);
        Assert.Equal(1, report.Revision);
        Assert.Equal(
            ["Acme_Http01_MaxAddresses", "Audit_FailMode", "Email_OAuth2ClientId", "IpWhitelist_ExemptPaths"],
            report.ImportedKeys);

        var snapshot = await Store().LoadAsync();
        Assert.NotNull(snapshot.ImportedAt);
        Assert.Equal(report.ImportedKeys, snapshot.Settings.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("8", snapshot.Settings["Acme_Http01_MaxAddresses"].ValueJson);
        Assert.All(snapshot.Settings.Values, s => Assert.Equal(("Import", SettingsRuntime.ImportActor), (s.Source, s.ActorName)));
        // No secret was touched: they are not moved yet.
        Assert.Empty(snapshot.Secrets);
    }

    [Fact]
    public async Task The_move_happens_once()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);
        var audits = _audit.Entries.Count;

        // A later start, from a file someone has edited since.
        var edited = FromFile();
        edited.Acme.Http01.MaxAddresses = 99;
        var again = await SettingsRuntime.ImportAsync(Store(), edited, NoEnvironment);

        Assert.False(again.Ran);
        Assert.Equal("8", (await Store().LoadAsync()).Settings["Acme_Http01_MaxAddresses"].ValueJson);
        Assert.Equal(audits, _audit.Entries.Count);
    }

    [Fact]
    public async Task A_move_with_nothing_to_store_is_still_a_move()
    {
        var report = await SettingsRuntime.ImportAsync(Store(), new SystemConfig(), NoEnvironment);

        Assert.True(report.Ran);
        Assert.Empty(report.ImportedKeys);
        var snapshot = await Store().LoadAsync();
        Assert.NotNull(snapshot.ImportedAt);
        Assert.Equal(0, snapshot.Revision);
        Assert.False((await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment)).Ran);
    }

    [Fact]
    public async Task A_setting_the_environment_supplies_is_neither_stored_nor_overridden()
    {
        var environment = new HashSet<string> { "Email.OAuth2ClientId" };

        var report = await SettingsRuntime.ImportAsync(Store(), FromFile(), environment);
        Assert.DoesNotContain("Email_OAuth2ClientId", report.ImportedKeys);

        var config = new SystemConfig { Email = { OAuth2ClientId = "client-id-from-the-environment" } };
        SettingsRuntime.Apply(config, await Store().LoadAsync(), environment);
        Assert.Equal("client-id-from-the-environment", config.Email.OAuth2ClientId);
    }

    [Fact]
    public async Task After_the_move_a_start_takes_its_instance_wide_settings_from_the_store()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);

        // The file as the move left it: host-local settings and secrets only.
        var config = new SystemConfig
        {
            Https = { Port = 9443 },
            JWT = { Secret = "the-jwt-secret-from-the-file" },
        };
        var report = SettingsRuntime.Apply(config, await Store().LoadAsync(), NoEnvironment);

        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        Assert.Equal(["/health", "/custom"], config.IpWhitelist.ExemptPaths);
        Assert.Equal(AuditFailMode.FailClosed, config.Audit.FailMode);
        Assert.Equal(9443, config.Https.Port);
        Assert.Equal("the-jwt-secret-from-the-file", config.JWT.Secret);
        Assert.Equal((1L, 4), (report.Revision, report.Applied));
        Assert.Empty(report.IgnoredFileKeys);
        Assert.Empty(report.Problems);
        // What the configuration now holds is what the store gives: nothing is waiting to be written.
        Assert.Empty(SettingsRuntime.Differences(config, await Store().LoadAsync(), NoEnvironment));
    }

    /// <summary>
    /// After the move the file does not decide an instance-wide setting. A value left or typed
    /// there is not applied, whether the store holds another or holds none, and is reported.
    /// </summary>
    [Fact]
    public async Task After_the_move_a_value_for_an_instance_wide_setting_in_the_file_is_ignored_and_reported()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);

        var config = new SystemConfig();
        config.Acme.Http01.MaxAddresses = 2;          // the store says 8
        config.Tokens.RefreshTokenDays = 3;            // the store says nothing: the default is in force
        config.Audit.FailMode = AuditFailMode.FailClosed; // the same as the store: nothing to say
        var defaults = new SystemConfig();

        var report = SettingsRuntime.Apply(config, await Store().LoadAsync(), NoEnvironment);

        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        Assert.Equal(defaults.Tokens.RefreshTokenDays, config.Tokens.RefreshTokenDays);
        Assert.Equal(["Acme.Http01.MaxAddresses", "Tokens.RefreshTokenDays"], report.IgnoredFileKeys.OrderBy(k => k));
    }

    /// <summary>A role that starts before the control role has moved the settings still has its whole file to go by.</summary>
    [Fact]
    public async Task Before_the_move_the_file_still_decides()
    {
        var config = FromFile();

        var report = SettingsRuntime.Apply(config, await Store().LoadAsync(), NoEnvironment);

        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        Assert.Equal((0, 0), (report.Applied, report.IgnoredFileKeys.Count));
    }

    [Fact]
    public async Task A_change_made_in_memory_is_saved_to_the_store_with_its_history()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);
        var config = FromFile();

        config.Acme.Http01.MaxAddresses = 12;
        config.Tokens.RefreshTokenDays = 14;
        config.Https.Port = 10443;                      // host-local: not the store's
        config.JWT.Secret = "a-new-jwt-secret";         // a secret: not moved yet
        var snapshot = await SettingsRuntime.SaveAsync(Store(), config, NoEnvironment, Alice, SettingsSource.Api);

        Assert.Equal(2, snapshot.Revision);
        Assert.Equal("12", snapshot.Settings["Acme_Http01_MaxAddresses"].ValueJson);
        Assert.Equal(("14", "alice", "Api"), (snapshot.Settings["Tokens_RefreshTokenDays"].ValueJson,
            snapshot.Settings["Tokens_RefreshTokenDays"].ActorName, snapshot.Settings["Tokens_RefreshTokenDays"].Source));
        Assert.False(snapshot.Settings.ContainsKey("Https_Port"));
        Assert.Empty(snapshot.Secrets);
        var history = await Store().HistoryAsync("Acme_Http01_MaxAddresses");
        Assert.Equal(["12", "8"], history.Select(h => h.ValueJson));

        // Saving again with nothing changed writes nothing.
        Assert.Equal(2, (await SettingsRuntime.SaveAsync(Store(), config, NoEnvironment, Alice, SettingsSource.Api)).Revision);

        // Putting a setting back to its default is a change like any other, and sticks.
        config.Acme.Http01.MaxAddresses = new SystemConfig().Acme.Http01.MaxAddresses;
        snapshot = await SettingsRuntime.SaveAsync(Store(), config, NoEnvironment, Alice, SettingsSource.Api);
        Assert.Equal(3, snapshot.Revision);
        var restarted = new SystemConfig();
        SettingsRuntime.Apply(restarted, snapshot, NoEnvironment);
        Assert.Equal(new SystemConfig().Acme.Http01.MaxAddresses, restarted.Acme.Http01.MaxAddresses);
    }

    // ---- the file ---------------------------------------------------------------------------

    [Fact]
    public void The_file_keeps_what_belongs_to_the_host_and_reads_back_the_same()
    {
        var config = FromFile();
        var stored = SettingsRuntime.Covered(NoEnvironment).Select(d => d.Path);

        var yaml = ConfigYamlWriter.Serialize(config, stored);

        Assert.StartsWith(ConfigYamlWriter.HostOnlyHeader, yaml);
        // Instance-wide settings and the sections they emptied are gone.
        Assert.DoesNotContain("MaxAddresses", yaml);
        Assert.DoesNotContain("ExemptPaths", yaml);
        Assert.DoesNotContain("Acme:", yaml);
        Assert.DoesNotContain("IpWhitelist:", yaml);
        Assert.DoesNotContain("client-id-from-the-file", yaml);
        // The database section is never written.
        Assert.DoesNotContain("db.internal", yaml);

        var path = Path.Combine(_dir, "config.yaml");
        File.WriteAllText(path, yaml);
        var loaded = YamlConfigLoader.Load(path);
        Assert.Equal(9443, loaded.Https.Port);
        Assert.Equal("/var/log/modularca/ca.log", loaded.Logging.FilePath);
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", loaded.Hsm.ModulePath);
        Assert.Equal("the-jwt-secret-from-the-file", loaded.JWT.Secret);
        Assert.Equal("the-api-key-from-the-file", loaded.IntegrationApi.ApiKey);
        // And nothing of the store's came back by another road.
        Assert.Equal(new SystemConfig().Acme.Http01.MaxAddresses, loaded.Acme.Http01.MaxAddresses);
        Assert.Empty(SettingsRuntime.Differences(loaded, new SettingsSnapshot(0, new Dictionary<string, StoredSetting>(), new Dictionary<string, StoredSecret>()), NoEnvironment));
    }

    [Fact]
    public async Task Saving_goes_to_the_whole_file_before_the_move_and_to_the_store_after_it()
    {
        var path = Path.Combine(_dir, "config.yaml");
        var config = FromFile();
        var persistence = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);

        // Before the move: the file is everything, as it always was.
        persistence.Use(await Store().LoadAsync());
        Assert.False(persistence.StoreInUse);
        await persistence.SaveAsync(Store(), Alice);
        Assert.Contains("MaxAddresses: 8", File.ReadAllText(path));
        Assert.Empty((await Store().LoadAsync()).Settings);

        await SettingsRuntime.ImportAsync(Store(), config, new HashSet<string>());
        persistence.Use(await Store().LoadAsync());
        Assert.True(persistence.StoreInUse);

        config.Acme.Http01.MaxAddresses = 12;
        config.Https.Port = 10443;
        await persistence.SaveAsync(Store(), Alice);

        Assert.Equal("12", (await Store().LoadAsync()).Settings["Acme_Http01_MaxAddresses"].ValueJson);
        Assert.Equal("12", persistence.Snapshot!.Settings["Acme_Http01_MaxAddresses"].ValueJson);
        var yaml = File.ReadAllText(path);
        Assert.DoesNotContain("MaxAddresses", yaml);
        Assert.Contains("Port: 10443", yaml);
        Assert.StartsWith(ConfigYamlWriter.HostOnlyHeader, yaml);
    }

    /// <summary>
    /// A settings endpoint that clears a text box leaves null where the setting's type says
    /// text. The file took that as nothing, and the store has to as well, or the save would be
    /// refused.
    /// </summary>
    [Fact]
    public async Task A_null_where_a_setting_takes_text_or_a_list_is_saved_as_empty()
    {
        var config = FromFile();
        await SettingsRuntime.ImportAsync(Store(), config, NoEnvironment);

        config.Acme.TermsOfServiceUrl = null!;
        config.IpWhitelist.ExemptPaths = null!;
        var snapshot = await SettingsRuntime.SaveAsync(Store(), config, NoEnvironment, Alice, SettingsSource.Api);

        Assert.Equal("[]", snapshot.Settings["IpWhitelist_ExemptPaths"].ValueJson);
        // The terms URL was empty already, so there was nothing to write for it.
        Assert.False(snapshot.Settings.ContainsKey("Acme_TermsOfServiceUrl"));
    }

    // ---- a default an earlier build shipped --------------------------------------------------

    /// <summary>
    /// Found on staging: the file carried the repository's address from before the organisation
    /// was renamed, written there by the build that had it as its default. The move stored it as
    /// if someone had chosen it.
    /// </summary>
    [Theory]
    [InlineData("https://github.com/Ephemeral-Intel/ModularCA")]
    [InlineData("https://github.com/ephemeral-intel/modularca/")]
    public async Task A_default_an_earlier_build_wrote_into_the_file_is_not_stored_as_a_choice(string oldDefault)
    {
        var config = FromFile();
        config.SourceCode.Url = oldDefault;

        var report = await SettingsRuntime.ImportAsync(Store(), config, NoEnvironment);

        Assert.DoesNotContain("SourceCode_Url", report.ImportedKeys);
        Assert.Equal(SourceCodeConfig.UpstreamUrl, config.SourceCode.Url);
        Assert.False((await Store().LoadAsync()).Settings.ContainsKey("SourceCode_Url"));
    }

    [Fact]
    public async Task An_operators_own_source_address_is_stored()
    {
        var config = FromFile();
        config.SourceCode.Url = "https://git.example.test/our-fork/ModularCA";

        var report = await SettingsRuntime.ImportAsync(Store(), config, NoEnvironment);

        Assert.Contains("SourceCode_Url", report.ImportedKeys);
    }

    [Fact]
    public async Task A_start_clears_such_a_default_that_an_earlier_move_stored()
    {
        // The store as dev.1.0 left it on staging.
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);
        await Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, System.Text.Json.Nodes.JsonNode?>
            {
                ["SourceCode_Url"] = System.Text.Json.Nodes.JsonValue.Create("https://github.com/Ephemeral-Intel/ModularCA"),
            },
            Actor = new SettingsActor(null, SettingsRuntime.ImportActor), Source = SettingsSource.Import,
        });
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, new SystemConfig { Https = { Port = 9443 } });

        // Another role sees it and leaves the store alone; what it publishes is right either way.
        var other = YamlConfigLoader.Load(path);
        await SettingsRuntime.StartAsync(Store(), other, new SettingsPersistence(other, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: false);
        Assert.Equal(SourceCodeConfig.UpstreamUrl, other.SourceCode.EffectiveUrl);
        Assert.NotNull((await Store().LoadAsync()).Settings["SourceCode_Url"].ValueJson);

        // The control role clears it, with a record of why.
        var config = YamlConfigLoader.Load(path);
        var report = await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);

        Assert.Equal(SourceCodeConfig.UpstreamUrl, config.SourceCode.Url);
        Assert.Equal(["SourceCode_Url"], report.SupersededCleared);
        Assert.Null(report.Snapshot.Settings["SourceCode_Url"].ValueJson);
        var cleared = (await Store().HistoryAsync("SourceCode_Url"))[0];
        Assert.Equal((null, "Upgrade"), (cleared.ValueJson, cleared.Source));
        Assert.Contains("never chosen", cleared.Reason);
        Assert.Empty(report.Load.IgnoredFileKeys);

        // And does it once.
        var revision = report.Snapshot.Revision;
        var again = YamlConfigLoader.Load(path);
        var next = await SettingsRuntime.StartAsync(Store(), again, new SettingsPersistence(again, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);
        Assert.Equal(revision, next.Snapshot.Revision);
    }

    // ---- a whole start ------------------------------------------------------------------------

    private string WriteFullFile(SystemConfig config)
    {
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, config);
        return path;
    }

    [Fact]
    public async Task The_control_roles_first_start_moves_the_settings_and_leaves_the_file_to_the_host()
    {
        var path = WriteFullFile(FromFile());
        var before = File.ReadAllText(path);
        var config = YamlConfigLoader.Load(path);
        var persistence = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);

        var report = await SettingsRuntime.StartAsync(Store(), config, persistence, NoEnvironment, mayMove: true);

        Assert.True(report.Import!.Ran);
        Assert.True(persistence.StoreInUse);
        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        // The file as it was is kept, and the file now holds the host's settings and the secrets.
        Assert.Equal(before, File.ReadAllText(report.FileBackup!));
        var yaml = File.ReadAllText(path);
        Assert.DoesNotContain("MaxAddresses", yaml);
        Assert.Contains("Port: 9443", yaml);
        Assert.Contains("the-jwt-secret-from-the-file", yaml);

        // The next start, from the rewritten file: the same settings, nothing moved, nothing rewritten.
        var again = YamlConfigLoader.Load(path);
        var next = await SettingsRuntime.StartAsync(Store(), again, new SettingsPersistence(again, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);
        Assert.False(next.Import!.Ran);
        Assert.Null(next.FileBackup);
        Assert.Empty(next.Load.IgnoredFileKeys);
        Assert.Equal(8, again.Acme.Http01.MaxAddresses);
        Assert.Equal(["/health", "/custom"], again.IpWhitelist.ExemptPaths);
        Assert.Equal(9443, again.Https.Port);
        Assert.Equal("the-jwt-secret-from-the-file", again.JWT.Secret);
        Assert.Equal(yaml, File.ReadAllText(path));
    }

    [Fact]
    public async Task Another_role_takes_the_stored_settings_and_does_not_touch_its_file()
    {
        // The control role has moved the settings; this host's file is as it always was, with one difference.
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);
        var theirs = FromFile();
        theirs.Acme.Http01.MaxAddresses = 2;
        var path = WriteFullFile(theirs);
        var before = File.ReadAllText(path);
        var config = YamlConfigLoader.Load(path);

        var report = await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: false);

        Assert.Null(report.Import);
        Assert.Null(report.FileBackup);
        Assert.Equal(before, File.ReadAllText(path));
        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        Assert.Equal(["Acme.Http01.MaxAddresses"], report.Load.IgnoredFileKeys);
    }

    [Fact]
    public async Task A_setting_typed_back_into_the_file_is_ignored_and_taken_out_again()
    {
        var path = WriteFullFile(FromFile());
        var config = YamlConfigLoader.Load(path);
        await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);

        File.AppendAllText(path, "Tokens:\n  RefreshTokenDays: 3\n");
        var edited = YamlConfigLoader.Load(path);
        Assert.Equal(3, edited.Tokens.RefreshTokenDays);
        var report = await SettingsRuntime.StartAsync(Store(), edited, new SettingsPersistence(edited, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);

        Assert.Equal(new SystemConfig().Tokens.RefreshTokenDays, edited.Tokens.RefreshTokenDays);
        Assert.Equal(["Tokens.RefreshTokenDays"], report.Load.IgnoredFileKeys);
        Assert.NotNull(report.FileBackup);
        Assert.DoesNotContain("RefreshTokenDays", File.ReadAllText(path));
    }

    /// <summary>A container mounts its configuration read-only. The stored settings still apply.</summary>
    [Fact]
    public async Task A_file_that_cannot_be_rewritten_does_not_stop_the_start()
    {
        var path = WriteFullFile(FromFile());
        var config = YamlConfigLoader.Load(path);
        // Held open for writing by someone else, which is as unwritable as a file can be made on every platform.
        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var report = await SettingsRuntime.StartAsync(Store(), config, new SettingsPersistence(config, new EnvVarConfigOverlay(), path), NoEnvironment, mayMove: true);

            Assert.True(report.Import!.Ran);
            Assert.NotNull(report.FileProblem);
            Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        }
    }

    [Fact]
    public async Task Saving_a_stored_setting_does_not_need_the_file_to_be_writable()
    {
        var path = WriteFullFile(FromFile());
        var config = YamlConfigLoader.Load(path);
        var persistence = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);
        await SettingsRuntime.StartAsync(Store(), config, persistence, NoEnvironment, mayMove: true);

        config.Acme.Http01.MaxAddresses = 12;
        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            await persistence.SaveAsync(Store(), Alice);

        Assert.Equal("12", (await Store().LoadAsync()).Settings["Acme_Http01_MaxAddresses"].ValueJson);
    }

    // ---- the secrets --------------------------------------------------------------------------

    private const string JwtSecret = "the-jwt-secret-from-the-file";
    private const string BindPassword = "the-directory-bind-password";
    private const string MailPassword = "the-mail-password";
    private const string HookSecret = "whsec-from-the-file";

    private static SystemConfig FromFileWithSecrets()
    {
        var config = FromFile();
        config.LdapAuth.BindPassword = BindPassword;
        config.Email.Password = MailPassword;
        config.Webhook.Endpoints = [new WebhookEndpoint { Url = "https://hooks.example.test/ca", Secret = HookSecret, Events = ["CertificateIssued"] }];
        return config;
    }

    private async Task<(SystemConfig Config, SettingsPersistence Persistence, SettingsStartReport Report)> StartFromFile(
        string path, ModularCA.Shared.Signing.ISigningService signer, bool mayMove = true, EnvVarConfigOverlay? environment = null)
    {
        var config = YamlConfigLoader.Load(path);
        var overlay = environment ?? new EnvVarConfigOverlay();
        var persistence = new SettingsPersistence(config, overlay, path);
        var report = await SettingsRuntime.StartAsync(Store(signer), config, persistence, overlay.EnvSourcedPaths, mayMove, withSecrets: true);
        return (config, persistence, report);
    }

    [Fact]
    public async Task The_secrets_the_node_uses_are_moved_out_of_the_file_wrapped_and_read_back_at_the_next_start()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());

        var first = await StartFromFile(path, signer);

        Assert.Equal(["Email_Password", "JWT_Secret", "LdapAuth_BindPassword", "Webhook_Endpoints"], first.Report.SecretsMoved!.Order());
        Assert.Empty(first.Report.SecretProblems!);
        // In force for this start, as they were.
        Assert.Equal(JwtSecret, first.Config.JWT.Secret);

        // Neither the file nor the copy of the file as it was holds one of them now.
        var yaml = File.ReadAllText(path);
        var copy = File.ReadAllText(first.Report.FileBackup!);
        foreach (var secret in new[] { JwtSecret, BindPassword, MailPassword, HookSecret })
        {
            Assert.DoesNotContain(secret, yaml);
            Assert.DoesNotContain(secret, copy);
        }
        // The copy still has what was not a secret, and the file still has the host's settings.
        Assert.Contains("MaxAddresses: 8", copy);
        Assert.Contains("Port: 9443", yaml);
        // The two single API keys are not moved: named keys replace them.
        Assert.Contains("the-api-key-from-the-file", yaml);
        // Nothing in the audit or the history holds one either.
        var audited = System.Text.Json.JsonSerializer.Serialize(_audit.Entries.Select(e => e.Details));
        Assert.DoesNotContain(JwtSecret, audited);
        Assert.DoesNotContain(HookSecret, audited);

        // The next start has only the stored ones to go by.
        var wraps = signer.Wraps;
        var second = await StartFromFile(path, signer);
        Assert.Equal(JwtSecret, second.Config.JWT.Secret);
        Assert.Equal(BindPassword, second.Config.LdapAuth.BindPassword);
        Assert.Equal(MailPassword, second.Config.Email.Password);
        Assert.Equal(HookSecret, Assert.Single(second.Config.Webhook.Endpoints).Secret);
        Assert.Empty(second.Report.SecretsMoved!);
        Assert.Empty(second.Report.SecretProblems!);
        Assert.Null(second.Report.FileBackup);
        Assert.Equal(wraps, signer.Wraps);
        Assert.Equal(yaml, File.ReadAllText(path));
    }

    /// <summary>A signer that is locked or out of reach at the first start must not cost anyone their secrets.</summary>
    [Fact]
    public async Task Without_a_signer_the_secrets_stay_in_the_file_and_keep_working_until_a_start_that_has_one()
    {
        var signer = new SettingsTestSigner { Unreachable = true };
        var path = WriteFullFile(FromFileWithSecrets());

        var first = await StartFromFile(path, signer);

        Assert.Empty(first.Report.SecretsMoved!);
        Assert.Contains(first.Report.SecretProblems!, p => p.StartsWith("The secrets stay in config.yaml"));
        Assert.Equal(JwtSecret, first.Config.JWT.Secret);
        Assert.Contains(JwtSecret, File.ReadAllText(path));
        Assert.DoesNotContain("MaxAddresses", File.ReadAllText(path));
        Assert.Empty((await Store().LoadAsync()).Secrets);

        signer.Unreachable = false;
        var second = await StartFromFile(path, signer);
        Assert.Equal(4, second.Report.SecretsMoved!.Count);
        Assert.DoesNotContain(JwtSecret, File.ReadAllText(path));
        Assert.DoesNotContain(JwtSecret, File.ReadAllText(second.Report.FileBackup!));
        Assert.Equal(JwtSecret, second.Config.JWT.Secret);
    }

    [Fact]
    public async Task A_stored_secret_that_cannot_be_read_back_is_reported_and_left_empty()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        await StartFromFile(path, signer);

        signer.Unreachable = true;
        var later = await StartFromFile(path, signer);

        Assert.Equal(string.Empty, later.Config.JWT.Secret);
        Assert.Contains(later.Report.SecretProblems!, p => p.StartsWith("JWT_Secret could not be unwrapped"));
        Assert.All(later.Report.SecretProblems!, p => Assert.DoesNotContain(JwtSecret, p));
    }

    [Fact]
    public async Task Another_role_reads_the_stored_secrets_and_moves_none()
    {
        var signer = new SettingsTestSigner();
        var controlPath = WriteFullFile(FromFileWithSecrets());
        await StartFromFile(controlPath, signer);

        // A host whose own file never had the mail password, and has an old bind password.
        var theirs = new SystemConfig { Https = { Port = 9443 }, LdapAuth = { BindPassword = "an-old-bind-password" } };
        var path = Path.Combine(_dir, "other-config.yaml");
        ConfigYamlWriter.Write(path, theirs);
        var before = File.ReadAllText(path);

        var other = await StartFromFile(path, signer, mayMove: false);

        Assert.Equal(MailPassword, other.Config.Email.Password);
        Assert.Equal(BindPassword, other.Config.LdapAuth.BindPassword);
        Assert.Empty(other.Report.SecretsMoved!);
        Assert.Equal(before, File.ReadAllText(path));
    }

    [Fact]
    public async Task A_secret_changed_in_memory_is_wrapped_and_stored_and_the_others_are_left_alone()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        var started = await StartFromFile(path, signer);
        var wraps = signer.Wraps;

        started.Config.Email.Password = "a-new-mail-password";
        started.Config.Acme.Http01.MaxAddresses = 12;
        await started.Persistence.SaveAsync(Store(signer), Alice);

        // One write, one wrap: the secrets that were not touched are not wrapped again.
        Assert.Equal(wraps + 1, signer.Wraps);
        var snapshot = await Store().LoadAsync();
        Assert.Equal(2, snapshot.Secrets["Email_Password"].Version);
        Assert.Equal(1, snapshot.Secrets["JWT_Secret"].Version);
        Assert.Equal(snapshot.Secrets["Email_Password"].Revision, snapshot.Settings["Acme_Http01_MaxAddresses"].Revision);
        Assert.DoesNotContain("a-new-mail-password", File.ReadAllText(path));
        Assert.DoesNotContain("a-new-mail-password", System.Text.Json.JsonSerializer.Serialize(_audit.Entries.Select(e => e.Details)));

        // Saving again changes nothing; emptying the secret clears it.
        await started.Persistence.SaveAsync(Store(signer), Alice);
        Assert.Equal(wraps + 1, signer.Wraps);
        started.Config.Email.Password = string.Empty;
        await started.Persistence.SaveAsync(Store(signer), Alice);
        Assert.Null((await Store().LoadAsync()).Secrets["Email_Password"].Value);

        var restarted = await StartFromFile(path, signer);
        Assert.Equal(string.Empty, restarted.Config.Email.Password);
        Assert.Equal(12, restarted.Config.Acme.Http01.MaxAddresses);
        Assert.Equal(JwtSecret, restarted.Config.JWT.Secret);
    }

    [Fact]
    public async Task When_the_signer_will_not_wrap_a_changed_secret_nothing_of_the_save_is_stored()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        var started = await StartFromFile(path, signer);
        var revision = (await Store().LoadAsync()).Revision;

        signer.Unreachable = true;
        started.Config.Email.Password = "a-new-mail-password";
        started.Config.Acme.Http01.MaxAddresses = 12;
        var refused = await Assert.ThrowsAsync<SettingsRefusedException>(() => started.Persistence.SaveAsync(Store(signer), Alice));

        Assert.Equal(SettingsRefusal.SignerRefused, refused.Reason);
        Assert.DoesNotContain("a-new-mail-password", refused.Message);
        Assert.Equal(revision, (await Store().LoadAsync()).Revision);
    }

    // ---- replacing the JWT secret ---------------------------------------------------------------

    [Fact]
    public async Task Rotating_the_JWT_secret_stores_a_new_one_for_the_next_start_and_leaves_this_start_on_its_own()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        var started = await StartFromFile(path, signer);
        Assert.Empty(started.Persistence.WaitingForRestart);

        var version = await started.Persistence.RotateJwtSecretAsync(Store(signer), Alice);

        // Stored, and not taken up: the key sessions are checked against was fixed at start.
        Assert.Equal(2, version);
        Assert.Equal(JwtSecret, started.Config.JWT.Secret);
        Assert.Equal([SettingsPersistence.JwtSecretKey], started.Persistence.WaitingForRestart);
        Assert.Equal(2, started.Persistence.Snapshot!.Secrets["JWT_Secret"].Version);

        // Saving something else afterwards does not put the old secret back.
        started.Config.Acme.Http01.MaxAddresses = 5;
        await started.Persistence.SaveAsync(Store(signer), Alice);
        Assert.Equal(2, (await Store().LoadAsync()).Secrets["JWT_Secret"].Version);

        // The next start runs on the new one, which is as long as the node requires.
        var next = await StartFromFile(path, signer);
        Assert.NotEqual(JwtSecret, next.Config.JWT.Secret);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(next.Config.JWT.Secret) >= 64);
        Assert.Empty(next.Persistence.WaitingForRestart);
        Assert.Empty(next.Report.SecretProblems!);

        // The change is recorded as a change to a secret, by who made it, and holds no secret.
        var record = _audit.Entries.Last(e => System.Text.Json.JsonSerializer.Serialize(e.Details).Contains("Rotated"));
        var recorded = System.Text.Json.JsonSerializer.Serialize(record.Details);
        Assert.Contains("replaced", recorded);
        Assert.DoesNotContain(next.Config.JWT.Secret, System.Text.Json.JsonSerializer.Serialize(_audit.Entries.Select(e => e.Details)));

        // A second rotation is a different secret.
        await next.Persistence.RotateJwtSecretAsync(Store(signer), Alice);
        var after = await StartFromFile(path, signer);
        Assert.NotEqual(next.Config.JWT.Secret, after.Config.JWT.Secret);
    }

    [Fact]
    public async Task Rotating_the_JWT_secret_is_refused_before_the_settings_are_moved_and_when_the_signer_will_not_wrap()
    {
        var config = FromFileWithSecrets();
        var path = WriteFullFile(config);
        var unmoved = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);
        var refused = await Assert.ThrowsAsync<SettingsRefusedException>(() => unmoved.RotateJwtSecretAsync(Store(new SettingsTestSigner()), Alice));
        Assert.Equal(SettingsRefusal.NotStoredInDatabase, refused.Reason);
        Assert.Empty((await Store().LoadAsync()).Secrets);

        var signer = new SettingsTestSigner();
        var started = await StartFromFile(path, signer);
        signer.Unreachable = true;
        refused = await Assert.ThrowsAsync<SettingsRefusedException>(() => started.Persistence.RotateJwtSecretAsync(Store(signer), Alice));
        Assert.Equal(SettingsRefusal.SignerRefused, refused.Reason);
        Assert.Empty(started.Persistence.WaitingForRestart);
        Assert.Equal(1, (await Store().LoadAsync()).Secrets["JWT_Secret"].Version);
    }

    /// <summary>
    /// A start that could not read the stored JWT secret runs on one it made up. That one is
    /// nobody's choice: saving a setting must not store it over the real one.
    /// </summary>
    [Fact]
    public async Task A_secret_the_process_made_up_for_itself_is_not_stored_by_a_later_save()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        await StartFromFile(path, signer);

        signer.Unreachable = true;
        var later = await StartFromFile(path, signer);
        Assert.Equal(string.Empty, later.Config.JWT.Secret);
        later.Config.JWT.Secret = "a-temporary-secret-made-up-for-this-start";
        later.Persistence.KeepSecretsAsHeld();

        signer.Unreachable = false;
        later.Config.Acme.Http01.MaxAddresses = 5;
        await later.Persistence.SaveAsync(Store(signer), Alice);

        Assert.Equal(1, (await Store().LoadAsync()).Secrets["JWT_Secret"].Version);
        var again = await StartFromFile(path, signer);
        Assert.Equal(JwtSecret, again.Config.JWT.Secret);
        Assert.Equal(5, again.Config.Acme.Http01.MaxAddresses);
    }

    // ---- what the console is told about each setting -------------------------------------------

    [Fact]
    public async Task The_console_is_told_where_each_setting_is_kept_and_when_a_change_takes_effect()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFullFile(FromFileWithSecrets());
        var started = await StartFromFile(path, signer);
        var environment = new HashSet<string> { "Email.OAuth2ClientId" };

        var described = SettingsDescriptions.Describe(started.Persistence.Snapshot, environment).ToDictionary(d => d.Key);

        // Stored, at its default, and from the environment.
        Assert.Equal(("database", "live", "database", 1), (described["Acme_Http01_MaxAddresses"].Kept, described["Acme_Http01_MaxAddresses"].Applies,
            described["Acme_Http01_MaxAddresses"].Source, described["Acme_Http01_MaxAddresses"].Version));
        Assert.Equal(("database", "default"), (described["Tokens_RefreshTokenDays"].Kept, described["Tokens_RefreshTokenDays"].Source));
        Assert.Equal("environment", described["Email_OAuth2ClientId"].Source);
        // Read once at start, so a change waits for a restart; and this host's own.
        Assert.Equal("restart", described["IpWhitelist_Enabled"].Applies);
        Assert.Equal(("host", "file"), (described["Https_Port"].Kept, described["Https_Port"].Source));
        Assert.Equal("bootstrap", described["DB_App_Host"].Kept);
        Assert.Equal("signer", described["Hsm_Pin"].Kept);
        // A moved secret is the database's; the single API keys are not moved.
        Assert.Equal((true, "database", "database"), (described["JWT_Secret"].Secret, described["JWT_Secret"].Kept, described["JWT_Secret"].Source));
        Assert.Equal(("host", "file"), (described["IntegrationApi_ApiKey"].Kept, described["IntegrationApi_ApiKey"].Source));
        // Nothing here is a value.
        var json = System.Text.Json.JsonSerializer.Serialize(described.Values);
        Assert.DoesNotContain(JwtSecret, json);
        Assert.DoesNotContain("the-api-key-from-the-file", json);

        // Before the settings are moved, the file decides every one of them.
        var before = SettingsDescriptions.Describe(null, new HashSet<string>()).ToDictionary(d => d.Key);
        Assert.Equal("file", before["Acme_Http01_MaxAddresses"].Source);
        Assert.Equal(SettingsCatalog.Definitions.Count, before.Count);
    }

    // ---- the host command ---------------------------------------------------------------------

    private async Task<(int Exit, string Out, string Err)> Run(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = await SettingsCommand.RunAsync(Store(), args, output, error);
        return (exit, output.ToString(), error.ToString());
    }

    [Fact]
    public async Task The_host_command_changes_a_setting_through_the_store_with_its_record()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);

        // The way back in after a setting locked the console out.
        var set = await Run("set", "IpWhitelist.Enabled", "false", "--reason", "locked out of the console");

        Assert.Equal(0, set.Exit);
        Assert.Contains("IpWhitelist_Enabled set at revision 2", set.Out);
        var stored = (await Store().LoadAsync()).Settings["IpWhitelist_Enabled"];
        Assert.Equal(("false", "Cli", SettingsCommand.Actor), (stored.ValueJson, stored.Source, stored.ActorName));
        Assert.Equal("locked out of the console", Assert.Single(await Store().HistoryAsync("IpWhitelist_Enabled")).Reason);
        Assert.Contains(_audit.Entries, e => e.TargetId == "2");

        // Text is taken as text, a list as JSON, and a key in any case.
        Assert.Equal(0, (await Run("set", "acme_cleanupschedule", "*/10 * * * *")).Exit);
        Assert.Equal(0, (await Run("set", "IpWhitelist_ExemptPaths", "[\"/health\"]")).Exit);
        var snapshot = await Store().LoadAsync();
        Assert.Equal("\"*/10 * * * *\"", snapshot.Settings["Acme_CleanupSchedule"].ValueJson);
        Assert.Equal("[\"/health\"]", snapshot.Settings["IpWhitelist_ExemptPaths"].ValueJson);

        var cleared = await Run("clear", "Acme_Http01_MaxAddresses");
        Assert.Equal(0, cleared.Exit);
        Assert.Null((await Store().LoadAsync()).Settings["Acme_Http01_MaxAddresses"].ValueJson);
    }

    [Fact]
    public async Task The_host_command_shows_what_is_set_and_where_a_value_comes_from()
    {
        await SettingsRuntime.ImportAsync(Store(), FromFile(), NoEnvironment);

        var list = await Run("list");
        Assert.Equal(0, list.Exit);
        Assert.Contains("Acme_Http01_MaxAddresses = 8", list.Out);
        Assert.DoesNotContain("JWT_Secret", list.Out);

        var stored = await Run("get", "Acme.Http01.MaxAddresses");
        Assert.Contains("value:   8", stored.Out);
        Assert.Contains("default: 4", stored.Out);
        var atDefault = await Run("get", "Tokens_RefreshTokenDays");
        Assert.Contains("the default; nothing is stored", atDefault.Out);

        var history = await Run("history", "Acme_Http01_MaxAddresses");
        Assert.Contains("revision 1", history.Out);
        Assert.Contains("(Import)", history.Out);
    }

    [Theory]
    [InlineData(1, "is not a setting", "set", "Acme_Http01_Bogus", "1")]
    [InlineData(1, "set per host", "set", "Https_Port", "9443")]
    [InlineData(1, "belongs to the signer", "get", "Hsm_Pin")]
    [InlineData(2, "is a secret", "set", "JWT_Secret", "anything-at-all")]
    [InlineData(1, "Usage", "clear", "JWT_Secret", "extra")]
    [InlineData(2, "a number", "set", "Acme_Http01_MaxAddresses", "many")]
    [InlineData(1, "Usage", "set", "Acme_Http01_MaxAddresses")]
    [InlineData(1, "Usage", "remove", "Acme_Http01_MaxAddresses")]
    [InlineData(1, "Usage")]
    public async Task The_host_command_refuses_what_the_store_does_not_hold_and_says_why(int exit, string says, params string[] args)
    {
        var result = await Run(args);

        Assert.Equal(exit, result.Exit);
        Assert.Contains(says, result.Err);
        Assert.Empty((await Store().LoadAsync()).Settings);
        Assert.DoesNotContain("anything-at-all", result.Err + result.Out);
    }
}

/// <summary>
/// Rotating the JWT secret on a node whose secret comes from the environment. Apart from
/// <see cref="SettingsRuntimeTests"/> because it sets a process-wide variable.
/// </summary>
[Collection(EnvVarsCollection.Name)]
public sealed class JwtSecretFromEnvironmentTests
{
    [Fact]
    public async Task Rotating_is_refused_where_an_environment_variable_supplies_the_secret()
    {
        const string variable = "MODULARCA__JWT__SECRET";
        var config = new SystemConfig();
        var overlay = new EnvVarConfigOverlay();
        var original = Environment.GetEnvironmentVariable(variable);
        Environment.SetEnvironmentVariable(variable, "the-jwt-secret-from-the-environment");
        try { overlay.Apply(config); }
        finally { Environment.SetEnvironmentVariable(variable, original); }

        var databaseName = $"settings-jwt-env-{Guid.NewGuid():N}";
        var signer = new SettingsTestSigner();
        SettingsStore Store() => new(InMemoryDbContextFactory.Create(databaseName), new RecordingAuditService(), signer, NullLogger<SettingsStore>.Instance);
        var path = Path.Combine(Path.GetTempPath(), $"mca-settings-jwt-env-{Guid.NewGuid():N}.yaml");
        try
        {
            var persistence = new SettingsPersistence(config, overlay, path);
            await SettingsRuntime.StartAsync(Store(), config, persistence, overlay.EnvSourcedPaths, mayMove: true, withSecrets: true);
            Assert.True(persistence.StoreInUse);

            var refused = await Assert.ThrowsAsync<SettingsRefusedException>(
                () => persistence.RotateJwtSecretAsync(Store(), new SettingsActor(Guid.NewGuid(), "alice")));

            Assert.Equal(SettingsRefusal.NotStoredInDatabase, refused.Reason);
            Assert.Contains("environment variable", refused.Message);
            Assert.False((await Store().LoadAsync()).Secrets.ContainsKey("JWT_Secret"));
            Assert.Equal(0, signer.Wraps);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }
}
