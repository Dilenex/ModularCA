using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--upgrade-check [--config-dir &lt;dir&gt;]</c>: whether this build's control role would upgrade
/// the installed databases cleanly, run as the service user before the build is installed.
/// Reads <c>db.yaml</c> (the runtime roles, as the control role uses them) and the <c>Schema</c>
/// budgets in <c>config.yaml</c> from the config directory, then runs
/// <see cref="SchemaStartup.UpgradeCheckAsync"/> with the integration keys' configured space
/// scopes, so a key fenced to a scope the upgrade deletes is refused too. Applies nothing: its only write is
/// a dry run it rolls back.
/// </summary>
public static class UpgradeCheckCommand
{
    /// <summary>
    /// Runs the check against the configuration in <paramref name="configDir"/> and returns the
    /// exit status: 0 clean, <see cref="SchemaStartup.ExitCode"/> refused (a configuration this
    /// build cannot start with included), <see cref="SchemaStartup.TempFailExitCode"/>
    /// unreachable, 1 when there is no <c>db.yaml</c> to check.
    /// </summary>
    public static async Task<int> RunAsync(string configDir)
    {
        Console.WriteLine($"ModularCA upgrade check against {configDir} (read-only; the dry run is rolled back)");
        var dbYamlPath = Path.Combine(configDir, "db.yaml");
        if (!File.Exists(dbYamlPath))
        {
            Console.Error.WriteLine($"{dbYamlPath} not found: nothing to check. Point --config-dir at an installed config directory.");
            return 1;
        }

        var config = new SystemConfig();
        try
        {
            var configPath = Path.Combine(configDir, "config.yaml");
            if (File.Exists(configPath))
                config = YamlConfigLoader.Load(configPath, Console.WriteLine);
            var dbYaml = YamlDbConfigLoader.Load(dbYamlPath)!;
            foreach (var (target, source) in new[] { (config.DB.App, dbYaml.App), (config.DB.Audit, dbYaml.Audit) })
            {
                target.Host = source.Host;
                target.Port = source.Port;
                target.Database = source.Database;
                target.Username = source.Username;
                target.Password = source.Password;
                target.SslMode = source.SslMode;
            }
            new EnvVarConfigOverlay().Apply(config);
            LegacyDatabaseGuard.EnsureNotMySql(config.DB);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"The configuration in {configDir} cannot be used by this build: {ex.Message}");
            Console.WriteLine("UPGRADE CHECK: REFUSED (configuration). Nothing was changed.");
            return SchemaStartup.ExitCode;
        }

        var targets = new List<SchemaTarget> { new("application", DatabaseKind.Application, config.DB.App) };
        if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
            targets.Add(new("audit", DatabaseKind.Audit, config.DB.Audit));
        return await SchemaStartup.UpgradeCheckAsync(targets, config.Schema,
            scopes: ModularCA.Core.Services.IntegrationScopeCheck.Configured(config));
    }
}
