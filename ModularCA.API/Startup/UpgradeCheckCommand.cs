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
/// scopes, so a key fenced to a scope the upgrade deletes is refused too, and with the installed
/// application directory (the config directory's parent), so the SSH CA key files the first start
/// imports into the signer are looked for where the install keeps them. Applies nothing: its only write is
/// a dry run it rolls back.
/// <para>
/// <c>--upgrade-check --read-only</c> is the same check without the dry run, for running beside a
/// node that is still serving: it reads only, takes no migration lock, and says whether anything is
/// pending (<see cref="SchemaStartup.PendingNotRehearsedExitCode"/>) so the caller knows whether the
/// full check, with the node stopped, is needed.
/// </para>
/// </summary>
public static class UpgradeCheckCommand
{
    /// <summary>
    /// What to say when <c>db.yaml</c> cannot be used: that this account may not read it, with the
    /// account to run as, or that it is not there.
    /// </summary>
    /// <param name="dbYamlPath">The path that was looked for.</param>
    /// <param name="unreadable">True when the file or its directory refused this account.</param>
    /// <param name="userName">The account the check is running as.</param>
    internal static string NoDbYamlMessage(string dbYamlPath, bool unreadable, string userName) => unreadable
        ? $"{dbYamlPath} cannot be read by '{userName}': nothing was checked. Run the check as the account the service runs as, for example: sudo -u modularca <build>/ModularCA.API --upgrade-check --config-dir {Path.GetDirectoryName(dbYamlPath)}"
        : $"{dbYamlPath} not found: nothing to check. Point --config-dir at an installed config directory.";

    /// <summary>
    /// True when opening <paramref name="path"/> is refused for lack of permission, on the file or
    /// on a directory above it. <see cref="File.Exists(string)"/> answers false for both that and
    /// a file that is absent.
    /// </summary>
    private static bool IsUnreadable(string path)
    {
        try
        {
            using var _ = File.OpenRead(path);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
        catch (Exception e) when (e is IOException or NotSupportedException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Runs the check against the configuration in <paramref name="configDir"/> and returns the
    /// exit status: 0 clean, <see cref="SchemaStartup.ExitCode"/> refused (a configuration this
    /// build cannot start with included), <see cref="SchemaStartup.TempFailExitCode"/>
    /// unreachable, 1 when there is no <c>db.yaml</c> to check. Before anything else it checks that
    /// this build can build its web host (<see cref="HostSelfCheck"/>): a build that cannot is
    /// refused here, while the version it would replace is still running. With
    /// <paramref name="readOnly"/> nothing is rehearsed and nothing is locked, and migrations that
    /// are pending with nothing read refusing them exit
    /// <see cref="SchemaStartup.PendingNotRehearsedExitCode"/>; the refusals, 75 and 1 are as
    /// without it.
    /// </summary>
    /// <param name="configDir">The installed config directory.</param>
    /// <param name="readOnly">True for <c>--read-only</c>: no dry run, no migration lock, no write.</param>
    /// <remarks>
    /// A <c>db.yaml</c> the caller may not read is told apart from one that is absent
    /// (<see cref="NoDbYamlMessage"/>): the config directory belongs to the service account, and
    /// the check run as anyone else used to say the file was not found.
    /// </remarks>
    public static async Task<int> RunAsync(string configDir, bool readOnly = false)
    {
        Console.WriteLine(readOnly
            ? $"ModularCA upgrade check against {configDir} (--read-only: reads only; nothing is rehearsed and no migration lock is taken)"
            : $"ModularCA upgrade check against {configDir} (read-only; the dry run is rolled back)");
        if (HostSelfCheck.Run() is { } cannotStart)
        {
            Console.Error.WriteLine(cannotStart);
            Console.WriteLine("UPGRADE CHECK: REFUSED (this build cannot start). Nothing was changed.");
            return SchemaStartup.ExitCode;
        }
        var dbYamlPath = Path.Combine(configDir, "db.yaml");
        if (!File.Exists(dbYamlPath))
        {
            Console.Error.WriteLine(NoDbYamlMessage(dbYamlPath, IsUnreadable(dbYamlPath), Environment.UserName));
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
        // A key path a row gives relative is relative to the installed application directory,
        // which is the config directory's parent, not to where this build was unpacked.
        var installDirectory = Path.GetDirectoryName(Path.GetFullPath(configDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            ?? Path.GetFullPath(configDir);
        return await SchemaStartup.UpgradeCheckAsync(targets, config.Schema,
            scopes: ModularCA.Core.Services.IntegrationScopeCheck.Configured(config),
            installDirectory: installDirectory, readOnly: readOnly);
    }
}
