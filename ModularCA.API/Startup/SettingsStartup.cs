using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// The settings step of a start: once the schema is current, the instance-wide settings are
/// taken from the database, and the control role moves them there out of <c>config.yaml</c> the
/// first time. It runs before the web host is built, over connections of its own, so nothing
/// that is configured from a setting sees the file's value instead of the stored one.
/// </summary>
public static class SettingsStartup
{
    /// <summary>
    /// Runs <see cref="SettingsRuntime.StartAsync"/> and says what it did. Throws when the store
    /// cannot be read or written: the schema check has just passed, so that is a fault and not
    /// something to start past, and a start on the file's values would, after the move, be a
    /// start on the defaults.
    /// </summary>
    public static async Task<SettingsStartReport> RunAsync(SystemConfig config, EnvVarConfigOverlay environment,
        SettingsPersistence persistence, bool controlActive)
    {
        await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(PostgresConnection.Build(config.DB.App)).Options);
        await using var auditDb = string.IsNullOrWhiteSpace(config.DB.Audit.Database) ? null
            : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                .UseNpgsql(PostgresConnection.Build(config.DB.Audit)).Options);

        // Ordinary settings only: the secrets are not moved yet, so no signer is asked.
        var store = new SettingsStore(db, new HostAuditService(auditDb), new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);
        var report = await SettingsRuntime.StartAsync(store, config, persistence, environment.EnvSourcedPaths, mayMove: controlActive);

        if (report.Import is { Ran: true } import)
        {
            Log.Warning("Settings: {Count} instance-wide setting(s) moved from config.yaml to the database at revision {Revision}: {Keys}",
                import.ImportedKeys.Count, import.Revision, string.Join(", ", import.ImportedKeys));
            Console.WriteLine($"[SETTINGS] Moved {import.ImportedKeys.Count} instance-wide setting(s) from config.yaml to the database (revision {import.Revision}).");
        }
        if (report.FileBackup != null)
        {
            Log.Warning("Settings: config.yaml rewritten with this host's settings only; the file as it was is {Backup}", report.FileBackup);
            Console.WriteLine($"[SETTINGS] config.yaml now holds this host's settings only. The file as it was: {report.FileBackup}");
        }
        foreach (var key in report.SupersededCleared ?? [])
            Log.Warning("Settings: {Key} held a default of an earlier build, which nobody chose. It was cleared, and the current default is in force.", key);
        if (report.FileProblem != null)
        {
            Log.Warning("Settings: config.yaml could not be rewritten without the settings that are now in the database ({Problem}). They are ignored where they stand.", report.FileProblem);
        }
        if (report.Snapshot.ImportedAt == null)
        {
            Log.Information("Settings: not yet moved to the database (the control role moves them at its first start); config.yaml decides.");
        }
        else
        {
            Log.Information("Settings: {Applied} stored setting(s) applied at revision {Revision}.", report.Load.Applied, report.Load.Revision);
            foreach (var path in report.Load.IgnoredFileKeys)
                Log.Warning("Settings: {Path} is set in config.yaml and ignored: instance-wide settings are in the database. Remove it from the file, or change it in the console.", path);
        }
        foreach (var problem in report.Load.Problems)
            Log.Warning("Settings: a stored setting was not applied. {Problem}", problem);
        return report;
    }
}
