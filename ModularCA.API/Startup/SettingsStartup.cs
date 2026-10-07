using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// The settings step of a start: once the schema is current, the instance-wide settings and the
/// secrets are taken from the database, and the control role moves them there out of
/// <c>config.yaml</c> the first time. It runs before the web host is built, over connections of
/// its own, so nothing that is configured from a setting sees the file's value instead of the
/// stored one.
/// </summary>
public static class SettingsStartup
{
    /// <summary>How this process reaches a signer before its web host exists.</summary>
    /// <param name="Remote">Whether the signer is another process, reached as <c>Signer.*</c> says.</param>
    /// <param name="KeystoresDirectory">The keystore files, for a signer in this process.</param>
    /// <param name="KeystoreYamlPath">The keystore configuration, for a signer in this process.</param>
    public sealed record SignerAccess(bool Remote, string KeystoresDirectory, string KeystoreYamlPath);

    /// <summary>
    /// Runs <see cref="SettingsRuntime.StartAsync"/> and says what it did. Throws when the store
    /// cannot be read or written: the schema check has just passed, so that is a fault and not
    /// something to start past, and a start on the file's values would, after the move, be a
    /// start on the defaults. A signer that cannot be reached is not such a fault: the secrets
    /// are then left where they are, and the log says which could not be read.
    /// </summary>
    /// <param name="signerAccess">How to reach a signer for the secrets; null for a process that uses none (an ingress).</param>
    public static async Task<SettingsStartReport> RunAsync(SystemConfig config, EnvVarConfigOverlay environment,
        SettingsPersistence persistence, bool controlActive, SignerAccess? signerAccess)
    {
        await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(PostgresConnection.Build(config.DB.App)).Options);
        await using var auditDb = string.IsNullOrWhiteSpace(config.DB.Audit.Database) ? null
            : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                .UseNpgsql(PostgresConnection.Build(config.DB.Audit)).Options);

        var signer = signerAccess == null ? null : OpenSigner(config, signerAccess);
        try
        {
            var store = new SettingsStore(db, new HostAuditService(auditDb), signer ?? new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);
            var report = await SettingsRuntime.StartAsync(store, config, persistence, environment.EnvSourcedPaths,
                mayMove: controlActive, withSecrets: signerAccess != null);
            Describe(report);
            return report;
        }
        finally
        {
            (signer as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// A signer for wrapping and unwrapping the secret settings: the remote one the node is
    /// configured for, or this process's own keystore, unlocked as the node unlocks it. Null,
    /// with the reason logged, when neither can be had; the secrets then wait for a start that
    /// has one.
    /// </summary>
    private static ISigningService? OpenSigner(SystemConfig config, SignerAccess access)
    {
        try
        {
            if (!access.Remote)
                return ModularCA.Keystore.Signing.MaintenanceSigner.CreateUnlocked(
                    access.KeystoresDirectory, access.KeystoreYamlPath, PostgresConnection.Build(config.DB.App));

            var options = new ModularCA.Signer.Client.RemoteSignerOptions(
                new Uri(config.Signer.Endpoint, UriKind.Absolute),
                ModularCA.Signer.Identity.Pkcs12Files.Load(
                    SignerConfig.ResolvePath(config.Signer.ClientCertificate, AppContext.BaseDirectory),
                    config.Signer.ClientCertificatePassword),
                config.Signer.PinnedServerSpki);
            return new ModularCA.Signer.Client.RemoteSigningService(options,
                NullLogger<ModularCA.Signer.Client.RemoteSigningService>.Instance);
        }
        catch (Exception ex)
        {
            Log.Warning("Settings: no signer could be opened for the secret settings ({Kind}: {Message}).", ex.GetType().Name, ex.Message);
            return null;
        }
    }

    private static void Describe(SettingsStartReport report)
    {
        if (report.Import is { Ran: true } import)
        {
            Log.Warning("Settings: {Count} instance-wide setting(s) moved from config.yaml to the database at revision {Revision}: {Keys}",
                import.ImportedKeys.Count, import.Revision, string.Join(", ", import.ImportedKeys));
            Console.WriteLine($"[SETTINGS] Moved {import.ImportedKeys.Count} instance-wide setting(s) from config.yaml to the database (revision {import.Revision}). The rest are at their defaults.");
        }
        if (report.SecretsMoved is { Count: > 0 } moved)
        {
            Log.Warning("Settings: {Count} secret(s) moved from config.yaml to the database, wrapped by the signer: {Keys}. Earlier copies of config.yaml, and backup archives made before now, still hold them in the clear.",
                moved.Count, string.Join(", ", moved));
            Console.WriteLine($"[SETTINGS] Moved {moved.Count} secret(s) from config.yaml to the database, wrapped by the signer.");
        }
        foreach (var problem in report.SecretProblems ?? [])
            Log.Warning("Settings: {Problem}", problem);
        foreach (var key in report.SupersededCleared ?? [])
            Log.Warning("Settings: {Key} held a default of an earlier build, which nobody chose. It was cleared, and the current default is in force.", key);
        if (report.FileBackup != null)
        {
            Log.Warning("Settings: config.yaml rewritten with this host's settings only; the file as it was, less the secrets that were moved, is {Backup}", report.FileBackup);
            Console.WriteLine($"[SETTINGS] config.yaml now holds this host's settings only. The file as it was, less the moved secrets: {report.FileBackup}");
        }
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
    }
}
