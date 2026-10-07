using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Settings;

/// <summary>
/// Where a change to the running configuration is saved. Every settings endpoint changes the
/// <see cref="SystemConfig"/> in memory and then calls here, as it used to call the YAML writer.
/// </summary>
/// <remarks>
/// <para>
/// Before the settings have been moved to the database (setup mode, or a start before the move),
/// the whole configuration is written to <c>config.yaml</c>, as it always was.
/// </para>
/// <para>
/// After the move, the instance-wide settings that changed are written to the settings store,
/// with their history and audit record, and <c>config.yaml</c> is written with what belongs to
/// the host only. The store is written first: if it refuses, the file is left alone, so the two
/// never disagree about which of them holds a setting.
/// </para>
/// </remarks>
public sealed class SettingsPersistence(
    SystemConfig config,
    EnvVarConfigOverlay environment,
    string configPath)
{
    private volatile SettingsSnapshot? _snapshot;

    /// <summary>The stored settings as last read or written by this process; null while the store is not in use.</summary>
    public SettingsSnapshot? Snapshot => _snapshot;

    /// <summary>Whether the instance-wide settings are in the database, which they are once they have been moved there.</summary>
    public bool StoreInUse => _snapshot?.ImportedAt != null;

    /// <summary>The <c>config.yaml</c> this process writes.</summary>
    public string ConfigPath { get; } = configPath;

    /// <summary>Takes <paramref name="snapshot"/> as the stored settings this process is running on.</summary>
    public void Use(SettingsSnapshot snapshot) => _snapshot = snapshot;

    /// <summary>The dotted paths of the settings the store holds for this process, which the file leaves out.</summary>
    public IReadOnlyList<string> StoredPaths() =>
        SettingsRuntime.Covered(environment.EnvSourcedPaths).Select(d => d.Path).ToList();

    /// <summary>
    /// Saves the configuration as it stands in memory: changed instance-wide settings to
    /// <paramref name="store"/> when the store is in use, then the file.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The store refused a value; neither the store nor the file was changed.</exception>
    public async Task SaveAsync(ISettingsStore store, SettingsActor actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        if (StoreInUse)
            _snapshot = await SettingsRuntime.SaveAsync(store, config, environment.EnvSourcedPaths, actor, SettingsSource.Api, reason, cancellationToken);
        WriteFile();
    }

    /// <summary>
    /// Writes <c>config.yaml</c> from the configuration in memory: all of it before the move,
    /// and what belongs to the host after it. Secrets supplied by the environment are left out
    /// either way. For a change that touches host-local settings only. After the move the file
    /// is left untouched when it already says what would be written, so saving a setting the
    /// store holds does not need the file to be writable.
    /// </summary>
    public void WriteFile()
    {
        Exception? failure = null;
        environment.WithSecretsProtected(config, () =>
        {
            try
            {
                if (!StoreInUse)
                {
                    ConfigYamlWriter.Write(ConfigPath, config);
                    return;
                }
                var contents = ConfigYamlWriter.Serialize(config, StoredPaths());
                if (File.Exists(ConfigPath) && File.ReadAllText(ConfigPath) == contents)
                    return;
                ConfigYamlWriter.WriteKeepingAccess(ConfigPath, contents);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        if (failure != null)
            throw failure;
    }
}
