using System.Security.Cryptography;
using System.Text.Json.Nodes;
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
    /// <summary>The key of the JWT secret in the settings store.</summary>
    public const string JwtSecretKey = "JWT_Secret";

    private volatile SettingsSnapshot? _snapshot;
    private volatile IReadOnlyDictionary<string, string>? _secretBaseline;
    private volatile IReadOnlyList<string> _waitingForRestart = [];

    /// <summary>
    /// The keys of secrets stored since this process started that it is not running on: it
    /// reads them at its next start.
    /// </summary>
    public IReadOnlyList<string> WaitingForRestart => _waitingForRestart;

    /// <summary>The stored settings as last read or written by this process; null while the store is not in use.</summary>
    public SettingsSnapshot? Snapshot => _snapshot;

    /// <summary>Whether the instance-wide settings are in the database, which they are once they have been moved there.</summary>
    public bool StoreInUse => _snapshot?.ImportedAt != null;

    /// <summary>The <c>config.yaml</c> this process writes.</summary>
    public string ConfigPath { get; } = configPath;

    /// <summary>
    /// Takes <paramref name="snapshot"/> as the stored settings this process is running on.
    /// <paramref name="secretBaseline"/> is what the configuration holds for each secret now, to
    /// tell a later change by; null when this process does not handle the stored secrets.
    /// </summary>
    public void Use(SettingsSnapshot snapshot, IReadOnlyDictionary<string, string>? secretBaseline = null)
    {
        _snapshot = snapshot;
        _secretBaseline = secretBaseline;
    }

    /// <summary>
    /// Takes the secrets as the configuration holds them now for unchanged. For a secret this
    /// process made up for itself (the temporary JWT secret of a start that could not read the
    /// stored one), which a later save must not store as if someone had set it.
    /// </summary>
    public void KeepSecretsAsHeld()
    {
        if (_secretBaseline != null)
            _secretBaseline = SettingsRuntime.SecretBaseline(config, environment.EnvSourcedPaths);
    }

    /// <summary>
    /// Stores a new, random JWT secret, wrapped by the signer, and returns its version. The
    /// configuration in memory keeps the secret this process started with, because the key
    /// sessions are checked against is fixed at start: the new one is used from the next start
    /// of each node, when access tokens signed with the old one stop being accepted.
    /// </summary>
    /// <exception cref="SettingsRefusedException">
    /// The settings are not in the database yet, an environment variable supplies the secret, or
    /// the signer would not wrap. Nothing was stored.
    /// </exception>
    public async Task<int> RotateJwtSecretAsync(ISettingsStore store, SettingsActor actor, CancellationToken cancellationToken = default)
    {
        if (!StoreInUse)
            throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                "The settings have not been moved to the database on this node, so the JWT secret is the one in its config.yaml.", JwtSecretKey);
        if (environment.EnvSourcedPaths.Contains(SettingsCatalog.Find(JwtSecretKey)!.Path))
            throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                "An environment variable supplies the JWT secret on this node and wins over a stored one. Change it there.", JwtSecretKey);

        // 64 random bytes, as setup generates it.
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        await store.WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, JsonNode?> { [JwtSecretKey] = JsonValue.Create(secret) },
            Actor = actor, Source = SettingsSource.Api,
            Reason = "Rotated: a new secret was generated. In use from each node's next start.",
        }, cancellationToken);

        var snapshot = await store.LoadAsync(cancellationToken);
        _snapshot = snapshot;
        if (!_waitingForRestart.Contains(JwtSecretKey))
            _waitingForRestart = [.. _waitingForRestart, JwtSecretKey];
        return snapshot.Secrets[JwtSecretKey].Version;
    }

    /// <summary>
    /// The dotted paths of the settings the store holds for this process, which the file leaves
    /// out: the instance-wide settings, and each secret that has been stored. A secret that has
    /// not been stored yet stays in the file, where it still works.
    /// </summary>
    public IReadOnlyList<string> StoredPaths()
    {
        var paths = SettingsRuntime.Covered(environment.EnvSourcedPaths).Select(d => d.Path).ToList();
        if (_snapshot is { } snapshot)
            paths.AddRange(SettingsRuntime.CoveredSecrets(environment.EnvSourcedPaths)
                .Where(d => snapshot.Secrets.ContainsKey(d.Key)).Select(d => d.Path));
        return paths;
    }

    /// <summary>
    /// Saves the configuration as it stands in memory: changed instance-wide settings to
    /// <paramref name="store"/> when the store is in use, then the file.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The store refused a value; neither the store nor the file was changed.</exception>
    public async Task SaveAsync(ISettingsStore store, SettingsActor actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        if (StoreInUse && _secretBaseline is { } baseline)
            (_snapshot, _secretBaseline) = await SettingsRuntime.SaveWithSecretsAsync(
                store, config, environment.EnvSourcedPaths, baseline, actor, SettingsSource.Api, reason, cancellationToken);
        else if (StoreInUse)
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
