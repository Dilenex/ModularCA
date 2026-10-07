using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services.Settings;

/// <summary>What bringing the stored settings onto the configuration found.</summary>
/// <param name="Revision">The revision the configuration now reflects.</param>
/// <param name="Applied">How many stored settings were set on the configuration.</param>
/// <param name="IgnoredFileKeys">
/// Settings the configuration file still sets to something other than what is in force. The
/// file no longer decides them, so each is named for the operator to remove.
/// </param>
/// <param name="Problems">Stored rows this build could not use.</param>
public sealed record SettingsLoadReport(long Revision, int Applied, IReadOnlyList<string> IgnoredFileKeys, IReadOnlyList<string> Problems);

/// <summary>What the one-time move from <c>config.yaml</c> to the store did.</summary>
/// <param name="Ran">False when the settings had been moved before, and nothing was done.</param>
/// <param name="Revision">The revision the move wrote, or the current one when every setting was at its default.</param>
/// <param name="ImportedKeys">The settings that were stored: those the file set to something other than the default.</param>
public sealed record SettingsImportReport(bool Ran, long Revision, IReadOnlyList<string> ImportedKeys);

/// <summary>What the settings step of a start did.</summary>
/// <param name="Snapshot">The stored settings the process is now running on.</param>
/// <param name="Import">The one-time move, when this process was allowed to make it; null otherwise.</param>
/// <param name="Load">What applying the stored settings found.</param>
/// <param name="FileBackup">Where the configuration file was copied before it was rewritten without the stored settings; null when it was not rewritten.</param>
/// <param name="FileProblem">Why the configuration file could not be rewritten, when it should have been; null otherwise.</param>
/// <param name="SupersededCleared">Stored settings this start cleared because their value was only a default an earlier build shipped.</param>
public sealed record SettingsStartReport(SettingsSnapshot Snapshot, SettingsImportReport? Import, SettingsLoadReport Load, string? FileBackup,
    string? FileProblem = null, IReadOnlyList<string>? SupersededCleared = null);

/// <summary>
/// The settings store as the running node uses it: which settings it covers, how the stored
/// values reach the configuration at start, how a change made to the configuration reaches the
/// store, and the one-time move out of <c>config.yaml</c>.
/// </summary>
/// <remarks>
/// <para>
/// It covers the instance-wide settings and not, yet, the secrets: those stay in the
/// configuration file until the node can ask its signer for them at start. Bootstrap, signer and
/// host-local settings never leave their files.
/// </para>
/// <para>
/// The store is sparse. A setting is stored when it differs from its built-in default, so the
/// test for "does this need writing" is the same at the move and at every save: compare what the
/// configuration holds with what the store would give, which is the stored value or the default.
/// </para>
/// </remarks>
public static class SettingsRuntime
{
    /// <summary>The actor recorded for the move out of the configuration file.</summary>
    public static string ImportActor => $"host:{Environment.MachineName}:import";

    /// <summary>
    /// The settings the store decides: instance-wide ones the environment does not set.
    /// <paramref name="environmentPaths"/> are the dotted paths an environment variable supplied,
    /// which the store neither overrides nor records.
    /// </summary>
    public static IEnumerable<SettingDefinition> Covered(IReadOnlySet<string> environmentPaths) =>
        SettingsCatalog.Definitions.Where(d => d.Class == SettingClass.InstanceWide && !environmentPaths.Contains(d.Path));

    /// <summary>
    /// Puts back to its default a setting whose value in <paramref name="config"/> is only a
    /// default an earlier build shipped. Such a value was written into <c>config.yaml</c> by that
    /// build and carried along ever since; nobody chose it, so it is not a choice to store or to
    /// warn about. The source-code URL is the one there is: the project's repository moved, and
    /// the old address is published as the new one already (<see cref="SourceCodeConfig.EffectiveUrl"/>).
    /// </summary>
    public static void DropSupersededDefaults(SystemConfig config)
    {
        if (SourceCodeConfig.IsSuperseded(config.SourceCode.Url))
            config.SourceCode.Url = SourceCodeConfig.UpstreamUrl;
    }

    /// <summary>
    /// The stored settings whose value is only a default an earlier build shipped, by key: what
    /// a start clears from the store, where a move made before this was known put them.
    /// </summary>
    public static IReadOnlyList<string> SupersededStored(SettingsSnapshot snapshot)
    {
        var keys = new List<string>();
        if (snapshot.Settings.GetValueOrDefault("SourceCode_Url")?.ValueJson is { } json)
        {
            try
            {
                if (JsonNode.Parse(json) is JsonValue value && value.TryGetValue<string>(out var url) && SourceCodeConfig.IsSuperseded(url))
                    keys.Add("SourceCode_Url");
            }
            catch (System.Text.Json.JsonException)
            {
            }
        }
        return keys;
    }

    /// <summary>
    /// What has to be written to make the store give what <paramref name="config"/> holds: each
    /// covered setting whose value differs from the stored one, or from the default where
    /// nothing is stored.
    /// </summary>
    public static IReadOnlyDictionary<string, JsonNode?> Differences(SystemConfig config, SettingsSnapshot snapshot, IReadOnlySet<string> environmentPaths)
    {
        var defaults = new SystemConfig();
        var changes = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var definition in Covered(environmentPaths))
        {
            // An endpoint that clears a text box leaves null where the setting's type says text.
            // The file took that as nothing; so does the store, as the empty value of the type.
            var held = SettingsCatalog.Read(config, definition)
                ?? (definition.AllowsNull ? null : SettingsCatalog.EmptyValue(definition));
            var heldJson = SettingsCatalog.CanonicalJson(definition, held);
            var stored = snapshot.Settings.GetValueOrDefault(definition.Key)?.ValueJson;
            var inForce = stored ?? SettingsCatalog.CanonicalJson(definition, SettingsCatalog.Read(defaults, definition));
            if (!string.Equals(heldJson, inForce, StringComparison.Ordinal))
                changes[definition.Key] = held;
        }
        return changes;
    }

    /// <summary>
    /// Sets the stored settings on <paramref name="config"/>. Once the settings have been moved
    /// out of the configuration file, the file no longer decides a covered setting: each goes
    /// back to its default before the stored values are applied, and one the file still sets
    /// differently is reported. Before the move, the file's values stand and stored ones are
    /// applied over them.
    /// </summary>
    public static SettingsLoadReport Apply(SystemConfig config, SettingsSnapshot snapshot, IReadOnlySet<string> environmentPaths)
    {
        DropSupersededDefaults(config);
        var defaults = new SystemConfig();
        var ignored = new List<string>();
        var problems = new List<string>();
        var applied = 0;

        foreach (var definition in Covered(environmentPaths))
        {
            var stored = snapshot.Settings.GetValueOrDefault(definition.Key)?.ValueJson;
            var defaultValue = SettingsCatalog.Read(defaults, definition);

            JsonNode? value;
            if (stored == null)
            {
                if (snapshot.ImportedAt == null) continue;
                value = defaultValue;
            }
            else
            {
                try { value = JsonNode.Parse(stored); }
                catch (System.Text.Json.JsonException)
                {
                    problems.Add($"{definition.Key} holds a value that is not JSON.");
                    continue;
                }
                if (SettingsCatalog.Problem(definition, value) is { } problem)
                {
                    problems.Add(problem);
                    continue;
                }
                applied++;
            }

            if (snapshot.ImportedAt != null)
            {
                var fromFile = SettingsCatalog.CanonicalJson(definition, SettingsCatalog.Read(config, definition));
                if (fromFile != SettingsCatalog.CanonicalJson(definition, defaultValue)
                    && fromFile != SettingsCatalog.CanonicalJson(definition, value))
                    ignored.Add(definition.Path);
            }
            SettingsCatalog.Apply(config, definition, value);
        }

        foreach (var key in snapshot.Settings.Keys.OrderBy(k => k, StringComparer.Ordinal))
            if (SettingsCatalog.Find(key) == null)
                problems.Add($"{key} is not a setting this build knows.");

        return new SettingsLoadReport(snapshot.Revision, applied, ignored, problems);
    }

    /// <summary>
    /// Writes to the store whatever <paramref name="config"/> holds that the store does not, and
    /// returns the snapshot afterwards. Called after a change was made to the configuration in
    /// memory, which is how every settings endpoint works.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The store refused the change; nothing was written.</exception>
    public static async Task<SettingsSnapshot> SaveAsync(ISettingsStore store, SystemConfig config, IReadOnlySet<string> environmentPaths,
        SettingsActor actor, string source, string? reason = null, CancellationToken cancellationToken = default)
    {
        var snapshot = await store.LoadAsync(cancellationToken);
        var changes = Differences(config, snapshot, environmentPaths);
        if (changes.Count == 0)
            return snapshot;

        await store.WriteAsync(new SettingsChange { Set = changes, Actor = actor, Source = source, Reason = reason }, cancellationToken);
        return await store.LoadAsync(cancellationToken);
    }

    /// <summary>
    /// The settings step of a start, after the schema is known to be current and before anything
    /// reads an instance-wide setting. The process that may move the settings (the control role)
    /// moves them if they have not been; every process then takes the stored values onto
    /// <paramref name="config"/>. The moving process also rewrites its configuration file to
    /// what belongs to the host, keeping a copy of the file as it was, whenever the file still
    /// sets an instance-wide setting: at the move, after a move that was interrupted before the
    /// rewrite, and after someone has typed such a setting back in.
    /// </summary>
    /// <param name="mayMove">Whether this process moves the settings and rewrites its file: the control role.</param>
    public static async Task<SettingsStartReport> StartAsync(ISettingsStore store, SystemConfig config, SettingsPersistence persistence,
        IReadOnlySet<string> environmentPaths, bool mayMove, CancellationToken cancellationToken = default)
    {
        var nothingStored = new SettingsSnapshot(0, new Dictionary<string, StoredSetting>(), new Dictionary<string, StoredSecret>());
        // Asked of the file as it is, before anything in it is put right: a value that is only an
        // old default still has to leave the file.
        var fileSetsStoredSettings = Differences(config, nothingStored, environmentPaths).Count > 0;

        var import = mayMove ? await ImportAsync(store, config, environmentPaths, cancellationToken) : null;
        var snapshot = await store.LoadAsync(cancellationToken);

        // A move made by a build that did not know better stored such a value as if it had been chosen.
        IReadOnlyList<string> supersededCleared = [];
        if (mayMove && snapshot.ImportedAt != null && SupersededStored(snapshot) is { Count: > 0 } superseded)
        {
            supersededCleared = superseded;
            await store.WriteAsync(new SettingsChange
            {
                Clear = superseded, Actor = new SettingsActor(null, ImportActor), Source = SettingsSource.Upgrade,
                Reason = "A default of an earlier build, written into config.yaml by that build and never chosen.",
            }, cancellationToken);
            snapshot = await store.LoadAsync(cancellationToken);
        }
        var load = Apply(config, snapshot, environmentPaths);
        persistence.Use(snapshot);

        string? backup = null;
        string? fileProblem = null;
        if (mayMove && snapshot.ImportedAt != null && fileSetsStoredSettings && File.Exists(persistence.ConfigPath))
        {
            // The file is tidied, not relied on: the stored values are in force whether or not
            // it can be rewritten. A read-only configuration directory is how a container runs.
            try
            {
                var stamp = $"{DateTime.UtcNow:yyyyMMdd'T'HHmmss'Z'}";
                var copy = $"{persistence.ConfigPath}.pre-settings-{stamp}.bak";
                for (var n = 2; File.Exists(copy); n++)
                    copy = $"{persistence.ConfigPath}.pre-settings-{stamp}-{n}.bak";
                File.Copy(persistence.ConfigPath, copy, overwrite: false);
                Shared.Utils.FileSecurityUtil.SetOwnerOnly(copy);
                backup = copy;
                persistence.WriteFile();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                fileProblem = ex.Message;
            }
        }
        return new SettingsStartReport(snapshot, import, load, backup, fileProblem, supersededCleared);
    }

    /// <summary>
    /// The one-time move: stores every covered setting <paramref name="config"/>, as read from
    /// the configuration file, holds at something other than its default, and marks the settings
    /// as moved. Safe to run again after a failure part way: what is already stored is not
    /// written twice, and once the mark is set it does nothing.
    /// </summary>
    public static async Task<SettingsImportReport> ImportAsync(ISettingsStore store, SystemConfig config, IReadOnlySet<string> environmentPaths,
        CancellationToken cancellationToken = default)
    {
        var before = await store.LoadAsync(cancellationToken);
        if (before.ImportedAt != null)
            return new SettingsImportReport(false, before.Revision, []);

        DropSupersededDefaults(config);

        var actor = new SettingsActor(null, ImportActor);
        var changes = Differences(config, before, environmentPaths);
        var revision = before.Revision;
        if (changes.Count > 0)
        {
            var result = await store.WriteAsync(new SettingsChange
            {
                Set = changes, Actor = actor, Source = SettingsSource.Import,
                Reason = "Moved from config.yaml at the first start of a build that keeps settings in the database.",
            }, cancellationToken);
            revision = result.Revision;
        }
        await store.MarkImportedAsync(actor.Name, cancellationToken);
        return new SettingsImportReport(true, revision, changes.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList());
    }
}

/// <summary>
/// An audit writer for the part of a start that runs before the web host exists: it appends to
/// the audit hash chain over a connection of its own, as the host commands do.
/// </summary>
public sealed class HostAuditService(AuditDbContext? auditDb) : IAuditService
{
    /// <inheritdoc />
    public async Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
        string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
        string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
    {
        if (auditDb == null)
            throw new InvalidOperationException("No audit database is configured, so the change cannot be recorded.");
        await new AuditHashChainService().AppendAsync(auditDb, new AuditLogEntity
        {
            ActionType = actionType,
            ActorUserId = actorUserId,
            ActorUsername = actorUsername,
            TargetEntityType = targetEntityType,
            TargetEntityId = targetEntityId,
            DetailsJson = AuditJsonScrubber.SerializeAndScrub(details),
            SourceIp = sourceIp,
            Success = success,
            ErrorMessage = errorMessage,
        });
    }
}

/// <summary>
/// The signer for a settings store that is only asked for ordinary settings. A secret would need
/// a real signer, and this one refuses, so nothing is stored unwrapped by mistake.
/// </summary>
public sealed class NoSecretsSigner : ISigningService
{
    private static SigningRefusedException Refusal() =>
        new(SigningRefusalReason.SignerUnavailable, "No signer is available here, and a secret is stored only wrapped by one.");

    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default) => throw Refusal();
}
