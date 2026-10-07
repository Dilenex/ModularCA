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
/// <param name="SecretsMoved">Secrets this start moved out of the configuration file, by key.</param>
/// <param name="SecretProblems">What went wrong with a secret: one that could not be moved or could not be read back. No secret is in any of them.</param>
public sealed record SettingsStartReport(SettingsSnapshot Snapshot, SettingsImportReport? Import, SettingsLoadReport Load, string? FileBackup,
    string? FileProblem = null, IReadOnlyList<string>? SupersededCleared = null,
    IReadOnlyList<string>? SecretsMoved = null, IReadOnlyList<string>? SecretProblems = null);

/// <summary>
/// The settings store as the running node uses it: which settings it covers, how the stored
/// values reach the configuration at start, how a change made to the configuration reaches the
/// store, and the one-time move out of <c>config.yaml</c>.
/// </summary>
/// <remarks>
/// <para>
/// It covers the instance-wide settings and the secrets the node has to use, which the signer
/// wraps. Bootstrap, signer and host-local settings never leave their files. Nor do the two
/// single integration API keys, which named API keys replace.
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
    /// The secrets the store decides: those the node uses, which the signer wraps, and the
    /// environment does not set.
    /// </summary>
    public static IEnumerable<SettingDefinition> CoveredSecrets(IReadOnlySet<string> environmentPaths) =>
        SettingsCatalog.Definitions.Where(d => d.Secret == SettingSecretKind.Wrapped && !environmentPaths.Contains(d.Path));

    /// <summary>A secret as <paramref name="config"/> holds it, in the one spelling values are compared in. Not for display.</summary>
    private static string HeldSecret(SystemConfig config, SettingDefinition definition) =>
        SettingsCatalog.CanonicalJson(definition,
            SettingsCatalog.Read(config, definition) ?? (definition.AllowsNull ? null : SettingsCatalog.EmptyValue(definition)));

    /// <summary>
    /// What <paramref name="config"/> holds for each covered secret, to compare a later state of
    /// it with. Kept in memory only, and only to tell whether a secret was changed.
    /// </summary>
    public static IReadOnlyDictionary<string, string> SecretBaseline(SystemConfig config, IReadOnlySet<string> environmentPaths) =>
        CoveredSecrets(environmentPaths).ToDictionary(d => d.Key, d => HeldSecret(config, d), StringComparer.Ordinal);

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
    /// <param name="withSecrets">
    /// Whether this process reads the stored secrets, and moves them when it may move: every
    /// process that can reach a signer. Without it the secrets are left wherever they are.
    /// </param>
    public static async Task<SettingsStartReport> StartAsync(ISettingsStore store, SystemConfig config, SettingsPersistence persistence,
        IReadOnlySet<string> environmentPaths, bool mayMove, bool withSecrets = false, CancellationToken cancellationToken = default)
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

        // The secrets. Until one is stored, the file's value stands. The control role stores
        // those the file holds; every role then reads the stored ones back through the signer.
        var secretsMoved = new List<string>();
        var secretProblems = new List<string>();
        var fileSetsStoredSecrets = false;
        IReadOnlyDictionary<string, string>? secretBaseline = null;
        if (withSecrets && snapshot.ImportedAt != null)
        {
            var defaults = new SystemConfig();
            var fromFile = SecretBaseline(config, environmentPaths);
            var secrets = CoveredSecrets(environmentPaths).ToList();

            var toMove = mayMove
                ? secrets.Where(d => !snapshot.Secrets.ContainsKey(d.Key) && fromFile[d.Key] != HeldSecret(defaults, d)).ToList()
                : [];
            if (toMove.Count > 0)
            {
                try
                {
                    await store.WriteAsync(new SettingsChange
                    {
                        Set = toMove.ToDictionary(d => d.Key, d => SettingsCatalog.Read(config, d)),
                        Actor = new SettingsActor(null, ImportActor), Source = SettingsSource.Import,
                        Reason = "Moved from config.yaml, wrapped by the signer.",
                    }, cancellationToken);
                    secretsMoved.AddRange(toMove.Select(d => d.Key));
                    snapshot = await store.LoadAsync(cancellationToken);
                }
                catch (SettingsRefusedException ex) when (ex.Reason == SettingsRefusal.SignerRefused)
                {
                    secretProblems.Add($"The secrets stay in config.yaml for now, where they still work. {ex.Message}");
                }
            }

            foreach (var definition in secrets)
            {
                if (!snapshot.Secrets.TryGetValue(definition.Key, out var stored)) continue;
                if (fromFile[definition.Key] != HeldSecret(defaults, definition))
                    fileSetsStoredSecrets = true;
                // A secret that was stored and then cleared is empty, whatever the file says.
                if (stored.Value == null)
                    SettingsCatalog.Apply(config, definition, SettingsCatalog.Read(defaults, definition));
            }

            var supplied = SettingsCatalog.Definitions.Where(d => environmentPaths.Contains(d.Path)).Select(d => d.Key).ToHashSet(StringComparer.Ordinal);
            secretProblems.AddRange(await store.ApplySecretsAsync(snapshot, config, cancellationToken, supplied));
            secretBaseline = SecretBaseline(config, environmentPaths);
        }
        persistence.Use(snapshot, secretBaseline);

        string? backup = null;
        string? fileProblem = null;
        if (mayMove && snapshot.ImportedAt != null && (fileSetsStoredSettings || fileSetsStoredSecrets) && File.Exists(persistence.ConfigPath))
        {
            // The file is tidied, not relied on: the stored values are in force whether or not
            // it can be rewritten. A read-only configuration directory is how a container runs.
            try
            {
                // The copy is of the file as it was, less the secrets that are now wrapped in the
                // database: a copy holding them in the clear would undo the move.
                var storedSecretPaths = CoveredSecrets(environmentPaths).Where(d => snapshot.Secrets.ContainsKey(d.Key)).Select(d => d.Path).ToList();
                var stamp = $"{DateTime.UtcNow:yyyyMMdd'T'HHmmss'Z'}";
                var copy = $"{persistence.ConfigPath}.pre-settings-{stamp}.bak";
                for (var n = 2; File.Exists(copy); n++)
                    copy = $"{persistence.ConfigPath}.pre-settings-{stamp}-{n}.bak";
                if (storedSecretPaths.Count == 0)
                {
                    File.Copy(persistence.ConfigPath, copy, overwrite: false);
                    Shared.Utils.FileSecurityUtil.SetOwnerOnly(copy);
                }
                else
                {
                    Shared.Utils.ConfigYamlWriter.WriteKeepingAccess(copy,
                        Shared.Utils.ConfigYamlWriter.WithoutPaths(File.ReadAllText(persistence.ConfigPath), storedSecretPaths));
                }
                backup = copy;
                persistence.WriteFile();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException)
            {
                fileProblem = ex.Message;
            }
        }
        return new SettingsStartReport(snapshot, import, load, backup, fileProblem, supersededCleared, secretsMoved, secretProblems);
    }

    /// <summary>
    /// <see cref="SaveAsync"/>, and the secrets with it: a covered secret whose value in
    /// <paramref name="config"/> differs from <paramref name="secretBaseline"/> is wrapped and
    /// stored, or cleared when it was emptied, in the same write as the ordinary settings.
    /// Returns the snapshot and the baseline afterwards.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The store refused, or the signer would not wrap; nothing was written.</exception>
    public static async Task<(SettingsSnapshot Snapshot, IReadOnlyDictionary<string, string> SecretBaseline)> SaveWithSecretsAsync(
        ISettingsStore store, SystemConfig config, IReadOnlySet<string> environmentPaths, IReadOnlyDictionary<string, string> secretBaseline,
        SettingsActor actor, string source, string? reason = null, CancellationToken cancellationToken = default)
    {
        var snapshot = await store.LoadAsync(cancellationToken);
        var set = new Dictionary<string, JsonNode?>(Differences(config, snapshot, environmentPaths), StringComparer.Ordinal);
        var clear = new List<string>();
        var defaults = new SystemConfig();
        foreach (var definition in CoveredSecrets(environmentPaths))
        {
            var held = HeldSecret(config, definition);
            if (held == (secretBaseline.GetValueOrDefault(definition.Key) ?? HeldSecret(defaults, definition)))
                continue;
            if (held == HeldSecret(defaults, definition))
                clear.Add(definition.Key);
            else
                set[definition.Key] = SettingsCatalog.Read(config, definition);
        }

        if (set.Count > 0 || clear.Count > 0)
        {
            await store.WriteAsync(new SettingsChange { Set = set, Clear = clear, Actor = actor, Source = source, Reason = reason }, cancellationToken);
            snapshot = await store.LoadAsync(cancellationToken);
        }
        return (snapshot, SecretBaseline(config, environmentPaths));
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
