using System.Text.Json.Nodes;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Settings;

/// <summary>How a settings change arrived. Recorded on the setting and in its history.</summary>
public static class SettingsSource
{
    public const string Api = "Api";
    public const string Import = "Import";
    public const string Cli = "Cli";
    public const string Bootstrap = "Bootstrap";
    public const string Rollback = "Rollback";
}

/// <summary>Who is changing settings.</summary>
/// <param name="UserId">The account, or null for a host actor such as the import.</param>
/// <param name="Name">The name recorded with the change.</param>
/// <param name="SourceIp">The caller's address, for the audit record.</param>
public sealed record SettingsActor(Guid? UserId, string Name, string? SourceIp = null);

/// <summary>
/// One write: any number of settings set or cleared together. They are saved in one transaction
/// under one revision, so a reader sees all of the change or none of it.
/// </summary>
public sealed class SettingsChange
{
    /// <summary>Settings to set, by catalog key. A JSON null sets the value null, where the setting allows it.</summary>
    public IReadOnlyDictionary<string, JsonNode?> Set { get; init; } = new Dictionary<string, JsonNode?>();

    /// <summary>Settings to clear back to their built-in default, by catalog key.</summary>
    public IReadOnlyCollection<string> Clear { get; init; } = [];

    /// <summary>
    /// The version each named setting is expected to be at (0 for one never set). A setting found
    /// at another version refuses the whole write. Settings not named are not checked.
    /// </summary>
    public IReadOnlyDictionary<string, int> ExpectedVersions { get; init; } = new Dictionary<string, int>();

    public required SettingsActor Actor { get; init; }

    /// <summary>One of <see cref="SettingsSource"/>.</summary>
    public required string Source { get; init; }

    public string? Reason { get; init; }
}

/// <summary>What a write did.</summary>
/// <param name="Revision">The revision the write took, or the current one when it changed nothing.</param>
/// <param name="ChangedKeys">The settings whose value changed. A setting written with the value it already had is not among them.</param>
public sealed record SettingsWriteResult(long Revision, IReadOnlyList<string> ChangedKeys);

/// <summary>Why a settings write was refused.</summary>
public enum SettingsRefusal
{
    /// <summary>No setting has this key.</summary>
    UnknownKey,

    /// <summary>The setting lives in a file on the host or with the signer, not in the database.</summary>
    NotStoredInDatabase,

    /// <summary>The setting is a secret, and the store does not hold secrets yet.</summary>
    SecretNotSupported,

    /// <summary>The value is not of the setting's type, or is null where the setting does not allow it.</summary>
    InvalidValue,

    /// <summary>A setting was not at the version the writer expected.</summary>
    VersionConflict,

    /// <summary>Other writes kept getting in first.</summary>
    Busy,
}

/// <summary>A settings write that was refused. Nothing was changed.</summary>
public sealed class SettingsRefusedException(SettingsRefusal reason, string message, string? key = null) : Exception(message)
{
    public SettingsRefusal Reason { get; } = reason;

    /// <summary>The setting the refusal is about, when it is about one.</summary>
    public string? Key { get; } = key;
}

/// <summary>A setting as stored.</summary>
/// <param name="Key">The catalog key.</param>
/// <param name="ValueJson">The value as JSON; null when the setting was cleared back to its default.</param>
/// <param name="Version">How many times the setting has been changed.</param>
/// <param name="Revision">The revision of the write that produced this value.</param>
public sealed record StoredSetting(string Key, string? ValueJson, int Version, long Revision, DateTime UpdatedAt, string ActorName, string Source);

/// <summary>One change in a setting's history.</summary>
public sealed record SettingHistoryEntry(
    long Revision, string Key, int Version, string? ValueJson, string? PreviousValueJson,
    DateTime ChangedAt, string ActorName, string Source, string? Reason);

/// <summary>Every stored setting as of one revision.</summary>
/// <param name="Revision">The revision of the latest write; 0 when nothing was ever written.</param>
/// <param name="Settings">The stored settings by key, cleared ones included.</param>
public sealed record SettingsSnapshot(long Revision, IReadOnlyDictionary<string, StoredSetting> Settings)
{
    /// <summary>
    /// Sets on <paramref name="config"/> every stored setting that has a value. A row this build
    /// cannot use is left out and reported, and the setting keeps what <paramref name="config"/>
    /// already held: a key the catalog does not know (a row from another build), a setting that
    /// does not live in the database, or a value that is not of the setting's type.
    /// </summary>
    /// <returns>One sentence per row that was not applied.</returns>
    public IReadOnlyList<string> ApplyTo(SystemConfig config)
    {
        var problems = new List<string>();
        foreach (var stored in Settings.Values.OrderBy(s => s.Key, StringComparer.Ordinal))
        {
            if (stored.ValueJson == null) continue;

            var definition = SettingsCatalog.Find(stored.Key);
            if (definition == null)
            {
                problems.Add($"{stored.Key} is not a setting this build knows.");
                continue;
            }
            if (!definition.StoredInDatabase)
            {
                problems.Add($"{stored.Key} does not live in the database.");
                continue;
            }

            JsonNode? value;
            try { value = JsonNode.Parse(stored.ValueJson); }
            catch (System.Text.Json.JsonException)
            {
                problems.Add($"{stored.Key} holds a value that is not JSON.");
                continue;
            }

            var problem = SettingsCatalog.Problem(definition, value);
            if (problem != null)
            {
                problems.Add(problem);
                continue;
            }
            SettingsCatalog.Apply(config, definition, value);
        }
        return problems;
    }
}

/// <summary>
/// The instance-wide settings in the database: one row per setting that has been set, every
/// change kept in a history and audited. See <c>docs/architecture/settings-store.md</c>.
/// </summary>
public interface ISettingsStore
{
    /// <summary>Every stored setting, and the revision they are at.</summary>
    Task<SettingsSnapshot> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets and clears settings together, under one new revision. A setting written with the
    /// value it already has is left alone, and a write that changes nothing takes no revision.
    /// The audit record is written before the change is saved.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The write was refused; nothing was changed.</exception>
    Task<SettingsWriteResult> WriteAsync(SettingsChange change, CancellationToken cancellationToken = default);

    /// <summary>The changes to one setting, newest first.</summary>
    Task<IReadOnlyList<SettingHistoryEntry>> HistoryAsync(string key, int limit = 50, CancellationToken cancellationToken = default);
}
