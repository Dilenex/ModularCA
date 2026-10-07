using System.Security.Cryptography;
using System.Text;
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

    /// <summary>A build correcting a stored value at its start: one an earlier build wrote and nobody chose.</summary>
    public const string Upgrade = "Upgrade";
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
    /// <summary>
    /// Settings to set, by catalog key. A JSON null sets the value null, where the setting allows
    /// it. A secret is given as its value like any other setting; it is wrapped or hashed before
    /// anything is stored, and is not kept, logged or audited as itself.
    /// </summary>
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

    /// <summary>The signer would not wrap a secret, or could not be reached. Nothing is stored in the clear instead.</summary>
    SignerRefused,

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

/// <summary>A secret setting as stored: never the secret.</summary>
/// <param name="Key">The catalog key.</param>
/// <param name="Kind">Whether <paramref name="Value"/> is a wrapped blob or a hash.</param>
/// <param name="Value">The wrapped blob or the hash; null when the secret was cleared.</param>
/// <param name="Version">How many times the secret has been changed.</param>
/// <param name="Revision">The revision of the write that produced this value.</param>
public sealed record StoredSecret(string Key, SettingSecretKind Kind, byte[]? Value, int Version, long Revision, DateTime UpdatedAt, string ActorName, string Source);

/// <summary>One change in a setting's history.</summary>
/// <param name="SecretDigest">For a secret, SHA-256 in hex of what was stored; the entry carries no value.</param>
public sealed record SettingHistoryEntry(
    long Revision, string Key, int Version, string? ValueJson, string? PreviousValueJson,
    DateTime ChangedAt, string ActorName, string Source, string? Reason, string? SecretDigest = null);

/// <summary>How a secret the node only has to recognise is kept: as the SHA-256 of itself.</summary>
/// <remarks>
/// A plain hash is safe only for a value nobody can guess, so one is taken only of a key of at
/// least <see cref="MinimumLength"/> characters. It needs no signer to check and cannot be read
/// back, which is right for a credential an administrator sets and a client presents.
/// </remarks>
public static class SettingsSecretHash
{
    /// <summary>The shortest key that may be stored as a hash.</summary>
    public const int MinimumLength = 32;

    /// <summary>SHA-256 over the UTF-8 of <paramref name="secret"/>.</summary>
    public static byte[] Compute(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    /// <summary>Whether <paramref name="presented"/> is the secret <paramref name="stored"/> is the hash of, in constant time.</summary>
    public static bool Matches(byte[]? stored, string? presented) =>
        stored != null && !string.IsNullOrEmpty(presented)
        && CryptographicOperations.FixedTimeEquals(stored, Compute(presented));
}

/// <summary>The name a wrapped secret setting is bound to, so its blob unwraps for that setting only.</summary>
public static class SettingsSecretBinding
{
    public static string For(string key) => "setting:" + key;
}

/// <summary>Every stored setting as of one revision.</summary>
/// <param name="Revision">The revision of the latest write; 0 when nothing was ever written.</param>
/// <param name="Settings">The stored settings by key, cleared ones included.</param>
/// <param name="Secrets">The stored secrets by key, wrapped or hashed, cleared ones included.</param>
/// <param name="ImportedAt">When the settings were moved out of <c>config.yaml</c>; null until they have been.</param>
public sealed record SettingsSnapshot(
    long Revision,
    IReadOnlyDictionary<string, StoredSetting> Settings,
    IReadOnlyDictionary<string, StoredSecret> Secrets,
    DateTime? ImportedAt = null)
{
    /// <summary>
    /// Whether <paramref name="presented"/> is the hashed secret stored under <paramref name="key"/>.
    /// False when none is stored, it was cleared, or it is not kept as a hash.
    /// </summary>
    public bool HashedSecretMatches(string key, string? presented) =>
        Secrets.TryGetValue(key, out var stored)
        && stored.Kind == SettingSecretKind.Hashed
        && SettingsSecretHash.Matches(stored.Value, presented);

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

    /// <summary>
    /// Sets on <paramref name="config"/> every wrapped secret in <paramref name="snapshot"/> that
    /// has a value, by asking the signer to unwrap each for its own setting. A secret that cannot
    /// be unwrapped or used is left out and reported, and the setting keeps what
    /// <paramref name="config"/> already held. Hashed secrets are not set: the node never holds
    /// those, and checks a presented key with <see cref="SettingsSnapshot.HashedSecretMatches"/>.
    /// </summary>
    /// <returns>One sentence per secret that was not applied. None of them contains a secret.</returns>
    Task<IReadOnlyList<string>> ApplySecretsAsync(SettingsSnapshot snapshot, SystemConfig config, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records that the settings have been moved out of <c>config.yaml</c>, by
    /// <paramref name="importedBy"/>. Does nothing when that is already recorded.
    /// </summary>
    Task MarkImportedAsync(string importedBy, CancellationToken cancellationToken = default);

    /// <summary>The changes to one setting, newest first.</summary>
    Task<IReadOnlyList<SettingHistoryEntry>> HistoryAsync(string key, int limit = 50, CancellationToken cancellationToken = default);
}
