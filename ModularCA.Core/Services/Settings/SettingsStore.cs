using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services.Settings;

/// <summary>
/// <see cref="ISettingsStore"/> over the application database.
/// </summary>
/// <remarks>
/// <para>
/// A write is one save: the changed <c>Settings</c> and <c>SettingsSecrets</c> rows, one
/// <c>SettingsHistory</c> row per changed setting, and the <c>SettingsState</c> row raised by
/// one. That row is a concurrency token, so of two writes that read the same revision only one
/// saves; the other reads again and retries, which is also when it finds out that a setting it
/// meant to change has moved.
/// </para>
/// <para>
/// The audit record is written before the save, so with a fail-closed audit no change exists
/// without its record. The price is a <c>ConfigUpdateAborted</c> record when the save then fails.
/// </para>
/// <para>
/// A secret arrives as its value and leaves this class only as a blob the signer wrapped, bound
/// to the setting's key, or as a hash. It is in no row, no history entry, no audit record and no
/// message. When the signer will not wrap, the write is refused: nothing is kept in the clear in
/// the meantime.
/// </para>
/// </remarks>
public sealed class SettingsStore(ModularCADbContext db, IAuditService audit, ISigningService signer, ILogger<SettingsStore> logger) : ISettingsStore
{
    /// <summary>The name this class gives the signer as its caller.</summary>
    public const string SignerCaller = "settings-store";

    private const int MaxAttempts = 5;
    private const string WrappedKind = "wrapped";
    private const string HashKind = "hash";

    private static SigningContext SecretContext => SigningContext.ForScope(SignerCaller, SigningPurpose.Configuration, spaceId: null);

    /// <summary>What one setting's row should hold after a write.</summary>
    /// <param name="Json">An ordinary setting's canonical JSON; null to clear it.</param>
    /// <param name="Plaintext">A wrapped secret's value as UTF-8 JSON, to be wrapped; null otherwise.</param>
    /// <param name="Hash">A hashed secret's hash; null otherwise.</param>
    private sealed record Wanted(SettingDefinition Definition, bool Clear, string? Json, byte[]? Plaintext, byte[]? Hash);

    /// <inheritdoc />
    public async Task<SettingsSnapshot> LoadAsync(CancellationToken cancellationToken = default)
    {
        var rows = await db.Settings.AsNoTracking().ToListAsync(cancellationToken);
        var secrets = await db.SettingsSecrets.AsNoTracking().ToListAsync(cancellationToken);
        var revision = await db.SettingsState.AsNoTracking()
            .Where(s => s.Id == SettingsStateEntity.SingletonId)
            .Select(s => (long?)s.Revision)
            .FirstOrDefaultAsync(cancellationToken) ?? 0;
        return new SettingsSnapshot(
            revision,
            rows.ToDictionary(
                r => r.Key,
                r => new StoredSetting(r.Key, r.ValueJson, r.Version, r.Revision, r.UpdatedAt, r.ActorName, r.Source),
                StringComparer.Ordinal),
            secrets.ToDictionary(
                r => r.Key,
                r => new StoredSecret(r.Key, r.Kind == HashKind ? SettingSecretKind.Hashed : SettingSecretKind.Wrapped,
                    r.Value, r.Version, r.Revision, r.UpdatedAt, r.ActorName, r.Source),
                StringComparer.Ordinal));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SettingHistoryEntry>> HistoryAsync(string key, int limit = 50, CancellationToken cancellationToken = default)
    {
        return await db.SettingsHistory.AsNoTracking()
            .Where(h => h.Key == key)
            .OrderByDescending(h => h.Version)
            .Take(Math.Clamp(limit, 1, 500))
            .Select(h => new SettingHistoryEntry(
                h.Revision, h.Key, h.Version, h.ValueJson, h.PreviousValueJson, h.ChangedAt, h.ActorName, h.Source, h.Reason, h.SecretDigest))
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ApplySecretsAsync(SettingsSnapshot snapshot, SystemConfig config, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(config);

        var problems = new List<string>();
        foreach (var stored in snapshot.Secrets.Values.OrderBy(s => s.Key, StringComparer.Ordinal))
        {
            if (stored.Value == null || stored.Kind != SettingSecretKind.Wrapped) continue;

            var definition = SettingsCatalog.Find(stored.Key);
            if (definition is not { Class: SettingClass.Secret, Secret: SettingSecretKind.Wrapped })
            {
                problems.Add($"{stored.Key} is not a wrapped secret this build knows.");
                continue;
            }

            byte[] plaintext;
            try
            {
                plaintext = await signer.UnwrapBoundSecretAsync(stored.Value, SettingsSecretBinding.For(stored.Key), SecretContext, cancellationToken);
            }
            catch (SigningRefusedException ex)
            {
                problems.Add($"{stored.Key} could not be unwrapped: {ex.Message}");
                continue;
            }

            try
            {
                var value = JsonNode.Parse(plaintext);
                if (SettingsCatalog.Problem(definition, value) != null)
                {
                    // Nothing about a secret's value belongs in a message, its type included.
                    problems.Add($"{stored.Key} unwrapped to a value this build cannot use.");
                    continue;
                }
                SettingsCatalog.Apply(config, definition, value);
            }
            catch (JsonException)
            {
                problems.Add($"{stored.Key} unwrapped to a value this build cannot use.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        return problems;
    }

    /// <inheritdoc />
    public async Task<SettingsWriteResult> WriteAsync(SettingsChange change, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(change);
        var wanted = Validate(change);
        var wrapped = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        try
        {
            for (var attempt = 1; ; attempt++)
            {
                var state = await db.SettingsState.FirstOrDefaultAsync(s => s.Id == SettingsStateEntity.SingletonId, cancellationToken);
                var keys = wanted.Keys.Concat(change.ExpectedVersions.Keys).Distinct(StringComparer.Ordinal).ToList();
                var rows = await db.Settings.Where(s => keys.Contains(s.Key)).ToDictionaryAsync(s => s.Key, StringComparer.Ordinal, cancellationToken);
                var secretRows = await db.SettingsSecrets.Where(s => keys.Contains(s.Key)).ToDictionaryAsync(s => s.Key, StringComparer.Ordinal, cancellationToken);

                foreach (var (key, expected) in change.ExpectedVersions)
                {
                    var actual = rows.GetValueOrDefault(key)?.Version ?? secretRows.GetValueOrDefault(key)?.Version ?? 0;
                    if (actual != expected)
                        throw new SettingsRefusedException(SettingsRefusal.VersionConflict,
                            $"{key} is at version {actual}, not {expected}: it was changed by someone else.", key);
                }

                var changes = wanted.Values
                    .Where(w => Changes(w, rows.GetValueOrDefault(w.Definition.Key), secretRows.GetValueOrDefault(w.Definition.Key)))
                    .OrderBy(w => w.Definition.Key, StringComparer.Ordinal)
                    .ToList();
                if (changes.Count == 0)
                    return new SettingsWriteResult(state?.Revision ?? 0, []);

                // Only now, with the write known to be wanted, is the signer asked; and once,
                // however many times the save is tried.
                foreach (var secret in changes.Where(w => w.Plaintext != null && !wrapped.ContainsKey(w.Definition.Key)))
                    wrapped[secret.Definition.Key] = await WrapAsync(secret, cancellationToken);

                var revision = (state?.Revision ?? 0) + 1;
                var now = DateTime.UtcNow;
                var audited = new List<object>();
                foreach (var item in changes)
                {
                    var key = item.Definition.Key;
                    var history = new SettingHistoryEntity
                    {
                        Revision = revision, Key = key, ChangedAt = now,
                        ActorId = change.Actor.UserId, ActorName = change.Actor.Name,
                        Source = change.Source, Reason = change.Reason,
                    };

                    if (item.Definition.Class == SettingClass.Secret)
                    {
                        secretRows.TryGetValue(key, out var row);
                        var had = row?.Value != null;
                        if (row == null)
                        {
                            row = new SettingSecretEntity { Key = key };
                            db.SettingsSecrets.Add(row);
                        }
                        row.Kind = item.Definition.Secret == SettingSecretKind.Hashed ? HashKind : WrappedKind;
                        row.Value = item.Clear ? null : item.Hash ?? wrapped[key];
                        row.Version += 1;
                        row.Revision = revision;
                        row.UpdatedAt = now;
                        row.ActorId = change.Actor.UserId;
                        row.ActorName = change.Actor.Name;
                        row.Source = change.Source;

                        history.Version = row.Version;
                        history.SecretDigest = row.Value == null ? null : Convert.ToHexStringLower(SHA256.HashData(row.Value));
                        // The key and what happened to it. Not the value, and not a digest of it.
                        audited.Add(new { key, secret = true, change = item.Clear ? "cleared" : had ? "replaced" : "set", version = row.Version });
                    }
                    else
                    {
                        rows.TryGetValue(key, out var row);
                        var previous = row?.ValueJson;
                        if (row == null)
                        {
                            row = new SettingEntity { Key = key };
                            db.Settings.Add(row);
                        }
                        row.ValueJson = item.Json;
                        row.Version += 1;
                        row.Revision = revision;
                        row.UpdatedAt = now;
                        row.ActorId = change.Actor.UserId;
                        row.ActorName = change.Actor.Name;
                        row.Source = change.Source;

                        history.Version = row.Version;
                        history.ValueJson = item.Json;
                        history.PreviousValueJson = previous;
                        audited.Add(new { key, before = Node(previous), after = Node(item.Json), cleared = item.Json == null, version = row.Version });
                    }
                    db.SettingsHistory.Add(history);
                }

                if (state == null)
                    db.SettingsState.Add(new SettingsStateEntity { Revision = revision });
                else
                    state.Revision = revision;

                await audit.LogAsync(AuditActionType.ConfigUpdated, change.Actor.UserId, change.Actor.Name,
                    targetEntityType: "Settings", targetEntityId: revision.ToString(),
                    details: new { revision, source = change.Source, reason = change.Reason, changes = audited },
                    sourceIp: change.Actor.SourceIp);

                try
                {
                    await db.SaveChangesAsync(cancellationToken);
                    return new SettingsWriteResult(revision, changes.Select(c => c.Definition.Key).ToList());
                }
                catch (DbUpdateException ex)
                {
                    // Nothing of this attempt reached the database, and the record written above
                    // says it would.
                    db.ChangeTracker.Clear();
                    await audit.LogAsync(AuditActionType.ConfigUpdateAborted, change.Actor.UserId, change.Actor.Name,
                        targetEntityType: "Settings", targetEntityId: revision.ToString(),
                        details: new { revision, source = change.Source, keys = changes.Select(c => c.Definition.Key) },
                        sourceIp: change.Actor.SourceIp, success: false, errorMessage: "The change was not saved.");

                    // Another write took this revision first, or created a row this one meant to
                    // create: read everything again and try once more. Anything else is not ours to retry.
                    var lostTheRace = ex is DbUpdateConcurrencyException || PostgresErrorUtil.IsUniqueViolation(ex);
                    if (!lostTheRace)
                        throw;
                    if (attempt >= MaxAttempts)
                    {
                        logger.LogWarning(ex, "A settings write gave up after {Attempts} attempts.", attempt);
                        throw new SettingsRefusedException(SettingsRefusal.Busy,
                            "Other settings changes kept getting in first. Nothing was changed; try again.");
                    }
                }
            }
        }
        finally
        {
            foreach (var item in wanted.Values)
                if (item.Plaintext != null)
                    CryptographicOperations.ZeroMemory(item.Plaintext);
        }
    }

    /// <summary>
    /// Whether writing <paramref name="wanted"/> changes anything. An ordinary setting and a
    /// hashed secret change when the stored text or hash differs. A wrapped secret that is set
    /// always changes: two wraps of one value differ, so the stored blob cannot say whether the
    /// value is the same, and setting a secret again is how it is replaced.
    /// </summary>
    private static bool Changes(Wanted wanted, SettingEntity? row, SettingSecretEntity? secretRow)
    {
        if (wanted.Definition.Class != SettingClass.Secret)
            return !string.Equals(row?.ValueJson, wanted.Json, StringComparison.Ordinal);
        if (wanted.Clear)
            return secretRow?.Value != null;
        if (wanted.Hash != null)
            return secretRow?.Value == null || !CryptographicOperations.FixedTimeEquals(secretRow.Value, wanted.Hash);
        return true;
    }

    private async Task<byte[]> WrapAsync(Wanted secret, CancellationToken cancellationToken)
    {
        var key = secret.Definition.Key;
        try
        {
            return await signer.WrapBoundSecretAsync(SecretKind.SettingSecret, SettingsSecretBinding.For(key), secret.Plaintext!, SecretContext, cancellationToken);
        }
        catch (SigningRefusedException ex)
        {
            throw new SettingsRefusedException(SettingsRefusal.SignerRefused,
                $"{key} is a secret and the signer did not wrap it, so nothing was changed: {ex.Message}", key);
        }
    }

    /// <summary>Checks every key and value of <paramref name="change"/> and returns what each setting's row should hold.</summary>
    private static Dictionary<string, Wanted> Validate(SettingsChange change)
    {
        if (string.IsNullOrWhiteSpace(change.Actor.Name))
            throw new ArgumentException("A settings change names its actor.", nameof(change));
        if (string.IsNullOrWhiteSpace(change.Source))
            throw new ArgumentException("A settings change names its source.", nameof(change));
        if (change.Set.Count == 0 && change.Clear.Count == 0)
            throw new ArgumentException("A settings change sets or clears at least one setting.", nameof(change));

        var wanted = new Dictionary<string, Wanted>(StringComparer.Ordinal);
        foreach (var key in change.Set.Keys.Concat(change.Clear).Concat(change.ExpectedVersions.Keys))
            Definition(key);

        foreach (var (key, value) in change.Set)
        {
            var definition = Definition(key);
            if (SettingsCatalog.Problem(definition, value) is { } problem)
                throw new SettingsRefusedException(SettingsRefusal.InvalidValue, problem, key);

            // One value has one stored spelling, so "the same value again" is a comparison of text.
            var json = SettingsCatalog.CanonicalJson(definition, value);
            wanted[key] = definition.Secret switch
            {
                SettingSecretKind.Wrapped => new Wanted(definition, false, null, Encoding.UTF8.GetBytes(json), null),
                SettingSecretKind.Hashed => new Wanted(definition, false, null, null, Hashed(definition, value)),
                _ => new Wanted(definition, false, json, null, null),
            };
        }
        foreach (var key in change.Clear)
        {
            if (wanted.ContainsKey(key))
                throw new ArgumentException($"{key} is both set and cleared.", nameof(change));
            wanted[key] = new Wanted(Definition(key), true, null, null, null);
        }
        return wanted;
    }

    /// <summary>
    /// The hash of a secret the node only has to recognise. A plain hash protects nothing that
    /// can be guessed, so a short key is refused; clearing the setting is how it is turned off.
    /// </summary>
    private static byte[] Hashed(SettingDefinition definition, JsonNode? value)
    {
        var key = definition.Key;
        if (value is not JsonValue text || !text.TryGetValue<string>(out var secret))
            throw new SettingsRefusedException(SettingsRefusal.InvalidValue, $"{key} takes a value of type text.", key);
        if (secret.Length < SettingsSecretHash.MinimumLength)
            throw new SettingsRefusedException(SettingsRefusal.InvalidValue,
                $"{key} is stored as a hash, which protects only a key nobody can guess: it needs at least {SettingsSecretHash.MinimumLength} characters. Clear it to turn it off.", key);
        return SettingsSecretHash.Compute(secret);
    }

    private static SettingDefinition Definition(string key)
    {
        var definition = SettingsCatalog.Find(key)
            ?? throw new SettingsRefusedException(SettingsRefusal.UnknownKey, $"{key} is not a setting.", key);
        return definition.Class switch
        {
            SettingClass.InstanceWide or SettingClass.Secret => definition,
            SettingClass.SignerLocal => throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                $"{key} belongs to the signer and is set in the signer's own directory.", key),
            _ => throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                $"{key} is set per host, in that host's configuration file.", key),
        };
    }

    private static JsonNode? Node(string? json) => json == null ? null : JsonNode.Parse(json);
}
