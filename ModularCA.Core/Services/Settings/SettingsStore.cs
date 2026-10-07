using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Settings;

namespace ModularCA.Core.Services.Settings;

/// <summary>
/// <see cref="ISettingsStore"/> over the application database.
/// </summary>
/// <remarks>
/// <para>
/// A write is one save: the changed <c>Settings</c> rows, one <c>SettingsHistory</c> row per
/// changed setting, and the <c>SettingsState</c> row raised by one. That row is a concurrency
/// token, so of two writes that read the same revision only one saves; the other reads again and
/// retries, which is also when it finds out that a setting it meant to change has moved.
/// </para>
/// <para>
/// The audit record is written before the save, so with a fail-closed audit no change exists
/// without its record. The price is a <c>ConfigUpdateAborted</c> record when the save then fails.
/// </para>
/// </remarks>
public sealed class SettingsStore(ModularCADbContext db, IAuditService audit, ILogger<SettingsStore> logger) : ISettingsStore
{
    private const int MaxAttempts = 5;

    /// <inheritdoc />
    public async Task<SettingsSnapshot> LoadAsync(CancellationToken cancellationToken = default)
    {
        var rows = await db.Settings.AsNoTracking().ToListAsync(cancellationToken);
        var revision = await db.SettingsState.AsNoTracking()
            .Where(s => s.Id == SettingsStateEntity.SingletonId)
            .Select(s => (long?)s.Revision)
            .FirstOrDefaultAsync(cancellationToken) ?? 0;
        return new SettingsSnapshot(revision, rows.ToDictionary(
            r => r.Key,
            r => new StoredSetting(r.Key, r.ValueJson, r.Version, r.Revision, r.UpdatedAt, r.ActorName, r.Source),
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
                h.Revision, h.Key, h.Version, h.ValueJson, h.PreviousValueJson, h.ChangedAt, h.ActorName, h.Source, h.Reason))
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<SettingsWriteResult> WriteAsync(SettingsChange change, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(change);
        var wanted = Validate(change);

        for (var attempt = 1; ; attempt++)
        {
            var state = await db.SettingsState.FirstOrDefaultAsync(s => s.Id == SettingsStateEntity.SingletonId, cancellationToken);
            var keys = wanted.Keys.Concat(change.ExpectedVersions.Keys).Distinct(StringComparer.Ordinal).ToList();
            var rows = await db.Settings.Where(s => keys.Contains(s.Key)).ToDictionaryAsync(s => s.Key, StringComparer.Ordinal, cancellationToken);

            foreach (var (key, expected) in change.ExpectedVersions)
            {
                var actual = rows.GetValueOrDefault(key)?.Version ?? 0;
                if (actual != expected)
                    throw new SettingsRefusedException(SettingsRefusal.VersionConflict,
                        $"{key} is at version {actual}, not {expected}: it was changed by someone else.", key);
            }

            var changes = wanted
                .Where(w => !string.Equals(rows.GetValueOrDefault(w.Key)?.ValueJson, w.Value, StringComparison.Ordinal))
                .OrderBy(w => w.Key, StringComparer.Ordinal)
                .ToList();
            if (changes.Count == 0)
                return new SettingsWriteResult(state?.Revision ?? 0, []);

            var revision = (state?.Revision ?? 0) + 1;
            var now = DateTime.UtcNow;
            var audited = new List<object>();
            foreach (var (key, valueJson) in changes)
            {
                rows.TryGetValue(key, out var row);
                var previous = row?.ValueJson;
                if (row == null)
                {
                    row = new SettingEntity { Key = key };
                    db.Settings.Add(row);
                }
                row.ValueJson = valueJson;
                row.Version += 1;
                row.Revision = revision;
                row.UpdatedAt = now;
                row.ActorId = change.Actor.UserId;
                row.ActorName = change.Actor.Name;
                row.Source = change.Source;

                db.SettingsHistory.Add(new SettingHistoryEntity
                {
                    Revision = revision, Key = key, Version = row.Version,
                    ValueJson = valueJson, PreviousValueJson = previous, ChangedAt = now,
                    ActorId = change.Actor.UserId, ActorName = change.Actor.Name,
                    Source = change.Source, Reason = change.Reason,
                });
                audited.Add(new { key, before = Node(previous), after = Node(valueJson), cleared = valueJson == null, version = row.Version });
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
                return new SettingsWriteResult(revision, changes.Select(c => c.Key).ToList());
            }
            catch (DbUpdateException ex)
            {
                // Nothing of this attempt reached the database, and the record written above says
                // it would.
                db.ChangeTracker.Clear();
                await audit.LogAsync(AuditActionType.ConfigUpdateAborted, change.Actor.UserId, change.Actor.Name,
                    targetEntityType: "Settings", targetEntityId: revision.ToString(),
                    details: new { revision, source = change.Source, keys = changes.Select(c => c.Key) },
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

    /// <summary>
    /// Checks every key and value of <paramref name="change"/> and returns what each setting's
    /// row should hold: canonical JSON for a set, null for a clear.
    /// </summary>
    private static Dictionary<string, string?> Validate(SettingsChange change)
    {
        if (string.IsNullOrWhiteSpace(change.Actor.Name))
            throw new ArgumentException("A settings change names its actor.", nameof(change));
        if (string.IsNullOrWhiteSpace(change.Source))
            throw new ArgumentException("A settings change names its source.", nameof(change));
        if (change.Set.Count == 0 && change.Clear.Count == 0)
            throw new ArgumentException("A settings change sets or clears at least one setting.", nameof(change));

        var wanted = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var key in change.Set.Keys.Concat(change.Clear).Concat(change.ExpectedVersions.Keys))
            Definition(key);

        foreach (var (key, value) in change.Set)
        {
            var definition = Definition(key);
            var problem = SettingsCatalog.Problem(definition, value);
            if (problem != null)
                throw new SettingsRefusedException(SettingsRefusal.InvalidValue, problem, key);

            // One value has one stored spelling, so "the same value again" is a string comparison.
            wanted[key] = SettingsCatalog.CanonicalJson(definition, value);
        }
        foreach (var key in change.Clear)
        {
            if (wanted.ContainsKey(key))
                throw new ArgumentException($"{key} is both set and cleared.", nameof(change));
            wanted[key] = null;
        }
        return wanted;
    }

    private static SettingDefinition Definition(string key)
    {
        var definition = SettingsCatalog.Find(key)
            ?? throw new SettingsRefusedException(SettingsRefusal.UnknownKey, $"{key} is not a setting.", key);
        return definition.Class switch
        {
            SettingClass.InstanceWide => definition,
            SettingClass.Secret => throw new SettingsRefusedException(SettingsRefusal.SecretNotSupported,
                $"{key} is a secret, and secrets are not stored in the database yet.", key),
            SettingClass.SignerLocal => throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                $"{key} belongs to the signer and is set in the signer's own directory.", key),
            _ => throw new SettingsRefusedException(SettingsRefusal.NotStoredInDatabase,
                $"{key} is set per host, in that host's configuration file.", key),
        };
    }

    private static JsonNode? Node(string? json) => json == null ? null : JsonNode.Parse(json);
}
