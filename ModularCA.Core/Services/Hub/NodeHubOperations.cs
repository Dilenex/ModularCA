using Microsoft.Extensions.DependencyInjection;
using ModularCA.Core.Services.Settings;
using ModularCA.HubConnection.Contract;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Settings;

namespace ModularCA.Core.Services.Hub;

/// <summary>
/// What this node does for each request on the hub's local connection: reads its identifier, its health and
/// mode, sets the mode in the per-host state file, writes a backup, prunes old backup archives,
/// replaces the hash of the affiliation token, and records every request in the audit trail
/// under the hub.
/// </summary>
/// <remarks>
/// <para>
/// The actor of every audit record is <see cref="Actor"/>, with no user id: the hub is not an
/// account. The operator name the hub gave is recorded in the details as a claim.
/// </para>
/// <para>
/// The hash of the affiliation token is the instance-wide setting
/// <c>Hub.AffiliationTokenSha256</c>: kept in the settings store with the instance's data, so it
/// follows the instance and its backups, and read here from the configuration in memory, so the
/// token check needs no database. A hash is not a secret; reading it lets nobody act as the hub.
/// </para>
/// </remarks>
/// <param name="modes">The mode's state file.</param>
/// <param name="config">The configuration in memory.</param>
/// <param name="scopes">Opens a scope for the audit service and the settings store, which are per request.</param>
/// <param name="health">Runs the readiness checks.</param>
/// <param name="backup">Writes a backup archive and returns it; throws when it does not complete.</param>
/// <param name="saveSettings">Saves the configuration in memory; null in a test that keeps nothing.</param>
/// <param name="instanceVersion">The product version.</param>
public sealed class NodeHubOperations(
    InstanceModeStore modes,
    SystemConfig config,
    IServiceScopeFactory scopes,
    Func<CancellationToken, Task<HubHealthReport>> health,
    Func<CancellationToken, Task<HubBackupResult>> backup,
    Func<ISettingsStore, SettingsActor, string, CancellationToken, Task>? saveSettings,
    string instanceVersion) : IHubLocalOperations
{
    /// <summary>The actor every record of the local connection is written under.</summary>
    public const string Actor = "hub";

    /// <summary>
    /// How often the hub's served reads (health, mode and inventory) are written to the audit trail. A hub
    /// polls health every few seconds; one record per request would fill the hash chain with
    /// them. Within this interval the reads are counted, and the first read after it writes one
    /// record with the counts. Changes, refusals and failures are always recorded one by one.
    /// </summary>
    public TimeSpan ReadAuditInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The clock the read interval is measured with; replaced in tests.</summary>
    public Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    private readonly object _readsLock = new();
    private readonly Dictionary<string, int> _readsSince = new(StringComparer.Ordinal);
    private DateTime? _readsRecordedAt;
    private DateTime? _readsSinceUtc;

    /// <summary>
    /// Counts a served read, and writes one <see cref="AuditActionType.HubRequestServed"/> record
    /// for the reads counted so far when none was written within <see cref="ReadAuditInterval"/>.
    /// The first read is recorded at once, so the trail shows when a hub began to read. Reads
    /// counted after the last record and before the process stops are not recorded.
    /// </summary>
    /// <param name="record">The served read.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    private async Task AuditReadAsync(HubRequestRecord record, CancellationToken cancellationToken)
    {
        Dictionary<string, int> counts;
        DateTime since;
        var now = UtcNow();
        lock (_readsLock)
        {
            _readsSinceUtc ??= now;
            _readsSince[record.Operation!] = _readsSince.GetValueOrDefault(record.Operation!) + 1;
            if (_readsRecordedAt is { } last && now - last < ReadAuditInterval)
                return;
            counts = new Dictionary<string, int>(_readsSince, StringComparer.Ordinal);
            since = _readsSinceUtc.Value;
            _readsSince.Clear();
            _readsSinceUtc = null;
            _readsRecordedAt = now;
        }

        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
            AuditActionType.HubRequestServed,
            null, Actor,
            "HubRequest", "reads",
            new
            {
                Operation = "reads",
                Counts = counts,
                SinceUtc = since,
                UntilUtc = now,
                ClaimedOperator = record.OperatorName,
                record.ContractVersion,
                record.TokenCheck,
            },
            success: true);
    }

    /// <summary>The settings key of the affiliation token's hash.</summary>
    public const string TokenHashKey = "Hub_AffiliationTokenSha256";

    private readonly object _hashLock = new();
    private string? _hashText;
    private byte[]? _hash;

    /// <inheritdoc/>
    public byte[]? AffiliationTokenHash
    {
        get
        {
            var text = config.Hub.AffiliationTokenSha256;
            lock (_hashLock)
            {
                if (!ReferenceEquals(text, _hashText))
                {
                    _hashText = text;
                    // A stored value that is not a SHA-256 can never match a token: the check
                    // stays on and refuses every request, rather than turning itself off.
                    _hash = string.IsNullOrWhiteSpace(text) ? null
                        : HubLocalHost.TryParseHashHex(text, out var parsed) ? parsed : new byte[32];
                }
                return _hash;
            }
        }
    }

    /// <inheritdoc/>
    public string InstanceVersion { get; } = instanceVersion;

    /// <summary>
    /// Reads the instance's identifier (<see cref="InstanceIdentity.ReadAsync"/> over this node's
    /// application database). Set by the node when it opens the connection; while it is null
    /// <see cref="ReadInstanceIdAsync"/> answers null and <c>hello</c> carries no identifier.
    /// </summary>
    public Func<CancellationToken, Task<InstanceIdReading>>? InstanceId { get; init; }

    private volatile string? _storedInstanceId;

    /// <inheritdoc/>
    /// <remarks>
    /// A stored identifier never changes, so the first one read is kept for the life of the
    /// process and the database is not asked again. A derived one (nothing is stored yet) is not
    /// kept: the next <c>hello</c> reads again, and takes the stored one once there is one.
    /// </remarks>
    public async Task<string?> ReadInstanceIdAsync(CancellationToken cancellationToken)
    {
        if (_storedInstanceId is { } known) return known;
        if (InstanceId == null) return null;
        InstanceIdReading reading;
        try
        {
            reading = await InstanceId(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
        if (reading is { Stored: true, Id: not null })
            _storedInstanceId = reading.Id;
        return reading.Id;
    }

    /// <inheritdoc/>
    public Task<HubHealthReport> ReadHealthAsync(CancellationToken cancellationToken) => health(cancellationToken);

    /// <inheritdoc/>
    public HubMode ReadMode() => Describe(modes.Current);

    /// <summary>
    /// Reads the inventory (<see cref="NodeInventoryReader"/> over this node's services). Set by
    /// the node when it opens the connection; while it is null <see cref="ReadInventoryAsync"/>
    /// fails and the hub is answered <c>internal_error</c>.
    /// </summary>
    public Func<CancellationToken, Task<HubInventory>>? Inventory { get; init; }

    /// <inheritdoc/>
    public Task<HubInventory> ReadInventoryAsync(CancellationToken cancellationToken)
        => (Inventory ?? throw new InvalidOperationException("This node was given no inventory reader."))(cancellationToken);

    /// <inheritdoc/>
    public async Task<HubMode> SetModeAsync(string mode, string? reason, string? operatorName, CancellationToken cancellationToken)
    {
        if (!InstanceModeGate.TryParse(mode, out var parsed))
            throw new ArgumentException(
                $"'{mode}' is not a mode. Use {InstanceModeGate.NamesForMessages}.");

        var before = modes.Current;
        // Audit first: with a fail-closed audit trail an unrecorded change must not happen.
        await using (var scope = scopes.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
                AuditActionType.InstanceModeChanged, null, Actor,
                "InstanceMode", InstanceModeGate.NameOf(parsed),
                new
                {
                    From = InstanceModeGate.NameOf(before.Mode),
                    To = InstanceModeGate.NameOf(parsed),
                    Reason = reason,
                    SetBy = InstanceModeStore.SourceName(InstanceModeSource.Hub),
                    ClaimedOperator = operatorName,
                    PreviousSource = InstanceModeStore.SourceName(before.Source),
                    PreviousSetBy = before.SetBy,
                });
        }
        return Describe(modes.Set(parsed, InstanceModeSource.Hub, operatorName, reason));
    }

    /// <inheritdoc/>
    public async Task<HubBackupResult> CreateBackupAsync(string? operatorName, CancellationToken cancellationToken)
    {
        HubBackupResult result;
        try
        {
            result = await backup(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await using var failed = scopes.CreateAsyncScope();
            await failed.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
                AuditActionType.BackupCreated, null, Actor, "Backup", null,
                new { trigger = "hub", ClaimedOperator = operatorName }, success: false, errorMessage: ex.Message);
            throw;
        }
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
            AuditActionType.BackupCreated, null, Actor, "Backup", result.FileName,
            new { trigger = "hub", ClaimedOperator = operatorName, result.SizeBytes });
        return result;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The rule is <see cref="BackupRetention"/>, the one the scheduled and the console backups
    /// prune by, with the instance's <c>Backup.MinimumRetentionDays</c> floor in force. What it
    /// selects is recorded first, as one <see cref="AuditActionType.BackupsPruned"/> record under
    /// <see cref="Actor"/>, and then deleted: with a fail-closed audit trail an unrecorded deletion
    /// must not happen. A file that then cannot be deleted is recorded in a second, failed record.
    /// </remarks>
    public async Task<HubPruneBackupsResult> PruneBackupsAsync(int? keep, int? maxAgeDays, string? operatorName, CancellationToken cancellationToken)
    {
        if (keep == null && maxAgeDays == null)
            throw new ArgumentException("Give keep (how many of the newest archives to keep), maxAgeDays, or both.");
        if (keep is < 1 or > HubPruneBackupsRequest.MaxKeep)
            throw new ArgumentException($"keep must be between 1 and {HubPruneBackupsRequest.MaxKeep}: the newest archive is never deleted.");
        if (maxAgeDays is < 1 or > HubPruneBackupsRequest.MaxMaxAgeDays)
            throw new ArgumentException($"maxAgeDays must be between 1 and {HubPruneBackupsRequest.MaxMaxAgeDays}.");

        var configured = string.IsNullOrWhiteSpace(config.Backup.OutputPath) ? "backups" : config.Backup.OutputPath;
        var directory = Path.GetFullPath(Path.IsPathRooted(configured) ? configured : Path.Combine(AppContext.BaseDirectory, configured));
        var minimumRetentionDays = Math.Max(0, config.Backup.MinimumRetentionDays);
        var selection = BackupRetention.Select(directory, keep, maxAgeDays is { } days ? TimeSpan.FromDays(days) : null,
            minimumRetentionDays, UtcNow());

        await using var scope = scopes.CreateAsyncScope();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        await audit.LogAsync(
            AuditActionType.BackupsPruned, null, Actor, "Backup", null,
            new
            {
                trigger = "hub",
                ClaimedOperator = operatorName,
                Keep = keep,
                MaxAgeDays = maxAgeDays,
                MinimumRetentionDays = minimumRetentionDays,
                Deleted = selection.ToDelete.Select(f => f.Name).ToList(),
                KeptByMinimumRetention = selection.KeptByMinimumRetention.Select(f => f.Name).ToList(),
                Remaining = selection.ToKeep.Count,
            });

        var pruned = BackupRetention.Delete(selection);
        if (pruned.Failed.Count > 0)
            await audit.LogAsync(
                AuditActionType.BackupsPruned, null, Actor, "Backup", null,
                new { trigger = "hub", ClaimedOperator = operatorName, NotDeleted = pruned.Failed.Select(f => f.Archive.FileName).ToList() },
                success: false, errorMessage: $"{pruned.Failed.Count} archive(s) could not be deleted: {pruned.Failed[0].Error}");

        static HubBackupFile Describe(BackupRetention.Archive a) => new(a.FileName, a.SizeBytes, a.CreatedAtUtc);
        return new HubPruneBackupsResult(
            pruned.Deleted.Select(Describe).ToList(),
            pruned.Remaining.Select(Describe).ToList(),
            pruned.KeptByMinimumRetention.Select(a => a.FileName).ToList(),
            pruned.Failed.Select(f => f.Archive.FileName).ToList());
    }

    /// <inheritdoc/>
    public async Task ReplaceAffiliationTokenAsync(byte[] newTokenSha256, string? operatorName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(newTokenSha256);
        if (newTokenSha256.Length != 32)
            throw new ArgumentException("A SHA-256 is 32 bytes.", nameof(newTokenSha256));

        var previous = config.Hub.AffiliationTokenSha256;
        var hadOne = !string.IsNullOrWhiteSpace(previous);
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
            AuditActionType.HubAffiliationTokenReplaced, null, Actor, "HubAffiliationToken", null,
            new { Replaced = hadOne, ClaimedOperator = operatorName, Source = "hub local connection" });

        config.Hub.AffiliationTokenSha256 = Convert.ToHexString(newTokenSha256).ToLowerInvariant();
        if (saveSettings == null) return;
        try
        {
            await saveSettings(scope.ServiceProvider.GetRequiredService<ISettingsStore>(), new SettingsActor(null, Actor),
                hadOne ? "The hub replaced its affiliation token" : "The hub gave its first affiliation token", cancellationToken);
        }
        catch
        {
            // Not kept, so not in force: the old token goes on working and the hub is told it failed.
            config.Hub.AffiliationTokenSha256 = previous;
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task AuditAsync(HubRequestRecord record, CancellationToken cancellationToken)
    {
        if (record.Refusal == null && record.Operation is HubLocalContract.Operations.HealthRead or HubLocalContract.Operations.ModeRead or HubLocalContract.Operations.InventoryRead)
        {
            await AuditReadAsync(record, cancellationToken);
            return;
        }

        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuditService>().LogAsync(
            record.Refusal == null ? AuditActionType.HubRequestServed : AuditActionType.HubRequestRefused,
            null, Actor,
            "HubRequest", record.Operation ?? $"{record.Method} {record.Path}",
            new
            {
                record.Operation,
                record.Method,
                record.Path,
                record.Status,
                record.RequestId,
                ClaimedOperator = record.OperatorName,
                record.ContractVersion,
                record.Replayed,
                record.TokenCheck,
            },
            success: record.Refusal == null,
            errorMessage: record.Refusal);
    }

    /// <summary>A mode record as the contract carries it.</summary>
    /// <param name="record">The record.</param>
    public static HubMode Describe(InstanceModeRecord record)
        => new(InstanceModeGate.NameOf(record.Mode), InstanceModeStore.SourceName(record.Source), record.SetBy, record.Reason, record.SetAtUtc);
}
