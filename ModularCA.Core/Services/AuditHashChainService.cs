using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// Computes and verifies SHA-256 hash chains for audit records. Writes to one tenant's chain
/// are serialised by an in-process semaphore and, on PostgreSQL, by a transaction-scoped
/// advisory lock shared by every process on the audit database; tenants proceed in parallel.
/// From 0.4.0 new records go to the instance chain (a null tenant); the per-tenant chains are
/// retired and sealed by <see cref="SealRetiredChainsAsync"/>.
/// </summary>
public class AuditHashChainService
{
    /// <summary>
    /// The canonical form in use. Version 1 is everything written before the form was versioned
    /// and is not verifiable: it hashed <c>ToString("O")</c>, which renders seven fractional
    /// digits where the column holds six, so the value the hash was taken from was destroyed by
    /// the write that stored it.
    /// </summary>
    public const int CurrentHashVersion = 2;

    /// <summary>
    /// The timestamp format the canonical form uses: microseconds, to match what the column can
    /// hold, and a literal Z rather than a designator that varies with
    /// <see cref="DateTimeKind"/> — which no database stores, so rendering it made the hash
    /// depend on how a driver happened to label the value on the way out.
    /// </summary>
    private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ss.ffffff'Z'";

    /// <summary>
    /// The action type of a record that begins a new chain epoch. Its <c>PreviousRecordHash</c>
    /// is null by design — it links to nothing — and verification treats it as a genesis rather
    /// than as a break. Every restart is itself a hashed, audited record naming who did it and
    /// why, and the verification report counts them, so a restart is visible rather than a way
    /// to hide something.
    /// </summary>
    public const string ChainRestartAction = "AuditChainRestarted";

    /// <summary>The actor recorded when the node restarts a chain on its own at startup.</summary>
    public const string SystemActor = "system";

    /// <summary>
    /// The action type of a record written by audit retention after it pruned the oldest records
    /// of a chain. Unlike a restart it chains forward; it declares the oldest surviving record so
    /// verification can start an epoch there. See <see cref="RecordPruneAsync"/>.
    /// </summary>
    public const string ChainPrunedAction = "AuditChainPruned";

    /// <summary>The last record of a retired per-tenant chain; see <see cref="SealRetiredChainsAsync"/>.</summary>
    public const string ChainSealedAction = "AuditChainSealed";

    /// <summary>The instance-chain record that anchors a sealed chain's final hash.</summary>
    public const string ChainSuccessionAction = "AuditChainSuccession";

    /// <summary>The migration that retired the per-tenant chains, named in every seal.</summary>
    public const string FoldMigrationId = "20260929051025_FoldSystemTenant";

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _tenantLocks = new();
    private readonly TimeProvider _time;

    /// <summary>Creates the service on the system clock.</summary>
    public AuditHashChainService() : this(TimeProvider.System) { }

    /// <summary>Creates the service on <paramref name="time"/>, which stamps every record.</summary>
    public AuditHashChainService(TimeProvider time) => _time = time;

    /// <summary>
    /// Begins a new epoch of the chain for a tenant: a record that links to nothing, after which
    /// every record verifies fully.
    /// <para>
    /// This exists because records written before the canonical form was versioned can never be
    /// recomputed — they were hashed from values the column did not keep — and a report that
    /// says "1,698 unverifiable, 40 verified" forever is a report nobody reads. A restart draws a
    /// line: the verification report says what is fully verifiable and since when, the old
    /// records keep their link checks, and an operator has one number to look at.
    /// </para>
    /// <para>
    /// The trade-off is stated rather than hidden. A restart resets the link, so a range deleted
    /// immediately before one would not show as a break. That is why the marker is a normal
    /// audited record — hashed, chained forward, naming its actor and reason — and why the
    /// report counts epochs: an unexpected restart is itself the finding.
    /// </para>
    /// </summary>
    /// <param name="db">The audit context.</param>
    /// <param name="tenantId">The tenant whose chain restarts, or null for the system chain.</param>
    /// <param name="actorUserId">Who did it, or null for the node itself.</param>
    /// <param name="actorUsername">The actor's name as recorded.</param>
    /// <param name="reason">Why, recorded in the details.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The marker record, already saved.</returns>
    public async Task<AuditLogEntity> RestartChainAsync(
        AuditDbContext db, Guid? tenantId, Guid? actorUserId, string actorUsername, string reason,
        CancellationToken ct = default)
    {
        var lockKey = LockKey(tenantId);
        var marker = new AuditLogEntity
        {
            ActorUserId = actorUserId,
            ActorUsername = actorUsername,
            ActionType = ChainRestartAction,
            TargetEntityType = "AuditChain",
            TargetEntityId = lockKey,
            Success = true,
            TenantId = tenantId,
        };

        await AppendCoreAsync(db, marker, genesis: true, async () =>
        {
            var preceding = await db.AuditLogs.CountAsync(a => a.TenantId == tenantId, ct);
            var unverifiable = await db.AuditLogs.CountAsync(
                a => a.TenantId == tenantId && a.RecordHash != null && a.HashVersion == null, ct);
            marker.DetailsJson = JsonSerializer.Serialize(new
            {
                reason,
                recordsBefore = preceding,
                unverifiableBefore = unverifiable,
                hashVersion = CurrentHashVersion,
            });
        }, ct);
        return marker;
    }

    /// <summary>
    /// Records that retention pruned the oldest records of a tenant's chain. The marker chains
    /// forward like any record, and declares the oldest surviving record and the hash it links
    /// to, so <see cref="VerifyAsync"/> starts a verifiable epoch at that record instead of
    /// reporting a break where the pruned prefix used to be. A prefix removed any other way has
    /// no such declaration and is still reported. When the prune stopped short of
    /// <paramref name="cutoff"/> (cancelled or failed between batches), the recorded cutoff is the
    /// anchor's timestamp, so the marker never claims more was deleted than was.
    /// </summary>
    /// <param name="db">The audit context.</param>
    /// <param name="tenantId">The tenant whose chain was pruned, or null for the system chain.</param>
    /// <param name="cutoff">Records before this instant were deleted.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The marker record, already saved.</returns>
    public async Task<AuditLogEntity> RecordPruneAsync(
        AuditDbContext db, Guid? tenantId, DateTime cutoff, CancellationToken ct = default)
    {
        var marker = new AuditLogEntity
        {
            ActorUsername = SystemActor,
            ActionType = ChainPrunedAction,
            TargetEntityType = "AuditChain",
            TargetEntityId = LockKey(tenantId),
            Success = true,
            TenantId = tenantId,
        };

        await AppendCoreAsync(db, marker, genesis: false, async () =>
        {
            var anchor = await db.AuditLogs
                .Where(a => a.TenantId == tenantId && a.RecordHash != null)
                .OrderBy(a => a.Timestamp).ThenBy(a => a.Id)
                .Select(a => new { a.Id, a.PreviousRecordHash, a.Timestamp })
                .FirstOrDefaultAsync(ct);
            var recorded = ToStorablePrecision(cutoff);
            if (anchor != null && anchor.Timestamp < recorded)
                recorded = ToStorablePrecision(DateTime.SpecifyKind(anchor.Timestamp, DateTimeKind.Utc));
            marker.DetailsJson = JsonSerializer.Serialize(new PruneDetails(
                "Audit retention deleted the records before the cutoff; the chain resumes at the anchor record.",
                recorded,
                anchor?.Id,
                anchor?.PreviousRecordHash));
        }, ct);
        return marker;
    }

    /// <summary>What a prune marker declares; serialised into its details and read back by verification.</summary>
    private sealed record PruneDetails(string Reason, DateTime Cutoff, Guid? AnchorRecordId, string? AnchorPreviousHash);

    /// <summary>
    /// Restarts the chain for every tenant that still has records from before the canonical
    /// form was versioned and has not been restarted since. A sealed chain is never restarted.
    /// Idempotent: a second call finds nothing to do.
    /// </summary>
    /// <param name="db">The audit context.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The tenants whose chains were restarted.</returns>
    public async Task<IReadOnlyList<Guid?>> RestartLegacyChainsAsync(AuditDbContext db, CancellationToken ct = default)
    {
        var tenants = await db.AuditLogs
            .Where(a => a.RecordHash != null && a.HashVersion == null)
            .Select(a => a.TenantId)
            .Distinct()
            .ToListAsync(ct);

        var restarted = new List<Guid?>();
        foreach (var tenant in tenants)
        {
            if (tenant != null && await db.AuditLogs.AnyAsync(a => a.TenantId == tenant && a.ActionType == ChainSealedAction, ct))
                continue;

            var lastLegacy = await db.AuditLogs
                .Where(a => a.TenantId == tenant && a.RecordHash != null && a.HashVersion == null)
                .OrderByDescending(a => a.Timestamp).ThenByDescending(a => a.Id)
                .Select(a => new { a.Timestamp, a.Id })
                .FirstAsync(ct);

            var alreadyRestarted = await db.AuditLogs.AnyAsync(
                a => a.TenantId == tenant
                     && a.ActionType == ChainRestartAction
                     && (a.Timestamp > lastLegacy.Timestamp
                         || (a.Timestamp == lastLegacy.Timestamp && a.Id.CompareTo(lastLegacy.Id) > 0)), ct);
            if (alreadyRestarted)
                continue;

            await RestartChainAsync(db, tenant, null, SystemActor,
                "The audit hash canonical form was versioned; records before this point were hashed at a "
                + "precision the column does not keep and cannot be recomputed. Their chain links are still "
                + "checked. Everything from here on verifies fully.", ct);
            restarted.Add(tenant);
        }

        return restarted;
    }

    /// <summary>What a seal declares: why, which migration, and the chain's head before the seal.</summary>
    private sealed record SealDetails(string Reason, string Migration, Guid? FinalRecordId, string? FinalRecordHash);

    /// <summary>What a succession record declares about the chain it anchors.</summary>
    private sealed record SuccessionDetails(string Reason, string Migration, Guid SealedChain, Guid SealRecordId, string SealRecordHash, DateTime SealTimestamp);

    /// <summary>
    /// Seals every retired per-tenant chain (every chain with a non-null tenant) once, at control
    /// start: under that chain's lock it appends an <see cref="ChainSealedAction"/> record naming
    /// the reason, <see cref="FoldMigrationId"/> and the chain's head; then, under the instance
    /// chain's lock, an <see cref="ChainSuccessionAction"/> record naming the sealed chain and the
    /// seal's hash. The seal is a retired chain's tail, and a tail can be deleted without breaking
    /// any link; anchoring its hash in the live chain makes that deletion detectable (see
    /// <see cref="CheckRetiredChainAsync"/>). Nothing already recorded is rewritten. Idempotent:
    /// each step checks, under its lock, that it has not already been done. A chain counts as
    /// sealed when its seal is present or a succession record names it, so a seal that retention
    /// has pruned is not replaced by a fresh one; a succession is written only over a seal that is
    /// still present.
    /// </summary>
    /// <param name="db">The audit context.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The chains sealed by this call.</returns>
    public async Task<IReadOnlyList<Guid>> SealRetiredChainsAsync(AuditDbContext db, CancellationToken ct = default)
    {
        const string reason = "Release 0.4.0 folded the tenants' audit chains into the single instance chain. "
            + "This chain is retired; its records stay as recorded and verify as an earlier epoch.";
        var chains = await db.AuditLogs
            .Where(a => a.TenantId != null && a.RecordHash != null)
            .Select(a => a.TenantId!.Value)
            .Distinct()
            .ToListAsync(ct);

        var sealedNow = new List<Guid>();
        foreach (var tenant in chains)
        {
            var target = LockKey(tenant);
            var seal = new AuditLogEntity
            {
                ActorUsername = SystemActor,
                ActionType = ChainSealedAction,
                TargetEntityType = "AuditChain",
                TargetEntityId = LockKey(tenant),
                Success = true,
                TenantId = tenant,
            };
            var wrote = await AppendUnlessAsync(db, seal,
                async () => await db.AuditLogs.AnyAsync(a => a.TenantId == tenant && a.ActionType == ChainSealedAction && a.RecordHash != null, ct)
                    || await db.AuditLogs.AnyAsync(a => a.TenantId == null && a.ActionType == ChainSuccessionAction && a.TargetEntityId == target, ct),
                async () =>
                {
                    var head = await db.AuditLogs
                        .Where(a => a.TenantId == tenant && a.RecordHash != null)
                        .OrderByDescending(a => a.Timestamp).ThenByDescending(a => a.Id)
                        .Select(a => new { a.Id, a.RecordHash })
                        .FirstOrDefaultAsync(ct);
                    seal.DetailsJson = JsonSerializer.Serialize(new SealDetails(reason, FoldMigrationId, head?.Id, head?.RecordHash));
                }, ct);
            if (wrote)
                sealedNow.Add(tenant);

            var sealRecord = await db.AuditLogs.AsNoTracking()
                .Where(a => a.TenantId == tenant && a.ActionType == ChainSealedAction && a.RecordHash != null)
                .OrderBy(a => a.Timestamp).ThenBy(a => a.Id)
                .Select(a => new { a.Id, a.RecordHash, a.Timestamp })
                .FirstOrDefaultAsync(ct);
            if (sealRecord == null)
                continue;
            var succession = new AuditLogEntity
            {
                ActorUsername = SystemActor,
                ActionType = ChainSuccessionAction,
                TargetEntityType = "AuditChain",
                TargetEntityId = target,
                Success = true,
                TenantId = null,
                DetailsJson = JsonSerializer.Serialize(new SuccessionDetails(
                    reason, FoldMigrationId, tenant, sealRecord.Id, sealRecord.RecordHash!, sealRecord.Timestamp)),
            };
            await AppendUnlessAsync(db, succession,
                () => db.AuditLogs.AnyAsync(a => a.TenantId == null && a.ActionType == ChainSuccessionAction && a.TargetEntityId == target, ct),
                null, ct);
        }
        return sealedNow;
    }

    /// <summary>
    /// Every retired chain: each tenant that still has chained records, together with each chain a
    /// succession record in the instance chain names, so a retired chain deleted outright, seal
    /// and all, is still listed and reports its missing tail.
    /// </summary>
    public async Task<IReadOnlyList<Guid>> ListRetiredChainsAsync(AuditDbContext db, CancellationToken ct = default)
    {
        var withRecords = await db.AuditLogs.AsNoTracking()
            .Where(a => a.TenantId != null && a.RecordHash != null)
            .Select(a => a.TenantId!.Value)
            .Distinct()
            .ToListAsync(ct);
        var successions = await db.AuditLogs.AsNoTracking()
            .Where(a => a.TenantId == null && a.ActionType == ChainSuccessionAction && a.RecordHash != null)
            .Select(a => new { a.TargetEntityId, a.DetailsJson })
            .ToListAsync(ct);

        var chains = new HashSet<Guid>(withRecords);
        foreach (var succession in successions)
        {
            if (Guid.TryParse(succession.TargetEntityId, out var target))
                chains.Add(target);
            if (succession.DetailsJson == null) continue;
            try
            {
                if (JsonSerializer.Deserialize<SuccessionDetails>(succession.DetailsJson) is { } details && details.SealedChain != Guid.Empty)
                    chains.Add(details.SealedChain);
            }
            catch (JsonException) { }
        }
        return chains.ToList();
    }

    /// <summary>
    /// Checks a retired chain's tail against the succession record that anchors it in the instance
    /// chain. <see cref="RetiredChainState.Sealed"/> when the seal named there is present with the
    /// same hash; <see cref="RetiredChainState.Pruned"/> when it is gone but a later prune marker in
    /// the chain declares a cutoff after it; <see cref="RetiredChainState.TailMissing"/> or
    /// <see cref="RetiredChainState.TailAltered"/> otherwise. <see cref="RetiredChainState.Unsealed"/>
    /// when no succession names the chain.
    /// </summary>
    public async Task<RetiredChainStatus> CheckRetiredChainAsync(AuditDbContext db, Guid tenantId, CancellationToken ct = default)
    {
        var target = LockKey(tenantId);
        var successionJson = await db.AuditLogs.AsNoTracking()
            .Where(a => a.TenantId == null && a.ActionType == ChainSuccessionAction && a.TargetEntityId == target && a.RecordHash != null)
            .OrderBy(a => a.Timestamp).ThenBy(a => a.Id)
            .Select(a => a.DetailsJson)
            .FirstOrDefaultAsync(ct);
        if (successionJson == null)
            return new RetiredChainStatus(tenantId, RetiredChainState.Unsealed, "No succession record in the instance chain names this chain.");

        SuccessionDetails? details;
        try { details = JsonSerializer.Deserialize<SuccessionDetails>(successionJson); }
        catch (JsonException) { details = null; }
        if (details == null || details.SealedChain != tenantId)
            return new RetiredChainStatus(tenantId, RetiredChainState.TailAltered, "The succession record naming this chain cannot be read.");

        var seal = await db.AuditLogs.AsNoTracking()
            .Where(a => a.Id == details.SealRecordId && a.TenantId == tenantId)
            .Select(a => new { a.RecordHash })
            .FirstOrDefaultAsync(ct);
        if (seal != null)
            return seal.RecordHash == details.SealRecordHash
                ? new RetiredChainStatus(tenantId, RetiredChainState.Sealed, null)
                : new RetiredChainStatus(tenantId, RetiredChainState.TailAltered,
                    $"The seal record {details.SealRecordId} no longer has the hash the instance chain recorded for it.");

        var pruneMarkers = await db.AuditLogs.AsNoTracking()
            .Where(a => a.TenantId == tenantId && a.ActionType == ChainPrunedAction && a.RecordHash != null)
            .Select(a => a.DetailsJson)
            .ToListAsync(ct);
        var prunedPastSeal = pruneMarkers.Select(ReadPruneDetails).Any(p => p != null && p.Cutoff > details.SealTimestamp);
        return prunedPastSeal
            ? new RetiredChainStatus(tenantId, RetiredChainState.Pruned, null)
            : new RetiredChainStatus(tenantId, RetiredChainState.TailMissing,
                $"The seal record {details.SealRecordId} the instance chain anchors is missing, and no prune marker accounts for it.");
    }

    /// <summary>
    /// Appends <paramref name="entry"/> under its chain's lock unless <paramref name="exists"/>,
    /// evaluated under the same lock, says it is already there. Returns whether it wrote.
    /// </summary>
    private async Task<bool> AppendUnlessAsync(
        AuditDbContext db, AuditLogEntity entry, Func<Task<bool>> exists, Func<Task>? prepare, CancellationToken ct)
    {
        await using var lease = await AcquireLockAsync(db, entry.TenantId, ct);
        if (await exists())
            return false;
        try
        {
            await StampAsync(db, entry, genesis: false, prepare, ct);
            db.AuditLogs.Add(entry);
            await db.SaveChangesAsync(ct);
            await lease.CommitAsync(ct);
            return true;
        }
        catch
        {
            db.Entry(entry).State = EntityState.Detached;
            throw;
        }
    }

    /// <summary>
    /// Drops a timestamp to the precision a database column can hold, so the value that is hashed
    /// is the value that comes back.
    /// </summary>
    /// <param name="value">A timestamp at .NET tick resolution.</param>
    /// <returns>The same instant, truncated to whole microseconds.</returns>
    public static DateTime ToStorablePrecision(DateTime value) =>
        new(value.Ticks - (value.Ticks % 10), value.Kind);

    /// <summary>
    /// Acquires the tenant's chain lock and computes the hash chain fields on the entry: string
    /// fields are fitted to their columns, the timestamp is re-stamped after the chain head, and
    /// the entry is linked to the head. On PostgreSQL the lock is also a transaction-scoped
    /// advisory lock, so writers in other processes sharing the audit database serialise too.
    /// <para>
    /// The caller adds the entry, saves, then calls <see cref="AuditChainLease.CommitAsync"/>
    /// before disposing the lease. Disposing without committing rolls the transaction back.
    /// <see cref="AppendAsync"/> does all of that and is what writers should use.
    /// </para>
    /// </summary>
    public Task<AuditChainLease> AcquireAndComputeAsync(
        AuditDbContext db, AuditLogEntity entry, CancellationToken ct = default)
        => AcquireAndStampAsync(db, entry, genesis: false, prepare: null, ct);

    /// <summary>
    /// Links, saves and commits one audit record under the tenant's chain lock. On failure the
    /// entry is detached from <paramref name="db"/>, so a failed write cannot poison later
    /// writes in the same scope or be committed later with a stale link.
    /// </summary>
    public Task AppendAsync(AuditDbContext db, AuditLogEntity entry, CancellationToken ct = default)
        => AppendCoreAsync(db, entry, genesis: false, prepare: null, ct);

    /// <summary>
    /// The one write path behind <see cref="AppendAsync"/> and the chain markers.
    /// <paramref name="prepare"/> runs under the lock, before the entry is hashed.
    /// </summary>
    private async Task AppendCoreAsync(
        AuditDbContext db, AuditLogEntity entry, bool genesis, Func<Task>? prepare, CancellationToken ct)
    {
        await using var lease = await AcquireAndStampAsync(db, entry, genesis, prepare, ct);
        try
        {
            db.AuditLogs.Add(entry);
            await db.SaveChangesAsync(ct);
            await lease.CommitAsync(ct);
        }
        catch
        {
            db.Entry(entry).State = EntityState.Detached;
            throw;
        }
    }

    /// <summary>
    /// Takes the lock, reads the chain head, fits and re-stamps the entry, and hashes it.
    /// A <paramref name="genesis"/> entry links to nothing but is still stamped after the head.
    /// </summary>
    private async Task<AuditChainLease> AcquireAndStampAsync(
        AuditDbContext db, AuditLogEntity entry, bool genesis, Func<Task>? prepare, CancellationToken ct)
    {
        var lease = await AcquireLockAsync(db, entry.TenantId, ct);
        try
        {
            await StampAsync(db, entry, genesis, prepare, ct);
            return lease;
        }
        catch
        {
            await lease.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Under a chain lock the caller holds: reads the chain head, runs <paramref name="prepare"/>,
    /// fits and re-stamps the entry, and hashes it.
    /// </summary>
    private async Task StampAsync(AuditDbContext db, AuditLogEntity entry, bool genesis, Func<Task>? prepare, CancellationToken ct)
    {
        var tenantId = entry.TenantId;
        var head = await db.AuditLogs
            .Where(a => a.TenantId == tenantId && a.RecordHash != null)
            .OrderByDescending(a => a.Timestamp)
            .ThenByDescending(a => a.Id)
            .Select(a => new { a.RecordHash, a.Timestamp })
            .FirstOrDefaultAsync(ct);

        if (prepare != null)
            await prepare();

        FitToColumns(entry);

        // The chain is ordered by Timestamp, so the entry is stamped here, under the lock and
        // after the head, rather than when the caller built it. Truncated before it is hashed
        // AND before it is stored, so the two agree.
        entry.Timestamp = NextTimestamp(_time.GetUtcNow().UtcDateTime, head?.Timestamp);

        var previousHash = genesis ? null : head?.RecordHash;
        entry.PreviousRecordHash = previousHash;
        entry.HashVersion = CurrentHashVersion;
        entry.RecordHash = ComputeHash(entry, previousHash);
    }

    /// <summary>
    /// Serialises writers to one tenant's chain: an in-process semaphore as the fast path and,
    /// on PostgreSQL, <c>pg_advisory_xact_lock</c> inside a transaction the lease owns, which
    /// serialises every process sharing the audit database and is released at commit or rollback.
    /// Other providers (InMemory, SQLite) get the semaphore only.
    /// </summary>
    private async Task<AuditChainLease> AcquireLockAsync(AuditDbContext db, Guid? tenantId, CancellationToken ct)
    {
        var lockKey = LockKey(tenantId);
        var semaphore = _tenantLocks.GetOrAdd(lockKey, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);

        IDbContextTransaction? transaction = null;
        try
        {
            if (db.Database.IsNpgsql())
            {
                if (db.Database.CurrentTransaction == null)
                    transaction = await db.Database.BeginTransactionAsync(ct);
                await db.Database.ExecuteSqlRawAsync(
                    "SELECT pg_advisory_xact_lock({0})", new object[] { AdvisoryLockKey(lockKey) }, ct);
            }
            return new AuditChainLease(semaphore, transaction);
        }
        catch
        {
            if (transaction != null)
            {
                try { await transaction.RollbackAsync(CancellationToken.None); } catch { }
                await transaction.DisposeAsync();
            }
            semaphore.Release();
            throw;
        }
    }

    /// <summary>The per-tenant lock name; the system chain has its own.</summary>
    private static string LockKey(Guid? tenantId) => tenantId?.ToString() ?? "__system__";

    /// <summary>
    /// The 64-bit advisory lock key for a chain, derived from a namespaced hash of its lock name
    /// so it cannot collide with advisory locks taken for other purposes by accident.
    /// </summary>
    internal static long AdvisoryLockKey(string lockKey) =>
        BinaryPrimitives.ReadInt64BigEndian(SHA256.HashData(Encoding.UTF8.GetBytes("modularca.audit-chain:" + lockKey)));

    /// <summary>
    /// The timestamp for the next record: now, or one microsecond after the chain head when the
    /// head is not earlier than now (clock skew between processes, or a head stamped in the
    /// future), truncated to storable precision.
    /// </summary>
    internal static DateTime NextTimestamp(DateTime utcNow, DateTime? previous)
    {
        var now = ToStorablePrecision(DateTime.SpecifyKind(utcNow, DateTimeKind.Utc));
        if (previous is { } p)
        {
            var floor = ToStorablePrecision(DateTime.SpecifyKind(p, DateTimeKind.Utc)).AddTicks(10);
            if (floor > now)
                return floor;
        }
        return now;
    }

    /// <summary>String columns of <see cref="AuditLogEntity"/> with a declared length, excluding the hash columns.</summary>
    private static readonly (PropertyInfo Property, int Max)[] BoundedColumns = typeof(AuditLogEntity)
        .GetProperties()
        .Where(p => p.PropertyType == typeof(string)
                    && p.Name is not nameof(AuditLogEntity.RecordHash) and not nameof(AuditLogEntity.PreviousRecordHash))
        .Select(p => (p, p.GetCustomAttribute<MaxLengthAttribute>()?.Length ?? 0))
        .Where(x => x.Item2 > 0)
        .ToArray();

    /// <summary>
    /// Truncates every length-bounded string field to its column limit, before it is hashed and
    /// saved, so an over-long value (a long exception message) cannot fail the audit write.
    /// </summary>
    internal static void FitToColumns(AuditLogEntity entry)
    {
        foreach (var (property, max) in BoundedColumns)
        {
            if (property.GetValue(entry) is string value && value.Length > max)
            {
                var cut = char.IsHighSurrogate(value[max - 1]) ? max - 1 : max;
                property.SetValue(entry, value[..cut]);
            }
        }
    }

    /// <summary>
    /// Verifies the hash chain for a tenant. Walks the oldest <paramref name="limit"/> records
    /// sequentially, recomputes hashes, and returns any broken links. When the chain holds more
    /// records than that, the result says so (<see cref="HashChainVerificationResult.Truncated"/>)
    /// rather than implying the unexamined records are clean. A walk that begins at the anchor a
    /// retention prune marker declared starts an epoch there instead of reporting a break, but only
    /// for a marker this walk examined and verified (see <see cref="EvaluatePruneMarkers"/>): a
    /// marker beyond <paramref name="limit"/> is not honoured, so a truncated walk of a pruned chain
    /// reports the oldest record's link until the limit covers the marker. A record after a seal,
    /// other than a prune marker, is a break; null <paramref name="tenantId"/> is the instance chain.
    /// </summary>
    public async Task<HashChainVerificationResult> VerifyAsync(
        AuditDbContext db, Guid? tenantId, int limit = 10000, CancellationToken ct = default)
    {
        var total = await db.AuditLogs.CountAsync(a => a.TenantId == tenantId && a.RecordHash != null, ct);

        var records = await db.AuditLogs
            .Where(a => a.TenantId == tenantId && a.RecordHash != null)
            .OrderBy(a => a.Timestamp)
            .ThenBy(a => a.Id)
            .Take(limit)
            .ToListAsync(ct);

        var breaks = new List<HashChainBreak>();
        var prunedAtOldest = EvaluatePruneMarkers(records, breaks);
        var unverifiable = 0;
        var epochs = 0;
        var pruned = false;
        var sealedChain = false;
        DateTime? verifiableSince = null;
        string? expectedPreviousHash = null;

        for (var i = 0; i < records.Count; i++)
        {
            var record = records[i];

            // Nothing but retention's prune markers may follow a seal.
            if (sealedChain && record.ActionType != ChainPrunedAction)
            {
                breaks.Add(new HashChainBreak
                {
                    RecordId = record.Id,
                    Timestamp = record.Timestamp,
                    Issue = "Record written after the chain was sealed",
                });
            }
            if (record.ActionType == ChainSealedAction && record.HashVersion is not null)
                sealedChain = true;

            // The oldest surviving record after a retention prune links to a deleted record. The
            // prune marker declared exactly this record and link, so the walk resumes from it.
            if (i == 0 && prunedAtOldest)
            {
                epochs++;
                pruned = true;
                expectedPreviousHash = record.PreviousRecordHash;
            }

            // A restart marker is a genesis by declaration: its own hash must still recompute,
            // and every record after it chains from it, but it is not expected to link to what
            // came before. Counted, so an unexpected one is visible in the report.
            if (record.ActionType == ChainRestartAction && record.HashVersion is not null
                && record.PreviousRecordHash is null)
            {
                epochs++;
                verifiableSince = record.Timestamp;
                expectedPreviousHash = null;
            }
            else if (verifiableSince is null && record.HashVersion is not null)
            {
                // No restart yet, but this record is the first that can be recomputed.
                verifiableSince = record.Timestamp;
            }

            // A record written before the canonical form was versioned cannot be re-hashed: the
            // timestamp it was hashed from carried precision the column did not keep. Its place in
            // the chain is still checked, because PreviousRecordHash is a stored value and links
            // fine; only the recomputation is skipped.
            if (record.HashVersion is null)
            {
                unverifiable++;
                if (record.PreviousRecordHash != expectedPreviousHash)
                {
                    breaks.Add(new HashChainBreak
                    {
                        RecordId = record.Id,
                        Timestamp = record.Timestamp,
                        Issue = $"PreviousRecordHash mismatch: stored '{record.PreviousRecordHash}', expected '{expectedPreviousHash}'"
                    });
                }
                expectedPreviousHash = record.RecordHash;
                continue;
            }

            if (record.PreviousRecordHash != expectedPreviousHash)
            {
                breaks.Add(new HashChainBreak
                {
                    RecordId = record.Id,
                    Timestamp = record.Timestamp,
                    Issue = $"PreviousRecordHash mismatch: stored '{record.PreviousRecordHash}', expected '{expectedPreviousHash}'"
                });
            }

            var recomputed = ComputeHash(record, record.PreviousRecordHash);
            if (record.RecordHash != recomputed)
            {
                breaks.Add(new HashChainBreak
                {
                    RecordId = record.Id,
                    Timestamp = record.Timestamp,
                    Issue = $"RecordHash tampered: stored '{record.RecordHash}', recomputed '{recomputed}'"
                });
            }

            expectedPreviousHash = record.RecordHash;
        }

        return new HashChainVerificationResult
        {
            TenantId = tenantId,
            RecordsVerified = records.Count - unverifiable,
            UnverifiableRecords = unverifiable,
            Epochs = epochs,
            Pruned = pruned,
            Sealed = sealedChain,
            VerifiableSince = verifiableSince,
            Breaks = breaks,
            FirstRecord = records.FirstOrDefault()?.Timestamp,
            LastRecord = records.LastOrDefault()?.Timestamp,
            TotalRecords = total,
            Truncated = total > records.Count,
        };
    }

    /// <summary>
    /// Decides whether the oldest walked record is the anchor of an honoured prune marker. A marker
    /// is honoured only when it was walked here, its hash recomputes, it links to the record walked
    /// before it, it comes after the anchor it names, and its cutoff is not later than the anchor's
    /// timestamp. A marker naming a walked anchor that fails the ordering or cutoff rule is added to
    /// <paramref name="breaks"/>; hash and link failures are already reported by the walk itself. A
    /// marker whose anchor is not among the walked records (deleted by a later prune, or beyond the
    /// limit) neither starts an epoch nor is reported.
    /// </summary>
    private static bool EvaluatePruneMarkers(List<AuditLogEntity> records, List<HashChainBreak> breaks)
    {
        if (records.Count == 0)
            return false;

        var position = new Dictionary<Guid, int>(records.Count);
        for (var i = 0; i < records.Count; i++)
            position.TryAdd(records[i].Id, i);

        var honoured = false;
        for (var i = 0; i < records.Count; i++)
        {
            var marker = records[i];
            if (marker.ActionType != ChainPrunedAction)
                continue;
            var details = ReadPruneDetails(marker.DetailsJson);
            if (details is not { AnchorRecordId: Guid anchorId, AnchorPreviousHash: not null }
                || !position.TryGetValue(anchorId, out var anchorAt))
                continue;
            var anchor = records[anchorAt];

            var hashVerifies = marker.HashVersion is not null && marker.RecordHash == ComputeHash(marker, marker.PreviousRecordHash);
            var linkVerifies = i > 0 && marker.PreviousRecordHash == records[i - 1].RecordHash;
            string? fault = null;
            if (anchorAt >= i)
                fault = "it does not come after the anchor record it names";
            else if (details.Cutoff > anchor.Timestamp)
                fault = $"its cutoff {details.Cutoff:O} is later than the anchor's timestamp {anchor.Timestamp:O}";

            if (fault != null)
            {
                breaks.Add(new HashChainBreak
                {
                    RecordId = marker.Id,
                    Timestamp = marker.Timestamp,
                    Issue = $"Prune marker not honoured: {fault} (anchor {anchorId})",
                });
                continue;
            }

            if (hashVerifies && linkVerifies && anchorAt == 0 && anchor.PreviousRecordHash == details.AnchorPreviousHash)
                honoured = true;
        }
        return honoured;
    }

    /// <summary>Reads a prune marker's details, or null when they are not a prune declaration.</summary>
    private static PruneDetails? ReadPruneDetails(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<PruneDetails>(json); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// Builds a canonical pipe-delimited representation and computes SHA-256.
    /// The previous hash is included in the input to create the chain link.
    /// Hash is computed on the SCRUBBED DetailsJson (safe/redacted version).
    /// </summary>
    internal static string ComputeHash(AuditLogEntity e, string? previousHash)
    {
        var canonical = string.Join("|",
            e.Id.ToString(),
            ToStorablePrecision(e.Timestamp).ToString(TimestampFormat, CultureInfo.InvariantCulture),
            e.ActorUserId?.ToString() ?? "",
            e.ActorUsername ?? "",
            e.ActionType ?? "",
            e.TargetEntityType ?? "",
            e.TargetEntityId ?? "",
            e.DetailsJson ?? "",
            e.SourceIp ?? "",
            e.Success.ToString(),
            e.ErrorMessage ?? "",
            e.CertificateAuthorityId?.ToString() ?? "",
            e.TenantId?.ToString() ?? "",
            previousHash ?? "GENESIS");

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

}

/// <summary>
/// Holds a tenant's audit chain lock between computing an entry's link and saving it. On
/// PostgreSQL it owns the transaction the advisory lock lives in: <see cref="CommitAsync"/>
/// commits it after a successful save, and disposing an uncommitted lease rolls it back, so an
/// exception can never lead to a commit. Disposal always releases the in-process lock.
/// </summary>
public sealed class AuditChainLease : IDisposable, IAsyncDisposable
{
    private readonly SemaphoreSlim _semaphore;
    private readonly IDbContextTransaction? _transaction;
    private bool _committed;
    private bool _disposed;

    internal AuditChainLease(SemaphoreSlim semaphore, IDbContextTransaction? transaction)
    {
        _semaphore = semaphore;
        _transaction = transaction;
    }

    /// <summary>Commits the owned transaction, if any. Call only after SaveChanges succeeded.</summary>
    public async Task CommitAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed) return;
        if (_transaction != null)
            await _transaction.CommitAsync(ct);
        _committed = true;
    }

    /// <summary>Rolls back an uncommitted transaction and releases the lock.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (_transaction != null)
            {
                if (!_committed)
                    try { _transaction.Rollback(); } catch { }
                _transaction.Dispose();
            }
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>Rolls back an uncommitted transaction and releases the lock.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (_transaction != null)
            {
                if (!_committed)
                    try { await _transaction.RollbackAsync(CancellationToken.None); } catch { }
                await _transaction.DisposeAsync();
            }
        }
        finally
        {
            _semaphore.Release();
        }
    }
}

/// <summary>Result of a hash chain verification run.</summary>
public class HashChainVerificationResult
{
    public Guid? TenantId { get; set; }
    public int RecordsVerified { get; set; }

    /// <summary>
    /// Records whose hash predates the versioned canonical form and cannot be reproduced. Not
    /// breaks: their chain links are still checked, only the recomputation is skipped.
    /// </summary>
    public int UnverifiableRecords { get; set; }

    /// <summary>
    /// How many times the chain was deliberately restarted. Each restart is an audited record
    /// naming its actor; one the operator did not expect is a finding in its own right.
    /// </summary>
    public int Epochs { get; set; }

    /// <summary>
    /// True when the walk began at the oldest surviving record of a chain that audit retention
    /// pruned, as declared by a prune marker. Counted in <see cref="Epochs"/> as well.
    /// </summary>
    public bool Pruned { get; set; }

    /// <summary>
    /// True when the walk met a seal: the chain was retired in 0.4.0 and only prune markers may
    /// follow the seal. Any other later record is reported as a break.
    /// </summary>
    public bool Sealed { get; set; }

    /// <summary>Every hashed record in the tenant's chain, whether or not this run examined it.</summary>
    public int TotalRecords { get; set; }

    /// <summary>
    /// True when the chain holds more records than the run examined. A truncated run with no
    /// breaks says nothing about the records it never looked at.
    /// </summary>
    public bool Truncated { get; set; }

    /// <summary>
    /// The moment from which every record recomputes and links: the latest restart, or the first
    /// record written under the versioned canonical form. Null when nothing is verifiable yet.
    /// </summary>
    public DateTime? VerifiableSince { get; set; }
    public List<HashChainBreak> Breaks { get; set; } = new();
    public DateTime? FirstRecord { get; set; }
    public DateTime? LastRecord { get; set; }
}

/// <summary>The state of a retired chain's tail; see <see cref="AuditHashChainService.CheckRetiredChainAsync"/>.</summary>
public enum RetiredChainState
{
    /// <summary>No succession record names the chain yet.</summary>
    Unsealed,
    /// <summary>The seal the instance chain anchors is present with the anchored hash.</summary>
    Sealed,
    /// <summary>The seal was removed by retention, as a later prune marker declares.</summary>
    Pruned,
    /// <summary>The anchored seal is missing and nothing accounts for it: the tail was deleted.</summary>
    TailMissing,
    /// <summary>The anchored seal's hash differs, or its succession record cannot be read.</summary>
    TailAltered,
}

/// <summary>A retired chain's tail check.</summary>
/// <param name="TenantId">The retired chain.</param>
/// <param name="State">What the check found.</param>
/// <param name="Issue">A description when the state is a finding, else null.</param>
public sealed record RetiredChainStatus(Guid TenantId, RetiredChainState State, string? Issue);

/// <summary>A single break detected in the hash chain.</summary>
public class HashChainBreak
{
    public Guid RecordId { get; set; }
    public DateTime Timestamp { get; set; }
    public string Issue { get; set; } = string.Empty;
}
