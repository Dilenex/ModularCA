using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// Computes and verifies SHA-256 hash chains for audit records.
/// Uses per-tenant SemaphoreSlim to serialize writes within a tenant
/// while allowing cross-tenant parallelism.
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

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _tenantLocks = new();

    /// <summary>
    /// Drops a timestamp to the precision a database column can hold, so the value that is hashed
    /// is the value that comes back.
    /// </summary>
    /// <param name="value">A timestamp at .NET tick resolution.</param>
    /// <returns>The same instant, truncated to whole microseconds.</returns>
    public static DateTime ToStorablePrecision(DateTime value) =>
        new(value.Ticks - (value.Ticks % 10), value.Kind);

    /// <summary>
    /// Acquires the per-tenant lock and computes the hash chain fields on the entry.
    /// The caller MUST call SaveChangesAsync before disposing the returned lock.
    /// </summary>
    public async Task<IDisposable> AcquireAndComputeAsync(
        AuditDbContext db, AuditLogEntity entry, CancellationToken ct = default)
    {
        var tenantId = entry.TenantId;
        var lockKey = tenantId?.ToString() ?? "__system__";
        var semaphore = _tenantLocks.GetOrAdd(lockKey, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);

        try
        {
            var previousHash = await db.AuditLogs
                .Where(a => a.TenantId == tenantId && a.RecordHash != null)
                .OrderByDescending(a => a.Timestamp)
                .ThenByDescending(a => a.Id)
                .Select(a => a.RecordHash)
                .FirstOrDefaultAsync(ct);

            // Truncated before it is hashed AND before it is stored, so the two agree. Both
            // datetime(6) and timestamptz keep microseconds, and the engines differ on whether
            // they round or truncate what they are given — handing them a value they can hold
            // exactly removes the question.
            entry.Timestamp = ToStorablePrecision(entry.Timestamp);
            entry.PreviousRecordHash = previousHash;
            entry.HashVersion = CurrentHashVersion;
            entry.RecordHash = ComputeHash(entry, previousHash);

            return new SemaphoreReleaser(semaphore);
        }
        catch
        {
            semaphore.Release();
            throw;
        }
    }

    /// <summary>
    /// Verifies the hash chain for a tenant. Walks records sequentially,
    /// recomputes hashes, and returns any broken links.
    /// </summary>
    public async Task<HashChainVerificationResult> VerifyAsync(
        AuditDbContext db, Guid? tenantId, int limit = 10000, CancellationToken ct = default)
    {
        var records = await db.AuditLogs
            .Where(a => a.TenantId == tenantId && a.RecordHash != null)
            .OrderBy(a => a.Timestamp)
            .ThenBy(a => a.Id)
            .Take(limit)
            .ToListAsync(ct);

        var breaks = new List<HashChainBreak>();
        var unverifiable = 0;
        string? expectedPreviousHash = null;

        foreach (var record in records)
        {
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
            Breaks = breaks,
            FirstRecord = records.FirstOrDefault()?.Timestamp,
            LastRecord = records.LastOrDefault()?.Timestamp
        };
    }

    /// <summary>
    /// Builds a canonical pipe-delimited representation and computes SHA-256.
    /// The previous hash is included in the input to create the chain link.
    /// Hash is computed on the SCRUBBED DetailsJson (safe/redacted version).
    /// </summary>
    private static string ComputeHash(AuditLogEntity e, string? previousHash)
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

    private sealed class SemaphoreReleaser(SemaphoreSlim semaphore) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (!_disposed) { _disposed = true; semaphore.Release(); }
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
    public List<HashChainBreak> Breaks { get; set; } = new();
    public DateTime? FirstRecord { get; set; }
    public DateTime? LastRecord { get; set; }
}

/// <summary>A single break detected in the hash chain.</summary>
public class HashChainBreak
{
    public Guid RecordId { get; set; }
    public DateTime Timestamp { get; set; }
    public string Issue { get; set; } = string.Empty;
}
