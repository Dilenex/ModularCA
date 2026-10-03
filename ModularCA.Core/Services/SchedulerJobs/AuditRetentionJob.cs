using System.IO.Compression;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that enforces audit retention by chunked deletes
/// across the AuditLogs / AuditEst / AuditScep / AuditCmp / AuditAcme / AuditMsae / AuditNetwork
/// tables. Respects separate retention windows for the "general" audit tables and
/// the noisier AuditNetwork table, deletes in bounded batches so no single DELETE
/// holds a long-running transaction, and optionally streams matching rows to a
/// gzip jsonl archive file before deleting them (<c>ArchiveBeforeDelete</c>).
///
/// Row-level DELETE only — the <c>modularca_audit</c> role does not own the audit database
/// and therefore cannot drop it or its tables by
/// design (see <c>project_audit_reset.md</c>), which is the reason old entries
/// survive <c>--reset --force</c>. Retention is the only mechanism that shrinks
/// the audit DB footprint on a live system.
///
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math
/// against <c>Audit.Retention.Schedule</c>, missed-run policy, timeout enforcement,
/// metrics, and <c>SchedulerJobStates</c> persistence — the body below is purely
/// the per-tick retention work. The <c>RunAsync(ct)</c> entry point is retained as
/// the operator-facing manual-run path: <c>SchedulerJobRegistry.RunNowAsync</c>
/// calls it directly when an operator clicks "Run Now" in the admin Schedules page —
/// bypassing the cron past-due gate that <see cref="SingletonCronJob.TickAsync"/>
/// evaluates so the work fires immediately regardless of schedule.
/// </summary>
public class AuditRetentionJob : SingletonCronJob
{
    private readonly AuditDbContext? _auditDb;
    private readonly AuditHashChainService? _hashChain;
    private readonly SystemConfig _config;
    private readonly ILogger<AuditRetentionJob> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="AuditRetentionJob"/>. The audit
    /// <see cref="AuditDbContext"/> is optional so the job resolves cleanly even in
    /// bootstrap scenarios where the audit database hasn't been provisioned. The
    /// <paramref name="hashChain"/> writes a prune marker for each chain pruned.
    /// </summary>
    public AuditRetentionJob(
        IServiceProvider serviceProvider,
        SystemConfig config,
        ILogger<AuditRetentionJob> logger,
        SchedulerJobRunner runner,
        AuditDbContext? auditDb = null,
        AuditHashChainService? hashChain = null)
        : base(serviceProvider, logger, config, runner)
    {
        _config = config;
        _logger = logger;
        _auditDb = auditDb;
        _hashChain = hashChain;
    }

    /// <inheritdoc />
    public override string Name => "AuditRetention";

    /// <summary>
    /// Cron expression for the retention sweep. Returns <see cref="string.Empty"/> when
    /// retention is disabled (or the <c>Audit.Retention</c> section is missing), which
    /// the base <see cref="SingletonCronJob.TickAsync"/> treats as "skip without state
    /// write". Operators turn this off in short-lived forensic investigations.
    /// </summary>
    protected override string CronExpression =>
        (_config.Audit?.Retention != null && _config.Audit.Retention.Enabled)
            ? _config.Audit.Retention.Schedule
            : string.Empty;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
    /// operator clicks "Run Now" for this job — bypassing the cron past-due gate that
    /// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
    /// regardless of schedule. The protected <see cref="ExecuteAsync"/> body is invoked
    /// directly.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Runs one retention pass across every audit table. Each table is pruned under
    /// its own retention window and batch size; failures on one table log and continue
    /// so a stuck index or missing column doesn't block the rest of the cleanup. When
    /// <c>ArchiveBeforeDelete</c> is set and the archive directory cannot be created, the run
    /// deletes nothing.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        if (_auditDb == null)
        {
            _logger.LogDebug("AuditRetentionJob: audit DB not configured; nothing to do.");
            return;
        }

        // CronExpression already short-circuits when retention is disabled. The check
        // here is defense-in-depth for the manual-run RunAsync path which bypasses
        // the cron evaluation in the base class.
        var retention = _config.Audit?.Retention;
        if (retention == null || !retention.Enabled)
        {
            _logger.LogDebug("AuditRetentionJob: retention disabled; skipping.");
            return;
        }

        var batchSize = retention.DeleteBatchSize <= 0 ? 10_000 : retention.DeleteBatchSize;
        var generalDays = retention.GeneralRetentionDays;
        var networkDays = retention.NetworkRetentionDays;
        var archive = retention.ArchiveBeforeDelete;
        var archivePath = retention.ArchivePath;

        // Resolve archive directory once per run so we don't fail halfway through the tables.
        string? resolvedArchiveDir = null;
        if (archive)
        {
            try
            {
                resolvedArchiveDir = Path.IsPathRooted(archivePath)
                    ? archivePath
                    : Path.Combine(AppContext.BaseDirectory, archivePath);
                Directory.CreateDirectory(resolvedArchiveDir);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "AuditRetentionJob: could not create archive directory {Path}; ArchiveBeforeDelete is set, so nothing is deleted this run",
                    resolvedArchiveDir ?? archivePath);
                return;
            }
        }

        // General audit tables (AuditLogs, AuditEst, AuditScep, AuditCmp, AuditAcme, AuditMsae).
        if (generalDays > 0)
        {
            var generalCutoff = TimeProvider.GetUtcNow().UtcDateTime.AddDays(-generalDays);

            await PruneTableAsync("AuditLogs", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
            await PruneTableAsync("AuditEst", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
            await PruneTableAsync("AuditScep", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
            await PruneTableAsync("AuditCmp", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
            await PruneTableAsync("AuditAcme", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
            await PruneTableAsync("AuditMsae", generalCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
        }
        else
        {
            _logger.LogInformation("AuditRetentionJob: general retention disabled (GeneralRetentionDays={Days})", generalDays);
        }

        // Network audit (higher volume, shorter window).
        if (networkDays > 0)
        {
            var networkCutoff = TimeProvider.GetUtcNow().UtcDateTime.AddDays(-networkDays);
            await PruneTableAsync("AuditNetwork", networkCutoff, batchSize,
                resolvedArchiveDir, cancellationToken);
        }
        else
        {
            _logger.LogInformation("AuditRetentionJob: network retention disabled (NetworkRetentionDays={Days})", networkDays);
        }
    }

    /// <summary>
    /// Optionally streams rows older than <paramref name="cutoff"/> in <paramref name="table"/>
    /// to a gzip jsonl file under <paramref name="archiveDir"/>, then chunked-deletes rows
    /// <paramref name="batchSize"/> at a time until none remain or cancellation fires. When the
    /// archive was requested and fails, nothing is deleted. AuditLogs is pruned one space chain at
    /// a time, and each chain's prune marker is written as soon as its rows are gone (even when a
    /// later batch failed or the run was cancelled), so no chain is left pruned without a marker.
    /// Catches per-table failures so one broken table can't abort the rest of the run.
    /// </summary>
    private async Task PruneTableAsync(
        string table,
        DateTime cutoff,
        int batchSize,
        string? archiveDir,
        CancellationToken ct)
    {
        try
        {
            if (archiveDir != null)
            {
                try
                {
                    await ArchiveTableAsync(table, cutoff, archiveDir, ct);
                }
                catch (Exception archiveEx)
                {
                    // ArchiveBeforeDelete promises the rows exist somewhere before they are gone.
                    // Deleting without the archive would break that promise silently.
                    _logger.LogError(archiveEx,
                        "AuditRetentionJob: archive step failed for {Table}; skipping delete for this run", table);
                    return;
                }
            }

            var totalDeleted = 0;
            if (table == "AuditLogs")
            {
                var chains = await _auditDb!.AuditLogs.Where(a => a.Timestamp < cutoff)
                    .Select(a => a.TenantId).Distinct().ToListAsync(ct);
                foreach (var spaceId in chains)
                {
                    var deleted = 0;
                    try
                    {
                        await DeleteInBatchesAsync(table, cutoff, true, spaceId, batchSize, n => deleted += n, ct);
                    }
                    finally
                    {
                        totalDeleted += deleted;
                        if (deleted > 0)
                            await RecordPruneMarkerAsync(spaceId, cutoff);
                    }
                }
            }
            else
            {
                await DeleteInBatchesAsync(table, cutoff, false, null, batchSize, n => totalDeleted += n, ct);
            }

            if (totalDeleted > 0)
                _logger.LogInformation(
                    "AuditRetentionJob: deleted {Count} rows from {Table} older than {Cutoff:u}",
                    totalDeleted, table, cutoff);
            else
                _logger.LogDebug(
                    "AuditRetentionJob: no rows to prune from {Table} (cutoff={Cutoff:u})",
                    table, cutoff);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AuditRetentionJob: prune failed for table {Table}", table);
        }
    }

    /// <summary>
    /// Deletes rows older than <paramref name="cutoff"/> from <paramref name="table"/> in batches
    /// until a short batch or cancellation, reporting each batch's count to
    /// <paramref name="onDeleted"/> as it commits so a caller still knows what was deleted when a
    /// later batch throws. With <paramref name="bySpace"/> only <paramref name="spaceId"/>'s rows
    /// (null meaning the system chain) are deleted.
    /// </summary>
    private async Task DeleteInBatchesAsync(
        string table, DateTime cutoff, bool bySpace, Guid? spaceId, int batchSize, Action<int> onDeleted, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var affected = await DeleteBatchAsync(table, cutoff, bySpace, spaceId, batchSize, ct);
            if (affected <= 0)
                break;
            onDeleted(affected);
            if (affected < batchSize)
                break;

            // Cooperative yield so a huge backlog doesn't wedge the scheduler cycle.
            await Task.Delay(50, ct);
        }
    }

    /// <summary>
    /// Deletes one batch of at most <paramref name="batchSize"/> rows older than
    /// <paramref name="cutoff"/> and returns how many went. PostgreSQL has no DELETE ... LIMIT,
    /// so the batch is selected first and deleted by ctid. The table name comes from the literals
    /// in <see cref="ExecuteAsync"/> and is quoted to keep EF's casing. Overridable so tests can
    /// run the job's control flow on a provider without ctid.
    /// </summary>
    protected virtual Task<int> DeleteBatchAsync(
        string table, DateTime cutoff, bool bySpace, Guid? spaceId, int batchSize, CancellationToken ct)
    {
        var quoted = "\"" + table.Replace("\"", "\"\"") + "\"";
        var spaceClause = !bySpace ? "" : spaceId == null ? " AND \"TenantId\" IS NULL" : " AND \"TenantId\" = {2}";
        var sql =
            $"DELETE FROM {quoted} WHERE ctid IN ("
            + $"SELECT ctid FROM {quoted} WHERE \"Timestamp\" < {{0}}{spaceClause} LIMIT {{1}})";
        var parameters = bySpace && spaceId != null
            ? new object[] { cutoff, batchSize, spaceId.Value }
            : new object[] { cutoff, batchSize };
        return _auditDb!.Database.ExecuteSqlRawAsync(sql, parameters, ct);
    }

    /// <summary>
    /// Writes the prune marker for one space chain right after its rows were deleted. Runs
    /// uncancellable, so a shutdown that arrives after the delete still leaves the chain marked;
    /// a failure is logged, since verification will then report a break at the chain's oldest record.
    /// </summary>
    private async Task RecordPruneMarkerAsync(Guid? spaceId, DateTime cutoff)
    {
        if (_hashChain == null)
            return;
        try
        {
            await _hashChain.RecordPruneAsync(_auditDb!, spaceId, cutoff, CancellationToken.None);
        }
        catch (Exception markerEx)
        {
            _logger.LogError(markerEx,
                "AuditRetentionJob: could not write the prune marker for audit chain {SpaceId}; verification will report a break at its oldest record",
                spaceId?.ToString() ?? "instance");
        }
    }

    /// <summary>
    /// Streams every row older than <paramref name="cutoff"/> in <paramref name="table"/>
    /// to a gzip jsonl file under <paramref name="archiveDir"/>. One file per table per
    /// run so operators can rotate / snapshot them independently. Rows are pulled via a
    /// forward-only ADO reader (not EF tracking) so memory usage stays flat even on
    /// multi-million-row tables.
    /// </summary>
    private async Task ArchiveTableAsync(string table, DateTime cutoff, string archiveDir, CancellationToken ct)
    {
        var stamp = TimeProvider.GetUtcNow().UtcDateTime.ToString("yyyyMMddHHmmss");
        var file = Path.Combine(archiveDir, $"audit-{table}-{stamp}.jsonl.gz");

        await using var fs = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await using var gz = new GZipStream(fs, CompressionLevel.Optimal);

        // Capture prior connection state so we can restore it: EF normally manages the
        // DbConnection lifetime, and leaving it open after we forced it open here would
        // leak a pooled connection if downstream EF expected closed-state semantics.
        var conn = _auditDb!.Database.GetDbConnection();
        var wasOpen = conn.State == System.Data.ConnectionState.Open;
        if (!wasOpen)
            await conn.OpenAsync(ct);

        try
        {
            using var cmd = conn.CreateCommand();
            // Double-quoted, not backticked: PostgreSQL uses backticks for nothing at all, and
            // folds an unquoted identifier to lower case, so both the table and the column have
            // to be quoted to match the casing EF created them with.
            cmd.CommandText =
                $"SELECT * FROM \"{table.Replace("\"", "\"\"")}\" WHERE \"Timestamp\" < @cutoff";
            var p = cmd.CreateParameter();
            p.ParameterName = "@cutoff";
            p.Value = cutoff;
            cmd.Parameters.Add(p);

            using var reader = await cmd.ExecuteReaderAsync(ct);
            var columns = new string[reader.FieldCount];
            for (int i = 0; i < reader.FieldCount; i++)
                columns[i] = reader.GetName(i);

            int rows = 0;
            while (await reader.ReadAsync(ct))
            {
                var dict = new Dictionary<string, object?>(reader.FieldCount);
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    var value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                    dict[columns[i]] = value;
                }
                var json = JsonSerializer.SerializeToUtf8Bytes(dict);
                await gz.WriteAsync(json, ct);
                await gz.WriteAsync(new byte[] { (byte)'\n' }, ct);
                rows++;
            }

            _logger.LogInformation(
                "AuditRetentionJob: archived {Rows} rows from {Table} to {File}",
                rows, table, file);
        }
        finally
        {
            if (!wasOpen && conn.State == System.Data.ConnectionState.Open)
                await conn.CloseAsync();
        }
    }
}
