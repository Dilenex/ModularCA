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
/// the noisier AuditNetwork table, uses per-batch <c>LIMIT</c> so no single DELETE
/// holds a long-running transaction, and optionally streams matching rows to a
/// gzip jsonl archive file before deleting them (<c>ArchiveBeforeDelete</c>).
///
/// Row-level DELETE only — the <c>modularca_audit</c> user cannot DROP tables by
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
    private readonly SystemConfig _config;
    private readonly ILogger<AuditRetentionJob> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="AuditRetentionJob"/>. The audit
    /// <see cref="AuditDbContext"/> is optional so the job resolves cleanly even in
    /// bootstrap scenarios where the audit database hasn't been provisioned.
    /// </summary>
    public AuditRetentionJob(
        IServiceProvider serviceProvider,
        SystemConfig config,
        ILogger<AuditRetentionJob> logger,
        SchedulerJobRunner runner,
        AuditDbContext? auditDb = null)
        : base(serviceProvider, logger, config, runner)
    {
        _config = config;
        _logger = logger;
        _auditDb = auditDb;
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
    /// so a stuck index or missing column doesn't block the rest of the cleanup.
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
                    "AuditRetentionJob: could not create archive directory {Path}; archive will be skipped for this run",
                    resolvedArchiveDir ?? archivePath);
                resolvedArchiveDir = null;
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
    /// <paramref name="batchSize"/> at a time until none remain or cancellation fires.
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
                    // Archive failure should NOT block the delete — if we can't write the
                    // archive we'd rather keep rolling retention than grow the table forever.
                    // Operators see the Error in logs and can retry later.
                    _logger.LogError(archiveEx,
                        "AuditRetentionJob: archive step failed for {Table}; proceeding with delete anyway", table);
                }
            }

            var totalDeleted = 0;
            while (!ct.IsCancellationRequested)
            {
                // Raw SQL keeps the DELETE off EF's change tracker. MySQL supports
                // DELETE ... LIMIT; the parameter form avoids any string-formatting risk
                // even though the cutoff is purely numeric.
                var sql = $"DELETE FROM `{table}` WHERE Timestamp < {{0}} LIMIT {{1}}";
                var affected = await _auditDb!.Database.ExecuteSqlRawAsync(
                    sql, new object[] { cutoff, batchSize }, ct);

                if (affected <= 0)
                    break;

                totalDeleted += affected;

                if (affected < batchSize)
                    break; // short batch — we're caught up

                // Cooperative yield so a huge backlog doesn't wedge the scheduler cycle.
                await Task.Delay(50, ct);
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
            cmd.CommandText = $"SELECT * FROM `{table}` WHERE Timestamp < @cutoff";
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
