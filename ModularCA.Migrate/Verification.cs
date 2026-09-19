using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using MySqlConnector;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// What the helper checks before it says the migration worked.
/// <para>
/// A copy that reports success and is subtly wrong is worse than one that fails, because the
/// source gets decommissioned on the strength of the report. So the claim is backed by four
/// different kinds of evidence: the server's own foreign key validation (done by the copier when
/// it restores the constraints), row counts per table, the audit hash chain re-verified end to
/// end, and a sample of certificates re-parsed from the bytes that crossed.
/// </para>
/// </summary>
public sealed class Verification
{
    private readonly Action<string> _say;
    private readonly List<string> _failures = [];

    /// <summary>Creates a verifier reporting through the given sink.</summary>
    /// <param name="say">Progress sink.</param>
    public Verification(Action<string> say) => _say = say;

    /// <summary>Everything that did not check out. Empty means the migration is sound.</summary>
    public IReadOnlyList<string> Failures => _failures;

    /// <summary>
    /// Resets every identity sequence past the largest value its column now holds.
    /// <para>
    /// This is the step whose absence produces a database that verifies perfectly and then fails
    /// on the very first insert. Copying preserves identifiers, which means the sequences behind
    /// the identity columns still sit at 1, and the next row written collides with one that came
    /// across. It is the most common way a PostgreSQL migration appears to have worked.
    /// </para>
    /// </summary>
    /// <param name="dest">An open connection to the destination database.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The number of sequences reset.</returns>
    public async Task<int> ResetSequencesAsync(NpgsqlConnection dest, CancellationToken ct)
    {
        var identities = new List<(string Table, string Column)>();
        await using (var cmd = new NpgsqlCommand(
            """
            SELECT c.relname, a.attname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND a.attidentity IN ('a', 'd') AND a.attnum > 0 AND NOT a.attisdropped
            """, dest))
        {
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                identities.Add((reader.GetString(0), reader.GetString(1)));
        }

        foreach (var (table, column) in identities)
        {
            // is_called is false for an empty table so the first value handed out is 1, and true
            // otherwise so the next is one past the largest that came across.
            var sql = $"""
                SELECT setval(
                    pg_get_serial_sequence('public."{table}"', '{column}'),
                    GREATEST(COALESCE((SELECT MAX("{column}") FROM "{table}"), 0), 1),
                    (SELECT COUNT(*) FROM "{table}") > 0)
                """;
            await using var cmd = new NpgsqlCommand(sql, dest);
            await cmd.ExecuteScalarAsync(ct);
        }

        _say($"  {identities.Count} identity sequences reset past their copied values");
        return identities.Count;
    }

    /// <summary>
    /// Compares the row count of every copied table against the source.
    /// </summary>
    /// <param name="dest">An open connection to the destination database.</param>
    /// <param name="results">What the copier reported per table.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task CheckRowCountsAsync(
        NpgsqlConnection dest, IReadOnlyList<TableCopier.TableResult> results, CancellationToken ct)
    {
        var checked_ = 0;
        foreach (var result in results.Where(r => !r.Skipped))
        {
            await using var cmd = new NpgsqlCommand($"SELECT COUNT(*) FROM \"{result.Table}\"", dest)
            {
                CommandTimeout = 0,
            };
            var actual = Convert.ToInt64(await cmd.ExecuteScalarAsync(ct));
            checked_++;

            if (actual != result.SourceRows)
                _failures.Add(
                    $"{result.Table}: {result.SourceRows:N0} rows on the source, {actual:N0} on the destination.");
        }
        _say($"  row counts match across {checked_} tables");
    }

    /// <summary>
    /// Re-parses a sample of certificates from the bytes that crossed and checks each against the
    /// serial number stored beside it.
    /// <para>
    /// This is the proof that the <c>bytea</c> round trip was byte-exact, tested on the data where
    /// a single flipped byte matters most. A certificate that no longer parses, or that parses to
    /// a different serial than the row claims, means the binary columns did not survive — and the
    /// same columns carry protected key material, which cannot be checked this directly.
    /// </para>
    /// </summary>
    /// <param name="dest">An open connection to the destination database.</param>
    /// <param name="sample">How many certificates to check.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task CheckCertificatesAsync(NpgsqlConnection dest, int sample, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            $"""
             SELECT "SerialNumber", "RawCertificate"
             FROM "Certificates"
             WHERE "RawCertificate" IS NOT NULL
             ORDER BY "NotBefore" DESC
             LIMIT {sample}
             """, dest);

        var checked_ = 0;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var storedSerial = reader.GetString(0);
            var raw = (byte[])reader[1];
            checked_++;

            try
            {
                using var certificate = X509CertificateLoader.LoadCertificate(raw);
                var parsedSerial = certificate.SerialNumber;

                if (!string.Equals(parsedSerial.TrimStart('0'), storedSerial.TrimStart('0'),
                        StringComparison.OrdinalIgnoreCase))
                    _failures.Add(
                        $"Certificate row claims serial {storedSerial} but its stored bytes parse to {parsedSerial}.");
            }
            catch (Exception ex)
            {
                _failures.Add($"Certificate with serial {storedSerial} no longer parses: {ex.Message}");
            }
        }

        if (checked_ == 0)
            _say("  no certificates to re-parse (none carry raw bytes)");
        else
            _say($"  {checked_} certificates re-parsed from their stored bytes");
    }

    /// <summary>
    /// Re-verifies the audit hash chain on the destination, and attributes anything broken.
    /// <para>
    /// Audit rows are chained, so they have to arrive in order and still verify afterwards. But a
    /// break found here has two possible causes with opposite responses, and reporting it without
    /// saying which is worse than not checking: either the copy damaged the record, which must
    /// fail the migration, or the record already failed to verify on the source, which must not —
    /// a hash chain cannot be repaired, so refusing would strand the deployment on MariaDB forever
    /// over a fault the move neither caused nor can fix.
    /// </para>
    /// <para>
    /// So each break is settled by comparing the record against the source, field by field over
    /// exactly the inputs the hash is computed from. Unchanged means carried over; anything else
    /// names what the copy altered.
    /// </para>
    /// </summary>
    /// <param name="audit">A context on the destination audit database.</param>
    /// <param name="source">An open connection to the source audit database.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task CheckAuditChainAsync(
        Database.AuditDbContext audit, MySqlConnection source, CancellationToken ct)
    {
        var tenants = await audit.AuditLogs
            .Where(a => a.RecordHash != null)
            .Select(a => a.TenantId)
            .Distinct()
            .ToListAsync(ct);

        if (tenants.Count == 0)
        {
            _say("  audit chain: no hashed rows to verify");
            return;
        }

        var service = new AuditHashChainService();
        var verified = 0;
        var carried = 0;
        string? firstCarriedIssue = null;

        foreach (var tenant in tenants)
        {
            var result = await service.VerifyAsync(audit, tenant, int.MaxValue, ct);
            verified += result.RecordsVerified;

            foreach (var chainBreak in result.Breaks)
            {
                var label = tenant?.ToString() ?? "(system)";
                var differences = await HashInputDifferencesAsync(source, audit, chainBreak.RecordId, ct);

                if (differences.Count == 0)
                {
                    carried++;
                    firstCarriedIssue ??= chainBreak.Issue;
                    continue;
                }

                _failures.Add(
                    $"Audit record {chainBreak.RecordId} (tenant {label}) was changed by the copy: "
                    + $"{string.Join("; ", differences)}. {chainBreak.Issue}");
            }
        }

        _say($"  audit chain checked over {verified:N0} records across {tenants.Count} chain(s)");

        if (carried == 0)
            return;

        // Loud, but not a failure. Every one of these rows crossed byte for byte.
        _say($"  (!) {carried:N0} record(s) do not verify, and did not verify on the source either —");
        _say("      every field the hash covers crossed unchanged, so the copy is faithful.");
        if (firstCarriedIssue is not null)
            _say($"      first: {firstCarriedIssue}");
    }

    /// <summary>
    /// Compares a record against the source over exactly the fields the audit hash is computed
    /// from, so a chain break can be attributed rather than merely reported.
    /// </summary>
    /// <remarks>
    /// The timestamp is compared as an instant rather than as text, deliberately. The canonical
    /// form the hash uses is <c>ToString("O")</c>, which renders both a
    /// <see cref="DateTimeKind"/> and seven fractional digits — neither of which a database
    /// column carries back faithfully. Comparing the rendering would report a difference where the
    /// stored moment is identical, which is the opposite of what this is for.
    /// </remarks>
    /// <param name="source">An open connection to the source audit database.</param>
    /// <param name="audit">A context on the destination audit database.</param>
    /// <param name="recordId">The record to compare.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A description of each field that differs; empty when the copy is faithful.</returns>
    private static async Task<IReadOnlyList<string>> HashInputDifferencesAsync(
        MySqlConnection source, Database.AuditDbContext audit, Guid recordId, CancellationToken ct)
    {
        var copy = await audit.AuditLogs.AsNoTracking().FirstOrDefaultAsync(a => a.Id == recordId, ct);
        if (copy is null)
            return ["the record is missing from the copy entirely"];

        await using var cmd = new MySqlCommand(
            """
            SELECT Timestamp, ActorUserId, ActorUsername, ActionType, TargetEntityType,
                   TargetEntityId, DetailsJson, SourceIp, Success, ErrorMessage,
                   CertificateAuthorityId, TenantId, RecordHash, PreviousRecordHash
            FROM AuditLogs WHERE Id = @id
            """, source);
        cmd.Parameters.AddWithValue("id", recordId.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return ["the record is missing from the source"];

        object? At(int i) => reader.IsDBNull(i) ? null : reader.GetValue(i);
        string? Text(int i) => At(i) as string ?? At(i)?.ToString();

        var differences = new List<string>();

        void Compare(string field, string? sourceValue, string? copyValue)
        {
            if (!string.Equals(sourceValue ?? "", copyValue ?? "", StringComparison.Ordinal))
                differences.Add($"{field} changed");
        }

        if (At(0) is DateTime sourceTimestamp && sourceTimestamp.Ticks != copy.Timestamp.Ticks)
            differences.Add($"Timestamp {sourceTimestamp:O} became {copy.Timestamp:O}");

        Compare("ActorUserId", Text(1), copy.ActorUserId?.ToString());
        Compare("ActorUsername", Text(2), copy.ActorUsername);
        Compare("ActionType", Text(3), copy.ActionType);
        Compare("TargetEntityType", Text(4), copy.TargetEntityType);
        Compare("TargetEntityId", Text(5), copy.TargetEntityId);
        Compare("DetailsJson", Text(6), copy.DetailsJson);
        Compare("SourceIp", Text(7), copy.SourceIp);
        Compare("Success", Convert.ToBoolean(At(8) ?? false).ToString(), copy.Success.ToString());
        Compare("ErrorMessage", Text(9), copy.ErrorMessage);
        Compare("CertificateAuthorityId", Text(10), copy.CertificateAuthorityId?.ToString());
        Compare("TenantId", Text(11), copy.TenantId?.ToString());
        Compare("RecordHash", Text(12), copy.RecordHash);
        Compare("PreviousRecordHash", Text(13), copy.PreviousRecordHash);

        return differences;
    }
}
