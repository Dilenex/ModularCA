using System.Security.Cryptography;
using System.Text;
using MySqlConnector;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// Copies one database's tables into another, preserving every identifier.
/// <para>
/// Foreign keys are dropped before the copy and added back after it, rather than the rows being
/// ordered so that no constraint is ever violated mid-run. Topological ordering cannot express a
/// table that references itself — a certificate whose issuer is another certificate — and the
/// alternative of suppressing constraints with <c>session_replication_role</c> needs a superuser,
/// which this helper deliberately does not require. Re-adding a constraint makes PostgreSQL scan
/// and validate it, so the referential integrity of the copy is checked by the database rather
/// than asserted by this file.
/// </para>
/// </summary>
public sealed class TableCopier
{
    private readonly Action<string> _say;

    /// <summary>Creates a copier that reports progress through the given sink.</summary>
    /// <param name="say">Progress sink.</param>
    public TableCopier(Action<string> say) => _say = say;

    /// <summary>How a single table's copy turned out.</summary>
    /// <param name="Table">The table name.</param>
    /// <param name="SourceRows">Rows counted on the source.</param>
    /// <param name="CopiedRows">Rows written to the destination.</param>
    /// <param name="Skipped">Set when the table does not exist on the source at all.</param>
    public sealed record TableResult(string Table, long SourceRows, long CopiedRows, bool Skipped);

    /// <summary>
    /// Copies every table, with foreign keys suspended for the duration.
    /// </summary>
    /// <param name="source">An open connection to the source database.</param>
    /// <param name="dest">An open connection to the destination database.</param>
    /// <param name="tables">The destination tables, from the model.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>One result per table.</returns>
    public async Task<IReadOnlyList<TableResult>> CopyAsync(
        MySqlConnection source, NpgsqlConnection dest,
        IReadOnlyList<ModelIntrospection.TableInfo> tables, CancellationToken ct)
    {
        var sourceSchema = await SourceSchemaAsync(source, ct);
        var foreignKeys = await CaptureForeignKeysAsync(dest, ct);
        _say($"  {foreignKeys.Count} foreign keys suspended for the copy");
        await DropForeignKeysAsync(dest, foreignKeys, ct);

        var results = new List<TableResult>();
        try
        {
            foreach (var table in tables)
            {
                if (!sourceSchema.TryGetValue(table.Name, out var sourceColumns))
                {
                    // A table that exists only on 0.3.1 has nothing to bring across. Recorded
                    // rather than silently passed over, so the report accounts for every table.
                    results.Add(new TableResult(table.Name, 0, 0, Skipped: true));
                    continue;
                }

                results.Add(await CopyTableAsync(source, dest, table, sourceColumns, ct));
            }
        }
        finally
        {
            // Restored even on failure. A destination left without its foreign keys would look
            // like a working database and behave like a corrupt one.
            await RestoreForeignKeysAsync(dest, foreignKeys, ct);
        }

        _say("  foreign keys restored and validated by the server");
        return results;
    }

    private async Task<TableResult> CopyTableAsync(
        MySqlConnection source, NpgsqlConnection dest,
        ModelIntrospection.TableInfo table, HashSet<string> sourceColumns, CancellationToken ct)
    {
        var transform = RowTransforms.For(table.Name);

        // Only columns that exist on both sides are read. A column new in 0.3.1 takes its
        // default, and one that 0.3.0 had and 0.3.1 does not is left behind — which is how
        // CmpSecretPlaintext stops existing without anything special being said about it.
        var copied = table.Columns
            .Where(c => sourceColumns.Contains(c.Name) || transform?.Supplies(c.Name) == true)
            .ToList();

        if (copied.Count == 0)
            return new TableResult(table.Name, 0, 0, Skipped: true);

        var readColumns = copied
            .Where(c => sourceColumns.Contains(c.Name))
            .Select(c => c.Name)
            .Concat(transform?.RequiresSourceColumns.Where(sourceColumns.Contains) ?? [])
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var sourceRows = await CountAsync(source, table.Name, ct);
        if (sourceRows == 0)
            return new TableResult(table.Name, 0, 0, Skipped: false);

        var quotedRead = string.Join(", ", readColumns.Select(c => $"`{c}`"));
        await using var cmd = new MySqlCommand($"SELECT {quotedRead} FROM `{table.Name}`", source);
        cmd.CommandTimeout = 0;
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        var ordinals = readColumns
            .Select((name, index) => (name, index))
            .ToDictionary(x => x.name, x => x.index, StringComparer.Ordinal);

        // PostgreSQL caps a statement at 65535 parameters; this keeps every batch well inside it
        // whatever the table's width.
        var batchSize = Math.Max(1, 2000 / Math.Max(1, copied.Count));
        var batch = new List<object?[]>(batchSize);
        long written = 0;

        while (await reader.ReadAsync(ct))
        {
            var raw = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (name, index) in ordinals)
                raw[name] = reader.IsDBNull(index) ? null : reader.GetValue(index);

            var row = new object?[copied.Count];
            for (var i = 0; i < copied.Count; i++)
            {
                var column = copied[i];
                object? value;

                if (transform is not null && transform.Supplies(column.Name))
                    value = transform.Produce(column.Name, raw);
                else
                    raw.TryGetValue(column.Name, out value);

                try
                {
                    row[i] = ValueCoercion.Coerce(value, column.ClrType);
                }
                catch (InvalidOperationException ex)
                {
                    throw new InvalidOperationException($"{table.Name}.{column.Name}: {ex.Message}", ex);
                }
            }

            batch.Add(row);
            if (batch.Count < batchSize)
                continue;

            written += await InsertBatchAsync(dest, table.Name, copied, batch, ct);
            batch.Clear();
        }

        if (batch.Count > 0)
            written += await InsertBatchAsync(dest, table.Name, copied, batch, ct);

        _say($"  {table.Name}: {written:N0} rows");
        return new TableResult(table.Name, sourceRows, written, Skipped: false);
    }

    private static async Task<long> InsertBatchAsync(
        NpgsqlConnection dest, string table,
        IReadOnlyList<ModelIntrospection.ColumnInfo> columns, List<object?[]> rows, CancellationToken ct)
    {
        var sql = new StringBuilder();
        sql.Append("INSERT INTO \"").Append(table).Append("\" (");
        sql.AppendJoin(", ", columns.Select(c => $"\"{c.Name}\""));
        sql.Append(") VALUES ");

        await using var cmd = new NpgsqlCommand { Connection = dest, CommandTimeout = 0 };
        for (var r = 0; r < rows.Count; r++)
        {
            if (r > 0) sql.Append(", ");
            sql.Append('(');
            for (var c = 0; c < columns.Count; c++)
            {
                if (c > 0) sql.Append(", ");
                var name = $"p{r}_{c}";
                sql.Append('@').Append(name);
                cmd.Parameters.AddWithValue(name, rows[r][c] ?? DBNull.Value);
            }
            sql.Append(')');
        }

        cmd.CommandText = sql.ToString();
        await cmd.ExecuteNonQueryAsync(ct);
        return rows.Count;
    }

    // ── Foreign keys ──────────────────────────────────────────────────────────

    /// <summary>A foreign key captured before it was dropped, with the definition to restore it.</summary>
    /// <param name="Table">The table the constraint is on, schema-qualified.</param>
    /// <param name="Name">The constraint name.</param>
    /// <param name="Definition">The full <c>FOREIGN KEY ...</c> clause as PostgreSQL renders it.</param>
    public sealed record ForeignKey(string Table, string Name, string Definition);

    private static async Task<List<ForeignKey>> CaptureForeignKeysAsync(NpgsqlConnection dest, CancellationToken ct)
    {
        var keys = new List<ForeignKey>();
        await using var cmd = new NpgsqlCommand(
            """
            SELECT c.conrelid::regclass::text, c.conname, pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE c.contype = 'f' AND n.nspname = 'public'
            """, dest);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            keys.Add(new ForeignKey(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        return keys;
    }

    private static async Task DropForeignKeysAsync(NpgsqlConnection dest, List<ForeignKey> keys, CancellationToken ct)
    {
        foreach (var key in keys)
        {
            await using var cmd = new NpgsqlCommand(
                $"ALTER TABLE {key.Table} DROP CONSTRAINT \"{key.Name}\"", dest) { CommandTimeout = 0 };
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task RestoreForeignKeysAsync(NpgsqlConnection dest, List<ForeignKey> keys, CancellationToken ct)
    {
        foreach (var key in keys)
        {
            await using var cmd = new NpgsqlCommand(
                $"ALTER TABLE {key.Table} ADD CONSTRAINT \"{key.Name}\" {key.Definition}", dest) { CommandTimeout = 0 };
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    // ── Source shape ──────────────────────────────────────────────────────────

    private static async Task<Dictionary<string, HashSet<string>>> SourceSchemaAsync(
        MySqlConnection source, CancellationToken ct)
    {
        var schema = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        await using var cmd = new MySqlCommand(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()",
            source);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var table = reader.GetString(0);
            if (!schema.TryGetValue(table, out var columns))
                schema[table] = columns = new HashSet<string>(StringComparer.Ordinal);
            columns.Add(reader.GetString(1));
        }
        return schema;
    }

    private static async Task<long> CountAsync(MySqlConnection source, string table, CancellationToken ct)
    {
        await using var cmd = new MySqlCommand($"SELECT COUNT(*) FROM `{table}`", source) { CommandTimeout = 0 };
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(ct));
    }
}

/// <summary>
/// The columns that do not copy across as they stand.
/// </summary>
/// <remarks>
/// There is exactly one table in this category, and it is here rather than inline in the copier so
/// that the list of exceptions is a thing you can read in one place and find empty for every other
/// table.
/// </remarks>
public abstract class RowTransform
{
    /// <summary>Source columns this transform needs read even if it does not write them.</summary>
    public abstract IReadOnlyList<string> RequiresSourceColumns { get; }

    /// <summary>Whether this transform produces the named destination column.</summary>
    /// <param name="column">A destination column name.</param>
    /// <returns>True when <see cref="Produce"/> should be asked for it.</returns>
    public abstract bool Supplies(string column);

    /// <summary>Produces the value for a destination column from the source row.</summary>
    /// <param name="column">The destination column name.</param>
    /// <param name="row">The source row, keyed by source column name.</param>
    /// <returns>The value to write.</returns>
    public abstract object? Produce(string column, IReadOnlyDictionary<string, object?> row);
}

/// <summary>Chooses the transform for a table, if it has one.</summary>
public static class RowTransforms
{
    private static readonly EnrollmentTokenTransform Tokens = new();

    /// <summary>Returns the transform for a table, or null when the table copies straight across.</summary>
    /// <param name="table">A destination table name.</param>
    /// <returns>The transform, or null.</returns>
    public static RowTransform? For(string table) =>
        string.Equals(table, "EnrollmentTokens", StringComparison.Ordinal) ? Tokens : null;
}

/// <summary>
/// The enrollment token split.
/// <para>
/// On 0.3.0 the <c>Token</c> column held the token itself; on 0.3.1 it holds a SHA-256 of it, so
/// existing tokens keep working and stop being readable — which is the whole point of the change,
/// and the reason the value is hashed on the way across rather than moved.
/// </para>
/// <para>
/// The two CMP columns are new and are left null. A CMP row's shared secret <em>was</em> its token
/// value, and on 0.3.1 that secret lives wrapped under a key only the signer holds. Preflight has
/// already refused if any CMP token is still live, so every CMP row reaching here is revoked or
/// expired: its history is worth keeping and its secret is not.
/// </para>
/// </summary>
public sealed class EnrollmentTokenTransform : RowTransform
{
    /// <inheritdoc />
    public override IReadOnlyList<string> RequiresSourceColumns { get; } = ["Token"];

    /// <inheritdoc />
    public override bool Supplies(string column) =>
        column is "Token" or "CmpSecretWrapped" or "CmpSecretLastFour";

    /// <inheritdoc />
    public override object? Produce(string column, IReadOnlyDictionary<string, object?> row)
    {
        if (column is "CmpSecretWrapped" or "CmpSecretLastFour")
            return null;

        row.TryGetValue("Token", out var token);
        if (token is not string plaintext || plaintext.Length == 0)
            return token;

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(plaintext)));
    }
}
