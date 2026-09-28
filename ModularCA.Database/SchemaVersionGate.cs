using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.Storage;
using ModularCA.Shared.Utils;

namespace ModularCA.Database;

/// <summary>
/// What a process may do with a database schema, given the migrations the database records as
/// applied and the migrations this build carries.
/// </summary>
public enum SchemaVerdict
{
    /// <summary>The database has exactly the migrations this build knows. Start.</summary>
    Current,

    /// <summary>This build carries migrations the database lacks, and this process applies them.</summary>
    ApplyPending,

    /// <summary>
    /// The database is missing, or has no tables: the instance has not been bootstrapped. Every
    /// role, the control role included, starts and leaves the schema to bootstrap; the runtime
    /// never creates a baseline.
    /// </summary>
    Unbootstrapped,

    /// <summary>
    /// This build carries migrations the database lacks, and this process is not the control
    /// role that applies them. Wait for the control role.
    /// </summary>
    PendingForControlRole,

    /// <summary>
    /// The database records migrations this build does not know, so its schema is newer than
    /// this build understands. Refuse, whichever role this is.
    /// </summary>
    NewerThanBuild,

    /// <summary>
    /// The database has tables but no migration history, so no bootstrap of this product made it
    /// or its history was lost. Refuse, whichever role this is.
    /// </summary>
    Unmanaged,
}

/// <summary>What a database holds, before its history is compared with the build.</summary>
public enum DatabasePresence
{
    /// <summary>The database does not exist (SQLSTATE 3D000).</summary>
    Missing,

    /// <summary>The database exists and has no tables, or only an empty history table.</summary>
    Empty,

    /// <summary>The database has tables but no migration history rows.</summary>
    Unmanaged,

    /// <summary>The database records at least one migration.</summary>
    Managed,
}

/// <summary>
/// The migrations a database records as applied and the migrations this build carries.
/// </summary>
/// <param name="Applied">Migration ids in the database's history table, in applied order.</param>
/// <param name="Known">Migration ids in this build's assembly, in order.</param>
public sealed record SchemaState(IReadOnlyList<string> Applied, IReadOnlyList<string> Known)
{
    /// <summary>Migrations this build carries that the database has not applied, in order.</summary>
    public IReadOnlyList<string> Pending { get; } = Known.Except(Applied, StringComparer.Ordinal).ToList();

    /// <summary>Migrations the database has applied that this build does not carry.</summary>
    public IReadOnlyList<string> Unknown { get; } = Applied.Except(Known, StringComparer.Ordinal).ToList();

    /// <summary>
    /// What the database holds. <see cref="SchemaVersionGate.ReadAsync"/> sets it from the
    /// catalog; otherwise it is <see cref="DatabasePresence.Managed"/> when anything is applied
    /// and <see cref="DatabasePresence.Empty"/> when nothing is.
    /// </summary>
    public DatabasePresence Presence { get; init; } = Applied.Count > 0 ? DatabasePresence.Managed : DatabasePresence.Empty;
}

/// <summary>
/// A migration the control role could not apply.
/// </summary>
/// <param name="Migration">
/// The first migration of the attempted batch that is not applied, or every id of the batch
/// joined with " or " when the history could not be read back.
/// </param>
/// <param name="Error">The underlying error.</param>
/// <param name="CommittedInThisRun">Migrations this call committed before the failure.</param>
/// <param name="LeavesNonTransactionalStatements">
/// The failed migration runs statements outside a transaction, which a failure does not roll back.
/// </param>
public sealed record MigrationFailure(
    string Migration,
    Exception Error,
    IReadOnlyList<string> CommittedInThisRun,
    bool LeavesNonTransactionalStatements);

/// <summary>
/// The startup rule for schema versions, shared by every process role.
/// </summary>
/// <remarks>
/// <para>
/// Only the control role applies migrations, and only to a database bootstrap created: a
/// missing or empty database is <see cref="SchemaVerdict.Unbootstrapped"/> for every role, and
/// a database with tables but no history is <see cref="SchemaVerdict.Unmanaged"/> and refused.
/// Every role refuses a database that records a migration this build does not know
/// (<see cref="SchemaVerdict.NewerThanBuild"/>). A role that does not apply migrations waits
/// on a database that lacks one of this build's migrations
/// (<see cref="SchemaVerdict.PendingForControlRole"/>). The upgrade order is therefore: control
/// role first, then the rest.
/// </para>
/// <para>
/// Only <see cref="ApplyAllForBootstrapAsync"/> applies a baseline.
/// </para>
/// </remarks>
public static class SchemaVersionGate
{
    private const string CreatedConcurrentlyAnnotation = "Npgsql:CreatedConcurrently";

    /// <summary>
    /// Reads what <paramref name="db"/>'s database holds and which migrations it records, as the
    /// context's own role. Only a database that does not exist (3D000) is reported as
    /// <see cref="DatabasePresence.Missing"/>; any other failure to connect throws
    /// <see cref="SchemaConnectException"/>. On PostgreSQL the connection is opened directly
    /// rather than through the provider's existence check, which reports a reset connection as
    /// a missing database. A history table the role cannot read throws
    /// <see cref="SchemaAccessException"/> before it is queried. Other errors propagate for
    /// <see cref="SchemaFailure.Classify"/>.
    /// </summary>
    public static async Task<SchemaState> ReadAsync(DbContext db, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var known = db.Database.GetMigrations().ToList();

        try
        {
            if (!db.Database.IsNpgsql() && !await db.GetService<IRelationalDatabaseCreator>().ExistsAsync(ct))
                return new SchemaState([], known) { Presence = DatabasePresence.Missing };
            await db.Database.OpenConnectionAsync(ct);
        }
        catch (Exception ex) when (SchemaFailure.SqlState(ex) == "3D000")
        {
            return new SchemaState([], known) { Presence = DatabasePresence.Missing };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new SchemaConnectException(ex);
        }

        try
        {
            var catalog = await ReadCatalogAsync(db, ct);
            if (catalog.HistoryExists && !catalog.HistoryReadable)
                throw new SchemaAccessException(catalog.Database, catalog.Role, catalog.HistoryTable);

            var applied = catalog.HistoryExists ? await QueryAppliedAsync(db, catalog, ct) : [];
            var presence = applied.Count > 0 ? DatabasePresence.Managed
                : catalog.OtherTables ? DatabasePresence.Unmanaged
                : DatabasePresence.Empty;
            return new SchemaState(applied, known) { Presence = presence };
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>
    /// Decides what a process may do with <paramref name="state"/>.
    /// </summary>
    /// <param name="state">The applied and known migrations.</param>
    /// <param name="appliesMigrations">Whether this process is the one that applies migrations (the control role).</param>
    public static SchemaVerdict Evaluate(SchemaState state, bool appliesMigrations)
    {
        ArgumentNullException.ThrowIfNull(state);
        switch (state.Presence)
        {
            case DatabasePresence.Missing:
            case DatabasePresence.Empty:
                return SchemaVerdict.Unbootstrapped;
            case DatabasePresence.Unmanaged:
                return SchemaVerdict.Unmanaged;
        }
        if (state.Unknown.Count > 0)
            return SchemaVerdict.NewerThanBuild;
        if (state.Pending.Count == 0)
            return SchemaVerdict.Current;
        return appliesMigrations ? SchemaVerdict.ApplyPending : SchemaVerdict.PendingForControlRole;
    }

    /// <summary>
    /// The operator-facing reason a process refuses to start or waits, or <see langword="null"/>
    /// when the verdict is neither.
    /// </summary>
    /// <param name="verdict">The verdict from <see cref="Evaluate"/>.</param>
    /// <param name="state">The state it was reached from.</param>
    /// <param name="contextName">Which database, for the message (e.g. "application", "audit").</param>
    public static string? RefusalMessage(SchemaVerdict verdict, SchemaState state, string contextName) => verdict switch
    {
        SchemaVerdict.NewerThanBuild =>
            $"The {contextName} database has migration(s) this build does not know: {string.Join(", ", state.Unknown)}. "
            + "Its schema is newer than this build. Run the build that applied them, or restore the pre-upgrade dump "
            + "before starting an older build.",
        SchemaVerdict.PendingForControlRole =>
            $"The {contextName} database lacks migration(s) this build needs: {string.Join(", ", state.Pending)}. "
            + "Only the control role applies migrations. Upgrade and start the control role first, then this process.",
        SchemaVerdict.Unmanaged =>
            $"The {contextName} database has tables but no migration history: it was not created by this product's "
            + "bootstrap, or its history was lost. Restore the pre-upgrade dump.",
        _ => null,
    };

    /// <summary>
    /// Applies the pending migrations of <paramref name="state"/> in order and returns the
    /// failure, or <see langword="null"/> when all were applied. EF commits each migration
    /// separately, so a failure leaves the ones before it applied.
    /// </summary>
    /// <remarks>
    /// Never reverts. EF treats a target older than an applied migration as a rollback, so a
    /// pending migration that sorts before the newest applied one (a merged branch) is applied by
    /// targeting that newest applied migration instead, which applies every gap migration in one
    /// call, each committed separately. The history is read again before each step, so a
    /// migration another process applied meanwhile is skipped rather than reverted to. On a
    /// failure the history is read back to name the first migration of the attempted batch that
    /// is not applied, and the ones this call committed. The connection is opened here, not by
    /// EF, so a failure to open it throws or reports <see cref="SchemaConnectException"/>.
    /// </remarks>
    public static async Task<MigrationFailure?> ApplyPendingAsync(
        DbContext db, SchemaState state, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(state);
        var migrator = db.GetService<IMigrator>();
        var known = state.Known;
        var order = known.Select((id, i) => (id, i)).ToDictionary(x => x.id, x => x.i, StringComparer.Ordinal);
        var committed = new List<string>();
        foreach (var migration in state.Pending)
        {
            var applied = (await ReadAppliedAsync(db, ct)).ToHashSet(StringComparer.Ordinal);
            if (applied.Contains(migration))
                continue;
            var newestApplied = applied.Where(order.ContainsKey).Select(id => order[id]).DefaultIfEmpty(-1).Max();
            var target = order[migration] < newestApplied ? known[newestApplied] : migration;
            var batch = known.Take(order[target] + 1).Where(id => !applied.Contains(id)).ToList();
            try
            {
                await OpenAsync(db, ct);
                try
                {
                    await migrator.MigrateAsync(target, ct);
                }
                finally
                {
                    await db.Database.CloseConnectionAsync();
                }
                committed.AddRange(batch);
            }
            catch (Exception ex)
            {
                return await DescribeFailureAsync(db, batch, migration, ex, committed);
            }
        }
        return null;
    }

    /// <summary>
    /// Applies every migration, the frozen baseline first, to a database bootstrap has just
    /// created. The only place a baseline is applied. Throws when the database is not
    /// <see cref="DatabasePresence.Empty"/>.
    /// </summary>
    public static async Task<MigrationFailure?> ApplyAllForBootstrapAsync(DbContext db, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var state = await ReadAsync(db, ct);
        if (state.Presence != DatabasePresence.Empty)
            throw new InvalidOperationException(
                $"Bootstrap applies the baseline only to an empty database; this one is {state.Presence}.");
        return await ApplyPendingAsync(db, state, ct);
    }

    /// <summary>
    /// The operator-facing message for a migration that failed while the control role applied it.
    /// </summary>
    /// <param name="contextName">Which database, for the message.</param>
    /// <param name="failure">The failure from <see cref="ApplyPendingAsync"/>.</param>
    /// <param name="commandTimeoutSeconds">The migration command timeout in force.</param>
    public static string MigrationFailedMessage(string contextName, MigrationFailure failure, int? commandTimeoutSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return MigrationFailedMessage(contextName, failure.Migration, failure.Error,
            failure.CommittedInThisRun, failure.LeavesNonTransactionalStatements, commandTimeoutSeconds);
    }

    /// <summary>
    /// The operator-facing message for a migration that failed while the control role applied it:
    /// the cause with its SQLSTATE or timeout, what was rolled back, and what this run committed.
    /// </summary>
    /// <param name="contextName">Which database, for the message.</param>
    /// <param name="failedMigration">The migration that failed.</param>
    /// <param name="error">The underlying error.</param>
    /// <param name="committedInThisRun">Migrations committed before the failure, in this run.</param>
    /// <param name="leavesNonTransactionalStatements">The migration runs statements outside a transaction.</param>
    /// <param name="commandTimeoutSeconds">The migration command timeout in force.</param>
    public static string MigrationFailedMessage(
        string contextName,
        string failedMigration,
        Exception error,
        IReadOnlyList<string>? committedInThisRun = null,
        bool leavesNonTransactionalStatements = false,
        int? commandTimeoutSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        var rollback = leavesNonTransactionalStatements
            ? "PostgreSQL rolled back this migration's transactional statements; statements it ran outside a transaction "
                + "stay applied; check the schema before starting again."
            : "It ran in its own transaction and was rolled back.";
        var committed = committedInThisRun is { Count: > 0 } ? string.Join(", ", committedInThisRun) : "none";
        return $"Migration {failedMigration} of the {contextName} database failed: {SchemaFailure.Describe(error, commandTimeoutSeconds)} "
            + $"{rollback} Committed in this run: {committed}. "
            + "The service will not start on a schema this build does not match. Fix the cause and start "
            + "again, or restore the pre-upgrade dump and run the previous release.";
    }

    /// <summary>
    /// Whether <paramref name="migrationId"/> runs a statement outside a transaction
    /// (<c>suppressTransaction</c>, or an index created concurrently), which a failure leaves
    /// applied. True when it cannot be told.
    /// </summary>
    public static bool LeavesNonTransactionalStatements(DbContext db, string migrationId)
    {
        ArgumentNullException.ThrowIfNull(db);
        try
        {
            var assembly = db.GetService<IMigrationsAssembly>();
            if (!assembly.Migrations.TryGetValue(migrationId, out var type))
                return false;
            var migration = assembly.CreateMigration(type, db.Database.ProviderName!);
            return migration.UpOperations.Any(op =>
                op is SqlOperation { SuppressTransaction: true }
                || op.FindAnnotation(CreatedConcurrentlyAnnotation)?.Value is true);
        }
        catch (Exception)
        {
            return true;
        }
    }

    /// <summary>
    /// Reads the history back after a failed step and names the migration that failed and the
    /// ones committed.
    /// </summary>
    private static async Task<MigrationFailure> DescribeFailureAsync(
        DbContext db, IReadOnlyList<string> batch, string migration, Exception error, List<string> committed)
    {
        try
        {
            var after = (await ReadAppliedAsync(db, CancellationToken.None)).ToHashSet(StringComparer.Ordinal);
            committed.AddRange(batch.Where(after.Contains));
            var failed = batch.FirstOrDefault(id => !after.Contains(id)) ?? migration;
            return new MigrationFailure(failed, error, committed, LeavesNonTransactionalStatements(db, failed));
        }
        catch (Exception)
        {
            return new MigrationFailure(string.Join(" or ", batch), error, committed,
                batch.Any(id => LeavesNonTransactionalStatements(db, id)));
        }
    }

    /// <summary>What the catalog says about the history table and the other tables, and how to read the history.</summary>
    private sealed record Catalog(
        bool HistoryExists, bool OtherTables, bool HistoryReadable, string Role, string Database, string HistoryTable,
        bool Queryable);

    /// <summary>
    /// The migrations the database records, read on the context's own connection. On
    /// PostgreSQL and SQLite the history table is queried directly: the provider's own read
    /// first runs an existence check that reports a reset connection as a missing database,
    /// which would make every migration look unapplied. A failure to open the connection throws
    /// <see cref="SchemaConnectException"/>.
    /// </summary>
    private static async Task<List<string>> ReadAppliedAsync(DbContext db, CancellationToken ct)
    {
        await OpenAsync(db, ct);
        try
        {
            var catalog = await ReadCatalogAsync(db, ct);
            return catalog.HistoryExists ? await QueryAppliedAsync(db, catalog, ct) : [];
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>Opens <paramref name="db"/>'s connection, wrapping a failure in <see cref="SchemaConnectException"/>.</summary>
    private static async Task OpenAsync(DbContext db, CancellationToken ct)
    {
        try
        {
            await db.Database.OpenConnectionAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new SchemaConnectException(ex);
        }
    }

    /// <summary>Reads the migration ids from the history table <paramref name="catalog"/> found, in order.</summary>
    private static async Task<List<string>> QueryAppliedAsync(DbContext db, Catalog catalog, CancellationToken ct)
    {
        if (!catalog.Queryable)
            return (await db.Database.GetAppliedMigrationsAsync(ct)).ToList();
        await using var cmd = db.Database.GetDbConnection().CreateCommand();
        cmd.CommandTimeout = db.Database.GetCommandTimeout() ?? 30;
        cmd.CommandText = $"SELECT \"MigrationId\" FROM {catalog.HistoryTable} ORDER BY \"MigrationId\"";
        var applied = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            applied.Add(reader.GetString(0));
        return applied;
    }

    /// <summary>
    /// One catalog read on the open connection: whether the history table exists and is
    /// readable, and whether any other table exists. Takes no lock on a user table.
    /// </summary>
    private static async Task<Catalog> ReadCatalogAsync(DbContext db, CancellationToken ct)
    {
        var extension = RelationalOptionsExtension.Extract(db.GetService<IDbContextOptions>());
        var table = extension.MigrationsHistoryTableName ?? HistoryRepository.DefaultTableName;
        var schema = extension.MigrationsHistoryTableSchema;
        var connection = db.Database.GetDbConnection();
        await using var cmd = connection.CreateCommand();
        cmd.CommandTimeout = db.Database.GetCommandTimeout() ?? 30;

        string qualified;
        if (db.Database.IsNpgsql())
        {
            qualified = $"{PostgresConnection.QuoteIdentifier(schema ?? "public")}.{PostgresConnection.QuoteIdentifier(table)}";
            cmd.CommandText = """
                SELECT to_regclass(@h) IS NOT NULL,
                       EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                                WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p')
                                  AND c.oid IS DISTINCT FROM to_regclass(@h)::oid
                                  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                                                   WHERE d.classid = 'pg_catalog.pg_class'::regclass
                                                     AND d.objid = c.oid AND d.deptype = 'e')),
                       coalesce(has_table_privilege(to_regclass(@h)::oid, 'SELECT'), false),
                       current_user::text,
                       current_database()::text
                """;
            AddParameter(cmd, "h", qualified);
        }
        else if (db.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            qualified = PostgresConnection.QuoteIdentifier(table);
            cmd.CommandText = """
                SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = @h),
                       EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name <> @h
                                  AND name NOT LIKE 'sqlite_%' AND name <> '__EFMigrationsLock'),
                       1, '', ''
                """;
            AddParameter(cmd, "h", table);
        }
        else
        {
            return new Catalog(true, false, true, "", "", table, Queryable: false);
        }

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            throw new InvalidOperationException("The schema catalog query returned no row.");
        return new Catalog(
            HistoryExists: Convert.ToBoolean(reader.GetValue(0)),
            OtherTables: Convert.ToBoolean(reader.GetValue(1)),
            HistoryReadable: Convert.ToBoolean(reader.GetValue(2)),
            Role: Convert.ToString(reader.GetValue(3)) ?? "",
            Database: Convert.ToString(reader.GetValue(4)) ?? "",
            HistoryTable: qualified,
            Queryable: true);
    }

    /// <summary>Adds a named parameter to <paramref name="cmd"/>.</summary>
    private static void AddParameter(DbCommand cmd, string name, object value)
    {
        var parameter = cmd.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        cmd.Parameters.Add(parameter);
    }
}
