using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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
/// How <see cref="SchemaVersionGate.DryRunPendingAsync"/> ended. Whatever the outcome, it was
/// rolled back and nothing was applied.
/// </summary>
/// <param name="Pending">The migrations the dry run found pending, in order.</param>
/// <param name="Rehearsed">The pending migrations every command of which ran without error, in order.</param>
/// <param name="Migration">
/// The migration the dry run stopped at, on an error that is not a refusal or one it cannot
/// rehearse, or <see langword="null"/> when it ran to the end or stopped before any migration ran.
/// </param>
/// <param name="Error">The error it stopped on, or <see langword="null"/>.</param>
/// <param name="NotRehearsable">
/// <paramref name="Migration"/> runs a statement outside a transaction, so it was not run.
/// </param>
public sealed record DryRunResult(
    IReadOnlyList<string> Pending,
    IReadOnlyList<string> Rehearsed,
    string? Migration,
    Exception? Error,
    bool NotRehearsable)
{
    /// <summary>Every refusal the dry run found, in the order it found them.</summary>
    public IReadOnlyList<DryRunRefusal> Refusals { get; init; } = [];

    /// <summary>The migrations whose later commands were skipped after a refusal in them, in order.</summary>
    public IReadOnlyList<DryRunSkip> Skipped { get; init; } = [];

    /// <summary>The 1-based command of <see cref="Migration"/> the dry run stopped at, or <see langword="null"/>.</summary>
    public int? Command { get; init; }

    /// <summary>How many commands <see cref="Migration"/> has, its history insert included, or <see langword="null"/>.</summary>
    public int? Commands { get; init; }

    /// <summary>The dry run stopped before running every command: the checks after that point did not run.</summary>
    public bool Stopped => Error is not null || NotRehearsable;

    /// <summary>Every command of every pending migration ran, with no refusal and no other error.</summary>
    public bool Passed => !Stopped && Refusals.Count == 0 && Skipped.Count == 0;
}

/// <summary>A refusal the dry run found: a precondition that raised SQLSTATE P0001.</summary>
/// <param name="Migration">The migration whose check refused.</param>
/// <param name="Check">
/// The check's label in the migration's source (<see cref="MigrationCheckLabels"/>), such as
/// "P1", or <see langword="null"/> when it has none.
/// </param>
/// <param name="Message">The refusal's message, verbatim.</param>
/// <param name="AlsoFound">
/// Found after an earlier refusal: real on the current data, but its outcome may change once the
/// earlier ones are fixed.
/// </param>
public sealed record DryRunRefusal(string Migration, string? Check, string Message, bool AlsoFound);

/// <summary>
/// The rest of a migration the dry run skipped: a command that is not a refusal failed after a
/// refusal in the same migration, most likely because of it.
/// </summary>
/// <param name="Migration">The migration.</param>
/// <param name="Command">The 1-based command that failed; it and every later command of the migration were skipped.</param>
/// <param name="Commands">How many commands the migration has, its history insert included.</param>
/// <param name="Error">The error the command failed with.</param>
public sealed record DryRunSkip(string Migration, int Command, int Commands, Exception Error);

/// <summary>What the dry run does after a command fails.</summary>
public enum DryRunAction
{
    /// <summary>Go on with the next command.</summary>
    Continue,

    /// <summary>Skip the rest of this migration and go on with the next migration.</summary>
    SkipMigration,

    /// <summary>Stop: the checks after this point cannot run.</summary>
    Stop,
}

/// <summary>
/// The dry run's collect mode: records each command that fails and decides what follows, so one
/// run reports every refusal it can reach without inventing any. A refusal (SQLSTATE P0001, what a
/// precondition raises) is recorded and the run continues. Another error in a migration that has
/// already refused is taken as a knock-on of that refusal: the rest of the migration is skipped
/// and the run continues with the next migration, unless the error is transient or a timeout,
/// which no refusal causes. Any other error stops the run.
/// </summary>
public sealed class DryRunCollector
{
    /// <summary>SQLSTATE raise_exception, which <see cref="MigrationPreconditions.FailIf"/> raises.</summary>
    public const string RefusalSqlState = "P0001";

    private readonly List<DryRunRefusal> _refusals = [];
    private readonly List<DryRunSkip> _skipped = [];

    /// <summary>The refusals so far, in order.</summary>
    public IReadOnlyList<DryRunRefusal> Refusals => _refusals;

    /// <summary>The skipped migration tails so far, in order.</summary>
    public IReadOnlyList<DryRunSkip> Skipped => _skipped;

    /// <summary>
    /// Records that command <paramref name="command"/> of <paramref name="commands"/> of
    /// <paramref name="migration"/>, labelled <paramref name="check"/>, failed with
    /// <paramref name="error"/>, and returns what the dry run does next.
    /// </summary>
    public DryRunAction Failed(string migration, int command, int commands, string? check, Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (IsRefusal(error))
        {
            _refusals.Add(new DryRunRefusal(migration, check, RefusalMessage(error), AlsoFound: _refusals.Count > 0));
            return DryRunAction.Continue;
        }
        if (_refusals.Any(r => r.Migration == migration)
            && !SchemaFailure.TransientForMigration(error) && !SchemaFailure.IsStatementTimeout(error))
        {
            _skipped.Add(new DryRunSkip(migration, command, commands, error));
            return DryRunAction.SkipMigration;
        }
        return DryRunAction.Stop;
    }

    /// <summary>True when <paramref name="error"/> is a precondition's refusal (SQLSTATE P0001).</summary>
    public static bool IsRefusal(Exception error) => SchemaFailure.SqlState(error) == RefusalSqlState;

    /// <summary>The text a refusal raised: the PostgreSQL message, without the driver's prefix.</summary>
    private static string RefusalMessage(Exception error)
    {
        for (var e = error; e is not null; e = e.InnerException)
            if (e is Npgsql.PostgresException pg)
                return pg.MessageText;
        return error.Message;
    }
}

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
/// Only <see cref="ApplyAllForBootstrapAsync"/> and <see cref="ApplyBaselineForBootstrapAsync"/>
/// apply a baseline, and only to an empty database.
/// </para>
/// <para>
/// The control role first rehearses every pending migration with
/// <see cref="DryRunPendingAsync"/>, in one transaction it rolls back, and applies nothing unless
/// all of them pass.
/// </para>
/// </remarks>
public static class SchemaVersionGate
{
    private const string CreatedConcurrentlyAnnotation = "Npgsql:CreatedConcurrently";
    private const string DryRunSavepoint = "modularca_dry_run_step";

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
    /// Applies the pending migrations of <paramref name="state"/> up to and including
    /// <paramref name="target"/>, through <see cref="ApplyPendingAsync"/>, and leaves the later
    /// ones pending. Never reverts: throws when the database has applied a migration that sorts
    /// after <paramref name="target"/>, or when this build does not carry <paramref name="target"/>.
    /// </summary>
    public static Task<MigrationFailure?> ApplyPendingThroughAsync(
        DbContext db, SchemaState state, string target, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(state);
        var known = state.Known.ToList();
        var at = known.IndexOf(target);
        if (at < 0)
            throw new ArgumentException($"This build carries no migration '{target}'.", nameof(target));
        var later = state.Applied.Where(id => known.IndexOf(id) > at).ToList();
        if (later.Count > 0)
            throw new InvalidOperationException(
                $"The database has already applied {string.Join(", ", later)}, after {target}; migrations are never reverted.");
        var through = new SchemaState(state.Applied, state.Known.Take(at + 1).ToList()) { Presence = state.Presence };
        return ApplyPendingAsync(db, through, ct);
    }

    /// <summary>
    /// Applies only the frozen <paramref name="baseline"/> to a database just created for it, so
    /// data in the baseline's shape can be loaded before the later migrations transform it, as
    /// they would on an upgrade. Throws when the database is not
    /// <see cref="DatabasePresence.Empty"/> or <paramref name="baseline"/> is not the first
    /// migration this build carries.
    /// </summary>
    public static async Task<MigrationFailure?> ApplyBaselineForBootstrapAsync(DbContext db, string baseline, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var state = await ReadAsync(db, ct);
        if (state.Presence != DatabasePresence.Empty)
            throw new InvalidOperationException(
                $"A baseline is applied only to an empty database; this one is {state.Presence}.");
        if (state.Known.Count == 0 || !string.Equals(state.Known[0], baseline, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"'{baseline}' is not this build's first migration ({(state.Known.Count == 0 ? "none" : state.Known[0])}).");
        return await ApplyPendingThroughAsync(db, state, baseline, ct);
    }

    /// <summary>
    /// Applies every migration, the frozen baseline first, to a database bootstrap has just
    /// created. Throws when the database is not <see cref="DatabasePresence.Empty"/>.
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
    /// Rehearses every migration <paramref name="db"/>'s database lacks, in order, in ONE
    /// transaction on <paramref name="db"/>'s connection, then rolls it back. Each migration runs
    /// exactly the commands the real apply runs (<see cref="UpCommands"/>), its history insert
    /// included, so a later migration sees what the earlier ones did. Takes the same history-table
    /// lock as the real apply, then reads the history under it. Collects every refusal it can
    /// reach instead of stopping at the first (<see cref="DryRunCollector"/>).
    /// </summary>
    /// <remarks>
    /// Each command runs under its own savepoint, released when it succeeds. A command that fails
    /// is rolled back to its savepoint, and <see cref="DryRunCollector"/> decides whether the run
    /// continues, skips the rest of that migration, or stops. Without savepoint support the first
    /// failure stops it. Nothing is ever committed: the transaction is rolled back and the
    /// connection closed on every path, so no lock outlives the call. A migration with a command
    /// that must run outside a transaction is not run, and is reported as
    /// <see cref="DryRunResult.NotRehearsable"/>. Errors, a failure to connect
    /// (<see cref="SchemaConnectException"/>) included, are returned in the result; only
    /// cancellation throws.
    /// </remarks>
    public static async Task<DryRunResult> DryRunPendingAsync(DbContext db, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var known = db.Database.GetMigrations().ToList();
        var pending = new List<string>();
        var rehearsed = new List<string>();
        var collector = new DryRunCollector();
        string? current = null;
        var opened = false;
        IDbContextTransaction? transaction = null;
        DryRunResult Result(string? migration, Exception? error, bool notRehearsable = false, int? command = null, int? commands = null) =>
            new(pending, rehearsed, migration, error, notRehearsable)
            {
                Refusals = collector.Refusals.ToList(),
                Skipped = collector.Skipped.ToList(),
                Command = command,
                Commands = commands,
            };
        try
        {
            await OpenAsync(db, ct);
            opened = true;
            transaction = await db.Database.BeginTransactionAsync(ct);
            var connection = db.GetService<IRelationalConnection>();
            var history = db.GetService<IHistoryRepository>();
            var catalog = await ReadCatalogAsync(db, ct);
            if (!catalog.HistoryExists)
                await RawCommand(db, history.GetCreateIfNotExistsScript()).ExecuteNonQueryAsync(connection, null, ct);
            if (history.LockReleaseBehavior == LockReleaseBehavior.Transaction)
                await history.AcquireDatabaseLockAsync(ct);
            var applied = (catalog.HistoryExists ? await QueryAppliedAsync(db, catalog, ct) : []).ToHashSet(StringComparer.Ordinal);
            pending.AddRange(known.Where(id => !applied.Contains(id)));

            foreach (var id in pending)
            {
                current = id;
                var commands = UpCommands(db, id);
                if (commands.Any(c => c.TransactionSuppressed))
                    return Result(id, null, notRehearsable: true);
                var checks = MigrationCheckLabels.ForCommands(id, commands.Select(c => c.CommandText).ToList());
                var clean = true;
                for (var i = 0; i < commands.Count; i++)
                {
                    var (error, recovered) = await RehearseAsync(transaction, commands[i], connection, ct);
                    if (error is null)
                        continue;
                    clean = false;
                    var action = recovered
                        ? collector.Failed(id, i + 1, commands.Count, checks[i], error)
                        : DryRunAction.Stop;
                    if (action == DryRunAction.Continue)
                        continue;
                    if (action == DryRunAction.SkipMigration)
                        break;
                    return Result(id, error, command: i + 1, commands: commands.Count);
                }
                if (clean)
                    rehearsed.Add(id);
            }
            return Result(null, null);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return Result(current, ex);
        }
        finally
        {
            if (transaction is not null)
            {
                try
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                }
                catch (Exception)
                {
                }
                await transaction.DisposeAsync();
            }
            if (opened)
                await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>
    /// Runs one dry-run command under its own savepoint: released when it succeeds, rolled back to
    /// when it fails. Returns the error, or <see langword="null"/>, and whether the transaction is
    /// still usable after it. Without savepoint support the error propagates.
    /// </summary>
    private static async Task<(Exception? Error, bool Recovered)> RehearseAsync(
        IDbContextTransaction transaction, MigrationCommand command, IRelationalConnection connection, CancellationToken ct)
    {
        if (!transaction.SupportsSavepoints)
        {
            await command.ExecuteNonQueryAsync(connection, null, ct);
            return (null, true);
        }
        await transaction.CreateSavepointAsync(DryRunSavepoint, ct);
        try
        {
            await command.ExecuteNonQueryAsync(connection, null, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            try
            {
                await transaction.RollbackToSavepointAsync(DryRunSavepoint, ct);
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                return (ex, false);
            }
            return (ex, true);
        }
        await transaction.ReleaseSavepointAsync(DryRunSavepoint, ct);
        return (null, true);
    }

    /// <summary>
    /// The commands EF's migrator runs to apply migration <paramref name="migrationId"/>: the
    /// provider's SQL for its up operations against its finalized target model, then the history
    /// insert, flagged as EF flags them.
    /// </summary>
    public static IReadOnlyList<MigrationCommand> UpCommands(DbContext db, string migrationId)
    {
        ArgumentNullException.ThrowIfNull(db);
        var assembly = db.GetService<IMigrationsAssembly>();
        var migration = assembly.CreateMigration(assembly.Migrations[migrationId], db.Database.ProviderName!);
        var model = migration.TargetModel is { } target
            ? db.GetService<IModelRuntimeInitializer>().Initialize(target, designTime: true, validationLogger: null)
            : null;
        var commands = db.GetService<IMigrationsSqlGenerator>()
            .Generate(migration.UpOperations, model, MigrationsSqlGenerationOptions.Default);
        var insert = RawCommand(db,
            db.GetService<IHistoryRepository>().GetInsertScript(new HistoryRow(migrationId, ProductInfo.GetVersion())),
            commands.Any(c => c.TransactionSuppressed));
        return [.. commands, insert];
    }

    /// <summary>
    /// The operator-facing message for a dry run that did not pass. With no refusal, one paragraph:
    /// where it stopped and why, or which migration cannot be rehearsed, and that nothing was
    /// applied. With refusals, one line per refusal ("1 of N", "also found" after the first), each
    /// with its message verbatim, then each migration whose later commands were skipped, where the
    /// run stopped and that the checks after that point could not run, and that nothing was applied.
    /// </summary>
    /// <param name="contextName">Which database, for the message.</param>
    /// <param name="result">The result of <see cref="DryRunPendingAsync"/>.</param>
    /// <param name="commandTimeoutSeconds">The migration command timeout in force.</param>
    /// <param name="scope">What nothing was applied to, e.g. "either database".</param>
    public static string DryRunFailedMessage(
        string contextName, DryRunResult result, int? commandTimeoutSeconds = null, string scope = "this database")
    {
        ArgumentNullException.ThrowIfNull(result);
        var pending = result.Pending.Count > 0 ? string.Join(", ", result.Pending) : "none";
        var footer = $"The dry run ran the pending migrations ({pending}) in one transaction and rolled it back; "
            + $"nothing was applied to {scope}.";
        var cause = result.Error is null ? "unknown error" : SchemaFailure.Describe(result.Error, commandTimeoutSeconds);
        var where = result.Command is int command ? $"command {command} of {result.Commands}" : null;

        if (result.Refusals.Count == 0 && result.Skipped.Count == 0)
        {
            if (result.NotRehearsable)
                return $"Migration {result.Migration} of the {contextName} database runs a statement outside a transaction, so the "
                    + $"dry run cannot rehearse it, and nothing is applied that was not rehearsed: nothing was applied to {scope}. "
                    + "This build is defective: install a correct build.";
            var what = result.Migration is null
                ? $"The dry run of the {contextName} database failed before any migration ran: {cause}."
                : $"The dry run of the {contextName} database failed at migration {result.Migration}{(where is null ? "" : ", " + where)}: {cause}.";
            return what + (result.Migration is not null ? " The checks after this point could not run." : "")
                + " " + footer;
        }

        var lines = new List<string>
        {
            $"The dry run of the {contextName} database found {result.Refusals.Count} refusal(s); fix each, then check again:",
        };
        for (var i = 0; i < result.Refusals.Count; i++)
        {
            var r = result.Refusals[i];
            lines.Add($"  {i + 1} of {result.Refusals.Count}{(r.AlsoFound ? ", also found" : "")}: migration {r.Migration}"
                + $"{(r.Check is null ? "" : $" ({CheckName(r.Check)})")} refuses: {r.Message}");
        }
        foreach (var s in result.Skipped)
            lines.Add($"  Skipped: the rest of migration {s.Migration}, from command {s.Command} of {s.Commands}, which failed "
                + $"after its refusal above ({SchemaFailure.Describe(s.Error, commandTimeoutSeconds)}). Those steps depend on fixing "
                + "that refusal; they are checked once it is fixed.");
        if (result.NotRehearsable)
            lines.Add($"  Stopped: migration {result.Migration} runs a statement outside a transaction, so the dry run cannot "
                + "rehearse it; this build is defective: install a correct build. The checks after this point could not run.");
        else if (result.Stopped)
            lines.Add("  Stopped: " + (result.Migration is null
                    ? $"the dry run failed outside any migration ({cause})"
                    : $"migration {result.Migration} failed{(where is null ? "" : " at " + where)} ({cause})")
                + (result.Skipped.Count > 0 ? ", which may follow from the steps skipped above" : "")
                + ". The checks after this point could not run.");
        if (result.Refusals.Any(r => r.AlsoFound))
            lines.Add("\"Also found\" refusals came after an earlier refusal: each is real on the current data, but its outcome "
                + "may change once the earlier ones are fixed.");
        lines.Add(footer);
        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// A few words for a dry run that did not pass: the migrations that refuse, and whether the
    /// run stopped early; or where it failed, or which migration cannot be rehearsed.
    /// </summary>
    public static string DryRunSummary(DryRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var refusing = result.Refusals.Select(r => r.Migration).Distinct(StringComparer.Ordinal).ToList();
        var stopped = result.NotRehearsable ? $"migration {result.Migration} cannot be rehearsed"
            : result.Migration is not null ? $"migration {result.Migration} fails"
            : "dry run failed";
        if (refusing.Count == 0)
            return stopped;
        var refuse = refusing.Count == 1
            ? $"migration {refusing[0]} refuses"
            : $"migrations {string.Join(", ", refusing)} refuse";
        return result.Stopped ? $"{refuse}; then {stopped}, and the checks after it could not run" : refuse;
    }

    /// <summary>"P1" as it is, a bare step number as "step 7".</summary>
    private static string CheckName(string check) => char.IsAsciiDigit(check[0]) ? $"step {check}" : check;

    /// <summary>A migration command running <paramref name="sql"/> on <paramref name="db"/>'s connection.</summary>
    private static MigrationCommand RawCommand(DbContext db, string sql, bool transactionSuppressed = false) =>
        new(db.GetService<IRawSqlCommandBuilder>().Build(sql), db,
            db.GetService<IRelationalCommandDiagnosticsLogger>(), transactionSuppressed);

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
        cmd.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
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
        cmd.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();

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
