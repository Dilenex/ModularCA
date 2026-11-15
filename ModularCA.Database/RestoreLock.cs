using Microsoft.Extensions.Logging;
using Npgsql;

namespace ModularCA.Database;

/// <summary>
/// The lock that keeps a restore and a running process apart
/// (<c>docs/architecture/restore-exclusion.md</c>): PostgreSQL advisory locks in the application
/// database, session-level, under two fixed keys. Nothing is stored and no migration is needed;
/// a lock ends with the connection that took it, so a process that dies releases it.
/// </summary>
/// <remarks>
/// <para>
/// Both keys are the two-integer form, <c>pg_advisory_lock(<see cref="LockClass"/>, key)</c>.
/// <see cref="NodeKey"/> is held <b>shared</b> by every node process (any of the roles control,
/// enrollment, validation, ingress, with or without the signer in process) for as long as it
/// runs. <see cref="SignerKey"/> is held shared by a process that is the signer and nothing else
/// (<c>--role signer</c>). A command-line restore takes both <b>exclusively</b> and refuses when
/// it cannot; a restore from the console takes <see cref="NodeKey"/> exclusively on the
/// connection its own node already holds it shared on, which PostgreSQL grants when no other
/// session holds it, and leaves <see cref="SignerKey"/> alone, because on a split install it
/// restores through the running signer.
/// </para>
/// <para>
/// Advisory locks are per database, so two instances on one server never meet, and
/// <c>pg_restore</c>, which runs on connections of its own, is not affected by them. Nothing
/// else in the product takes these keys: every one-off command (<c>--upgrade-check</c>,
/// <c>--backup</c>, <c>--settings</c>, <c>--db-ownership</c> and the rest) runs beside either
/// kind of holder.
/// </para>
/// </remarks>
public static class RestoreLock
{
    /// <summary>The first integer of both keys: the ASCII bytes of "MCAR" (1296253266).</summary>
    public const int LockClass = 0x4D434152;

    /// <summary>The second integer of the key every node process holds shared.</summary>
    public const int NodeKey = 1;

    /// <summary>The second integer of the key a signer-only process holds shared.</summary>
    public const int SignerKey = 2;

    /// <summary>What a restore says when <see cref="NodeKey"/> cannot be had from the command line.</summary>
    public const string NodeInUse =
        "a node is serving from this application database, or another restore is running on it: stop the node, "
        + "every process of it on every host, or wait for the other restore, then restore again";

    /// <summary>What a restore says when <see cref="SignerKey"/> cannot be had.</summary>
    public const string SignerInUse =
        "the signer service is running on this application database: stop the signer, then restore again";

    /// <summary>What a restore from the console says when another session holds <see cref="NodeKey"/>.</summary>
    public const string OtherNodeInUse =
        "another node is serving from this application database, or another restore is running on it: stop every "
        + "other node of this instance, or wait for the other restore, then restore again";

    /// <summary>The command-line restore's way of taking the lock: on a connection of its own, both keys.</summary>
    public static IRestoreExclusion OwnConnection { get; } = new OwnConnectionRestoreExclusion(TimeSpan.FromSeconds(2));

    /// <summary>
    /// The connection string of a connection that holds one of these locks: never pooled, so it
    /// is handed to no other code and closing it ends the session, with short time limits so a
    /// server that does not answer is noticed.
    /// </summary>
    /// <param name="appConnectionString">The application database.</param>
    public static string ConnectionString(string appConnectionString) =>
        new NpgsqlConnectionStringBuilder(appConnectionString)
        {
            Pooling = false,
            Timeout = 10,
            CommandTimeout = 15,
            ApplicationName = "ModularCA restore lock",
        }.ConnectionString;

    /// <summary>Asks for a key on <paramref name="connection"/> without waiting; true when it was granted.</summary>
    /// <param name="connection">An open connection to the application database.</param>
    /// <param name="key"><see cref="NodeKey"/> or <see cref="SignerKey"/>.</param>
    /// <param name="shared">True for the shared lock, false for the exclusive one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<bool> TryAsync(NpgsqlConnection connection, int key, bool shared, CancellationToken cancellationToken = default)
    {
        await using var command = new NpgsqlCommand(
            shared ? "SELECT pg_try_advisory_lock_shared(@c, @k)" : "SELECT pg_try_advisory_lock(@c, @k)", connection);
        command.Parameters.AddWithValue("c", LockClass);
        command.Parameters.AddWithValue("k", key);
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    /// <summary>Releases a key this session holds; the session's other hold on it, if any, stays.</summary>
    /// <param name="connection">The connection that holds it.</param>
    /// <param name="key"><see cref="NodeKey"/> or <see cref="SignerKey"/>.</param>
    /// <param name="shared">True to release the shared lock, false the exclusive one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task UnlockAsync(NpgsqlConnection connection, int key, bool shared, CancellationToken cancellationToken = default)
    {
        await using var command = new NpgsqlCommand(
            shared ? "SELECT pg_advisory_unlock_shared(@c, @k)" : "SELECT pg_advisory_unlock(@c, @k)", connection);
        command.Parameters.AddWithValue("c", LockClass);
        command.Parameters.AddWithValue("k", key);
        await command.ExecuteScalarAsync(cancellationToken);
    }

    /// <summary>True when <paramref name="connection"/> is open and its session still answers.</summary>
    /// <param name="connection">A connection that holds a lock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<bool> AliveAsync(NpgsqlConnection connection, CancellationToken cancellationToken = default)
    {
        if (connection.FullState != System.Data.ConnectionState.Open)
            return false;
        try
        {
            await using var command = new NpgsqlCommand("SELECT 1", connection);
            await command.ExecuteScalarAsync(cancellationToken);
            return true;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}

/// <summary>How a restore gets the application database to itself before it changes anything.</summary>
public interface IRestoreExclusion
{
    /// <summary>
    /// Asks for the database, without waiting for a holder to leave. Throws what the driver
    /// throws when the database cannot be reached; the restore has changed nothing by then.
    /// </summary>
    /// <param name="appConnectionString">The application database the restore writes into.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<RestoreExclusionAttempt> TryTakeAsync(string appConnectionString, CancellationToken cancellationToken = default);
}

/// <summary>What <see cref="IRestoreExclusion.TryTakeAsync"/> came back with.</summary>
/// <param name="Hold">The lock, held until disposed; null when it was refused.</param>
/// <param name="Refusal">Who is using the database and what to do, when refused.</param>
public sealed record RestoreExclusionAttempt(IRestoreExclusionHold? Hold, string? Refusal);

/// <summary>A restore's exclusive hold on the application database. Disposing it lets nodes start.</summary>
public interface IRestoreExclusionHold : IAsyncDisposable
{
    /// <summary>False when the connection that held the lock has dropped, and the lock with it.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> StillHeldAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// The command-line restore's lock: a connection of its own, <see cref="RestoreLock.NodeKey"/>
/// and <see cref="RestoreLock.SignerKey"/> both exclusive. A key that is not granted at once is
/// asked for again for a short grace, which covers a node stopped a moment ago whose session the
/// server has not closed yet, and no more: a restore never waits for a running node.
/// </summary>
/// <param name="grace">How long a key is asked for again before the restore is refused.</param>
public sealed class OwnConnectionRestoreExclusion(TimeSpan grace) : IRestoreExclusion
{
    /// <inheritdoc />
    public async Task<RestoreExclusionAttempt> TryTakeAsync(string appConnectionString, CancellationToken cancellationToken = default)
    {
        var connection = new NpgsqlConnection(RestoreLock.ConnectionString(appConnectionString));
        try
        {
            await connection.OpenAsync(cancellationToken);
            foreach (var (key, refusal) in new[] { (RestoreLock.NodeKey, RestoreLock.NodeInUse), (RestoreLock.SignerKey, RestoreLock.SignerInUse) })
            {
                var asked = System.Diagnostics.Stopwatch.StartNew();
                while (!await RestoreLock.TryAsync(connection, key, shared: false, cancellationToken))
                {
                    if (asked.Elapsed >= grace)
                    {
                        // Closing the connection releases a key already granted.
                        await connection.DisposeAsync();
                        return new RestoreExclusionAttempt(null, refusal);
                    }
                    await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
                }
            }
            return new RestoreExclusionAttempt(new Hold(connection), null);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    /// <summary>The connection that holds both keys; closing it releases them.</summary>
    private sealed class Hold(NpgsqlConnection connection) : IRestoreExclusionHold
    {
        /// <inheritdoc />
        public Task<bool> StillHeldAsync(CancellationToken cancellationToken = default) => RestoreLock.AliveAsync(connection, cancellationToken);

        /// <inheritdoc />
        public ValueTask DisposeAsync() => connection.DisposeAsync();
    }
}

/// <summary>Where a process stands with the lock it holds while it runs.</summary>
public enum ServingLockState
{
    /// <summary>Never taken: setup mode, or the database has not answered since this process started.</summary>
    NotTaken,

    /// <summary>Held shared on a live connection.</summary>
    Held,

    /// <summary>The connection that held it dropped and it has not been taken again yet: the database is down or restarting.</summary>
    Reconnecting,

    /// <summary>
    /// The lock could not be taken again because a restore holds it: a restore is replacing the
    /// database under this running process.
    /// </summary>
    RestoreRunning,

    /// <summary>
    /// A restore ran while this process was running and has finished. The lock is held again,
    /// but what the process holds in memory is from before the restore: it must be restarted.
    /// </summary>
    RestartNeeded,
}

/// <summary>How one attempt to take the shared lock ended.</summary>
public enum ServingLockAttemptKind
{
    /// <summary>The lock is held.</summary>
    Held,

    /// <summary>A restore holds it exclusively.</summary>
    Busy,

    /// <summary>The server could not be reached, or is not accepting connections yet.</summary>
    Unreachable,

    /// <summary>The database is missing or refuses this role: the schema check says which and decides.</summary>
    Unavailable,
}

/// <summary>One attempt to take the shared lock.</summary>
/// <param name="Kind">How it ended.</param>
/// <param name="Error">What the driver raised, for <see cref="ServingLockAttemptKind.Unreachable"/> and <see cref="ServingLockAttemptKind.Unavailable"/>.</param>
public sealed record ServingLockAttempt(ServingLockAttemptKind Kind, Exception? Error = null);

/// <summary>
/// The shared lock a long-running process holds on the application database for as long as it
/// runs (<see cref="RestoreLock"/>), on one dedicated, unpooled connection that no other code is
/// given. A restore that finds it held is refused; a process that finds a restore holding the
/// key exclusively does not start.
/// </summary>
/// <remarks>
/// <para>
/// <b>When the connection drops</b> (the database restarts, the network blinks) the server has
/// released the lock. <see cref="CheckNowAsync"/>, run every few seconds once
/// <see cref="StartKeeping"/> was called, notices and takes it again when the database answers:
/// <see cref="ServingLockState.Reconnecting"/>, then <see cref="ServingLockState.Held"/>. An
/// ordinary database restart therefore costs nothing but a log line. If a restore took the key
/// while it was free, the process is running beside a restore:
/// <see cref="ServingLockState.RestoreRunning"/>, logged as an error, and when the restore has
/// finished <see cref="ServingLockState.RestartNeeded"/>, which stays until the process is
/// restarted. In both states <see cref="HoldReason"/> is set, which the scheduler and the health
/// check read. The process is not stopped: it goes on answering what it can.
/// </para>
/// <para>
/// <b>The console's restore</b> runs inside the node that holds this lock. It asks for the same
/// key exclusively on this same connection (<see cref="IRestoreExclusion"/>): a session never
/// conflicts with itself, so the request is granted exactly when no other session, another node
/// or another restore, holds the key.
/// </para>
/// </remarks>
public sealed class ServingDatabaseLock : IRestoreExclusion, IAsyncDisposable
{
    private readonly string _connectionString;
    private readonly int _key;
    private readonly string _holder;
    private readonly ILogger? _logger;
    private readonly TimeSpan _probeInterval;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    private NpgsqlConnection? _connection;
    private Task? _keeper;
    private long _generation;
    private bool _everHeld;
    private bool _restoreRunning;
    private bool _restartNeeded;
    private bool _restoringHere;
    private bool _disposed;
    private DateTimeOffset _since = DateTimeOffset.UtcNow;

    /// <summary>Creates the lock; nothing is opened until <see cref="TryTakeAsync"/>.</summary>
    /// <param name="appConnectionString">The application database.</param>
    /// <param name="key"><see cref="RestoreLock.NodeKey"/> for a node, <see cref="RestoreLock.SignerKey"/> for a signer-only process.</param>
    /// <param name="logger">Where changes of state are logged; nowhere when null.</param>
    /// <param name="probeInterval">How often the connection is checked once <see cref="StartKeeping"/> was called; 5 s when null.</param>
    /// <param name="holder">What this process is called in the log: "node" or "signer".</param>
    public ServingDatabaseLock(string appConnectionString, int key, ILogger? logger = null, TimeSpan? probeInterval = null, string holder = "node")
    {
        ArgumentNullException.ThrowIfNull(appConnectionString);
        _connectionString = RestoreLock.ConnectionString(appConnectionString);
        _key = key;
        _logger = logger;
        _probeInterval = probeInterval ?? TimeSpan.FromSeconds(5);
        _holder = holder;
    }

    /// <summary>Where this process stands with its lock.</summary>
    public ServingLockState State =>
        _restartNeeded ? ServingLockState.RestartNeeded
        : _restoreRunning ? ServingLockState.RestoreRunning
        : _connection != null ? ServingLockState.Held
        : _everHeld ? ServingLockState.Reconnecting
        : ServingLockState.NotTaken;

    /// <summary>Since when <see cref="State"/> is what it is.</summary>
    public DateTimeOffset Since => _since;

    /// <summary>True while a restore started from this process's console holds the key exclusively.</summary>
    public bool RestoringHere => _restoringHere;

    /// <summary>
    /// Called once, from the keeper, when this process first finds that a restore took the
    /// database while it was running (<see cref="ServingLockState.RestoreRunning"/>). A serving
    /// process sets it to stop itself with the status that means "start me again": what it holds
    /// in memory is from before the restore, and the start that follows waits for the restore to
    /// finish. Left null, the state is only reported.
    /// </summary>
    public Action? RestoreFoundBeside { get; set; }

    /// <summary>
    /// Why scheduled work must not run in this process right now, or null when it may: a restore
    /// is running here or beside this process, or one has run and the process was not restarted.
    /// </summary>
    public string? HoldReason => State switch
    {
        ServingLockState.RestartNeeded =>
            "A restore replaced the application database while this process was running. Restart this process: what it holds in memory is from before the restore.",
        ServingLockState.RestoreRunning =>
            "A restore is running on the application database while this process is running. Stop this process until the restore has finished.",
        _ when _restoringHere => "A restore started from this node's console is running.",
        _ => null,
    };

    /// <summary>
    /// One attempt to take the shared lock, for a process that is starting: opens the dedicated
    /// connection if there is none and asks without waiting. A restore found holding the key is
    /// reported as <see cref="ServingLockAttemptKind.Busy"/> and changes no state: the caller
    /// waits or gives up, and has not started.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<ServingLockAttempt> TryTakeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection != null && await RestoreLock.AliveAsync(_connection, cancellationToken))
                return new ServingLockAttempt(ServingLockAttemptKind.Held);
            await DropAsync();
            return await TakeAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Starts checking the connection every probe interval, for the life of the process. Idempotent.</summary>
    public void StartKeeping()
    {
        if (_keeper != null || _disposed)
            return;
        _keeper = Task.Run(async () =>
        {
            while (!_stop.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_probeInterval, _stop.Token);
                    await CheckNowAsync(_stop.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Restore lock: the check of the {Holder}'s lock connection failed", _holder);
                }
            }
        });
    }

    /// <summary>
    /// One check, as the keeper makes it: a live connection is left alone; a dropped one is
    /// replaced and the lock asked for again, and a restore found holding the key is recorded
    /// (<see cref="ServingLockState.RestoreRunning"/>, then <see cref="ServingLockState.RestartNeeded"/>).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task CheckNowAsync(CancellationToken cancellationToken = default)
    {
        var restoreFound = false;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection != null)
            {
                if (await RestoreLock.AliveAsync(_connection, cancellationToken))
                    return;
                await DropAsync();
                _logger?.LogWarning("Restore lock: the connection holding this {Holder}'s lock on the application database dropped, and the lock with it. "
                    + "Taking it again as soon as the database answers.", _holder);
            }

            var wasHeldBefore = _everHeld;
            var attempt = await TakeAsync(cancellationToken);
            switch (attempt.Kind)
            {
                case ServingLockAttemptKind.Held when _restoreRunning:
                    _restoreRunning = false;
                    _restartNeeded = true;
                    _since = DateTimeOffset.UtcNow;
                    _logger?.LogError("Restore lock: a restore replaced the application database while this {Holder} was running, and has finished. "
                        + "Restart this process: what it holds in memory is from before the restore. Scheduled jobs are held and /health/ready says so until then.", _holder);
                    break;
                case ServingLockAttemptKind.Held when !_restartNeeded:
                    _logger?.LogInformation(wasHeldBefore
                        ? "Restore lock: the {Holder}'s lock on the application database was taken again."
                        : "Restore lock: the {Holder}'s lock on the application database is taken.", _holder);
                    break;
                case ServingLockAttemptKind.Busy when !_restoreRunning:
                    _restoreRunning = true;
                    _since = DateTimeOffset.UtcNow;
                    _logger?.LogError("Restore lock: a restore is running on the application database while this {Holder} is running: "
                        + "its lock was lost (its connection dropped, or it was never taken) and a restore took the database meanwhile. "
                        + "Stop this process until the restore has finished. Scheduled jobs are held and /health/ready says so.", _holder);
                    restoreFound = true;
                    break;
                case ServingLockAttemptKind.Unreachable or ServingLockAttemptKind.Unavailable:
                    _logger?.LogDebug(attempt.Error, "Restore lock: the {Holder}'s lock could not be taken yet", _holder);
                    break;
            }
        }
        finally
        {
            _gate.Release();
        }
        // Outside the gate: the handler may end the process, and must not hold up a reader of the state.
        if (restoreFound)
            RestoreFoundBeside?.Invoke();
    }

    /// <summary>
    /// The console's restore: asks for this process's key exclusively on the connection that
    /// holds it shared. Granted when no other session holds the key; refused, naming the other
    /// node or restore, when one does. The connection string is not used: the lock is taken in
    /// the database this process serves from.
    /// </summary>
    /// <param name="appConnectionString">Ignored.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    async Task<RestoreExclusionAttempt> IRestoreExclusion.TryTakeAsync(string appConnectionString, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection != null && !await RestoreLock.AliveAsync(_connection, cancellationToken))
                await DropAsync();
            if (_connection == null)
            {
                var attempt = await TakeAsync(cancellationToken);
                if (attempt.Kind == ServingLockAttemptKind.Busy)
                    return new RestoreExclusionAttempt(null, RestoreLock.OtherNodeInUse);
                if (attempt.Kind != ServingLockAttemptKind.Held)
                    throw attempt.Error ?? new InvalidOperationException("The restore lock could not be taken.");
            }
            if (!await RestoreLock.TryAsync(_connection!, _key, shared: false, cancellationToken))
                return new RestoreExclusionAttempt(null, RestoreLock.OtherNodeInUse);
            _restoringHere = true;
            return new RestoreExclusionAttempt(new ExclusiveHold(this, _generation), null);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Opens a connection and asks for the shared lock. Call with the gate held and no connection.</summary>
    private async Task<ServingLockAttempt> TakeAsync(CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(_connectionString);
        try
        {
            try
            {
                await connection.OpenAsync(cancellationToken);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new SchemaConnectException(ex);
            }
            if (!await RestoreLock.TryAsync(connection, _key, shared: true, cancellationToken))
            {
                await connection.DisposeAsync();
                return new ServingLockAttempt(ServingLockAttemptKind.Busy);
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            await connection.DisposeAsync();
            return new ServingLockAttempt(
                SchemaFailure.Classify(ex) is SchemaFailureKind.Unreachable or SchemaFailureKind.MigrationInProgress
                    ? ServingLockAttemptKind.Unreachable
                    : ServingLockAttemptKind.Unavailable,
                ex);
        }
        _connection = connection;
        _generation++;
        if (!_restoreRunning && !_restartNeeded)
            _since = DateTimeOffset.UtcNow;
        _everHeld = true;
        return new ServingLockAttempt(ServingLockAttemptKind.Held);
    }

    /// <summary>Closes the connection, if any; the server releases every lock of its session. Call with the gate held.</summary>
    private async Task DropAsync()
    {
        if (_connection == null)
            return;
        var dropped = _connection;
        _connection = null;
        _restoringHere = false;
        if (!_restoreRunning && !_restartNeeded)
            _since = DateTimeOffset.UtcNow;
        try { await dropped.DisposeAsync(); } catch (Exception) { /* it is gone either way */ }
    }

    /// <summary>Stops the keeper and closes the connection, which releases the lock.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        await _stop.CancelAsync();
        if (_keeper != null)
            try { await _keeper; } catch (Exception) { /* stopping */ }
        await _gate.WaitAsync();
        try { await DropAsync(); }
        finally { _gate.Release(); }
        _stop.Dispose();
    }

    /// <summary>The exclusive hold of a console restore, on the connection generation it was taken on.</summary>
    private sealed class ExclusiveHold(ServingDatabaseLock owner, long generation) : IRestoreExclusionHold
    {
        /// <inheritdoc />
        public async Task<bool> StillHeldAsync(CancellationToken cancellationToken = default)
        {
            await owner._gate.WaitAsync(cancellationToken);
            try
            {
                return owner._connection != null && owner._generation == generation
                    && await RestoreLock.AliveAsync(owner._connection, cancellationToken);
            }
            finally
            {
                owner._gate.Release();
            }
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            await owner._gate.WaitAsync();
            try
            {
                owner._restoringHere = false;
                if (owner._connection != null && owner._generation == generation)
                {
                    try { await RestoreLock.UnlockAsync(owner._connection, owner._key, shared: false); }
                    catch (Exception) { /* a dropped connection released it already */ }
                }
            }
            finally
            {
                owner._gate.Release();
            }
        }
    }
}
