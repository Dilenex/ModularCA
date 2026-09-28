using System.Net.Sockets;
using System.Security.Authentication;
using Npgsql;

namespace ModularCA.Database;

/// <summary>
/// Why a schema read or a migration could not complete, sorted by what the process should do
/// about it.
/// </summary>
public enum SchemaFailureKind
{
    /// <summary>
    /// Another session holds the schema: a lock wait timed out, a statement was cancelled, or a
    /// read timed out behind the control role's migration lock. Wait and read again.
    /// </summary>
    MigrationInProgress,

    /// <summary>
    /// The operator must act: authentication, authorisation, TLS, an unreadable history table,
    /// or anything not recognised. Never retried.
    /// </summary>
    Misconfigured,

    /// <summary>The database does not exist (SQLSTATE 3D000).</summary>
    Missing,

    /// <summary>The server could not be reached or is not accepting connections yet. Wait and read again.</summary>
    Unreachable,
}

/// <summary>
/// The history table exists but the runtime role cannot read it. Always
/// <see cref="SchemaFailureKind.Misconfigured"/>: a database this role cannot read is never a
/// reason to continue.
/// </summary>
public sealed class SchemaAccessException : Exception
{
    /// <summary>Creates the exception for <paramref name="role"/> on <paramref name="database"/>.</summary>
    public SchemaAccessException(string database, string role, string historyTable)
        : base($"The migration history table {historyTable} in database '{database}' exists, but role '{role}' cannot read it. "
            + "The role does not own the schema it runs on.")
    {
        Database = database;
        Role = role;
    }

    /// <summary>The database whose history could not be read.</summary>
    public string Database { get; }

    /// <summary>The role that could not read it.</summary>
    public string Role { get; }
}

/// <summary>
/// The connection for a schema read, an ownership probe or a migration could not be opened.
/// Wraps the driver's error so that a timeout while connecting is told apart from a timeout
/// behind a migration lock or a statement that ran too long.
/// </summary>
public sealed class SchemaConnectException : Exception
{
    /// <summary>Wraps <paramref name="inner"/>, the error raised while connecting.</summary>
    public SchemaConnectException(Exception inner)
        : base($"Could not connect to the database: {inner.Message}", inner)
    {
    }
}

/// <summary>
/// Sorts the errors a schema read or a migration raises into <see cref="SchemaFailureKind"/>,
/// and describes them for an operator.
/// </summary>
public static class SchemaFailure
{
    /// <summary>SQLSTATE lock_not_available: <c>lock_timeout</c> expired.</summary>
    public const string LockNotAvailable = "55P03";

    /// <summary>SQLSTATE query_canceled: <c>statement_timeout</c> expired or the statement was cancelled.</summary>
    public const string QueryCanceled = "57014";

    /// <summary>
    /// Classifies <paramref name="error"/>. A <see cref="SchemaConnectException"/> anywhere in the
    /// chain decides first: a failure to connect is never a migration in progress. Otherwise the
    /// chain is searched for the most specific cause: a PostgreSQL SQLSTATE, a TLS failure or an
    /// unreadable history table first, then driver timeouts and socket errors.
    /// </summary>
    public static SchemaFailureKind Classify(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (Chain(error).OfType<SchemaConnectException>().FirstOrDefault() is { InnerException: { } inner })
        {
            var kind = Classify(inner);
            return kind == SchemaFailureKind.MigrationInProgress ? SchemaFailureKind.Unreachable : kind;
        }

        foreach (var e in Chain(error))
        {
            switch (e)
            {
                case SchemaAccessException:
                case AuthenticationException:
                    return SchemaFailureKind.Misconfigured;
                case PostgresException pg:
                    return ClassifySqlState(pg);
            }
        }

        foreach (var e in Chain(error))
        {
            switch (e)
            {
                case NpgsqlException { InnerException: TimeoutException }:
                case TimeoutException:
                    return SchemaFailureKind.MigrationInProgress;
                case NpgsqlException { IsTransient: true }:
                case SocketException:
                case IOException:
                    return SchemaFailureKind.Unreachable;
            }
        }
        return SchemaFailureKind.Misconfigured;
    }

    /// <summary>
    /// True when waiting and reading again can succeed without anyone acting: a migration in
    /// progress, an unreachable server, a deadlock or a serialization failure.
    /// </summary>
    public static bool Transient(Exception error) =>
        Classify(error) is SchemaFailureKind.MigrationInProgress or SchemaFailureKind.Unreachable;

    /// <summary>
    /// True when a failed migration may be retried: a connection that could not be opened for a
    /// reason that passes on its own (checked first, so a connect timeout is never taken for a
    /// statement timeout), a lock wait that timed out, a deadlock, a serialization failure, or a
    /// lost connection. A statement that ran past its timeout is not: the same statement would
    /// time out again, so the operator must raise <c>Schema.MigrationCommandTimeoutSeconds</c>.
    /// </summary>
    public static bool TransientForMigration(Exception error)
    {
        if (IsConnectFailure(error))
            return Classify(error) == SchemaFailureKind.Unreachable;
        if (SqlState(error) is LockNotAvailable or "40P01" or "40001")
            return true;
        if (IsStatementTimeout(error))
            return false;
        return Classify(error) == SchemaFailureKind.Unreachable;
    }

    /// <summary>
    /// True when a statement ran past its time limit: the server's <c>statement_timeout</c>
    /// (57014) or the driver's command timeout. Never true for a failure to connect.
    /// </summary>
    public static bool IsStatementTimeout(Exception error) =>
        !IsConnectFailure(error) && (SqlState(error) == QueryCanceled || IsClientTimeout(error));

    /// <summary>True when the chain holds a <see cref="SchemaConnectException"/>: the connection was never opened.</summary>
    public static bool IsConnectFailure(Exception error) => Chain(error).Any(e => e is SchemaConnectException);

    /// <summary>True when the chain holds a TLS handshake failure.</summary>
    public static bool IsTlsFailure(Exception error) => Chain(error).Any(e => e is AuthenticationException);

    /// <summary>
    /// The SQLSTATE of the first <see cref="PostgresException"/> in the chain, or
    /// <see langword="null"/>.
    /// </summary>
    public static string? SqlState(Exception error) =>
        Chain(error).OfType<PostgresException>().FirstOrDefault()?.SqlState;

    /// <summary>
    /// A one-line description for an operator: the exception type, the SQLSTATE and what it
    /// means, <c>connect timeout</c> for a connection that timed out while opening, or
    /// <c>command timeout (N s)</c> for a client-side statement timeout, then the root message.
    /// </summary>
    /// <param name="error">The error.</param>
    /// <param name="commandTimeoutSeconds">The command timeout in force, named in a timeout description.</param>
    public static string Describe(Exception error, int? commandTimeoutSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        var root = Chain(error).Last();
        var pg = Chain(error).OfType<PostgresException>().FirstOrDefault();
        if (pg is not null)
        {
            var meaning = pg.SqlState switch
            {
                LockNotAvailable => "lock timeout",
                QueryCanceled => commandTimeoutSeconds is > 0
                    ? $"statement timeout ({commandTimeoutSeconds} s) or cancelled"
                    : "statement cancelled",
                "40P01" => "deadlock",
                "40001" => "serialization failure",
                "42501" => "insufficient privilege",
                "28P01" => "password authentication failed",
                "28000" => "login refused",
                "3D000" => "database does not exist",
                _ => null,
            };
            return $"{pg.GetType().Name} {pg.SqlState}{(meaning is null ? "" : $" ({meaning})")}: {pg.MessageText}";
        }
        if (IsConnectFailure(error) && Chain(error).Any(e => e is TimeoutException))
            return $"{error.GetType().Name} (connect timeout): {root.Message}";
        if (IsClientTimeout(error))
        {
            var limit = commandTimeoutSeconds is > 0 ? $"command timeout ({commandTimeoutSeconds} s)" : "command timeout";
            return $"{error.GetType().Name} ({limit}): {root.Message}";
        }
        return root == error
            ? $"{error.GetType().Name}: {error.Message}"
            : $"{error.GetType().Name} ({root.GetType().Name}): {root.Message}";
    }

    /// <summary>Maps a PostgreSQL error to its kind.</summary>
    private static SchemaFailureKind ClassifySqlState(PostgresException pg) => pg.SqlState switch
    {
        LockNotAvailable or QueryCanceled or "40P01" or "40001" => SchemaFailureKind.MigrationInProgress,
        "28P01" or "28000" or "42501" => SchemaFailureKind.Misconfigured,
        "3D000" => SchemaFailureKind.Missing,
        "57P01" or "57P02" or "57P03" or "53300" => SchemaFailureKind.Unreachable,
        var s when s.StartsWith("08", StringComparison.Ordinal) => SchemaFailureKind.Unreachable,
        _ when pg.IsTransient => SchemaFailureKind.Unreachable,
        _ => SchemaFailureKind.Misconfigured,
    };

    /// <summary>True when the chain holds a driver timeout rather than a server error, and the connection had been opened.</summary>
    private static bool IsClientTimeout(Exception error) =>
        !IsConnectFailure(error)
        && Chain(error).Any(e => e is NpgsqlException { InnerException: TimeoutException } and not PostgresException);

    /// <summary>The exception and its inner exceptions, outermost first.</summary>
    private static IEnumerable<Exception> Chain(Exception error)
    {
        for (var e = error; e is not null; e = e.InnerException)
            yield return e;
    }
}
