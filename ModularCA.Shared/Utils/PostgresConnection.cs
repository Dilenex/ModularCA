using Npgsql;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Single place where a PostgreSQL connection string is built, and the single place that
/// decides what the operator-facing <c>SslMode</c> vocabulary means.
/// <para>
/// Before the PostgreSQL move every call site constructed a <c>MySqlConnectionStringBuilder</c>
/// by hand — there were fourteen of them, each repeating the same five assignments and the same
/// "clamp an unparseable TLS mode back to Required" fallback. They are now one method, because a
/// connection string assembled by string concatenation is how a password containing a semicolon
/// silently produces an authentication failure nobody can explain.
/// </para>
/// </summary>
public static class PostgresConnection
{
    /// <summary>
    /// The port PostgreSQL listens on by default. Used as the default in generated
    /// <c>db.yaml</c> and as the value the setup wizard pre-fills.
    /// </summary>
    public const int DefaultPort = 5432;

    /// <summary>
    /// The maintenance database every PostgreSQL cluster has. Administrative work (CREATE
    /// DATABASE, CREATE ROLE, DROP DATABASE) cannot run inside the database it targets, so the
    /// bootstrap connects here instead. MySQL had no equivalent requirement, which is why the
    /// old code could do all of this on a single connection.
    /// </summary>
    public const string MaintenanceDatabase = "postgres";

    /// <summary>
    /// Translates the operator-facing TLS mode string into an Npgsql <see cref="SslMode"/>.
    /// <para>
    /// Both vocabularies are accepted. The MySQL spellings (<c>None</c>, <c>Preferred</c>,
    /// <c>Required</c>) are what every existing <c>db.yaml</c>, every documented environment
    /// variable and every setup-wizard screenshot in the wild contains, so rejecting them would
    /// turn a database migration into a configuration migration for no benefit. The Npgsql
    /// spellings (<c>Disable</c>, <c>Allow</c>, <c>Prefer</c>, <c>Require</c>) are accepted
    /// because that is what an operator reading the PostgreSQL documentation will type.
    /// </para>
    /// <para>
    /// Anything unrecognised clamps to <see cref="SslMode.Require"/>. A typo must not silently
    /// downgrade the transport protecting the credentials of a certificate authority.
    /// </para>
    /// </summary>
    /// <param name="value">The configured mode, in either vocabulary. Null or blank clamps.</param>
    /// <returns>The Npgsql TLS mode to apply.</returns>
    public static SslMode ParseSslMode(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "none" or "disable" or "disabled" => SslMode.Disable,
        "allow" => SslMode.Allow,
        "preferred" or "prefer" => SslMode.Prefer,
        "required" or "require" => SslMode.Require,
        "verifyca" or "verify-ca" => SslMode.VerifyCA,
        "verifyfull" or "verify-full" => SslMode.VerifyFull,
        _ => SslMode.Require,
    };

    /// <summary>
    /// Builds a connection string for one database on the configured server.
    /// </summary>
    /// <param name="host">Server hostname or address.</param>
    /// <param name="port">Server port.</param>
    /// <param name="database">Database name to connect to.</param>
    /// <param name="username">Role to authenticate as.</param>
    /// <param name="password">That role's password.</param>
    /// <param name="sslMode">TLS mode in either vocabulary; see <see cref="ParseSslMode"/>.</param>
    /// <param name="commandTimeoutSeconds">Optional per-command timeout, in seconds.</param>
    /// <returns>A fully escaped Npgsql connection string.</returns>
    public static string Build(
        string host,
        int port,
        string database,
        string username,
        string password,
        string? sslMode = null,
        int? commandTimeoutSeconds = null)
    {
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port <= 0 ? DefaultPort : port,
            Database = database,
            Username = username,
            Password = password,
            SslMode = ParseSslMode(sslMode),
        };
        if (commandTimeoutSeconds is int timeout)
            builder.CommandTimeout = timeout;
        return builder.ConnectionString;
    }

    /// <summary>
    /// Builds a connection string for the configured application database.
    /// </summary>
    /// <param name="instance">The <c>DB.App</c> or <c>DB.Audit</c> configuration block.</param>
    /// <param name="commandTimeoutSeconds">Optional per-command timeout, in seconds.</param>
    /// <returns>A fully escaped Npgsql connection string.</returns>
    public static string Build(DbInstance instance, int? commandTimeoutSeconds = null) =>
        Build(instance.Host, instance.Port, instance.Database, instance.Username, instance.Password,
              instance.SslMode, commandTimeoutSeconds);

    /// <summary>
    /// Builds a connection string to the cluster's maintenance database rather than to an
    /// application database. Administrative statements — CREATE DATABASE, DROP DATABASE,
    /// CREATE ROLE — must run from a connection that is not attached to the database they
    /// operate on, so every administrative path in bootstrap and setup goes through here.
    /// </summary>
    /// <param name="host">Server hostname or address.</param>
    /// <param name="port">Server port.</param>
    /// <param name="username">Superuser (or role-creating) login.</param>
    /// <param name="password">That login's password.</param>
    /// <param name="sslMode">TLS mode in either vocabulary; see <see cref="ParseSslMode"/>.</param>
    /// <param name="database">Maintenance database to attach to; defaults to <c>postgres</c>.</param>
    /// <returns>A fully escaped Npgsql connection string.</returns>
    public static string BuildMaintenance(
        string host,
        int port,
        string username,
        string password,
        string? sslMode = null,
        string database = MaintenanceDatabase) =>
        Build(host, port, database, username, password, sslMode);

    /// <summary>
    /// Quotes a PostgreSQL identifier (database name, role name, table name) for interpolation
    /// into DDL that cannot take parameters.
    /// <para>
    /// PostgreSQL folds unquoted identifiers to lower case, which matters here: the database is
    /// called <c>modularca-app</c> and contains a hyphen, so it can only ever be written quoted.
    /// The embedded quote is doubled, which is what makes this safe rather than merely tidy.
    /// </para>
    /// </summary>
    /// <param name="identifier">The raw identifier.</param>
    /// <returns>The identifier wrapped in double quotes, internal quotes doubled.</returns>
    public static string QuoteIdentifier(string identifier) =>
        "\"" + identifier.Replace("\"", "\"\"") + "\"";

    /// <summary>
    /// Quotes a string literal for interpolation into DDL that cannot take parameters —
    /// specifically the <c>PASSWORD '...'</c> clause of CREATE ROLE, which PostgreSQL will not
    /// accept as a bound parameter.
    /// </summary>
    /// <param name="literal">The raw value.</param>
    /// <returns>The value wrapped in single quotes, internal quotes doubled.</returns>
    public static string QuoteLiteral(string literal) =>
        "'" + literal.Replace("'", "''") + "'";
}
