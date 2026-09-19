using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Database.Conventions;
using ModularCA.Shared.Utils;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// Creates everything the destination needs, in the order that makes each step reversible until
/// the last one: roles, then databases, then the citext extension, then both schemas.
/// <para>
/// Nothing here is a copy. When this class finishes, the destination holds two empty ModularCA
/// databases with the right owners and grants, and if anything after it fails those two databases
/// can be dropped, because this is what created them.
/// </para>
/// <para>
/// Two PostgreSQL rules shape all of it, and both only appear when the administrative account is
/// not a superuser — which is the case this deliberately supports.
/// </para>
/// <para>
/// <b>Creating a database for someone else needs membership of them.</b> <c>CREATE DATABASE ...
/// OWNER x</c> requires the creator to be able to <c>SET ROLE</c> to <c>x</c>. A <c>CREATEROLE</c>
/// account is granted the roles it creates, but on PostgreSQL 16 that grant does not carry the
/// <c>SET</c> option by default, so creating a role and then handing it a database fails with
/// <c>must be able to SET ROLE</c>. The grant is therefore made explicit.
/// </para>
/// <para>
/// <b>A role cannot be dropped while anything still points at it.</b> That includes databases and
/// extensions it owns, and privileges it granted — the grantor is recorded, not just the grantee.
/// When the administrative account is the temporary one this tool borrows, every such trace would
/// keep it alive past the end of the run. So each database is created with a durable owner, and
/// everything owned or granted afterwards is done under <c>SET ROLE</c> as that owner rather than
/// as the account that happens to be driving.
/// </para>
/// </summary>
public sealed class DestinationBuilder
{
    /// <summary>
    /// PostgreSQL 16, where a role membership grant gained separate <c>INHERIT</c>, <c>SET</c> and
    /// <c>ADMIN</c> options and stopped implying the first two.
    /// </summary>
    private const int RoleGrantOptionsVersion = 160000;

    private readonly MigrationOptions _options;
    private readonly Action<string> _say;
    private int _serverVersion;

    /// <summary>Creates a builder for the given options.</summary>
    /// <param name="options">The parsed command line.</param>
    /// <param name="say">Progress sink.</param>
    public DestinationBuilder(MigrationOptions options, Action<string> say)
    {
        _options = options;
        _say = say;
    }

    /// <summary>The password generated for the application role.</summary>
    public string AppPassword { get; } = GeneratePassword();

    /// <summary>The password generated for the audit role.</summary>
    public string AuditPassword { get; } = GeneratePassword();

    /// <summary>
    /// Creates the roles, the databases, the extension and both schemas.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task BuildAsync(CancellationToken ct)
    {
        await using (var admin = new NpgsqlConnection(_options.TargetConnectionString()))
        {
            await admin.OpenAsync(ct);
            _serverVersion = await ServerVersionAsync(admin, ct);

            // Roles before databases: a database can be created OWNER a role only once that role
            // exists. Preflight has already established that none of the three names is taken.
            await CreateLoginRoleAsync(admin, _options.TargetAppRole, AppPassword, ct);
            await CreateLoginRoleAsync(admin, _options.TargetAuditRole, AuditPassword, ct);

            // The audit database's owner, and the reason it is a role of its own. The audit
            // database must not be owned by the account the node connects with, or the node could
            // drop its own audit — the guarantee the MySQL setup claimed and did not hold. It
            // cannot be owned by the administrative account either, because that account may be
            // the temporary one, and a database would keep it alive. So it is owned by a role that
            // can never log in and has no password to steal.
            await CreateOwnerRoleAsync(admin, _options.TargetAuditOwnerRole, ct);

            // Explicit membership, because CREATE DATABASE ... OWNER needs SET ROLE and the
            // implicit grant a CREATEROLE account receives does not provide it on 16.
            foreach (var role in new[]
                     { _options.TargetAppRole, _options.TargetAuditRole, _options.TargetAuditOwnerRole })
            {
                await GrantMembershipAsync(admin, role, ct);
            }

            // TEMPLATE template0 with an explicit encoding, rather than inheriting template1.
            // template1 is whatever a previous administrator left it as, and the encoding is not a
            // detail here: citext folds case through lower(), which is locale-dependent, so the
            // case rules the model declares are only true if the database agrees with it.
            await CreateDatabaseAsync(admin, _options.TargetAppDatabase, _options.TargetAppRole, ct);
            await CreateDatabaseAsync(admin, _options.TargetAuditDatabase, _options.TargetAuditOwnerRole, ct);
        }

        await ReportCollationAsync(ct);
        await CreateExtensionAsync(ct);
        await GrantAuditRightsAsync(ct);
        await ApplySchemasAsync(ct);
    }

    private static async Task<int> ServerVersionAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("SHOW server_version_num", conn);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
    }

    private async Task CreateLoginRoleAsync(
        NpgsqlConnection conn, string role, string password, CancellationToken ct)
    {
        await ExecuteAsync(conn,
            $"CREATE ROLE {PostgresConnection.QuoteIdentifier(role)} WITH LOGIN PASSWORD "
            + PostgresConnection.QuoteLiteral(password), ct);
        _say($"  role '{role}' created");
    }

    private async Task CreateOwnerRoleAsync(NpgsqlConnection conn, string role, CancellationToken ct)
    {
        await ExecuteAsync(conn, $"CREATE ROLE {PostgresConnection.QuoteIdentifier(role)} WITH NOLOGIN", ct);
        _say($"  role '{role}' created (no login — it exists to own the audit database)");
    }

    private async Task GrantMembershipAsync(NpgsqlConnection conn, string role, CancellationToken ct)
    {
        // WITH SET TRUE is 16 syntax and is what the version check is for; before 16 a plain role
        // grant already carried the ability to SET ROLE.
        var options = _serverVersion >= RoleGrantOptionsVersion ? " WITH SET TRUE" : "";
        await ExecuteAsync(conn,
            $"GRANT {PostgresConnection.QuoteIdentifier(role)} TO "
            + $"{PostgresConnection.QuoteIdentifier(_options.TargetAdminUser)}{options}", ct);
    }

    private async Task CreateDatabaseAsync(
        NpgsqlConnection conn, string database, string owner, CancellationToken ct)
    {
        await ExecuteAsync(conn,
            $"CREATE DATABASE {PostgresConnection.QuoteIdentifier(database)} "
            + $"OWNER {PostgresConnection.QuoteIdentifier(owner)} ENCODING 'UTF8' TEMPLATE template0", ct);
        _say($"  database '{database}' created, owned by '{owner}'");
    }

    private async Task ReportCollationAsync(CancellationToken ct)
    {
        await using var conn = new NpgsqlConnection(_options.TargetConnectionString());
        await conn.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = @n", conn);
        cmd.Parameters.AddWithValue("n", _options.TargetAppDatabase);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (await reader.ReadAsync(ct))
            _say($"  encoding {reader.GetString(0)}, collation {reader.GetString(1)}, ctype {reader.GetString(2)}");
    }

    private async Task CreateExtensionAsync(CancellationToken ct)
    {
        // citext has to exist before the first migration runs: the application schema declares its
        // identifier columns with that type (see TextCaseSensitivity), and a type that does not
        // exist yet is a CREATE TABLE that fails on its first line.
        //
        // Created as the application role rather than as the administrator, because an extension
        // records an owner and the administrator may be a temporary role this run is about to drop.
        // The application role owns the database and citext is a trusted extension, so it is
        // allowed to do this itself — which is also exactly what happens on a fresh install.
        await using var conn = new NpgsqlConnection(_options.TargetConnectionString(_options.TargetAppDatabase));
        await conn.OpenAsync(ct);
        await AsRoleAsync(conn, _options.TargetAppRole,
            $"CREATE EXTENSION IF NOT EXISTS {TextCaseSensitivity.Extension}", ct);
        _say($"  {TextCaseSensitivity.Extension} extension created in '{_options.TargetAppDatabase}'");
    }

    private async Task GrantAuditRightsAsync(CancellationToken ct)
    {
        // Granted from inside the audit database: schema rights and default privileges are
        // per-database objects, so a connection to the maintenance database cannot see them.
        //
        // Every statement runs as the database's owner. A privilege records who granted it, so
        // granting these as the administrator would leave the audit database pointing at an
        // account this run intends to drop, and the drop would fail.
        var qRole = PostgresConnection.QuoteIdentifier(_options.TargetAuditRole);
        var qDb = PostgresConnection.QuoteIdentifier(_options.TargetAuditDatabase);

        await using var conn = new NpgsqlConnection(_options.TargetConnectionString(_options.TargetAuditDatabase));
        await conn.OpenAsync(ct);

        await AsRoleAsync(conn, _options.TargetAuditOwnerRole,
        [
            $"GRANT CONNECT ON DATABASE {qDb} TO {qRole}",
            // CREATE on the schema is what lets the audit context apply its own migrations.
            $"GRANT USAGE, CREATE ON SCHEMA public TO {qRole}",
            $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {qRole}",
            $"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {qRole}",
            // Covers tables created later by the owner — during a restore, say — without which the
            // role would lose access to everything added after this point.
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {qRole}",
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {qRole}",
        ], ct);

        _say($"  audit role '{_options.TargetAuditRole}' granted rights on '{_options.TargetAuditDatabase}'");
    }

    private async Task ApplySchemasAsync(CancellationToken ct)
    {
        // The application schema, applied as the application role rather than as the
        // administrator. Running it as the owner the node will actually use is what proves the
        // node can apply its own migrations on the next upgrade, rather than discovering months
        // later that only the administrator ever could.
        await using (var app = AppContext(_options.AppInstance(AppPassword)))
        {
            await app.Database.MigrateAsync(ct);
        }
        _say($"  application schema applied as '{_options.TargetAppRole}'");

        // The audit schema, applied as the audit role — which is the narrowest guess in the whole
        // cutover. The audit role deliberately owns nothing and holds everything by grant, and
        // whether that grant set is enough for its own migrations has never been executed before
        // this line. If it is not, this is where it says so, with nothing yet copied.
        await using (var audit = AuditContext(_options.AuditInstance(AuditPassword)))
        {
            await audit.Database.MigrateAsync(ct);
        }
        _say($"  audit schema applied as '{_options.TargetAuditRole}' — its grants are sufficient");
    }

    /// <summary>Opens an application context against the destination as a given account.</summary>
    /// <param name="instance">The account and database to connect as.</param>
    /// <returns>A context the caller owns and must dispose.</returns>
    public static ModularCADbContext AppContext(Shared.Models.Config.DbInstance instance) =>
        new(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(PostgresConnection.Build(instance))
            .Options);

    /// <summary>Opens an audit context against the destination as a given account.</summary>
    /// <param name="instance">The account and database to connect as.</param>
    /// <returns>A context the caller owns and must dispose.</returns>
    public static AuditDbContext AuditContext(Shared.Models.Config.DbInstance instance) =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(PostgresConnection.Build(instance))
            .Options);

    /// <summary>
    /// Drops whatever was created. Safe precisely because preflight refused unless none of it
    /// existed: everything named here was made by this run.
    /// </summary>
    /// <param name="options">The options naming what to drop.</param>
    /// <param name="say">Progress sink.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task RollbackAsync(MigrationOptions options, Action<string> say, CancellationToken ct)
    {
        await using var admin = new NpgsqlConnection(options.TargetConnectionString());
        await admin.OpenAsync(ct);

        // Databases before roles: a role that still owns one cannot be dropped. WITH (FORCE)
        // terminates sessions still attached; without it one leftover connection turns the
        // cleanup into an error the operator cannot act on.
        foreach (var database in new[] { options.TargetAppDatabase, options.TargetAuditDatabase })
        {
            await TryExecuteAsync(admin,
                $"DROP DATABASE IF EXISTS {PostgresConnection.QuoteIdentifier(database)} WITH (FORCE)", say, ct);
        }
        foreach (var role in new[]
                 { options.TargetAppRole, options.TargetAuditRole, options.TargetAuditOwnerRole })
        {
            await TryExecuteAsync(admin,
                $"DROP ROLE IF EXISTS {PostgresConnection.QuoteIdentifier(role)}", say, ct);
        }
        say("  destination returned to the state preflight found it in");
    }

    /// <summary>
    /// Runs statements as another role, so anything they own or grant belongs to that role rather
    /// than to whichever account is driving the migration.
    /// </summary>
    private static async Task AsRoleAsync(
        NpgsqlConnection conn, string role, IEnumerable<string> statements, CancellationToken ct)
    {
        await ExecuteAsync(conn, $"SET ROLE {PostgresConnection.QuoteIdentifier(role)}", ct);
        try
        {
            foreach (var sql in statements)
                await ExecuteAsync(conn, sql, ct);
        }
        finally
        {
            await ExecuteAsync(conn, "RESET ROLE", CancellationToken.None);
        }
    }

    private static Task AsRoleAsync(NpgsqlConnection conn, string role, string statement, CancellationToken ct) =>
        AsRoleAsync(conn, role, [statement], ct);

    private static async Task ExecuteAsync(NpgsqlConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task TryExecuteAsync(
        NpgsqlConnection conn, string sql, Action<string> say, CancellationToken ct)
    {
        try
        {
            await ExecuteAsync(conn, sql, ct);
        }
        catch (Exception ex)
        {
            say($"  (!) cleanup step failed, continuing: {ex.Message}");
        }
    }

    private static string GeneratePassword() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
}
