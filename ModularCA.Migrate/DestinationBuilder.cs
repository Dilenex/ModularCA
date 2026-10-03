using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Utils;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// Creates everything the destination needs, in the order that makes each step reversible until
/// the last one: roles, then databases, then the citext extension and the audit grants, then both
/// frozen baselines, then a check of who owns them. After the copy,
/// <see cref="ApplyUpgradeMigrationsAsync"/> applies every later migration.
/// <para>
/// The SQL comes from <see cref="PostgresRoleLayout"/>, the same builders bootstrap provisions
/// with, so a migrated install and a fresh one share one layout: the app role owns the
/// application database and every object in it; the audit database is owned by a NOLOGIN role,
/// and the audit role owns every table in it but cannot drop the database; PUBLIC has no access
/// to either.
/// </para>
/// <para>
/// Nothing here is a copy. When <see cref="BuildAsync"/> finishes, the destination holds two empty
/// ModularCA databases at the baselines with the right owners and grants, and if anything after it
/// fails those two databases can be dropped, because this is what created them.
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
/// <c>must be able to SET ROLE</c>. The grant is therefore made explicit, and revoked again at the
/// end of a successful run (<see cref="RevokeAdministratorMembershipsAsync"/>).
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
    private bool _adminIsSuperuser;

    /// <summary>Creates a builder for the given options.</summary>
    /// <param name="options">The parsed command line.</param>
    /// <param name="say">Progress sink.</param>
    public DestinationBuilder(MigrationOptions options, Action<string> say)
    {
        _options = options;
        _say = say;
    }

    /// <summary>The password generated for the application role.</summary>
    public string AppPassword { get; } = PostgresRoleLayout.GeneratePassword();

    /// <summary>The password generated for the audit role.</summary>
    public string AuditPassword { get; } = PostgresRoleLayout.GeneratePassword();

    /// <summary>The role and database names this run creates, in the shared layout's terms.</summary>
    private PostgresLayoutNames Names => new(
        _options.TargetAdminUser, _options.TargetAppRole, _options.TargetAuditRole,
        _options.TargetAppDatabase, _options.TargetAuditDatabase);

    /// <summary>
    /// Creates the roles, the databases, the extension and the audit grants, revokes PUBLIC's
    /// access, applies both frozen baselines as the runtime roles, and proves each role owns its
    /// schema before anything is copied.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task BuildAsync(CancellationToken ct)
    {
        var names = Names;
        await using (var admin = new NpgsqlConnection(_options.TargetConnectionString()))
        {
            await admin.OpenAsync(ct);
            (_serverVersion, _adminIsSuperuser) = await ServerFactsAsync(admin, ct);

            // Roles before databases: a database can be created OWNER a role only once that role
            // exists. Preflight has already established that none of the three names is taken.
            await ExecuteAsync(admin, PostgresRoleLayout.LoginRoleSql(names.AppRole, AppPassword, exists: false), ct);
            _say($"  role '{names.AppRole}' created");
            await ExecuteAsync(admin, PostgresRoleLayout.LoginRoleSql(names.AuditRole, AuditPassword, exists: false), ct);
            _say($"  role '{names.AuditRole}' created");

            // The audit database's owner can never log in, so neither the node nor anyone holding
            // its credentials can drop the audit database.
            await ExecuteAsync(admin, PostgresRoleLayout.OwnerRoleSql(_options.TargetAuditOwnerRole), ct);
            _say($"  role '{_options.TargetAuditOwnerRole}' created (no login — it exists to own the audit database)");

            foreach (var role in new[] { names.AppRole, names.AuditRole, _options.TargetAuditOwnerRole })
                await GrantMembershipAsync(admin, role, ct);

            await ExecuteAsync(admin, PostgresRoleLayout.CreateDatabaseSql(names.AppDatabase, names.AppRole), ct);
            _say($"  database '{names.AppDatabase}' created, owned by '{names.AppRole}'");
            await ExecuteAsync(admin, PostgresRoleLayout.CreateDatabaseSql(names.AuditDatabase, _options.TargetAuditOwnerRole), ct);
            _say($"  database '{names.AuditDatabase}' created, owned by '{_options.TargetAuditOwnerRole}'");
        }

        await ReportCollationAsync(ct);
        await PrepareApplicationDatabaseAsync(ct);
        await GrantAuditRightsAsync(ct);
        await RevokePublicAccessAsync(ct);
        await ApplySchemasAsync(ct);
        await VerifyOwnershipAsync("Nothing was copied.", ct);
    }

    /// <summary>
    /// The statement that takes back the memberships <see cref="BuildAsync"/> gave the
    /// administrative account, for printing when it cannot be run.
    /// </summary>
    /// <param name="options">The options naming the roles.</param>
    public static string AdministratorMembershipRevokeSql(MigrationOptions options) =>
        $"REVOKE {PostgresConnection.QuoteIdentifier(options.TargetAppRole)}, "
        + $"{PostgresConnection.QuoteIdentifier(options.TargetAuditRole)}, "
        + $"{PostgresConnection.QuoteIdentifier(options.TargetAuditOwnerRole)} "
        + $"FROM {PostgresConnection.QuoteIdentifier(options.TargetAdminUser)}";

    /// <summary>
    /// Takes back the app, audit and audit-owner memberships the administrative account was given
    /// to build the destination. Run at the end of a successful run when that account is durable
    /// rather than the borrowed temporary role: left in place, it could <c>SET ROLE</c> to the
    /// audit database's owner and drop the audit database.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task RevokeAdministratorMembershipsAsync(CancellationToken ct)
    {
        await using var admin = new NpgsqlConnection(_options.TargetConnectionString());
        await admin.OpenAsync(ct);
        await ExecuteAsync(admin, AdministratorMembershipRevokeSql(_options), ct);
    }

    /// <summary>The server version and whether the administrative account is a superuser.</summary>
    private static async Task<(int Version, bool Superuser)> ServerFactsAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT current_setting('server_version_num')::int, "
            + "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        await reader.ReadAsync(ct);
        return (reader.GetInt32(0), !reader.IsDBNull(1) && reader.GetBoolean(1));
    }

    /// <summary>Whether schema <c>public</c> of <paramref name="conn"/>'s database is owned by <c>pg_database_owner</c> or <paramref name="role"/>.</summary>
    private static async Task<bool> PublicSchemaOwnedByAsync(NpgsqlConnection conn, string role, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner "
            + "WHERE n.nspname = 'public' AND r.rolname IN ('pg_database_owner', @role))", conn);
        cmd.Parameters.AddWithValue("role", role);
        return await cmd.ExecuteScalarAsync(ct) is true;
    }

    /// <summary>Makes the administrative account a member of <paramref name="role"/> with the right to SET ROLE to it.</summary>
    private async Task GrantMembershipAsync(NpgsqlConnection conn, string role, CancellationToken ct)
    {
        // WITH SET TRUE is 16 syntax and is what the version check is for; before 16 a plain role
        // grant already carried the ability to SET ROLE.
        var options = _serverVersion >= RoleGrantOptionsVersion ? " WITH SET TRUE" : "";
        await ExecuteAsync(conn,
            $"GRANT {PostgresConnection.QuoteIdentifier(role)} TO "
            + $"{PostgresConnection.QuoteIdentifier(_options.TargetAdminUser)}{options}", ct);
    }

    /// <summary>Prints the application database's encoding and collation.</summary>
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

    /// <summary>
    /// Creates <c>citext</c> as the app role. When the administrator is a superuser (only a
    /// superuser can) and schema <c>public</c> is owned by neither <c>pg_database_owner</c> nor
    /// the app role, as on PostgreSQL 14 or a cluster pg_upgraded from it, hands it to the app
    /// role and removes PUBLIC's CREATE; decided from the catalog, not the server version.
    /// </summary>
    private async Task PrepareApplicationDatabaseAsync(CancellationToken ct)
    {
        var names = Names;
        await using var conn = new NpgsqlConnection(_options.TargetConnectionString(names.AppDatabase));
        await conn.OpenAsync(ct);

        if (_adminIsSuperuser)
        {
            await ExecuteAsync(conn, PostgresRoleLayout.PublicSchemaSql(names.AppRole), ct);
            _say($"  schema public of '{names.AppDatabase}' owned by '{names.AppRole}' or the database owner; PUBLIC may not create in it");
        }
        else if (!await PublicSchemaOwnedByAsync(conn, names.AppRole, ct))
        {
            _say($"  schema public of '{names.AppDatabase}' stays with the bootstrap superuser (non-superuser "
                + "administrator); the app role creates its tables through PUBLIC's CREATE");
        }

        // citext has to exist before the first migration runs: the application schema declares its
        // identifier columns with that type. Created as the app role, so the extension belongs to
        // the database's owner rather than to an administrator this run may be about to drop.
        await AsRoleAsync(conn, names.AppRole, [PostgresRoleLayout.ExtensionSql], ct);
        _say($"  citext extension created in '{names.AppDatabase}', owned by '{names.AppRole}'");
    }

    /// <summary>
    /// Grants the audit role CONNECT on the audit database and USAGE and CREATE on its schema, as
    /// the audit database's owner, so the grantor is a durable role. When the administrator is a
    /// superuser, schema <c>public</c> is first handed to that owner if <c>pg_database_owner</c>
    /// does not already own it, decided from the catalog.
    /// </summary>
    private async Task GrantAuditRightsAsync(CancellationToken ct)
    {
        var names = Names;
        await using var conn = new NpgsqlConnection(_options.TargetConnectionString(names.AuditDatabase));
        await conn.OpenAsync(ct);

        if (_adminIsSuperuser)
            await ExecuteAsync(conn, PostgresRoleLayout.PublicSchemaSql(_options.TargetAuditOwnerRole), ct);

        await AsRoleAsync(conn, _options.TargetAuditOwnerRole,
            [PostgresRoleLayout.AuditConnectSql(names), .. PostgresRoleLayout.AuditSchemaGrantSql(names)], ct);
        _say($"  audit role '{names.AuditRole}' may connect to '{names.AuditDatabase}' and create its tables there");
    }

    /// <summary>
    /// Removes PUBLIC's default CONNECT and TEMPORARY on both databases, each as its owner. Runs
    /// after the administrator's last session in either database.
    /// </summary>
    private async Task RevokePublicAccessAsync(CancellationToken ct)
    {
        var names = Names;
        await using var admin = new NpgsqlConnection(_options.TargetConnectionString());
        await admin.OpenAsync(ct);
        await AsRoleAsync(admin, names.AppRole, [PostgresRoleLayout.RevokePublicSql(names.AppDatabase)], ct);
        await AsRoleAsync(admin, _options.TargetAuditOwnerRole, [PostgresRoleLayout.RevokePublicSql(names.AuditDatabase)], ct);
        _say("  PUBLIC access to both databases revoked");
    }

    /// <summary>
    /// Applies the frozen baselines only (<see cref="PostgresRoleLayout.AppBaselineMigration"/>,
    /// <see cref="PostgresRoleLayout.AuditBaselineMigration"/>), the 0.3.0 schema the copy writes
    /// into, as the runtime roles on migration connections. Running as the roles the node uses is
    /// what makes them own what they will later migrate.
    /// </summary>
    private async Task ApplySchemasAsync(CancellationToken ct)
    {
        await using (var app = MigrationContext(DatabaseKind.Application))
            await SchemaStages.ApplyBaselineAsync(app, PostgresRoleLayout.AppBaselineMigration, "application", ct);
        _say($"  application baseline {PostgresRoleLayout.AppBaselineMigration} applied as '{_options.TargetAppRole}'");

        await using (var audit = MigrationContext(DatabaseKind.Audit))
            await SchemaStages.ApplyBaselineAsync(audit, PostgresRoleLayout.AuditBaselineMigration, "audit", ct);
        _say($"  audit baseline {PostgresRoleLayout.AuditBaselineMigration} applied as '{_options.TargetAuditRole}', which owns its tables");
    }

    /// <summary>
    /// After the copy has been verified: applies every later migration, the application
    /// database's first, as the runtime roles through <see cref="SchemaVersionGate"/>, as the
    /// control role would at startup, then proves each role still owns its schema. A refusal
    /// throws <see cref="MigrationFailedException"/> with the migration's message.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task ApplyUpgradeMigrationsAsync(CancellationToken ct)
    {
        foreach (var (kind, name) in new[] { (DatabaseKind.Application, "application"), (DatabaseKind.Audit, "audit") })
        {
            await using var db = MigrationContext(kind);
            var applied = await SchemaStages.ApplyLaterAsync(db, name, ct);
            _say(applied.Count == 0
                ? $"  {name} database: no later migrations"
                : $"  {name} database: {string.Join(", ", applied)} applied");
        }
        await VerifyOwnershipAsync("The later migrations were applied.", ct);
    }

    /// <summary>A context of <paramref name="kind"/> on the migration connection, as that database's runtime role.</summary>
    private DbContext MigrationContext(DatabaseKind kind) => MigrationConnection.CreateContext(kind,
        kind == DatabaseKind.Application ? _options.AppInstance(AppPassword) : _options.AuditInstance(AuditPassword),
        new Shared.Models.Config.SchemaConfig());

    /// <summary>
    /// Reads the ownership report as each runtime role and fails the run unless each owns every
    /// object in its schema and can create tables. <paramref name="stage"/> ends the message.
    /// </summary>
    private async Task VerifyOwnershipAsync(string stage, CancellationToken ct)
    {
        foreach (var (kind, instance) in new[]
                 {
                     (DatabaseKind.Application, _options.AppInstance(AppPassword)),
                     (DatabaseKind.Audit, _options.AuditInstance(AuditPassword)),
                 })
        {
            await using var conn = new NpgsqlConnection(PostgresConnection.Build(instance));
            var report = await SchemaOwnership.ProbeAsync(conn, kind, ct);
            if (!report.IsSound)
                throw new MigrationFailedException(
                    $"'{report.Role}' does not own the schema of '{report.Database}': "
                    + $"{report.NotOwned.Count} object(s) owned by another role "
                    + $"({string.Join(", ", report.NotOwned.Take(10).Select(o => $"{o.Object} owned by {o.Owner}"))}), "
                    + $"can create tables: {(report.CanCreateTables ? "yes" : "no")}. {stage}");
            _say($"  '{report.Role}' owns every object in '{report.Database}'");
        }
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

    /// <summary>Runs one statement.</summary>
    private static async Task ExecuteAsync(NpgsqlConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Runs one cleanup statement, reporting rather than throwing a failure.</summary>
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
}
