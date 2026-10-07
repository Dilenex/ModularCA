using System.Data;
using System.Data.Common;
using ModularCA.Shared.Utils;

namespace ModularCA.Database;

/// <summary>Which of the two ModularCA databases a check or a repair is about.</summary>
public enum DatabaseKind
{
    /// <summary>The application database (<see cref="ModularCADbContext"/>).</summary>
    Application,

    /// <summary>The audit database (<see cref="AuditDbContext"/>).</summary>
    Audit,
}

/// <summary>An object in schema <c>public</c> that the runtime role does not own.</summary>
/// <param name="Object">The qualified name, as PostgreSQL prints it.</param>
/// <param name="Kind">The relkind (<c>r</c>, <c>S</c>, ...), <c>function</c> or <c>type</c>.</param>
/// <param name="Owner">The role that owns it.</param>
/// <param name="Usable">Whether the runtime role can still read or use it.</param>
public sealed record NotOwnedObject(string Object, string Kind, string Owner, bool Usable);

/// <summary>A role granted directly to another.</summary>
/// <param name="Member">The role that holds the membership.</param>
/// <param name="Role">The role it is a member of.</param>
public sealed record RoleMembership(string Member, string Role);

/// <summary>
/// What the runtime role can do to its own database's schema, read from <c>pg_catalog</c> as
/// that role.
/// </summary>
/// <param name="Kind">Which database this is.</param>
/// <param name="Role">The role the probe ran as.</param>
/// <param name="Database">The database the probe ran in.</param>
/// <param name="DatabaseOwner">The database's owner.</param>
/// <param name="ServerVersionNum">The server's <c>server_version_num</c>.</param>
/// <param name="NotOwned">Objects in <c>public</c> the role cannot alter, extension members excluded.</param>
/// <param name="CanCreateTables">CREATE on schema <c>public</c>.</param>
/// <param name="CanCreateSchema">CREATE on the database.</param>
/// <param name="CanBecomeDbOwner">The role owns the database or is a member of its owner.</param>
/// <param name="AdminAttributes">SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS.</param>
/// <param name="OtherMembers">
/// Direct members, other than the runtime role itself and superusers, of the runtime role, of the
/// database owner, or of <c>&lt;role&gt;_owner</c>: each could act as that role.
/// </param>
public sealed record OwnershipReport(
    DatabaseKind Kind,
    string Role,
    string Database,
    string DatabaseOwner,
    int ServerVersionNum,
    IReadOnlyList<NotOwnedObject> NotOwned,
    bool CanCreateTables,
    bool CanCreateSchema,
    bool CanBecomeDbOwner,
    bool AdminAttributes,
    IReadOnlyList<RoleMembership> OtherMembers)
{
    /// <summary>The role owns everything it would migrate and can create tables.</summary>
    public bool IsSound => NotOwned.Count == 0 && CanCreateTables;

    /// <summary>The role cannot even read some of its own objects.</summary>
    public bool Unusable => NotOwned.Any(o => !o.Usable);
}

/// <summary>
/// The ownership rule every ModularCA database follows: the runtime login role owns every object
/// in schema <c>public</c> of its own database, so the control role can apply migrations with
/// nothing but the <c>db.yaml</c> credentials. Reads the catalog as that role, and prints the
/// one repair when it does not hold.
/// </summary>
public static class SchemaOwnership
{
    /// <summary>Where the Linux packages install the repair script, root-owned.</summary>
    public const string LinuxRepairScriptPath = "/usr/share/modularca/sql/adopt-ownership.sql";

    /// <summary>The embedded copy of the repair script.</summary>
    public const string RepairScriptResource = "ModularCA.Database.Sql.adopt-ownership.sql";

    private const int ObjectsListed = 10;

    private const string NotOwnedSql = """
        SELECT c.oid::regclass::text, c.relkind::text, pg_get_userbyid(c.relowner),
               CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'USAGE') ELSE has_table_privilege(c.oid, 'SELECT') END
          FROM pg_catalog.pg_class c
         WHERE c.relnamespace = 'public'::regnamespace
           AND c.relkind IN ('r','p','v','m','f','S')
           AND NOT pg_has_role(current_user, c.relowner, 'USAGE')
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
        UNION ALL
        SELECT p.oid::regprocedure::text, 'function', pg_get_userbyid(p.proowner), has_function_privilege(p.oid, 'EXECUTE')
          FROM pg_catalog.pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace
           AND NOT pg_has_role(current_user, p.proowner, 'USAGE')
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
        UNION ALL
        SELECT t.oid::regtype::text, 'type', pg_get_userbyid(t.typowner), has_type_privilege(t.oid, 'USAGE')
          FROM pg_catalog.pg_type t
         WHERE t.typnamespace = 'public'::regnamespace
           AND t.typtype IN ('d','e','r','m')
           AND NOT pg_has_role(current_user, t.typowner, 'USAGE')
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e')
         ORDER BY 1
        """;

    private const string StandingSql = """
        SELECT current_user::text,
               current_database()::text,
               pg_get_userbyid(d.datdba),
               current_setting('server_version_num')::int,
               has_schema_privilege('public', 'CREATE'),
               has_database_privilege(current_database(), 'CREATE'),
               pg_has_role(current_user, d.datdba, 'MEMBER'),
               (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
          FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles r ON r.rolname = current_user
         WHERE d.datname = current_database()
        """;

    private const string MembersSql = """
        SELECT m.rolname::text, g.rolname::text
          FROM pg_catalog.pg_auth_members am
          JOIN pg_catalog.pg_roles g ON g.oid = am.roleid
          JOIN pg_catalog.pg_roles m ON m.oid = am.member
         WHERE (g.rolname = current_user
                OR g.rolname = current_user || '_owner'
                OR g.oid = (SELECT datdba FROM pg_catalog.pg_database WHERE datname = current_database()))
           AND m.rolname <> current_user
           AND NOT m.rolsuper
         GROUP BY 1, 2
         ORDER BY 2, 1
        """;

    /// <summary>
    /// Reads the ownership report for the database <paramref name="connection"/> is attached to,
    /// as the role it logged in with. Reads only <c>pg_catalog</c> and locks no user table, so
    /// it neither needs a privilege on the schema nor waits behind a migration. Opens the
    /// connection when it is closed, wrapping a failure to open it in
    /// <see cref="SchemaConnectException"/>, and closes it again.
    /// </summary>
    /// <param name="connection">A PostgreSQL connection as the runtime role.</param>
    /// <param name="kind">Which database it is.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<OwnershipReport> ProbeAsync(DbConnection connection, DatabaseKind kind, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var opened = false;
        if (connection.State != ConnectionState.Open)
        {
            try
            {
                await connection.OpenAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new SchemaConnectException(ex);
            }
            opened = true;
        }
        try
        {
            var notOwned = new List<NotOwnedObject>();
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = NotOwnedSql;
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    notOwned.Add(new NotOwnedObject(reader.GetString(0), reader.GetString(1), reader.GetString(2),
                        !reader.IsDBNull(3) && reader.GetBoolean(3)));
            }

            var members = new List<RoleMembership>();
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = MembersSql;
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    members.Add(new RoleMembership(reader.GetString(0), reader.GetString(1)));
            }

            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = StandingSql;
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                    throw new InvalidOperationException("The ownership probe found no row for the current database and role.");
                return new OwnershipReport(
                    kind,
                    Role: reader.GetString(0),
                    Database: reader.GetString(1),
                    DatabaseOwner: reader.GetString(2),
                    ServerVersionNum: reader.GetInt32(3),
                    NotOwned: notOwned,
                    CanCreateTables: reader.GetBoolean(4),
                    CanCreateSchema: reader.GetBoolean(5),
                    CanBecomeDbOwner: reader.GetBoolean(6),
                    AdminAttributes: reader.GetBoolean(7),
                    OtherMembers: members);
            }
        }
        finally
        {
            if (opened)
                await connection.CloseAsync();
        }
    }

    /// <summary><c>app</c> or <c>audit</c>, the value the repair script's <c>kind</c> variable takes.</summary>
    public static string ScriptKind(DatabaseKind kind) => kind == DatabaseKind.Application ? "app" : "audit";

    /// <summary>
    /// The repair script's path on this platform: the root-owned copy under
    /// <c>/usr/share/modularca</c> on Linux, the copy beside the binary elsewhere.
    /// </summary>
    public static string RepairScriptPath() => OperatingSystem.IsWindows()
        ? Path.Combine(AppContext.BaseDirectory, "sql", "adopt-ownership.sql")
        : LinuxRepairScriptPath;

    /// <summary>
    /// The exact command that hands <paramref name="database"/>'s objects to
    /// <paramref name="role"/>, run as the PostgreSQL superuser on the database host.
    /// </summary>
    /// <param name="kind">Which database.</param>
    /// <param name="database">The database name.</param>
    /// <param name="role">The runtime role from <c>db.yaml</c>.</param>
    /// <param name="port">The server port; named only when it is not 5432.</param>
    public static string RepairCommand(DatabaseKind kind, string database, string role, int? port = null)
    {
        var portArg = port is > 0 and not 5432 ? $" -p {port}" : "";
        var script = RepairScriptPath();
        return OperatingSystem.IsWindows()
            ? $"psql -X -U postgres{portArg} -d \"{database}\" -v kind={ScriptKind(kind)} -v target=\"{role}\" -f \"{script}\""
            : $"sudo -u postgres psql -X{portArg} -d {ShellQuote(database)} -v kind={ScriptKind(kind)} -v target={ShellQuote(role)} -f {script}";
    }

    /// <summary>
    /// Why the control role refuses to migrate a database whose objects its runtime role does not
    /// own, or why any role refuses one it cannot read, with the repair.
    /// </summary>
    /// <param name="report">The ownership report.</param>
    /// <param name="pendingIds">The migrations that would have been applied, or null when unknown.</param>
    /// <param name="port">The server port, for the repair command.</param>
    public static string RefusalMessage(OwnershipReport report, IReadOnlyList<string>? pendingIds, int? port = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        var context = report.Kind == DatabaseKind.Application ? "application" : "audit";
        var parts = new List<string>();
        if (report.NotOwned.Count > 0)
        {
            var listed = string.Join(", ", report.NotOwned.Take(ObjectsListed).Select(o => $"{o.Object} (owner {o.Owner})"));
            var more = report.NotOwned.Count > ObjectsListed ? $" and {report.NotOwned.Count - ObjectsListed} more" : "";
            parts.Add($"The {context} database '{report.Database}' has {report.NotOwned.Count} object(s) its runtime role "
                + $"'{report.Role}' does not own: {listed}{more}.");
            var unusable = report.NotOwned.Count(o => !o.Usable);
            if (unusable > 0)
                parts.Add($"The role cannot even read {unusable} of them.");
        }
        if (!report.CanCreateTables)
            parts.Add($"Role '{report.Role}' cannot create tables in schema public of '{report.Database}'; "
                + $"as the database owner run: GRANT USAGE, CREATE ON SCHEMA public TO {Quote(report.Role)};");
        if (pendingIds is { Count: > 0 })
            parts.Add($"Pending migration(s): {string.Join(", ", pendingIds)}. Migrations run as '{report.Role}' and must own what they alter.");
        parts.Add("Nothing was applied to either database.");
        if (report.NotOwned.Count > 0)
            parts.Add("Repair once on the database host as the PostgreSQL superuser, with every ModularCA unit stopped: "
                + RepairCommand(report.Kind, report.Database, report.Role, port));
        return string.Join(" ", parts);
    }

    /// <summary>
    /// The warning for a database that breaks the ownership rule while nothing is pending: it
    /// starts now, and the next release that carries a migration will refuse until it is repaired.
    /// </summary>
    /// <param name="report">An ownership report that is not sound.</param>
    /// <param name="port">The server port, for the repair command.</param>
    public static string DriftWarning(OwnershipReport report, int? port = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        var context = report.Kind == DatabaseKind.Application ? "application" : "audit";
        var what = report.NotOwned.Count > 0
            ? $"has {report.NotOwned.Count} object(s) its runtime role '{report.Role}' does not own (e.g. "
                + $"{string.Join(", ", report.NotOwned.Take(3).Select(o => $"{o.Object} owned by {o.Owner}"))})"
            : $"does not let its runtime role '{report.Role}' create tables in schema public";
        var repair = report.NotOwned.Count > 0
            ? RepairCommand(report.Kind, report.Database, report.Role, port) + " (with every ModularCA unit stopped)"
            : $"as the database owner run: GRANT USAGE, CREATE ON SCHEMA public TO {Quote(report.Role)};";
        return $"The {context} database '{report.Database}' {what}. It starts, but the next release that carries a "
            + $"migration will refuse to start until this is repaired: {repair}";
    }

    /// <summary>
    /// Standing problems that do not stop a start but weaken what the ownership rule protects,
    /// each with the statement that fixes it: administrative attributes on the runtime role; any
    /// other non-superuser role that is a member of the runtime role, of the database owner or of
    /// <c>&lt;role&gt;_owner</c>, with the exact REVOKE and the advice to drop or NOLOGIN a
    /// leftover administrative role; and, for the audit database, a runtime role that could drop
    /// it or create schemas in it.
    /// </summary>
    /// <param name="report">The ownership report.</param>
    public static IReadOnlyList<string> Warnings(OwnershipReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var warnings = new List<string>();
        var role = Quote(report.Role);
        var context = report.Kind == DatabaseKind.Application ? "application" : "audit";
        if (report.AdminAttributes)
            warnings.Add($"Runtime role '{report.Role}' holds an administrative attribute. As a superuser run: "
                + $"ALTER ROLE {role} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;");
        foreach (var m in report.OtherMembers)
        {
            if (m.Member == report.Role)
                continue;
            var what = m.Role == report.DatabaseOwner && report.Kind == DatabaseKind.Audit
                ? "which owns the audit database, and could drop it"
                : m.Role == report.Role
                    ? $"the runtime role of the {context} database, and could alter or drop its tables"
                    : "and could act as it";
            warnings.Add($"Role '{m.Member}' is a member of '{m.Role}', {what}. As a superuser run: "
                + $"REVOKE {Quote(m.Role)} FROM {Quote(m.Member)}; If '{m.Member}' is a leftover administrative role "
                + $"(such as a migration account), drop it (DROP ROLE {Quote(m.Member)};) or stop it logging in "
                + $"(ALTER ROLE {Quote(m.Member)} NOLOGIN;).");
        }
        if (report.Kind != DatabaseKind.Audit)
            return warnings;

        if (report.CanBecomeDbOwner)
            warnings.Add(report.DatabaseOwner == report.Role
                ? $"Audit role '{report.Role}' owns the audit database '{report.Database}' and could drop it. As a superuser run: "
                    + $"CREATE ROLE {Quote(report.Role + "_owner")} NOLOGIN; ALTER DATABASE {Quote(report.Database)} OWNER TO {Quote(report.Role + "_owner")};"
                : $"Audit role '{report.Role}' is a member of '{report.DatabaseOwner}', which owns the audit database, and could drop it. "
                    + $"As a superuser run: REVOKE {Quote(report.DatabaseOwner)} FROM {role};");
        if (report.CanCreateSchema)
            warnings.Add($"Audit role '{report.Role}' can create schemas in '{report.Database}'. As a superuser run: "
                + $"REVOKE CREATE ON DATABASE {Quote(report.Database)} FROM {role}, PUBLIC;");
        return warnings;
    }

    /// <summary>The repair script as embedded in this assembly.</summary>
    public static string ReadRepairScript()
    {
        using var stream = typeof(SchemaOwnership).Assembly.GetManifestResourceStream(RepairScriptResource)
            ?? throw new InvalidOperationException($"Embedded resource {RepairScriptResource} is missing from {typeof(SchemaOwnership).Assembly.GetName().Name}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// The repair script's <c>DO</c> block alone, for callers that set <c>modularca.kind</c> and
    /// <c>modularca.target</c> with bound parameters instead of psql variables.
    /// </summary>
    public static string RepairBlock()
    {
        var script = ReadRepairScript();
        const string open = "DO $adopt$";
        const string close = "END $adopt$;";
        var start = script.IndexOf(open, StringComparison.Ordinal);
        var end = script.IndexOf(close, StringComparison.Ordinal);
        if (start < 0 || end < start)
            throw new InvalidOperationException("The embedded repair script has no DO $adopt$ block.");
        return script[start..(end + close.Length)];
    }

    /// <summary>Quotes a PostgreSQL identifier.</summary>
    private static string Quote(string identifier) => PostgresConnection.QuoteIdentifier(identifier);

    /// <summary>Quotes a value for a POSIX shell.</summary>
    private static string ShellQuote(string value) => "'" + value.Replace("'", "'\\''") + "'";
}
