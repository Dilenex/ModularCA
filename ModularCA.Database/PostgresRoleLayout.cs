using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database.Conventions;
using ModularCA.Shared.Utils;
using Npgsql;

namespace ModularCA.Database;

/// <summary>The names the provisioning SQL uses.</summary>
/// <param name="AdminRole">SqlRoot: the superuser bootstrap connects as.</param>
/// <param name="AppRole">db.yaml App.Username.</param>
/// <param name="AuditRole">db.yaml Audit.Username.</param>
/// <param name="AppDatabase">db.yaml App.Database.</param>
/// <param name="AuditDatabase">db.yaml Audit.Database.</param>
public sealed record PostgresLayoutNames(
    string AdminRole, string AppRole, string AuditRole, string AppDatabase, string AuditDatabase)
{
    /// <summary>The suffix of the audit database's owner role, as ModularCA.Migrate derives it.</summary>
    public const string OwnerSuffix = "_owner";

    /// <summary>The NOLOGIN role that owns the audit database.</summary>
    public string AuditOwnerRole => AuditRole + OwnerSuffix;
}

/// <summary>A role that already exists in the cluster.</summary>
public sealed record ExistingRole(
    string Name, bool CanLogin, bool Superuser, bool CreateDb, bool CreateRole, bool Replication, bool BypassRls,
    IReadOnlyList<string> MemberOf)
{
    /// <summary>SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS.</summary>
    public bool HasAdminAttributes => Superuser || CreateDb || CreateRole || Replication || BypassRls;
}

/// <summary>What <see cref="PostgresRoleLayout.ProbeAsync"/> read from the cluster, without changing anything.</summary>
/// <param name="AdminRole">The role the probe connected as.</param>
/// <param name="IsSuperuser">Whether it is a superuser.</param>
/// <param name="ServerVersionNum">The server's <c>server_version_num</c>.</param>
/// <param name="AppDatabaseExists">Whether the application database exists.</param>
/// <param name="AuditDatabaseExists">Whether the audit database exists.</param>
/// <param name="AuditDatabaseOwner">The audit database's owner, when it exists.</param>
/// <param name="AuditState">
/// The audit database's presence and history, when it exists and the administrator is a
/// superuser; not read otherwise.
/// </param>
/// <param name="Roles">The app, audit and audit-owner roles that exist, by name.</param>
/// <param name="AuditNotAdoptable">
/// Objects in the audit database's schema <c>public</c> that the takeover of a preserved audit
/// database would not hand to the audit role (owned by an ordinary role, or a function or type),
/// when it was read; null otherwise.
/// </param>
public sealed record ClusterFacts(
    string AdminRole,
    bool IsSuperuser,
    int ServerVersionNum,
    bool AppDatabaseExists,
    bool AuditDatabaseExists,
    string? AuditDatabaseOwner,
    SchemaState? AuditState,
    IReadOnlyDictionary<string, ExistingRole> Roles,
    IReadOnlyList<NotOwnedObject>? AuditNotAdoptable = null);

/// <summary>What provisioning may destroy.</summary>
/// <param name="ResetApp">Drop and recreate the application database. Required when it exists.</param>
/// <param name="WipeAudit">Drop and recreate the audit database instead of preserving it.</param>
public sealed record ProvisioningMode(bool ResetApp, bool WipeAudit);

/// <summary>One statement batch of the provisioning plan.</summary>
/// <param name="Database">The database to run it in, or null for the maintenance database.</param>
/// <param name="Sql">The statements.</param>
/// <param name="Description">What it does, for progress output. Never contains a password.</param>
/// <param name="AssertDatabaseAbsent">A database that must not exist once the step has run.</param>
/// <param name="Parameters">Bound parameters, by name.</param>
public sealed record ProvisioningStep(
    string? Database,
    string Sql,
    string Description,
    string? AssertDatabaseAbsent = null,
    IReadOnlyDictionary<string, string>? Parameters = null);

/// <summary>Provisioning refused before any DDL ran.</summary>
public sealed class PostgresLayoutRefusedException : InvalidOperationException
{
    /// <summary>Creates the exception for <paramref name="reasons"/>.</summary>
    public PostgresLayoutRefusedException(IReadOnlyList<string> reasons)
        : base("PostgreSQL provisioning refused before any change was made: " + string.Join(" ", reasons))
    {
        Reasons = reasons;
    }

    /// <summary>Every reason, each a sentence.</summary>
    public IReadOnlyList<string> Reasons { get; }
}

/// <summary>
/// The single source of the SQL that lays out the two ModularCA databases: the application
/// database owned by the app role, the audit database owned by a NOLOGIN
/// <c>&lt;audit&gt;_owner</c> role with the audit role owning its tables, PUBLIC access revoked.
/// Runs as a PostgreSQL superuser only. Creates no table: the schema is applied afterwards as
/// the runtime roles, by <see cref="SchemaVersionGate.ApplyAllForBootstrapAsync"/>.
/// </summary>
public static class PostgresRoleLayout
{
    /// <summary>PostgreSQL 14, the oldest server this release supports.</summary>
    public const int MinimumServerVersionNum = 140000;

    /// <summary>The audit context's frozen baseline, which a preserved audit database must record.</summary>
    public const string AuditBaselineMigration = "20260919181510_InitialAuditSchema";

    /// <summary>The longest identifier PostgreSQL keeps without truncating, in bytes.</summary>
    public const int MaxIdentifierBytes = 63;

    private const int ObjectsListed = 10;

    private static readonly Regex SafeIdentifier = new(@"^[A-Za-z0-9_\-]+$", RegexOptions.CultureInvariant);

    private const string NotAdoptableSql = """
        SELECT c.oid::regclass::text, c.relkind::text, pg_catalog.pg_get_userbyid(c.relowner)
          FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles w ON w.oid = c.relowner
         WHERE c.relnamespace = 'public'::regnamespace
           AND c.relkind IN ('r','p','v','m','f','S')
           AND w.rolname <> @u AND w.rolname <> @o
           AND NOT (w.rolsuper OR w.rolcreatedb OR w.rolcreaterole)
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles t WHERE t.rolname = @u AND pg_catalog.pg_has_role(t.oid, c.relowner, 'USAGE'))
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid
                              AND (d.deptype = 'e' OR (c.relkind = 'S' AND d.deptype IN ('a','i'))))
        UNION ALL
        SELECT p.oid::regprocedure::text, 'function', pg_catalog.pg_get_userbyid(p.proowner)
          FROM pg_catalog.pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles t WHERE t.rolname = @u AND pg_catalog.pg_has_role(t.oid, p.proowner, 'USAGE'))
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
        UNION ALL
        SELECT ty.oid::regtype::text, 'type', pg_catalog.pg_get_userbyid(ty.typowner)
          FROM pg_catalog.pg_type ty
         WHERE ty.typnamespace = 'public'::regnamespace
           AND ty.typtype IN ('d','e','r','m')
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles t WHERE t.rolname = @u AND pg_catalog.pg_has_role(t.oid, ty.typowner, 'USAGE'))
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_type'::regclass AND d.objid = ty.oid AND d.deptype = 'e')
         ORDER BY 1
        """;

    /// <summary>
    /// Why the names cannot be used: characters outside letters, digits, underscore and hyphen,
    /// more than <see cref="MaxIdentifierBytes"/> bytes, or two roles or databases that collide.
    /// Empty when they can.
    /// </summary>
    public static IReadOnlyList<string> ValidateNames(PostgresLayoutNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        var problems = new List<string>();
        foreach (var (value, label) in new[]
                 {
                     (names.AppRole, "app role"), (names.AuditRole, "audit role"),
                     (names.AuditOwnerRole, "audit database owner role"),
                     (names.AppDatabase, "app database"), (names.AuditDatabase, "audit database"),
                 })
        {
            if (string.IsNullOrEmpty(value) || !SafeIdentifier.IsMatch(value))
                problems.Add($"The {label} name '{value}' may contain only letters, digits, underscore and hyphen.");
            else if (Encoding.UTF8.GetByteCount(value) > MaxIdentifierBytes)
                problems.Add($"The {label} name '{value}' is longer than {MaxIdentifierBytes} bytes, which PostgreSQL would truncate.");
        }
        if (string.IsNullOrWhiteSpace(names.AdminRole))
            problems.Add("SqlRoot has no username.");

        var roles = new[] { (names.AdminRole, "SqlRoot"), (names.AppRole, "app role"), (names.AuditRole, "audit role"), (names.AuditOwnerRole, "audit database owner role") };
        for (var i = 0; i < roles.Length; i++)
            for (var j = i + 1; j < roles.Length; j++)
                if (string.Equals(roles[i].Item1, roles[j].Item1, StringComparison.OrdinalIgnoreCase))
                    problems.Add($"The {roles[i].Item2} and the {roles[j].Item2} are both '{roles[i].Item1}'; they must be different roles.");
        if (string.Equals(names.AppDatabase, names.AuditDatabase, StringComparison.OrdinalIgnoreCase))
            problems.Add($"The app and audit databases are both '{names.AppDatabase}'; they must be different databases.");
        return problems;
    }

    /// <summary>
    /// Reads the cluster as the administrator, read-only: whether it is a superuser (first), the
    /// server version, which databases and roles exist, and, only for a superuser, the preserved
    /// audit database's presence, history and the objects its takeover would not move. A
    /// password or <c>pg_hba.conf</c> refusal of SqlRoot's login throws
    /// <see cref="PostgresLayoutRefusedException"/>.
    /// </summary>
    /// <param name="adminConnectionString">SqlRoot's connection string, to any database; the maintenance database is used.</param>
    /// <param name="names">The layout names.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<ClusterFacts> ProbeAsync(string adminConnectionString, PostgresLayoutNames names, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(names);
        await using var conn = new NpgsqlConnection(ConnectionTo(adminConnectionString, null));
        try
        {
            await conn.OpenAsync(ct);
        }
        catch (PostgresException ex) when (LoginRefusal(ex.SqlState, names.AdminRole) is { } refusal)
        {
            throw new PostgresLayoutRefusedException([refusal]);
        }

        string admin;
        bool superuser;
        int version;
        await using (var cmd = new NpgsqlCommand(
            "SELECT current_user::text, (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user), "
            + "current_setting('server_version_num')::int", conn))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            await reader.ReadAsync(ct);
            admin = reader.GetString(0);
            superuser = !reader.IsDBNull(1) && reader.GetBoolean(1);
            version = reader.GetInt32(2);
        }

        var databases = new Dictionary<string, string>(StringComparer.Ordinal);
        await using (var cmd = new NpgsqlCommand(
            "SELECT datname::text, pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname = ANY(@names)", conn))
        {
            cmd.Parameters.AddWithValue("names", new[] { names.AppDatabase, names.AuditDatabase });
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                databases[reader.GetString(0)] = reader.GetString(1);
        }

        var roles = new Dictionary<string, ExistingRole>(StringComparer.Ordinal);
        await using (var cmd = new NpgsqlCommand("""
            SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls,
                   ARRAY(SELECT g.rolname::text FROM pg_catalog.pg_auth_members am JOIN pg_catalog.pg_roles g ON g.oid = am.roleid
                          WHERE am.member = r.oid ORDER BY 1)
              FROM pg_catalog.pg_roles r WHERE r.rolname = ANY(@names)
            """, conn))
        {
            cmd.Parameters.AddWithValue("names", new[] { names.AppRole, names.AuditRole, names.AuditOwnerRole });
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var role = new ExistingRole(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2), reader.GetBoolean(3),
                    reader.GetBoolean(4), reader.GetBoolean(5), reader.GetBoolean(6), reader.GetFieldValue<string[]>(7));
                roles[role.Name] = role;
            }
        }

        SchemaState? auditState = null;
        List<NotOwnedObject>? notAdoptable = null;
        var auditExists = databases.TryGetValue(names.AuditDatabase, out var auditOwner);
        if (auditExists && superuser)
        {
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                .UseNpgsql(ConnectionTo(adminConnectionString, names.AuditDatabase)).Options))
                auditState = await SchemaVersionGate.ReadAsync(audit, ct);

            if (auditState.Presence == DatabasePresence.Managed)
            {
                notAdoptable = [];
                await using var auditConn = new NpgsqlConnection(ConnectionTo(adminConnectionString, names.AuditDatabase));
                await auditConn.OpenAsync(ct);
                await using var cmd = new NpgsqlCommand(NotAdoptableSql, auditConn);
                cmd.Parameters.AddWithValue("u", names.AuditRole);
                cmd.Parameters.AddWithValue("o", names.AuditOwnerRole);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    notAdoptable.Add(new NotOwnedObject(reader.GetString(0), reader.GetString(1), reader.GetString(2), Usable: true));
            }
        }

        return new ClusterFacts(admin, superuser, version, databases.ContainsKey(names.AppDatabase), auditExists,
            auditOwner, auditState, roles, notAdoptable);
    }

    /// <summary>
    /// The refusal for a login PostgreSQL turned down as <paramref name="role"/>: a wrong
    /// password (28P01) or a <c>pg_hba.conf</c> rule (28000). Null for any other SQLSTATE.
    /// </summary>
    public static string? LoginRefusal(string? sqlState, string role) => sqlState switch
    {
        "28P01" => $"PostgreSQL rejected the password for SqlRoot '{role}' (28P01). Correct SqlRoot's password and try again.",
        "28000" => $"PostgreSQL refused SqlRoot '{role}' from this host (28000). Allow it in pg_hba.conf, or use a role "
            + "the server accepts from here, and try again.",
        _ => null,
    };

    /// <summary>
    /// Every reason provisioning must not start, checked before any DDL: an administrator that
    /// is not a superuser, a server older than PostgreSQL 14, unusable or colliding names,
    /// runtime roles with administrative attributes or membership of the audit owner, and a
    /// preserved audit database that is not this product's, lacks the audit baseline, is owned by
    /// the audit role, or holds objects its takeover would not move.
    /// </summary>
    public static IReadOnlyList<string> Refusals(ClusterFacts facts, PostgresLayoutNames names, ProvisioningMode mode)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(names);
        ArgumentNullException.ThrowIfNull(mode);
        var reasons = new List<string>();
        if (!facts.IsSuperuser)
            reasons.Add($"SqlRoot '{facts.AdminRole}' is not a PostgreSQL superuser. This release provisions the databases, "
                + "roles and ownership as a superuser only (for example the postgres role); SqlRoot is used during bootstrap "
                + "and its file is deleted afterwards. CREATEDB and CREATEROLE are not enough.");
        if (facts.ServerVersionNum < MinimumServerVersionNum)
            reasons.Add($"The server is PostgreSQL {facts.ServerVersionNum / 10000}; this release needs PostgreSQL 14 or later.");
        reasons.AddRange(ValidateNames(names));

        foreach (var name in new[] { names.AppRole, names.AuditRole })
        {
            if (!facts.Roles.TryGetValue(name, out var role))
                continue;
            if (role.HasAdminAttributes)
                reasons.Add($"Role '{name}' exists with SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS; a runtime "
                    + $"role must have none of them. As a superuser run: ALTER ROLE {Q(name)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;");
            if (role.MemberOf.Contains(names.AuditOwnerRole, StringComparer.Ordinal))
                reasons.Add($"Role '{name}' is a member of '{names.AuditOwnerRole}', which owns the audit database, and could drop it. "
                    + $"As a superuser run: REVOKE {Q(names.AuditOwnerRole)} FROM {Q(name)};");
        }
        if (facts.Roles.TryGetValue(names.AuditOwnerRole, out var owner) && (owner.CanLogin || owner.HasAdminAttributes))
            reasons.Add($"Role '{names.AuditOwnerRole}' exists and can log in or holds an administrative attribute; it must be a plain NOLOGIN role.");

        if (facts.AppDatabaseExists && !mode.ResetApp)
            reasons.Add($"The application database '{names.AppDatabase}' exists and a reset was not requested.");

        if (facts.AuditDatabaseExists && !mode.WipeAudit)
        {
            if (string.Equals(facts.AuditDatabaseOwner, names.AuditRole, StringComparison.Ordinal))
                reasons.Add($"The audit database '{names.AuditDatabase}' is owned by the audit role '{names.AuditRole}', which could "
                    + "have dropped or rewritten it. Restore it from a dump, or wipe it deliberately with --wipe-audit.");
            if (facts.AuditState is { } audit)
            {
                var verdict = SchemaVersionGate.Evaluate(audit, appliesMigrations: true);
                if (verdict is SchemaVerdict.Unmanaged or SchemaVerdict.NewerThanBuild)
                    reasons.Add(SchemaVersionGate.RefusalMessage(verdict, audit, "audit")
                        + " Or wipe it deliberately with --wipe-audit.");
                if (audit.Presence == DatabasePresence.Managed && !audit.Applied.Contains(AuditBaselineMigration, StringComparer.Ordinal))
                    reasons.Add($"The audit database '{names.AuditDatabase}' records migrations but not the baseline "
                        + $"{AuditBaselineMigration}, so it is not a ModularCA audit database bootstrap can take over. "
                        + "Restore it from a dump, or wipe it deliberately with --wipe-audit.");
            }
            if (facts.AuditNotAdoptable is { Count: > 0 } stray)
            {
                var listed = string.Join(", ", stray.Take(ObjectsListed).Select(o => $"{o.Object} ({o.Kind}, owner {o.Owner})"));
                var more = stray.Count > ObjectsListed ? $" and {stray.Count - ObjectsListed} more" : "";
                reasons.Add($"The audit database '{names.AuditDatabase}' has {stray.Count} object(s) that bootstrap would not hand "
                    + $"to the audit role '{names.AuditRole}': {listed}{more}. Only tables, views and sequences an administrator "
                    + $"created are moved. As a superuser, in '{names.AuditDatabase}', give each to {Q(names.AuditRole)} "
                    + "(ALTER TABLE|SEQUENCE|FUNCTION|TYPE ... OWNER TO), or drop it, then run bootstrap again; "
                    + "or wipe the audit database deliberately with --wipe-audit.");
            }
        }
        return reasons;
    }

    /// <summary>
    /// The provisioning statements for <paramref name="facts"/>, in order. Pure: nothing runs.
    /// Roles that do not exist are created first; the destructive DROP DATABASE steps come next,
    /// and only after them are the passwords of roles that already existed rotated, so a drop
    /// that fails leaves the credentials in <c>db.yaml</c> working. Schema <c>public</c> of each
    /// database is handed to its owner and PUBLIC's CREATE removed by a block that decides from
    /// the catalog when it runs, not from the server version, so a database upgraded from
    /// PostgreSQL 14 is covered too. Built from the same statement builders ModularCA.Migrate
    /// uses, so both paths emit the same SQL.
    /// </summary>
    public static IReadOnlyList<ProvisioningStep> Plan(
        ClusterFacts facts, PostgresLayoutNames names, ProvisioningMode mode, string appPassword, string auditPassword)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(names);
        ArgumentNullException.ThrowIfNull(mode);
        var da = Q(names.AppDatabase);
        var du = Q(names.AuditDatabase);
        var logins = new[] { (names.AppRole, appPassword), (names.AuditRole, auditPassword) };
        var steps = new List<ProvisioningStep>();
        foreach (var (role, password) in logins.Where(l => !facts.Roles.ContainsKey(l.Item1)))
            steps.Add(new(null, LoginRoleSql(role, password, exists: false), $"role '{role}' created"));
        if (!facts.Roles.ContainsKey(names.AuditOwnerRole))
            steps.Add(new(null, OwnerRoleSql(names.AuditOwnerRole), $"role '{names.AuditOwnerRole}' created (no login; it owns the audit database)"));

        if (mode.ResetApp)
            steps.Add(new(null, $"DROP DATABASE IF EXISTS {da} WITH (FORCE)", $"database '{names.AppDatabase}' dropped",
                AssertDatabaseAbsent: names.AppDatabase));
        if (facts.AuditDatabaseExists && mode.WipeAudit)
            steps.Add(new(null, $"DROP DATABASE IF EXISTS {du} WITH (FORCE)", $"database '{names.AuditDatabase}' dropped (--wipe-audit)",
                AssertDatabaseAbsent: names.AuditDatabase));
        foreach (var (role, password) in logins.Where(l => facts.Roles.ContainsKey(l.Item1)))
            steps.Add(new(null, LoginRoleSql(role, password, exists: true), $"role '{role}' existed; password rotated"));

        steps.Add(new(null, CreateDatabaseSql(names.AppDatabase, names.AppRole),
            $"database '{names.AppDatabase}' created, owned by '{names.AppRole}'"));

        var preserveAudit = facts.AuditDatabaseExists && !mode.WipeAudit;
        steps.Add(preserveAudit
            ? new(null, $"ALTER DATABASE {du} OWNER TO {Q(names.AuditOwnerRole)}", $"database '{names.AuditDatabase}' preserved, now owned by '{names.AuditOwnerRole}'")
            : new(null, CreateDatabaseSql(names.AuditDatabase, names.AuditOwnerRole),
                $"database '{names.AuditDatabase}' created, owned by '{names.AuditOwnerRole}'"));

        steps.Add(new(null, RevokePublicSql(names.AppDatabase), $"PUBLIC access to '{names.AppDatabase}' revoked"));
        steps.Add(new(null, RevokePublicSql(names.AuditDatabase), $"PUBLIC access to '{names.AuditDatabase}' revoked"));
        steps.Add(new(null, AuditConnectSql(names), $"'{names.AuditRole}' may connect to '{names.AuditDatabase}'"));

        steps.Add(new(names.AppDatabase, PublicSchemaSql(names.AppRole),
            $"schema public of '{names.AppDatabase}' owned by '{names.AppRole}' or the database owner, PUBLIC may not create in it"));
        steps.Add(new(names.AppDatabase, AsRole(names.AppRole, [ExtensionSql]),
            $"{TextCaseSensitivity.Extension} extension present in '{names.AppDatabase}', owned by '{names.AppRole}'"));

        steps.Add(new(names.AuditDatabase, PublicSchemaSql(names.AuditOwnerRole),
            $"schema public of '{names.AuditDatabase}' owned by '{names.AuditOwnerRole}' or the database owner, PUBLIC may not create in it"));
        steps.Add(new(names.AuditDatabase, AsRole(names.AuditOwnerRole, AuditSchemaGrantSql(names)),
            $"'{names.AuditRole}' may create its tables in '{names.AuditDatabase}'"));

        if (preserveAudit && facts.AuditState?.Presence == DatabasePresence.Managed)
            steps.Add(new(names.AuditDatabase,
                "SET lock_timeout = '10s'; SELECT set_config('modularca.kind', @kind, false), set_config('modularca.target', @target, false); "
                + SchemaOwnership.RepairBlock(),
                $"preserved audit tables in '{names.AuditDatabase}' handed to '{names.AuditRole}'",
                Parameters: new Dictionary<string, string> { ["kind"] = "audit", ["target"] = names.AuditRole }));
        else if (preserveAudit)
            steps.Add(new(names.AuditDatabase, $"ALTER TABLE IF EXISTS public.\"__EFMigrationsHistory\" OWNER TO {Q(names.AuditRole)}",
                $"empty audit history in '{names.AuditDatabase}' handed to '{names.AuditRole}'"));
        return steps;
    }

    /// <summary>
    /// Probes, refuses on any <see cref="Refusals"/> before a single statement changes anything,
    /// then runs <see cref="Plan"/> fail-fast: nothing is caught, and each dropped database is
    /// confirmed gone before the next step. Returns the passwords it set on the two runtime
    /// roles.
    /// </summary>
    /// <param name="adminConnectionString">SqlRoot's connection string.</param>
    /// <param name="names">The layout names.</param>
    /// <param name="mode">What may be destroyed.</param>
    /// <param name="say">Progress output; never receives a password.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<(string AppPassword, string AuditPassword)> ProvisionAsync(
        string adminConnectionString, PostgresLayoutNames names, ProvisioningMode mode,
        Action<string>? say = null, CancellationToken ct = default)
    {
        var nameProblems = ValidateNames(names);
        if (nameProblems.Count > 0)
            throw new PostgresLayoutRefusedException(nameProblems);
        var facts = await ProbeAsync(adminConnectionString, names, ct);
        var reasons = Refusals(facts, names, mode);
        if (reasons.Count > 0)
            throw new PostgresLayoutRefusedException(reasons);

        var appPassword = GeneratePassword();
        var auditPassword = GeneratePassword();
        foreach (var step in Plan(facts, names, mode, appPassword, auditPassword))
        {
            await using var conn = new NpgsqlConnection(ConnectionTo(adminConnectionString, step.Database));
            await conn.OpenAsync(ct);
            await using (var cmd = new NpgsqlCommand(step.Sql, conn))
            {
                foreach (var (name, value) in step.Parameters ?? new Dictionary<string, string>())
                    cmd.Parameters.AddWithValue(name, value);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            if (step.AssertDatabaseAbsent is { } gone)
            {
                await using var check = new NpgsqlCommand("SELECT 1 FROM pg_catalog.pg_database WHERE datname = @n", conn);
                check.Parameters.AddWithValue("n", gone);
                if (await check.ExecuteScalarAsync(ct) is not null)
                    throw new InvalidOperationException($"Database '{gone}' still exists after DROP DATABASE; provisioning stopped.");
            }
            say?.Invoke(step.Description);
        }
        return (appPassword, auditPassword);
    }

    /// <summary>A random 256-bit password in URL-safe base64, safe inside a quoted literal.</summary>
    public static string GeneratePassword() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace("+", "-").Replace("/", "_").TrimEnd('=');

    /// <summary>The <c>citext</c> extension, created as the app role in the application database.</summary>
    public static string ExtensionSql { get; } = $"CREATE EXTENSION IF NOT EXISTS {TextCaseSensitivity.Extension}";

    /// <summary>
    /// <c>CREATE ROLE</c>, or <c>ALTER ROLE</c> when <paramref name="exists"/>, as a login role
    /// with <paramref name="password"/> and no other attribute.
    /// </summary>
    public static string LoginRoleSql(string role, string password, bool exists) =>
        $"{(exists ? "ALTER" : "CREATE")} ROLE {Q(role)} WITH LOGIN PASSWORD {PostgresConnection.QuoteLiteral(password)}";

    /// <summary>The NOLOGIN role that owns the audit database.</summary>
    public static string OwnerRoleSql(string role) => $"CREATE ROLE {Q(role)} WITH NOLOGIN";

    /// <summary><c>CREATE DATABASE</c> owned by <paramref name="owner"/>, UTF8 from <c>template0</c>.</summary>
    public static string CreateDatabaseSql(string database, string owner) =>
        $"CREATE DATABASE {Q(database)} OWNER {Q(owner)} ENCODING 'UTF8' TEMPLATE template0";

    /// <summary>Removes PUBLIC's default CONNECT and TEMPORARY on <paramref name="database"/>. Run by its owner or a superuser.</summary>
    public static string RevokePublicSql(string database) => $"REVOKE ALL ON DATABASE {Q(database)} FROM PUBLIC";

    /// <summary>The audit role's explicit CONNECT on the audit database. Run by its owner or a superuser.</summary>
    public static string AuditConnectSql(PostgresLayoutNames names) =>
        $"GRANT CONNECT ON DATABASE {Q(names.AuditDatabase)} TO {Q(names.AuditRole)}";

    /// <summary>
    /// A block, run as a superuser in one database, that decides from that database's catalog:
    /// schema <c>public</c> is handed to <paramref name="owner"/> unless <c>pg_database_owner</c>
    /// or that role already owns it, and PUBLIC's CREATE on it is revoked when PUBLIC holds it.
    /// Does nothing on a PostgreSQL 15 default layout; covers a PostgreSQL 14 database, and one
    /// pg_upgraded from 14, whose schema public the bootstrap superuser still owns.
    /// </summary>
    public static string PublicSchemaSql(string owner) =>
        "DO $public$ DECLARE n pg_catalog.pg_namespace%ROWTYPE; BEGIN "
        + "SELECT * INTO n FROM pg_catalog.pg_namespace WHERE nspname = 'public'; "
        + "IF NOT FOUND THEN RETURN; END IF; "
        + "IF (n.nspowner::regrole IN (pg_catalog.to_regrole('pg_database_owner'), "
        + $"pg_catalog.to_regrole({PostgresConnection.QuoteLiteral(Q(owner))}))) IS NOT TRUE THEN "
        + $"ALTER SCHEMA public OWNER TO {Q(owner)}; END IF; "
        + "IF EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a "
        + "WHERE a.grantee = 0 AND a.privilege_type = 'CREATE') THEN REVOKE CREATE ON SCHEMA public FROM PUBLIC; END IF; "
        + "END $public$";

    /// <summary>
    /// What the audit database's owner grants the audit role in schema <c>public</c>: USAGE and
    /// CREATE so it applies its own migrations, default DML rights on what the owner creates, and
    /// no CREATE for PUBLIC. Run as the owner, in the audit database.
    /// </summary>
    public static IReadOnlyList<string> AuditSchemaGrantSql(PostgresLayoutNames names)
    {
        var u = Q(names.AuditRole);
        return
        [
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
            $"GRANT USAGE, CREATE ON SCHEMA public TO {u}",
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {u}",
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {u}",
        ];
    }

    /// <summary><paramref name="statements"/> as one batch run under <c>SET ROLE</c> <paramref name="role"/>, so the role owns or grants what they create.</summary>
    public static string AsRole(string role, IEnumerable<string> statements) =>
        $"SET ROLE {Q(role)}; {string.Join("; ", statements)}; RESET ROLE";

    /// <summary><paramref name="connectionString"/> pointed at <paramref name="database"/> (the maintenance database when null), unpooled.</summary>
    private static string ConnectionTo(string connectionString, string? database) =>
        new NpgsqlConnectionStringBuilder(connectionString)
        {
            Database = database ?? PostgresConnection.MaintenanceDatabase,
            Pooling = false,
        }.ConnectionString;

    /// <summary>Quotes a PostgreSQL identifier.</summary>
    private static string Q(string identifier) => PostgresConnection.QuoteIdentifier(identifier);
}
