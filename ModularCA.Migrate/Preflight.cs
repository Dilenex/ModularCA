using MySqlConnector;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// Everything that is checked before anything is created, and the reason the helper can be safely
/// re-run: until preflight passes, nothing outside the operator's terminal has changed.
/// <para>
/// The rule on the destination is <em>the target databases and roles must not exist</em>, not
/// "the server must be empty". Nobody dedicates a PostgreSQL cluster to one application, so
/// demanding an empty server would refuse almost every real deployment. Demanding absence rather
/// than emptiness buys two things an empty-but-present database cannot: the helper creates them
/// and therefore controls their encoding and collation — which matters directly, because
/// <c>citext</c> folds case through a locale-dependent <c>lower()</c> and the model's case rules
/// are only true if the database agrees — and a failed run can drop what it made, because it knows
/// it made it.
/// </para>
/// <para>
/// Roles are the part a database-name check misses. A PostgreSQL role is cluster-wide, so on a
/// shared server the target databases can be absent while a role of the same name already belongs
/// to something else entirely. Rotating that role's password, which is what bootstrap does to an
/// existing role, would quietly break a neighbour. So roles are checked by the same rule.
/// </para>
/// </summary>
public sealed class Preflight
{
    /// <summary>
    /// The oldest PostgreSQL this helper targets: the product's supported minimum, 14. 13 is where
    /// <c>citext</c> became a trusted extension, so a database owner can create it without being a
    /// superuser, and where <c>DROP DATABASE ... WITH (FORCE)</c> arrived, which is what makes the
    /// failure path able to clean up after itself; 14 is the oldest release the node supports.
    /// </summary>
    public const int MinimumServerVersionNum = ModularCA.Database.PostgresRoleLayout.MinimumServerVersionNum;

    /// <summary>
    /// The last migration a 0.3.0 MariaDB schema has applied, and the only schema this helper
    /// understands.
    /// <para>
    /// This is the source's final migration, not the destination's. An earlier version compared
    /// against <c>InitialCreate</c>, which is the name of the single migration 0.3.1 generates for
    /// PostgreSQL — so a correct 0.3.0 database was told to go and upgrade to 0.3.0.
    /// </para>
    /// </summary>
    public const string SupportedSourceMigration = "20260918103422_LinkScepTransactionToRequest";

    private readonly MigrationOptions _options;
    private readonly List<string> _refusals = [];
    private readonly List<string> _notes = [];

    /// <summary>Creates a preflight for the given options.</summary>
    /// <param name="options">The parsed command line.</param>
    public Preflight(MigrationOptions options) => _options = options;

    /// <summary>Everything that must be fixed before the helper will run.</summary>
    public IReadOnlyList<string> Refusals => _refusals;

    /// <summary>Things worth saying that are not refusals.</summary>
    public IReadOnlyList<string> Notes => _notes;

    /// <summary>
    /// Runs every check. Collects all refusals rather than stopping at the first, so an operator
    /// fixes one set of problems instead of discovering them one run at a time.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True when nothing refused.</returns>
    public async Task<bool> RunAsync(CancellationToken ct)
    {
        await CheckSourceAsync(ct);
        await CheckTargetAsync(ct);
        return _refusals.Count == 0;
    }

    // ── Source ────────────────────────────────────────────────────────────────

    private async Task CheckSourceAsync(CancellationToken ct)
    {
        await using var conn = new MySqlConnection(_options.SourceConnectionString(_options.SourceAppDatabase));
        try
        {
            await conn.OpenAsync(ct);
        }
        catch (Exception ex)
        {
            _refusals.Add($"Cannot connect to the source database: {ex.Message}");
            return;
        }

        // Identify the engine rather than trusting the port. A PostgreSQL server reached on 3306
        // would have failed the handshake above, but a MySQL that is not MariaDB would not, and
        // the schema this helper understands was only ever produced against MariaDB.
        var version = await ScalarAsync<string>(conn, "SELECT VERSION()", ct) ?? "";
        _notes.Add($"Source engine: {version}");
        if (version.IndexOf("mariadb", StringComparison.OrdinalIgnoreCase) < 0)
            _refusals.Add(
                $"The source reports '{version}', which is not MariaDB. This helper reads the schema a "
                + "0.3.0 ModularCA deployment produced on MariaDB and nothing else.");

        // The schema version. The narrow upgrade path is what makes this a script rather than a
        // product: it has exactly one schema to understand, so it checks for exactly one.
        var applied = await ScalarAsync<string>(conn,
            "SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId DESC LIMIT 1", ct);
        if (applied is null)
        {
            _refusals.Add(
                $"'{_options.SourceAppDatabase}' has no __EFMigrationsHistory table, so it is not a "
                + "ModularCA application database.");
        }
        else if (!string.Equals(applied, SupportedSourceMigration, StringComparison.Ordinal))
        {
            _refusals.Add(
                $"The source schema is at '{applied}'. This helper migrates a 0.3.0 database, whose last "
                + $"migration is '{SupportedSourceMigration}'. Upgrade the deployment to 0.3.0 on MariaDB "
                + "first — that is step one of the supported path.");
        }
        else
        {
            _notes.Add($"Source schema: {applied}");
        }

        await CheckLiveCmpTokensAsync(conn, ct);
        await CheckTenantHostnamesAsync(conn, ct);
        await CheckCaseCollisionsAsync(conn, ct);

        await using var auditConn = new MySqlConnection(_options.SourceConnectionString(_options.SourceAuditDatabase));
        try
        {
            await auditConn.OpenAsync(ct);
            var rows = await ScalarAsync<long>(auditConn, "SELECT COUNT(*) FROM AuditLogs", ct);
            _notes.Add($"Source audit: {rows:N0} rows in AuditLogs");
        }
        catch (Exception ex)
        {
            _refusals.Add($"Cannot read the source audit database '{_options.SourceAuditDatabase}': {ex.Message}");
        }
    }

    /// <summary>
    /// Refuses while any CMP enrollment token is still live.
    /// <para>
    /// On 0.3.0 the <c>Token</c> column held the token itself, and for a CMP row that value
    /// <em>is</em> the PBMAC shared secret. On 0.3.1 the token column holds a hash and the secret
    /// lives wrapped under a key only the signer can use, so carrying a live CMP credential across
    /// would mean wrapping it — which would mean handing this helper a keystore and its passphrase
    /// to run a one-way copy with. The credential is short-lived and cheap to re-issue, so it is
    /// not worth that.
    /// </para>
    /// <para>
    /// Revoked and expired rows copy across untouched with no secret, because they are already
    /// dead and their history is still worth keeping. The refusal is only ever about credentials
    /// somebody could still use, and it fails loudly now rather than leaving a CMP client that
    /// authenticates against a secret the database no longer holds.
    /// </para>
    /// </summary>
    private async Task CheckLiveCmpTokensAsync(MySqlConnection conn, CancellationToken ct)
    {
        var live = await ScalarAsync<long>(conn,
            "SELECT COUNT(*) FROM EnrollmentTokens WHERE UsedForCmp = 1 AND IsRevoked = 0 AND ExpiresAt > UTC_TIMESTAMP()",
            ct);
        if (live == 0)
        {
            _notes.Add("CMP credentials: none live");
            return;
        }

        _refusals.Add(
            $"{live} CMP enrollment token(s) are still live (not revoked, not expired). Their shared secret is "
            + "stored in the clear on 0.3.0 and wrapped by the signer on 0.3.1, and this helper does not hold a "
            + "signer, so it cannot carry one across. Revoke them in the console and issue replacements after the "
            + "migration, then re-run. Revoked and expired CMP rows migrate normally.");
    }

    /// <summary>
    /// Refuses while the source still has tenant hostnames. 0.4.0 retired them and its schema has
    /// no table for them, so the copy would leave them behind without a word; a PostgreSQL install
    /// refuses the same rows in the <c>RetireTenantHostnames</c> migration.
    /// </summary>
    private async Task CheckTenantHostnamesAsync(MySqlConnection conn, CancellationToken ct)
    {
        long rows;
        try
        {
            await using var cmd = new MySqlCommand("SELECT COUNT(*) FROM TenantHostnames", conn);
            rows = Convert.ToInt64(await cmd.ExecuteScalarAsync(ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _refusals.Add($"Could not count the source's tenant hostnames ({ex.Message}); refusing rather than risk "
                + "leaving them behind. Check the source account can read TenantHostnames, then re-run.");
            return;
        }
        if (rows == 0)
        {
            _notes.Add("Tenant hostnames: none");
            return;
        }

        _refusals.Add(
            $"{rows} tenant hostname(s) exist. This release no longer serves tenant hostnames and has no table for "
            + "them, so they would not be copied. Remove them in the 0.3.0 console, or move those names to the "
            + "instance's public domain or to a reverse proxy, then re-run.");
    }

    /// <summary>
    /// Looks for rows that would collide once case stops distinguishing them, keyed on each whole
    /// uniqueness constraint.
    /// <para>
    /// MariaDB's collation should have made this impossible, which is exactly why it is worth
    /// confirming rather than assuming before a one-way copy: a pair of rows that differ only in
    /// case would violate the destination's unique index halfway through a table, leaving a
    /// half-copied database and a constraint error naming a row rather than a cause.
    /// </para>
    /// <para>
    /// The key is the whole index. Grouping by one column at a time reports a collision wherever a
    /// composite key legitimately repeats one of its parts — four certificates from one issuer,
    /// several protocols configured on one CA — which is the schema working exactly as intended.
    /// </para>
    /// </summary>
    private async Task CheckCaseCollisionsAsync(MySqlConnection conn, CancellationToken ct)
    {
        var checks = ModelIntrospection.UniquenessChecks(ModelIntrospection.DestinationModel()).ToList();
        var sourceSchema = await SourceSchemaAsync(conn, ct);
        var swept = 0;
        var collisions = 0;

        foreach (var check in checks)
        {
            if (!sourceSchema.TryGetValue(check.Table, out var sourceColumns))
                continue;   // A table new in 0.3.1 has nothing to collide.
            if (!check.Columns.All(sourceColumns.Contains))
                continue;   // A key that gained a column in 0.3.1 cannot be evaluated on 0.3.0.

            // A folding column is compared lowered; every other column is compared exactly, which
            // on MariaDB needs BINARY because its own collation would otherwise fold those too and
            // report collisions PostgreSQL would never have.
            var selected = check.Columns.Select(c =>
                check.FoldsCase.Contains(c) ? $"LOWER(`{c}`)" : $"BINARY `{c}`").ToList();

            // A key column that is NULL never conflicts: both engines treat NULLs as distinct.
            var notNull = string.Join(" AND ", check.Columns.Select(c => $"`{c}` IS NOT NULL"));
            var grouping = string.Join(", ", Enumerable.Range(1, selected.Count));

            var q = $"SELECT COUNT(*) FROM (SELECT {string.Join(", ", selected)} FROM `{check.Table}` "
                + $"WHERE {notNull} GROUP BY {grouping} HAVING COUNT(*) > 1) AS d";

            swept++;
            var duplicates = await ScalarAsync<long>(conn, q, ct);
            if (duplicates <= 0)
                continue;

            collisions++;
            _refusals.Add(
                $"{check.Table} ({string.Join(", ", check.Columns)}) has {duplicates} group(s) of rows that "
                + "differ only in the case of "
                + $"{string.Join(" and ", check.FoldsCase)}. Those rows are distinct on MariaDB and would "
                + "collide on the destination's unique index. Resolve them on the source first.");
        }

        if (collisions == 0)
            _notes.Add($"Case collisions: none across {swept} uniqueness constraints that fold case");
    }

    /// <summary>
    /// The source's tables and their columns, so a check can tell a table that is new in 0.3.1
    /// from one that is genuinely missing, and a key that gained a column from one it can evaluate.
    /// </summary>
    private static async Task<Dictionary<string, HashSet<string>>> SourceSchemaAsync(
        MySqlConnection conn, CancellationToken ct)
    {
        var schema = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        await using var cmd = new MySqlCommand(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()",
            conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var table = reader.GetString(0);
            if (!schema.TryGetValue(table, out var columns))
                schema[table] = columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            columns.Add(reader.GetString(1));
        }
        return schema;
    }

    // ── Destination ───────────────────────────────────────────────────────────

    private async Task CheckTargetAsync(CancellationToken ct)
    {
        await using var conn = new NpgsqlConnection(_options.TargetConnectionString());
        try
        {
            await conn.OpenAsync(ct);
        }
        catch (Exception ex)
        {
            _refusals.Add($"Cannot connect to the destination server: {ex.Message}");
            return;
        }

        // Version first: every check below is written against a server that has trusted
        // extensions and FORCE, and failing here reads better than failing obscurely later.
        var versionNum = await ScalarAsync<int>(conn, "SHOW server_version_num", ct);
        var versionText = await ScalarAsync<string>(conn, "SHOW server_version", ct);
        _notes.Add($"Destination engine: PostgreSQL {versionText}");
        if (versionNum < MinimumServerVersionNum)
            _refusals.Add(
                $"PostgreSQL {versionText} is older than the minimum this helper supports "
                + $"({MinimumServerVersionNum / 10000}), which is the oldest PostgreSQL ModularCA supports. Upgrade the "
                + "server first.");

        // citext availability is a packaging question, not a permissions one, and the two failures
        // read nothing alike. Asking pg_available_extensions separates them before either bites.
        var citextAvailable = await ScalarAsync<long>(conn,
            "SELECT COUNT(*) FROM pg_available_extensions WHERE name = 'citext'", ct) > 0;
        if (!citextAvailable)
            _refusals.Add(
                "The citext extension is not available on this server. It ships in the PostgreSQL contrib "
                + "package (postgresql-contrib on Debian and Ubuntu, postgresqlNN-contrib on RHEL), and the "
                + "schema cannot be created without it: usernames, CA labels and hostnames are citext columns "
                + "so that they keep comparing without regard to case, as they did on MariaDB.");
        else
            _notes.Add("citext: available");

        // CREATE DATABASE and CREATE ROLE are not transactional, so neither can be tested by
        // trying it and rolling back. The catalogue is the only honest answer here.
        var (canCreateDb, canCreateRole, isSuper) = await RolePrivilegesAsync(conn, _options.TargetAdminUser, ct);
        if (!canCreateDb && !isSuper)
            _refusals.Add(
                $"The role '{_options.TargetAdminUser}' cannot create databases. Grant it CREATEDB, or connect "
                + "as a role that has it — the helper creates both databases rather than being handed them.");
        if (!canCreateRole && !isSuper)
            _refusals.Add(
                $"The role '{_options.TargetAdminUser}' cannot create roles. Grant it CREATEROLE, or connect as "
                + "a role that has it — the helper creates the application and audit login roles.");

        await CheckNameCollisionsAsync(conn, ct);
    }

    private async Task CheckNameCollisionsAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        foreach (var database in new[] { _options.TargetAppDatabase, _options.TargetAuditDatabase })
        {
            var exists = await ScalarAsync<long>(conn,
                "SELECT COUNT(*) FROM pg_database WHERE datname = @n", ct, ("n", database)) > 0;
            if (exists)
                _refusals.Add(
                    $"The database '{database}' already exists on the destination. This helper creates the "
                    + "databases it migrates into, so that it controls their encoding and collation and so that "
                    + "a failed run can drop what it made. Choose a name that is free, or remove that database "
                    + "if it is a previous attempt.");
        }

        // The check a database-name sweep misses. Roles are cluster-wide, so on a shared server
        // the databases can be free while the role names are not — and the existing-role
        // behaviour elsewhere in the product is to rotate the password, which on a role belonging
        // to something else is a quiet outage for a neighbour rather than an error for us.
        foreach (var role in new[]
                 { _options.TargetAppRole, _options.TargetAuditRole, _options.TargetAuditOwnerRole })
        {
            var exists = await ScalarAsync<long>(conn,
                "SELECT COUNT(*) FROM pg_roles WHERE rolname = @n", ct, ("n", role)) > 0;
            if (exists)
                _refusals.Add(
                    $"The role '{role}' already exists on this server. A PostgreSQL role is cluster-wide, not "
                    + "per-database, so this one may belong to another application sharing the server. The helper "
                    + "will not take it over or rotate its password. Choose a different role name, or drop it if "
                    + "you are certain it is yours and unused.");
        }

        if (string.Equals(_options.TargetAppRole, _options.TargetAdminUser, StringComparison.OrdinalIgnoreCase)
            || string.Equals(_options.TargetAuditRole, _options.TargetAdminUser, StringComparison.OrdinalIgnoreCase))
            _refusals.Add(
                "The application or audit role is the same as the administrative role used for this migration. "
                + "The running node must not hold the account that can create and drop databases.");

        if (string.Equals(_options.TargetAppDatabase, _options.TargetAuditDatabase, StringComparison.OrdinalIgnoreCase))
            _refusals.Add("The application and audit databases must be two different databases.");

        if (string.Equals(_options.TargetAppRole, _options.TargetAuditRole, StringComparison.OrdinalIgnoreCase))
            _refusals.Add(
                "The application and audit roles must differ. Separating them is what keeps the node's own "
                + "account from being able to rewrite its audit.");
    }

    private static async Task<(bool CreateDb, bool CreateRole, bool Super)> RolePrivilegesAsync(
        NpgsqlConnection conn, string role, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT rolcreatedb, rolcreaterole, rolsuper FROM pg_roles WHERE rolname = @n", conn);
        cmd.Parameters.AddWithValue("n", role);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return (false, false, false);
        return (reader.GetBoolean(0), reader.GetBoolean(1), reader.GetBoolean(2));
    }

    // ── Small helpers ─────────────────────────────────────────────────────────

    private static async Task<T?> ScalarAsync<T>(
        MySqlConnection conn, string sql, CancellationToken ct)
    {
        try
        {
            await using var cmd = new MySqlCommand(sql, conn);
            var value = await cmd.ExecuteScalarAsync(ct);
            return value is null or DBNull ? default : (T)Convert.ChangeType(value, typeof(T));
        }
        catch
        {
            return default;
        }
    }

    private static async Task<T> ScalarAsync<T>(
        NpgsqlConnection conn, string sql, CancellationToken ct, params (string Name, object Value)[] parameters)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is null or DBNull ? default! : (T)Convert.ChangeType(result, typeof(T));
    }
}
