using System.Security.Cryptography;
using ModularCA.Auth.Utils;
using ModularCA.Shared.Utils;
using Npgsql;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using ModularCA.Database.Conventions;

namespace ModularCA.Bootstrap;

/// <summary>
/// Handles PostgreSQL role and database creation, runtime config.yaml generation,
/// and SQL identifier validation during the bootstrap process.
/// </summary>
public static class BootstrapDatabaseSetup
{
    private static readonly System.Text.RegularExpressions.Regex SafeIdentifier = new(@"^[a-zA-Z0-9_\-]+$");

    /// <summary>
    /// Validates that a SQL identifier (database name, username, hostname) contains only safe characters.
    /// Throws <see cref="ArgumentException"/> if the value is empty or contains disallowed characters.
    /// </summary>
    public static void ValidateIdentifier(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || !SafeIdentifier.IsMatch(value))
            throw new ArgumentException($"Invalid {name} '{value}': only alphanumeric, underscore, and hyphen characters are allowed.");
    }

    /// <summary>
    /// Resolves a PostgreSQL role name from config.
    /// <para>
    /// PostgreSQL has no user-at-host concept: a role is a cluster-wide object, and where a
    /// client may connect from is decided separately by <c>pg_hba.conf</c>, not by the role's
    /// name. So the host half of a <c>user@host</c> value is meaningless here and is discarded.
    /// It is still accepted and stripped rather than rejected, because existing
    /// <c>setup-database.yaml</c> files contain it and an operator reusing one should get a
    /// working install rather than a validation error about a concept that no longer exists.
    /// </para>
    /// </summary>
    /// <param name="rawUsername">The configured username, with or without an <c>@host</c> suffix.</param>
    /// <returns>The bare role name.</returns>
    public static string ResolveRoleName(string rawUsername)
    {
        var atIndex = rawUsername.IndexOf('@');
        return atIndex >= 0 ? rawUsername[..atIndex] : rawUsername;
    }

    /// <summary>
    /// Creates dedicated PostgreSQL roles and databases for the application and audit stores.
    /// The app role owns its database outright; the audit role gets append-mostly rights on the
    /// audit database and is explicitly denied the ability to drop its tables. Guards against
    /// accidentally dropping and recreating the superuser role. Returns the generated passwords
    /// for both roles.
    /// <para>
    /// The MySQL version of this method created users with <c>CREATE USER 'u'@'host'</c> and
    /// granted <c>ON `db`.*</c>. Neither exists in PostgreSQL. What replaces them:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <c>CREATE ROLE ... LOGIN PASSWORD ...</c> — cluster-wide, no host component.
    ///   </description></item>
    ///   <item><description>
    ///     The application database is created <c>OWNER</c> the app role. Ownership, rather than
    ///     a grant list, is what gives EF Core migrations the right to create and alter tables:
    ///     PostgreSQL grants apply to objects that already exist, so an enumerated grant cannot
    ///     cover a table a future migration has not created yet. This is also why bootstrap can
    ///     no longer be re-run to "top up" permissions — it does not need to be.
    ///   </description></item>
    ///   <item><description>
    ///     The audit database is owned by the superuser, and the audit role gets CONNECT on the
    ///     database, USAGE plus CREATE on its schema (so migrations can add tables), and default
    ///     privileges of SELECT, INSERT, UPDATE and DELETE on tables it creates. It never gets
    ///     ownership of the database, which is what keeps DROP DATABASE out of its reach.
    ///   </description></item>
    ///   <item><description>
    ///     There is no <c>FLUSH PRIVILEGES</c>. PostgreSQL grants take effect on commit.
    ///   </description></item>
    /// </list>
    /// </summary>
    /// <param name="wipeAuditDatabase">
    /// When true, the audit database is dropped and recreated. Default false, which preserves it.
    /// <para>
    /// This used to be unconditional, and it made three separate operator-facing statements
    /// false: the comment below saying "audit schema survives --reset --force", the
    /// <c>--reset</c> usage text, and the reset banner's "Historical audit rows will persist
    /// into the next install." Technically <c>--reset</c> never dropped it — the next bootstrap
    /// did, from here, three lines above the comment promising otherwise. Withholding DROP from
    /// the audit user achieves nothing when this pass runs as root.
    /// </para>
    /// <para>
    /// An audit trail that a reinstall silently erases is not tamper-evidence. Preserving it by
    /// default is what the rest of the system already claims; wiping is now something an
    /// operator has to ask for.
    /// </para>
    /// </param>
    public static (string appPassword, string auditPassword) CreateDatabaseUsers(
        YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig,
        YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig,
        bool wipeAuditDatabase = false)
    {
        var appPassword = PasswordUtil.Generate() + PasswordUtil.Generate();
        var auditPassword = PasswordUtil.Generate() + PasswordUtil.Generate();
        var appDbName = setupDbConfig.SqlApp.Database;
        var auditDbName = setupDbConfig.SqlAudit.Database;

        var appUser = ResolveRoleName(setupDbConfig.SqlApp.Username);
        var auditUser = ResolveRoleName(setupDbConfig.SqlAudit.Username);

        // Validate all identifiers before any SQL execution. Still worth doing even though every
        // identifier below is also quoted: a role or database name outside this alphabet is a
        // configuration mistake worth reporting by name rather than passing through to the
        // server and reading back whatever it says about it.
        ValidateIdentifier(appUser, "app username");
        ValidateIdentifier(appDbName, "app database name");
        ValidateIdentifier(auditUser, "audit username");
        ValidateIdentifier(auditDbName, "audit database name");

        // Guard: prevent dropping/recreating the root user
        var rootUser = rootConfig.Username.Trim();
        if (string.Equals(appUser, rootUser, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"❌ SqlApp.Username '{appUser}' matches the SqlRoot admin role '{rootUser}'.");
            Console.WriteLine("   This would drop and recreate your admin account. Change SqlApp.Username in setup-database.yaml.");
            throw new InvalidOperationException($"SqlApp.Username must differ from SqlRoot.Username (both are '{rootUser}')");
        }
        if (string.Equals(auditUser, rootUser, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"❌ SqlAudit.Username '{auditUser}' matches the SqlRoot admin role '{rootUser}'.");
            Console.WriteLine("   This would drop and recreate your admin account. Change SqlAudit.Username in setup-database.yaml.");
            throw new InvalidOperationException($"SqlAudit.Username must differ from SqlRoot.Username (both are '{rootUser}')");
        }

        // The superuser DB-setup pass runs over TLS. The operator-selected mode from the setup
        // wizard is stored on rootConfig.SslMode; unparseable / missing values clamp back to
        // Require so a typo can't silently disable TLS.
        //
        // Connects to the maintenance database rather than to either application database,
        // because CREATE DATABASE and DROP DATABASE cannot run from inside the database they
        // name. MySQL had no such rule, which is why the old code did everything on one
        // connection.
        var serverConnStr = PostgresConnection.BuildMaintenance(
            rootConfig.Host, rootConfig.Port, rootConfig.Username, rootConfig.Password, rootConfig.SslMode);
        using var conn = new NpgsqlConnection(serverConnStr);
        conn.Open();

        var qAppDb = PostgresConnection.QuoteIdentifier(appDbName);
        var qAuditDb = PostgresConnection.QuoteIdentifier(auditDbName);
        var qAppRole = PostgresConnection.QuoteIdentifier(appUser);
        var qAuditRole = PostgresConnection.QuoteIdentifier(auditUser);

        // Roles first: a database can be created OWNER a role only once that role exists.
        // An existing role has its password rotated rather than being dropped and recreated —
        // see CreateLoginRole for why the MySQL DROP USER / CREATE USER pair does not port.
        CreateLoginRole(conn, qAppRole, appUser, appPassword);
        CreateLoginRole(conn, qAuditRole, auditUser, auditPassword);

        // Application database, owned by the app role. Ownership rather than an enumerated
        // grant list, because EF Core migrations create tables that do not exist yet and a
        // grant cannot name them.
        if (!DatabaseExists(conn, appDbName))
        {
            ExecuteSql(conn, $"CREATE DATABASE {qAppDb} OWNER {qAppRole}");
            Console.WriteLine($"✓ Application database '{appDbName}' created, owned by role '{appUser}'.");
        }
        else
        {
            ExecuteSql(conn, $"ALTER DATABASE {qAppDb} OWNER TO {qAppRole}");
            Console.WriteLine($"✓ Application database '{appDbName}' already present; ownership confirmed for role '{appUser}'.");
        }

        // citext has to exist before the first migration runs: the application schema declares its
        // identifier columns with that type (see TextCaseSensitivity), and a type that does not
        // exist yet is a CREATE TABLE that fails on its first line. InitialCreate carries its own
        // CREATE EXTENSION IF NOT EXISTS, but that one runs as the application role and succeeds
        // only because PostgreSQL 13 marks citext trusted and the role owns the database. Creating
        // it here, on the privileged connection that just created the database, makes the
        // migration's copy a no-op and leaves the install standing on neither of those facts.
        var appAdminConnStr = PostgresConnection.BuildMaintenance(
            rootConfig.Host, rootConfig.Port, rootConfig.Username, rootConfig.Password,
            rootConfig.SslMode, appDbName);
        using (var appConn = new NpgsqlConnection(appAdminConnStr))
        {
            appConn.Open();
            ExecuteSql(appConn, $"CREATE EXTENSION IF NOT EXISTS {TextCaseSensitivity.Extension}");
        }
        Console.WriteLine($"✓ '{TextCaseSensitivity.Extension}' extension present in '{appDbName}' — usernames, CA labels and hostnames compare without regard to case.");

        // Audit database: preserved unless the operator explicitly asked for a wipe.
        if (wipeAuditDatabase)
        {
            Console.WriteLine($"⚠  Wiping audit database '{auditDbName}' — every historical audit row is being destroyed.");
            // WITH (FORCE) terminates other sessions on the database; without it a single
            // leftover connection from a previous run turns the wipe into an error the operator
            // cannot act on.
            ExecuteSql(conn, $"DROP DATABASE IF EXISTS {qAuditDb} WITH (FORCE)");
            ExecuteSql(conn, $"CREATE DATABASE {qAuditDb}");
            Console.WriteLine($"✓ Audit database '{auditDbName}' dropped and recreated.");
        }
        else if (!DatabaseExists(conn, auditDbName))
        {
            // A first install still creates it. An existing audit database is left untouched;
            // StartModularCA migrates it forward on the next start, so a schema from an earlier
            // version is brought up to date rather than discarded.
            ExecuteSql(conn, $"CREATE DATABASE {qAuditDb}");
            Console.WriteLine($"✓ Audit database '{auditDbName}' created.");
        }
        else
        {
            Console.WriteLine($"✓ Audit database '{auditDbName}' ready (existing rows preserved — pass --wipe-audit to discard).");
        }

        // The audit role's rights have to be granted from inside the audit database: schema and
        // default privileges are per-database objects, so a connection to the maintenance
        // database cannot see them.
        //
        // DELETE is granted so the AuditRetentionJob can prune old rows per the configured
        // retention window. Ownership of the database is deliberately NOT granted, which is what
        // puts DROP DATABASE beyond the running application's reach — the guarantee the MySQL
        // version stated but did not hold, because that setup pass ran as root and dropped the
        // audit database itself a few lines earlier.
        var auditAdminConnStr = PostgresConnection.BuildMaintenance(
            rootConfig.Host, rootConfig.Port, rootConfig.Username, rootConfig.Password,
            rootConfig.SslMode, auditDbName);
        using (var auditConn = new NpgsqlConnection(auditAdminConnStr))
        {
            auditConn.Open();
            ExecuteSql(auditConn, $"GRANT CONNECT ON DATABASE {qAuditDb} TO {qAuditRole}");
            // CREATE on the schema is what lets the audit context apply its own migrations.
            ExecuteSql(auditConn, $"GRANT USAGE, CREATE ON SCHEMA public TO {qAuditRole}");
            ExecuteSql(auditConn, $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {qAuditRole}");
            ExecuteSql(auditConn, $"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {qAuditRole}");
            // ALTER DEFAULT PRIVILEGES covers tables created later — by a migration, or by the
            // superuser during a restore — without which the role would lose access to every
            // table added after this point.
            ExecuteSql(auditConn, $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {qAuditRole}");
            ExecuteSql(auditConn, $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {qAuditRole}");
        }
        Console.WriteLine($"✓ PostgreSQL role '{auditUser}' granted audit rights on '{auditDbName}' (SELECT, INSERT, UPDATE, DELETE — not owner, so no DROP DATABASE).");

        // No FLUSH PRIVILEGES: PostgreSQL grants are transactional and take effect on commit.

        return (appPassword, auditPassword);
    }

    /// <summary>
    /// Generates the runtime config.yaml containing database credentials, JWT settings,
    /// security parameters, logging, email, HTTPS, and other application configuration.
    /// </summary>
    public static void WriteConfigFile(
        string configDir,
        YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig,
        YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig,
        YamlBootstrapLoader.BootstrapConfig bootstrapConfig,
        string appUserPassword,
        string auditUserPassword,
        string pfxPassword,
        int httpsPort,
        int httpPort = 8080,
        string? publicDomain = null,
        int? httpsPublicPort = null,
        int? httpPublicPort = null,
        Shared.Models.Setup.SetupSecurity? security = null,
        Shared.Models.Setup.SetupNetwork? network = null,
        string? pendingSubjectDn = null,
        List<string>? pendingSans = null,
        int? pendingValidityDays = null,
        string? pendingKeyAlgorithm = null,
        int? pendingKeySize = null)
    {
        var jwtSecret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64));

        var appUser = ResolveRoleName(setupDbConfig.SqlApp.Username);
        var auditUser = ResolveRoleName(setupDbConfig.SqlAudit.Username);

        // Validate database name identifiers before writing config
        ValidateIdentifier(setupDbConfig.SqlApp.Database, "app database name");
        ValidateIdentifier(setupDbConfig.SqlAudit.Database, "audit database name");

        // DB credentials are stored in db.yaml (written separately by BootstrapService).
        // config.yaml no longer duplicates them — db.yaml is the single source of truth
        // for database connection strings.
        var config = new
        {
            JWT = new
            {
                Secret = jwtSecret,
                ExpirationMinutes = security?.JwtExpirationMinutes ?? 30,
                Issuer = "ModularCA",
                Audience = "ModularCA-API"
            },
            // Security yaml block intentionally omitted — session/lockout/MFA/OCSP policy
            // now lives in the DB-backed SecurityPolicy table (seeded by BootstrapProfileSeeder
            // from request.Security.MaxFailedLoginAttempts / .LockoutMinutes). The remaining
            // SecurityConfig fields (BindJwtToIp, refresh-token binding, BehindReverseProxy,
            // per-username rate limit) use their class defaults on first boot and are tunable
            // via PUT /api/v1/admin/config/security afterwards.
            LdapAuth = new
            {
                Enabled = false,
                Host = "",
                Port = 389,
                UseSsl = true,
                RequireTls = true,
                SearchBaseDn = "",
                SearchFilter = "(&(objectClass=user)(sAMAccountName={0}))"
            },
            Logging = new
            {
                MinLevel = network?.LogLevel ?? "Information",
                FilePath = "logs/modularca-.log",
                RetentionDays = network?.LogRetentionDays ?? 30
            },
            Http = new
            {
                Port = httpPort,
                PublicPort = httpPublicPort,
                CorsOrigins = "",
                SwaggerEnabled = security?.SwaggerEnabled ?? false
            },
            RateLimiting = new
            {
                MaxLoginAttempts = 10,
                WindowMinutes = 5
            },
            // Scheduler section intentionally omitted: Enabled and PollIntervalSeconds
            // are now hardcoded in code (always-on, 30-second poll). Other Scheduler
            // knobs (LeaseTtlSeconds, MissedRunPolicy, etc.) inherit defaults from
            // SchedulerConfig and can be tuned later via PUT /api/v1/admin/config/scheduler.
            Tokens = new
            {
                RefreshTokenDays = 7
            },
            Email = new
            {
                Enabled = false,
                SmtpHost = "",
                SmtpPort = 587,
                UseTls = true,
                AuthMethod = "Password",
                Username = "",
                Password = "",
                OAuth2AccessToken = "",
                OAuth2ClientId = "",
                OAuth2ClientSecret = "",
                OAuth2TokenUrl = "",
                OAuth2Scopes = "",
                FromAddress = "ca@example.com",
                FromName = "ModularCA",
                AdminRecipients = ""
            },
            Https = new
            {
                Mode = pendingSubjectDn != null ? "Pending" : "SelfIssued",
                ListenAddress = network?.ListenAddress ?? "0.0.0.0",
                CertificatePath = "config/api-tls.pfx",
                CertificatePassword = pfxPassword,
                Port = httpsPort,
                RenewalWindow = "P30D",
                PublicDomain = publicDomain ?? "",
                PublicPort = httpsPublicPort,
                PendingSubjectDn = pendingSubjectDn,
                PendingSans = pendingSans,
                PendingValidityDays = pendingValidityDays,
                PendingKeyAlgorithm = pendingKeyAlgorithm,
                PendingKeySize = pendingKeySize
            },
            Mtls = new
            {
                Enabled = network?.MtlsEnabled ?? false,
                AuthSubdomain = network?.MtlsAuthSubdomain ?? "",
                // RequiredPaths: empty by default. The SNI-gated design never requests a
                // client cert on the main hostname, so any path listed here would 403 every
                // JWT request. Only populate when fronting with a reverse proxy that
                // forwards client certs.
                RequiredPaths = Array.Empty<string>(),
                // TrustedCaCertPaths: intentionally empty even when the operator ticked
                // "enable mTLS" in the wizard. At this point in bootstrap no CA group has an
                // mTLS signing CA assigned yet and there is nothing to export, so there is no
                // honest value to write. Startup treats an empty list as "seed anchors from
                // the enrolled mTLS signing CAs in the database" (see the trust-anchor block
                // in StartModularCA.cs), which is the correct anchor set for an instance that
                // issues its own client certificates. Populate this only to pin an external
                // or narrower trust set — doing so disables the database fallback.
                TrustedCaCertPaths = Array.Empty<string>()
            },
            WebAuthn = new
            {
                Enabled = security?.WebAuthnEnabled ?? true,
                RelyingPartyName = "ModularCA"
            },
            Backup = new
            {
                Enabled = security?.BackupEnabled ?? true,
                Schedule = security?.BackupSchedule ?? "0 2 * * *",
                OutputPath = network?.BackupOutputPath ?? "backups",
                RetentionCount = network?.BackupRetentionCount ?? 10
            }
        };

        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .Build();

        var yaml = serializer.Serialize(config);
        var yamlPath = Path.Combine(configDir, "config.yaml");
        File.WriteAllText(yamlPath, yaml);
        FileSecurityUtil.SetOwnerOnly(yamlPath);

        Console.WriteLine($"\n📝 Runtime configuration written to: {yamlPath}");
        Console.WriteLine("   (Contains DB credentials and JWT secret — protect this file)");
    }

    /// <summary>
    /// Executes a single SQL statement on the given connection.
    /// </summary>
    /// <param name="conn">An open connection.</param>
    /// <param name="sql">The statement to run.</param>
    private static void ExecuteSql(NpgsqlConnection conn, string sql)
    {
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Returns true when a database of the given name exists in the cluster.
    /// <para>
    /// PostgreSQL has no <c>CREATE DATABASE IF NOT EXISTS</c> and no <c>DO</c> block that can
    /// contain one (CREATE DATABASE cannot run inside a transaction or a function body), so the
    /// existence test is a query rather than a clause.
    /// </para>
    /// </summary>
    /// <param name="conn">An open connection to the maintenance database.</param>
    /// <param name="databaseName">The database to look for.</param>
    /// <returns>True when <c>pg_database</c> holds a row with that name.</returns>
    private static bool DatabaseExists(NpgsqlConnection conn, string databaseName)
    {
        using var cmd = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @name", conn);
        cmd.Parameters.AddWithValue("name", databaseName);
        return cmd.ExecuteScalar() != null;
    }

    /// <summary>
    /// Returns true when a role of the given name exists in the cluster.
    /// </summary>
    /// <param name="conn">An open connection.</param>
    /// <param name="roleName">The role to look for.</param>
    /// <returns>True when <c>pg_roles</c> holds a row with that name.</returns>
    private static bool RoleExists(NpgsqlConnection conn, string roleName)
    {
        using var cmd = new NpgsqlCommand("SELECT 1 FROM pg_roles WHERE rolname = @name", conn);
        cmd.Parameters.AddWithValue("name", roleName);
        return cmd.ExecuteScalar() != null;
    }

    /// <summary>
    /// Creates a login role, or resets the password of an existing one.
    /// <para>
    /// Not a drop-and-recreate: DROP ROLE fails while the role owns any object, so on a re-run
    /// against an existing install it would fail on the app role and leave the bootstrap
    /// half-done. ALTER ROLE ... PASSWORD achieves the one thing that actually has to happen —
    /// the freshly generated password becomes the role's password — and is idempotent.
    /// </para>
    /// </summary>
    /// <param name="conn">An open connection to the maintenance database.</param>
    /// <param name="quotedRole">The role name, already quoted for DDL.</param>
    /// <param name="roleName">The raw role name, for the existence check and for logging.</param>
    /// <param name="password">The generated password to set.</param>
    private static void CreateLoginRole(NpgsqlConnection conn, string quotedRole, string roleName, string password)
    {
        // PostgreSQL will not take the password as a bound parameter in CREATE/ALTER ROLE, so it
        // is quoted as a string literal. Doubling the single quote is the whole of the escaping
        // PostgreSQL standard-conforming strings require — there are no backslash escapes to
        // worry about, which is why the MySQL-specific EscapeSql helper this replaces is gone.
        var quotedPassword = PostgresConnection.QuoteLiteral(password);
        if (RoleExists(conn, roleName))
        {
            ExecuteSql(conn, $"ALTER ROLE {quotedRole} WITH LOGIN PASSWORD {quotedPassword}");
            Console.WriteLine($"✓ PostgreSQL role '{roleName}' already existed; password rotated.");
        }
        else
        {
            ExecuteSql(conn, $"CREATE ROLE {quotedRole} WITH LOGIN PASSWORD {quotedPassword}");
            Console.WriteLine($"✓ PostgreSQL role '{roleName}' created.");
        }
    }
}
