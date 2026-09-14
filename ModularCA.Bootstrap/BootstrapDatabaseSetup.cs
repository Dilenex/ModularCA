using System.Security.Cryptography;
using ModularCA.Auth.Utils;
using ModularCA.Shared.Utils;
using MySqlConnector;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Bootstrap;

/// <summary>
/// Handles MySQL database user creation, runtime config.yaml generation,
/// and SQL username validation during the bootstrap process.
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
    /// Resolves a MySQL username from config. If the username contains '@' (e.g. "modularca_app@localhost"),
    /// the host portion is stripped and replaced with the SqlRoot host value.
    /// Returns (username, mysqlHost) where mysqlHost is used in CREATE USER 'user'@'host'.
    /// </summary>
    public static (string Username, string MysqlHost) ResolveMysqlUser(string rawUsername, string rootHost)
    {
        var atIndex = rawUsername.IndexOf('@');
        var username = atIndex >= 0 ? rawUsername[..atIndex] : rawUsername;
        var mysqlHost = rootHost == "localhost" || rootHost == "127.0.0.1" ? "localhost" : rootHost;
        return (username, mysqlHost);
    }

    /// <summary>
    /// Creates dedicated MySQL users for the application and audit databases.
    /// The app user receives full DML/DDL permissions; the audit user receives append-only permissions.
    /// Guards against accidentally dropping/recreating the root admin user.
    /// Returns the generated passwords for both users.
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

        var (appUser, appHost) = ResolveMysqlUser(setupDbConfig.SqlApp.Username, rootConfig.Host);
        var (auditUser, auditHost) = ResolveMysqlUser(setupDbConfig.SqlAudit.Username, rootConfig.Host);

        // Validate all identifiers before any SQL execution
        ValidateIdentifier(appUser, "app username");
        ValidateIdentifier(appHost, "app host");
        ValidateIdentifier(appDbName, "app database name");
        ValidateIdentifier(auditUser, "audit username");
        ValidateIdentifier(auditHost, "audit host");
        ValidateIdentifier(auditDbName, "audit database name");

        // Guard: prevent dropping/recreating the root user
        var rootUser = rootConfig.Username.Trim();
        if (string.Equals(appUser, rootUser, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"❌ SqlApp.Username '{appUser}' matches the SqlRoot admin user '{rootUser}'.");
            Console.WriteLine("   This would drop and recreate your admin account. Change SqlApp.Username in setup-database.yaml.");
            throw new InvalidOperationException($"SqlApp.Username must differ from SqlRoot.Username (both are '{rootUser}')");
        }
        if (string.Equals(auditUser, rootUser, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"❌ SqlAudit.Username '{auditUser}' matches the SqlRoot admin user '{rootUser}'.");
            Console.WriteLine("   This would drop and recreate your admin account. Change SqlAudit.Username in setup-database.yaml.");
            throw new InvalidOperationException($"SqlAudit.Username must differ from SqlRoot.Username (both are '{rootUser}')");
        }

        // The root-credential DB-setup pass runs over TLS. The
        // operator-selected mode from the setup wizard is stored on rootConfig.SslMode;
        // unparseable / missing values clamp back to Required so a typo can't silently
        // disable TLS.
        var rootSslMode = Enum.TryParse<MySqlSslMode>(
            rootConfig.SslMode, ignoreCase: true, out var _rootSsl)
            ? _rootSsl : MySqlSslMode.Required;
        var serverConnBuilder = new MySqlConnectionStringBuilder
        {
            Server = rootConfig.Host,
            Port = (uint)rootConfig.Port,
            UserID = rootConfig.Username,
            Password = rootConfig.Password,
            SslMode = rootSslMode
        };
        using var conn = new MySqlConnection(serverConnBuilder.ConnectionString);
        conn.Open();

        // Audit database: preserved unless the operator explicitly asked for a wipe.
        if (wipeAuditDatabase)
        {
            Console.WriteLine($"⚠  Wiping audit database '{auditDbName}' — every historical audit row is being destroyed.");
            ExecuteSql(conn, $"DROP DATABASE IF EXISTS `{auditDbName}`");
            ExecuteSql(conn, $"CREATE DATABASE `{auditDbName}`");
            Console.WriteLine($"✓ Audit database '{auditDbName}' dropped and recreated.");
        }
        else
        {
            // IF NOT EXISTS so a first install still creates it. An existing audit database is
            // left untouched; StartModularCA migrates it forward on the next start, so a schema
            // from an earlier version is brought up to date rather than discarded.
            ExecuteSql(conn, $"CREATE DATABASE IF NOT EXISTS `{auditDbName}`");
            Console.WriteLine($"✓ Audit database '{auditDbName}' ready (existing rows preserved — pass --wipe-audit to discard).");
        }

        // Create app user with full app DB permissions
        ExecuteSql(conn, $"DROP USER IF EXISTS '{appUser}'@'{appHost}'");
        ExecuteSql(conn, $"CREATE USER '{appUser}'@'{appHost}' IDENTIFIED BY '{EscapeSql(appPassword)}'");
        ExecuteSql(conn, $"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES ON `{appDbName}`.* TO '{appUser}'@'{appHost}'");
        Console.WriteLine($"✓ MySQL user '{appUser}'@'{appHost}' created with permissions on '{appDbName}'.");

        // Create audit user with append-mostly permissions. DELETE is granted so the
        // AuditRetentionJob can prune old rows per the configured retention window.
        // DROP TABLE is intentionally NOT granted so the running application cannot discard
        // audit history. That is necessary but was never sufficient: this setup pass runs as
        // root and used to drop the whole audit database a few lines above, which is why the
        // "survives --reset --force" guarantee this comment used to assert was false.
        ExecuteSql(conn, $"DROP USER IF EXISTS '{auditUser}'@'{auditHost}'");
        ExecuteSql(conn, $"CREATE USER '{auditUser}'@'{auditHost}' IDENTIFIED BY '{EscapeSql(auditPassword)}'");
        ExecuteSql(conn, $"GRANT SELECT, INSERT, DELETE, CREATE, ALTER, INDEX, LOCK TABLES, SHOW VIEW ON `{auditDbName}`.* TO '{auditUser}'@'{auditHost}'");
        Console.WriteLine($"✓ MySQL user '{auditUser}'@'{auditHost}' created with audit permissions on '{auditDbName}' (SELECT, INSERT, DELETE — no DROP).");

        ExecuteSql(conn, "FLUSH PRIVILEGES");

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

        var (appUser, _) = ResolveMysqlUser(setupDbConfig.SqlApp.Username, rootConfig.Host);
        var (auditUser, _) = ResolveMysqlUser(setupDbConfig.SqlAudit.Username, rootConfig.Host);

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
    private static void ExecuteSql(MySqlConnection conn, string sql)
    {
        using var cmd = new MySqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// MySQL string-literal escape for values interpolated inside
    /// single-quoted SQL strings (e.g. <c>IDENTIFIED BY '...'</c>). Handles the complete
    /// set of MySQL-recognized backslash escapes (<c>\0 \' \" \b \n \r \t \Z \\ \% \_</c>)
    /// so a future widening of the generated-password alphabet to include control characters
    /// or NUL bytes cannot silently fall through the old two-character escape.
    /// Order matters: the backslash doubling must run first so that the backslashes we emit
    /// while escaping the other characters are not themselves re-escaped.
    /// </summary>
    internal static string EscapeSql(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        var sb = new System.Text.StringBuilder(value.Length + 8);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '"':  sb.Append("\\\""); break;
                case '\0': sb.Append("\\0"); break;
                case '\b': sb.Append("\\b"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\x1A': sb.Append("\\Z"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
