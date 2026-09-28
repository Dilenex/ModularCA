using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Npgsql;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Bootstrap;

/// <summary>The two databases bootstrap provisioned, as the node will connect to them.</summary>
/// <param name="App">The application database as the app role, with the password provisioning set.</param>
/// <param name="Audit">The audit database as the audit role, with the password provisioning set.</param>
public sealed record ProvisionedDatabases(DbInstance App, DbInstance Audit);

/// <summary>
/// PostgreSQL refused a runtime role's login from this host during bootstrap. Carries no secret.
/// </summary>
public sealed class BootstrapLoginRefusedException : InvalidOperationException
{
    /// <summary>Creates the exception for <paramref name="role"/> connecting to <paramref name="host"/>.</summary>
    public BootstrapLoginRefusedException(string role, string host, Exception inner)
        : base($"PostgreSQL refused login for role '{role}' from this host (server {host}); allow it in pg_hba.conf "
            + "and run bootstrap again. Nothing was written to the configuration.", inner)
    {
    }
}

/// <summary>
/// The database half of bootstrap: provisions the roles and databases through
/// <see cref="PostgresRoleLayout"/> as the SqlRoot superuser, applies both schemas as the runtime
/// roles, proves the ownership rule, and writes the runtime config.yaml. Also validates SQL
/// identifiers.
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
    /// SqlRoot's connection string to the maintenance database. Refuses a SqlRoot with no
    /// username or password: bootstrap never falls back to the application role.
    /// </summary>
    /// <param name="rootConfig">SqlRoot from setup-database.yaml.</param>
    /// <exception cref="PostgresLayoutRefusedException">SqlRoot has no username or password.</exception>
    public static string AdminConnectionString(YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig)
    {
        ArgumentNullException.ThrowIfNull(rootConfig);
        if (string.IsNullOrWhiteSpace(rootConfig.Username) || string.IsNullOrWhiteSpace(rootConfig.Password))
            throw new PostgresLayoutRefusedException(
            [
                "SqlRoot in setup-database.yaml has no username or password. Bootstrap connects as a PostgreSQL "
                + "superuser (for example postgres) and never falls back to the application role.",
            ]);
        return PostgresConnection.BuildMaintenance(
            rootConfig.Host, rootConfig.Port, rootConfig.Username.Trim(), rootConfig.Password, rootConfig.SslMode);
    }

    /// <summary>The role and database names setup-database.yaml gives, with any <c>@host</c> suffix removed.</summary>
    /// <param name="rootConfig">SqlRoot.</param>
    /// <param name="setupDbConfig">The whole setup-database.yaml.</param>
    public static PostgresLayoutNames LayoutNames(
        YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig, YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig) =>
        new(rootConfig.Username.Trim(),
            ResolveRoleName(setupDbConfig.SqlApp.Username).Trim(),
            ResolveRoleName(setupDbConfig.SqlAudit.Username).Trim(),
            setupDbConfig.SqlApp.Database,
            setupDbConfig.SqlAudit.Database);

    /// <summary>
    /// Read-only: connects as SqlRoot, reads the cluster, and throws
    /// <see cref="PostgresLayoutRefusedException"/> with every reason provisioning would refuse
    /// (a SqlRoot that is not a superuser first among them). Changes nothing, so the CLI can run
    /// it before asking the operator to confirm anything.
    /// </summary>
    /// <param name="rootConfig">SqlRoot.</param>
    /// <param name="setupDbConfig">The whole setup-database.yaml.</param>
    /// <param name="wipeAuditDatabase">Whether the audit database will be dropped rather than preserved.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<ClusterFacts> CheckProvisioningAsync(
        YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig,
        YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig,
        bool wipeAuditDatabase,
        CancellationToken ct = default)
    {
        var admin = AdminConnectionString(rootConfig);
        var names = LayoutNames(rootConfig, setupDbConfig);
        var problems = PostgresRoleLayout.ValidateNames(names);
        if (problems.Count > 0)
            throw new PostgresLayoutRefusedException(problems);
        var facts = await PostgresRoleLayout.ProbeAsync(admin, names, ct);
        var reasons = PostgresRoleLayout.Refusals(facts, names, new ProvisioningMode(ResetApp: true, WipeAudit: wipeAuditDatabase));
        if (reasons.Count > 0)
            throw new PostgresLayoutRefusedException(reasons);
        return facts;
    }

    /// <summary>
    /// Provisions both databases as SqlRoot through <see cref="PostgresRoleLayout.ProvisionAsync"/>:
    /// the application database is dropped and recreated owned by the app role, the audit database
    /// is preserved and handed to the NOLOGIN <c>&lt;audit&gt;_owner</c> role unless
    /// <paramref name="wipeAuditDatabase"/>, and both runtime roles get fresh passwords. Fail-fast:
    /// it refuses before any DDL, and any later failure propagates. Creates no table.
    /// </summary>
    /// <param name="rootConfig">SqlRoot.</param>
    /// <param name="setupDbConfig">The whole setup-database.yaml.</param>
    /// <param name="wipeAuditDatabase">Drop the audit database instead of preserving it.</param>
    /// <param name="appSslMode">The TLS mode the node will use for the application database.</param>
    /// <param name="auditSslMode">The TLS mode the node will use for the audit database.</param>
    /// <param name="say">Progress output; never receives a password.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The two databases as the runtime roles, with their new passwords.</returns>
    public static async Task<ProvisionedDatabases> ProvisionAsync(
        YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig,
        YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig,
        bool wipeAuditDatabase,
        string? appSslMode,
        string? auditSslMode,
        Action<string>? say,
        CancellationToken ct = default)
    {
        var admin = AdminConnectionString(rootConfig);
        var names = LayoutNames(rootConfig, setupDbConfig);

        NpgsqlConnection.ClearAllPools();
        var (appPassword, auditPassword) = await PostgresRoleLayout.ProvisionAsync(
            admin, names, new ProvisioningMode(ResetApp: true, WipeAudit: wipeAuditDatabase),
            line => say?.Invoke($"✓ {line}"), ct);
        NpgsqlConnection.ClearAllPools();

        return new ProvisionedDatabases(
            new DbInstance
            {
                Host = rootConfig.Host, Port = rootConfig.Port, Database = names.AppDatabase,
                Username = names.AppRole, Password = appPassword,
                SslMode = PostgresConnection.ParseSslMode(appSslMode).ToString(),
            },
            new DbInstance
            {
                Host = rootConfig.Host, Port = rootConfig.Port, Database = names.AuditDatabase,
                Username = names.AuditRole, Password = auditPassword,
                SslMode = PostgresConnection.ParseSslMode(auditSslMode).ToString(),
            });
    }

    /// <summary>
    /// Applies both schemas as the runtime roles, over unpooled migration connections with the
    /// default <see cref="SchemaConfig"/> lock and statement timeouts: every migration, the frozen
    /// baseline first, on the new application database; on the audit database the same when it
    /// is empty, or the migrations a preserved audit database lacks. The only schema writes
    /// bootstrap makes; nothing here runs as SqlRoot.
    /// </summary>
    /// <param name="databases">The provisioned databases.</param>
    /// <param name="say">Progress output.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task ApplySchemasAsync(ProvisionedDatabases databases, Action<string>? say, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(databases);
        var schema = new SchemaConfig();

        await AsRuntimeRoleAsync(databases.App, async () =>
        {
            await using var app = CreateMigrationContext(DatabaseKind.Application, databases.App, schema);
            ThrowIfFailed(databases.App, "application", await SchemaVersionGate.ApplyAllForBootstrapAsync(app, ct), schema);
        });
        say?.Invoke($"✓ Application schema applied as '{databases.App.Username}'.");

        await AsRuntimeRoleAsync(databases.Audit, async () =>
        {
            await using var audit = CreateMigrationContext(DatabaseKind.Audit, databases.Audit, schema);
            var state = await SchemaVersionGate.ReadAsync(audit, ct);
            var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations: true);
            if (state.Presence == DatabasePresence.Empty)
                ThrowIfFailed(databases.Audit, "audit", await SchemaVersionGate.ApplyAllForBootstrapAsync(audit, ct), schema);
            else if (verdict == SchemaVerdict.ApplyPending)
                ThrowIfFailed(databases.Audit, "audit", await SchemaVersionGate.ApplyPendingAsync(audit, state, ct), schema);
            else if (verdict != SchemaVerdict.Current)
                throw new InvalidOperationException(
                    $"The audit database is {state.Presence} ({verdict}) after provisioning; bootstrap stopped before seeding. "
                    + (SchemaVersionGate.RefusalMessage(verdict, state, "audit") ?? ""));
            say?.Invoke(state.Presence == DatabasePresence.Empty
                ? $"✓ Audit schema applied as '{databases.Audit.Username}'."
                : $"✓ Preserved audit schema brought up to date as '{databases.Audit.Username}' ({state.Pending.Count} migration(s)).");
        });
    }

    /// <summary>
    /// Proves the ownership rule the next upgrade depends on, as each runtime role on its own
    /// connection: it owns every object in its schema and can create tables. Throws when either
    /// database breaks it, so bootstrap fails before any configuration is written. Prints the
    /// standing warnings (such as other members of the audit database's owner).
    /// </summary>
    /// <param name="databases">The provisioned databases.</param>
    /// <param name="say">Progress output.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task VerifyOwnershipAsync(ProvisionedDatabases databases, Action<string>? say, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(databases);
        foreach (var (kind, instance) in new[] { (DatabaseKind.Application, databases.App), (DatabaseKind.Audit, databases.Audit) })
        {
            var report = await AsRuntimeRoleAsync(instance, async () =>
            {
                await using var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance))
                {
                    Pooling = false,
                }.ConnectionString);
                return await SchemaOwnership.ProbeAsync(conn, kind, ct);
            });
            if (!report.IsSound)
                throw new InvalidOperationException(
                    $"The {(kind == DatabaseKind.Application ? "application" : "audit")} database '{report.Database}' breaks the "
                    + $"ownership rule after bootstrap: role '{report.Role}' does not own {report.NotOwned.Count} object(s) "
                    + $"({string.Join(", ", report.NotOwned.Take(10).Select(o => $"{o.Object} owned by {o.Owner}"))}) "
                    + $"or cannot create tables (can create: {(report.CanCreateTables ? "yes" : "no")}). "
                    + "Setup did not complete and no configuration was written.");
            foreach (var warning in SchemaOwnership.Warnings(report))
                say?.Invoke($"⚠  {warning}");
            say?.Invoke($"✓ '{report.Role}' owns the schema of '{report.Database}'.");
        }
    }

    /// <summary>
    /// A context of <paramref name="kind"/> on the migration connection for
    /// <paramref name="instance"/>: unpooled, with the server-side lock and statement timeouts of
    /// <paramref name="schema"/> and a client timeout slightly longer. The same shape the control
    /// role migrates with at startup.
    /// </summary>
    private static DbContext CreateMigrationContext(DatabaseKind kind, DbInstance instance, SchemaConfig schema)
    {
        var clientTimeout = schema.MigrationCommandTimeoutSeconds > 0 ? schema.MigrationCommandTimeoutSeconds + 30 : 0;
        var connectionString = new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance))
        {
            Pooling = false,
            CommandTimeout = clientTimeout,
            Options = $"-c lock_timeout={Math.Max(0, schema.MigrationLockTimeoutSeconds) * 1000L} "
                + $"-c statement_timeout={Math.Max(0, schema.MigrationCommandTimeoutSeconds) * 1000L}",
        }.ConnectionString;
        return kind == DatabaseKind.Application
            ? new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(connectionString, o => o.CommandTimeout(clientTimeout)).Options)
            : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                .UseNpgsql(connectionString, o => o.CommandTimeout(clientTimeout)).Options);
    }

    /// <summary>Throws the operator-facing migration failure, or the login refusal it hides, when <paramref name="failure"/> is set.</summary>
    private static void ThrowIfFailed(DbInstance instance, string contextName, MigrationFailure? failure, SchemaConfig schema)
    {
        if (failure is null)
            return;
        if (SchemaFailure.SqlState(failure.Error) is "28P01" or "28000")
            throw new BootstrapLoginRefusedException(instance.Username, instance.Host, failure.Error);
        throw new InvalidOperationException(
            SchemaVersionGate.MigrationFailedMessage(contextName, failure, schema.MigrationCommandTimeoutSeconds), failure.Error);
    }

    /// <summary>Runs <paramref name="work"/> as a runtime role, turning a refused login into <see cref="BootstrapLoginRefusedException"/>.</summary>
    private static async Task AsRuntimeRoleAsync(DbInstance instance, Func<Task> work) =>
        await AsRuntimeRoleAsync(instance, async () => { await work(); return true; });

    /// <summary>Runs <paramref name="work"/> as a runtime role, turning a refused login into <see cref="BootstrapLoginRefusedException"/>.</summary>
    private static async Task<T> AsRuntimeRoleAsync<T>(DbInstance instance, Func<Task<T>> work)
    {
        try
        {
            return await work();
        }
        catch (Exception ex) when (ex is not BootstrapLoginRefusedException && SchemaFailure.SqlState(ex) is "28P01" or "28000")
        {
            throw new BootstrapLoginRefusedException(instance.Username, instance.Host, ex);
        }
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
}
