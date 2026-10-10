using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Utils;
using Npgsql;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Text.Json;
using static ModularCA.Keystore.Services.KeystoreService;

namespace ModularCA.Bootstrap;

/// <summary>
/// Orchestrates initial CA setup: database provisioning (as the SqlRoot superuser, through
/// <see cref="BootstrapDatabaseSetup"/>), schema and seeding as the runtime roles, root CA
/// generation, keystore creation, and configuration. Delegates to
/// <see cref="BootstrapProfileSeeder"/>, <see cref="BootstrapCertCreator"/>,
/// <see cref="BootstrapKeystoreWriter"/>, and <see cref="BootstrapDatabaseSetup"/> for focused work.
/// </summary>
public class BootstrapModularCA
{

    /// <summary>
    /// Factory reset: drops all tables and recreates the schema, deletes keystores and policy files.
    /// The tables are dropped first, in one transaction and only after a catalog check that the
    /// app role owns them; a refusal or a failed drop returns 1 with every keystore still in place.
    /// The keystores deleted are all three: the CA keystore, the trust keystore and the SSH keystore.
    /// SSH CA key files still on the host in plaintext are overwritten and deleted too: the default
    /// key directory, and the files the key rows named, read before the tables are dropped.
    /// Deletes config.yaml, db.yaml, and keystore.yaml (regenerated during setup). Preserves bootstrap.yaml as reference.
    /// Called via <c>dotnet run --reset --force</c>. After reset, a normal <c>dotnet run</c> will
    /// trigger the web setup wizard since no CAs exist.
    /// </summary>
    public static int FactoryReset(string? expectedDatabaseName = null)
    {
        try
        {
            var configDir = Path.Combine(AppContext.BaseDirectory, "config");
            var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
            var certPath = Path.Combine(keystoreDir, "ca-certs.keystore");
            var trustPath = Path.Combine(keystoreDir, "ca-trust.keystore");

            // Try db.yaml first (has app credentials), fall back to config.yaml
            string connStr;
            string? appDatabase = null;
            string? auditDatabase = null;
            var appPort = 5432;

            // The reset intent is logged before any DROP so operators have a
            // record of which deployment was targeted. Going to a file is cheap and doesn't
            // require DB connectivity.
            try
            {
                var auditLogPath = Path.Combine(configDir, "factory-reset.log");
                File.AppendAllText(auditLogPath,
                    $"{DateTime.UtcNow:O} RESET_STARTED user={Environment.UserName} " +
                    $"host={Environment.MachineName} expected-db={expectedDatabaseName ?? "<unspecified>"}{Environment.NewLine}");
            }
            catch { /* best-effort audit — don't block the reset on disk failures */ }

            var dbYamlPath = Path.Combine(configDir, "db.yaml");
            var runtimeConfigPath = Path.Combine(configDir, "config.yaml");

            if (File.Exists(dbYamlPath))
            {
                var dbCfg = YamlDbConfigLoader.Load(dbYamlPath);
                if (dbCfg == null) { Console.WriteLine("❌ Failed to load db.yaml."); return 1; }
                // Honor SslMode stamped in db.yaml; clamp typos to Require. Connects to the
                // maintenance database: PostgreSQL has no "connect to the server without naming
                // a database", and the work below drops tables in the app database, which
                // cannot be done from a session attached to it.
                connStr = PostgresConnection.BuildMaintenance(
                    dbCfg.App.Host, dbCfg.App.Port, dbCfg.App.Username, dbCfg.App.Password, dbCfg.App.SslMode);
                appDatabase = dbCfg.App.Database;
                auditDatabase = dbCfg.Audit.Database;
                appPort = dbCfg.App.Port;
                Console.WriteLine($"Using db.yaml for DB connection ({dbCfg.App.Host}:{dbCfg.App.Port})");
            }
            else if (File.Exists(runtimeConfigPath))
            {
                var cfg = YamlConfigLoader.Load(runtimeConfigPath);
                // Honor SslMode from runtime config; clamp typos to Require.
                connStr = PostgresConnection.BuildMaintenance(
                    cfg.DB.App.Host, cfg.DB.App.Port, cfg.DB.App.Username, cfg.DB.App.Password, cfg.DB.App.SslMode);
                appDatabase = cfg.DB.App.Database;
                auditDatabase = cfg.DB.Audit.Database;
                appPort = cfg.DB.App.Port;
                Console.WriteLine($"Using runtime config for DB connection ({cfg.DB.App.Host}:{cfg.DB.App.Port})");
            }
            else
            {
                Console.WriteLine("❌ No db.yaml or config.yaml found. Cannot determine database connection.");
                return 1;
            }

            // If the operator supplied an expected database name, require it to
            // match the one resolved from the on-disk config before dropping any tables. This
            // catches the "stale db.yaml from a prior deployment" footgun: if the config on
            // disk points at db_A but the operator intends to reset db_B, we refuse. Comparison
            // is case-insensitive because MySQL identifier case rules are platform-dependent.
            if (!string.IsNullOrWhiteSpace(expectedDatabaseName))
            {
                if (!string.Equals(expectedDatabaseName, appDatabase, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine(
                        $"❌ Expected database '{expectedDatabaseName}' does not match configured database '{appDatabase}'. Aborting reset.");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine(
                    "⚠  Proceeding without --expected-db flag. Operator is responsible for verifying target database.");
            }

            // Validate database name identifiers before any SQL operations
            if (!string.IsNullOrWhiteSpace(appDatabase))
                BootstrapDatabaseSetup.ValidateIdentifier(appDatabase, "app database name");
            if (!string.IsNullOrWhiteSpace(auditDatabase))
                BootstrapDatabaseSetup.ValidateIdentifier(auditDatabase, "audit database name");

            // Prove the database is reachable BEFORE deleting anything.
            //
            // The keystore files used to be deleted here and the connection opened afterwards.
            // A reset against an unreachable database — wrong host, rotated credentials, server
            // down, a stale db.yaml pointing somewhere that no longer exists — therefore
            // destroyed every CA private key and only then failed, leaving DB rows that
            // reference keys no longer on disk. That install can neither sign nor be cleanly
            // reset: the operator holds certificate records for CAs whose keys are gone.
            //
            // The keystores are the only irreplaceable artifact in this operation. Dropped
            // tables can be recreated; a deleted signing key cannot.
            // Connect without a specific database first to check existence.
            Console.WriteLine("\nVerifying database connectivity before deleting anything...");
            using var conn = new NpgsqlConnection(connStr);
            try
            {
                conn.Open();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Could not connect to the database: {ex.Message}");
                Console.WriteLine("   Nothing has been deleted. Fix the connection and re-run the reset.");
                return 1;
            }
            Console.WriteLine("✓ Database reachable.");

            // The tables go before the keystores, in one transaction, after a catalog-only check
            // that the app role owns them: on an install whose tables an administrator owns the
            // drops would fail with 42501, and must do so while the keys still exist.
            Console.WriteLine("\nDropping all tables...");

            // Where SSH CA keys are still files on this host is in the key rows, which the
            // drop below removes: read before it, used after the keystores are deleted.
            IReadOnlyList<string> legacySshKeyFiles = [];

            // Check if app database exists before attempting to drop tables
            if (!string.IsNullOrWhiteSpace(appDatabase))
            {
                bool appDbExists;
                using (var checkCmd = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @name", conn))
                {
                    checkCmd.Parameters.AddWithValue("name", appDatabase);
                    appDbExists = checkCmd.ExecuteScalar() != null;
                }

                if (appDbExists)
                {
                    // Npgsql has no ChangeDatabase: a PostgreSQL session is bound to one database
                    // for its lifetime. A second connection to the app database is therefore
                    // opened here, while `conn` stays on the maintenance database.
                    var appConnStr = new NpgsqlConnectionStringBuilder(connStr) { Database = appDatabase }.ConnectionString;
                    using var appConn = new NpgsqlConnection(appConnStr);
                    appConn.Open();

                    var ownership = SchemaOwnership.ProbeAsync(appConn, DatabaseKind.Application).GetAwaiter().GetResult();
                    var foreignTables = ownership.NotOwned.Where(o => o.Kind is "r" or "p").ToList();
                    if (foreignTables.Count > 0)
                    {
                        Console.WriteLine($"❌ Role '{ownership.Role}' does not own {foreignTables.Count} table(s) in '{appDatabase}' "
                            + $"(e.g. {string.Join(", ", foreignTables.Take(3).Select(o => $"{o.Object} owned by {o.Owner}"))}), "
                            + "so it cannot drop them.");
                        Console.WriteLine("   Nothing has been deleted. Repair ownership once on the database host, with every ModularCA unit stopped:");
                        Console.WriteLine("   " + SchemaOwnership.RepairCommand(DatabaseKind.Application, appDatabase, ownership.Role, appPort));
                        Console.WriteLine("   then re-run the reset.");
                        return 1;
                    }

                    try
                    {
                        legacySshKeyFiles = BackupRestore.LegacySshKeyFilesAsync(appConnStr).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"(i) The SSH CA key rows could not be read ({SchemaFailure.Describe(ex)}); only the default SSH CA key directory is cleared.");
                    }

                    var tables = new List<string>();
                    using (var listCmd = new NpgsqlCommand(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename", appConn))
                    using (var reader = listCmd.ExecuteReader())
                    {
                        while (reader.Read())
                            tables.Add(reader.GetString(0));
                    }

                    // CASCADE rather than a foreign-key-checks toggle: PostgreSQL has no session
                    // switch that suspends referential integrity, and CASCADE removes the
                    // dependent constraints along with the table, which is the same end state
                    // the MySQL version reached by turning the checks off around the loop.
                    using (var tx = appConn.BeginTransaction())
                    {
                        try
                        {
                            foreach (var table in tables)
                            {
                                using var dropCmd = new NpgsqlCommand(
                                    $"DROP TABLE IF EXISTS public.{PostgresConnection.QuoteIdentifier(table)} CASCADE", appConn, tx);
                                dropCmd.ExecuteNonQuery();
                            }
                            tx.Commit();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"❌ Could not drop the tables of '{appDatabase}': {SchemaFailure.Describe(ex)}");
                            Console.WriteLine("   Nothing has been deleted: the drops were rolled back and the keystores are untouched.");
                            return 1;
                        }
                    }
                    Console.WriteLine($"✓ Dropped {tables.Count} table(s) from {appDatabase}");
                }
                else
                {
                    Console.WriteLine($"(i) App database '{appDatabase}' does not exist — skipping table drop.");
                }
            }

            // The three keystore files go together: ssh-ca.keystore has lost its Keystores row
            // with the tables, and a file without its row leaves the signer locked.
            Console.WriteLine("\nDeleting keystore files...");
            DeleteArtifacts(certPath, trustPath);
            DeleteLegacySshKeyFiles(configDir, legacySshKeyFiles);

            // The audit database is left alone by design, not for lack of rights: on installs
            // built by 0.4.0 bootstrap or ModularCA.Migrate the audit role owns its tables and could
            // drop them. Only the database itself is beyond it. History persists into the next
            // install unless that bootstrap is told to wipe it.
            if (!string.IsNullOrWhiteSpace(auditDatabase))
            {
                Console.WriteLine($"(i) Audit database '{auditDatabase}' preserved; the next bootstrap keeps it unless told to wipe it (--wipe-audit).");
            }

            conn.Close();

            // Delete api-tls.pfx (Web TLS certificate tied to deleted CA — disk filename kept for backwards compat)
            var webTlsPath = Path.Combine(configDir, "api-tls.pfx");
            if (File.Exists(webTlsPath))
            {
                File.Delete(webTlsPath);
                Console.WriteLine("✓ Deleted Web TLS certificate (api-tls.pfx)");
            }

            // Delete setup-database.yaml if it exists (root creds should not survive reset)
            var setupDbPath = Path.Combine(configDir, "setup-database.yaml");
            if (File.Exists(setupDbPath))
            {
                File.Delete(setupDbPath);
                Console.WriteLine("✓ Deleted setup-database.yaml");
            }

            // Archive backup.key to a timestamped name instead of deleting so
            // historical audit entries encrypted with the previous key remain decryptable by
            // the operator. The archived file inherits the same owner-only ACL as the live one.
            var backupKeyPath = Path.Combine(configDir, "backup.key");
            if (File.Exists(backupKeyPath))
            {
                var archivedName = $"backup.key.pre-reset-{DateTime.UtcNow:yyyy-MM-ddTHH-mm-ssZ}";
                var archivedPath = Path.Combine(configDir, archivedName);
                File.Move(backupKeyPath, archivedPath);
                try { FileSecurityUtil.SetOwnerOnly(archivedPath); } catch { /* best-effort */ }
                Console.WriteLine($"✓ Archived backup.key → {archivedName}");
                Console.WriteLine("  (retain this file for the audit retention period; post-reset audit entries use a new key)");
            }

            // Delete generated config files — config.yaml and db.yaml are regenerated during setup
            Console.WriteLine("\nCleaning config files...");
            var preserveFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "bootstrap.yaml", "bootstrap.yaml.example", "OIDSeed.yaml"
            };
            foreach (var file in Directory.GetFiles(configDir, "*.yaml"))
            {
                if (!preserveFiles.Contains(Path.GetFileName(file)))
                {
                    File.Delete(file);
                    Console.WriteLine($"✓ Deleted {Path.GetFileName(file)}");
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Factory reset failed: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Runs the full CA bootstrap procedure from bootstrap.yaml and setup-database.yaml. Deciding
    /// comes before acting: the cluster is probed read-only as SqlRoot and every refusal is
    /// reported before anything changes, and the confirmation prompt has no side effects. Then
    /// the roles and databases are provisioned fail-fast, the keystores are deleted, both schemas
    /// are applied and the data seeded as the runtime roles, the ownership rule is proved, and
    /// only then is the configuration written. No migration ever runs as SqlRoot.
    /// <c>Administration.MultipleAdministrators</c> in bootstrap.yaml decides whether key
    /// ceremonies start on (<see cref="ApplyAdministratorChoice"/>); absent, they do.
    /// <c>Acme.AllowPrivateAddressValidation</c> lets the first CA's http-01 validator reach
    /// private addresses when ACME is on; absent, it does not.
    /// Returns 0 on success, 1 on a refusal, a failure or an abort. A refusal (a SqlRoot that is
    /// not a superuser, or whose login PostgreSQL rejects, among them), a runtime role's refused
    /// login and any other database error are printed as a message, never as a stack trace.
    /// </summary>
    /// <param name="wipeAuditDatabase">
    /// Drop the audit database instead of preserving it. False by default, so historical audit
    /// rows survive a reinstall, which is what the reset banner tells operators.
    /// </param>
    public static int Run(bool wipeAuditDatabase = false)
    {
        try
        {
            return RunCore(wipeAuditDatabase);
        }
        catch (PostgresLayoutRefusedException ex)
        {
            Console.WriteLine("❌ Bootstrap refused before any change was made:");
            foreach (var reason in ex.Reasons)
                Console.WriteLine($"   - {reason}");
            return 1;
        }
        catch (BootstrapLoginRefusedException ex)
        {
            Console.WriteLine($"❌ {ex.Message}");
            return 1;
        }
        catch (NpgsqlException ex)
        {
            Console.WriteLine($"❌ Bootstrap stopped on a database error: {SchemaFailure.Describe(ex)}");
            return 1;
        }
        catch (Exception ex) when (ex is SchemaConnectException or InvalidOperationException)
        {
            Console.WriteLine($"❌ Bootstrap stopped: {SchemaFailure.Describe(ex)}");
            return 1;
        }
    }

    /// <summary>The bootstrap procedure <see cref="Run"/> performs, with refusals propagating as exceptions.</summary>
    private static int RunCore(bool wipeAuditDatabase)
    {
        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
        string certPath = Path.Combine(keystoreDir, "ca-certs.keystore");
        string trustPath = Path.Combine(keystoreDir, "ca-trust.keystore");
        var bootstrapPath = Path.Combine(configDir, "bootstrap.yaml");
        var OIDPath = Path.Combine(configDir, "OIDSeed.yaml");
        var OIDConfig = YamlOIDLoader.Load(OIDPath);
        var bootstrapConfig = YamlBootstrapLoader.Load(bootstrapPath);
        if (bootstrapConfig == null)
        {
            Console.WriteLine("❌ Failed to load bootstrap configuration. Aborting.");
            return 1;
        }
        try
        {
            BootstrapCertCreator.EnsureRootLabelUsable(bootstrapConfig.CA.Subject.CN ?? "ModularCA");
            BootstrapCertCreator.EnsureWebTlsSansSupported(bootstrapConfig.HttpsApi?.SANs);
            BootstrapServiceUrlBuilder.EnsurePublicDomainUsable(bootstrapConfig.HttpsApi?.PublicDomain);
        }
        catch (ModularCA.Shared.Errors.RequestValidationException ex)
        {
            Console.WriteLine($"❌ Bootstrap refused before any change was made: {ex.Message}");
            return 1;
        }

        var setupDbPath = Path.Combine(configDir, "setup-database.yaml");
        var setupDbConfig = YamlSetupDatabaseLoader.Load(setupDbPath);
        if (setupDbConfig == null) { Console.WriteLine("❌ setup-database.yaml not found"); return 1; }

        // SqlRoot only, never a fallback to SqlApp: provisioning needs a superuser, and the
        // runtime roles never hold one.
        var rootConfig = setupDbConfig.SqlRoot;

        // 1. Decide, read-only. Every refusal is reported before the prompt and before any DDL.
        BootstrapDatabaseSetup.CheckProvisioningAsync(rootConfig, setupDbConfig, wipeAuditDatabase).GetAwaiter().GetResult();
        bool dbExists = DatabaseExists(setupDbConfig, rootConfig);
        if (dbExists)
            Console.WriteLine($"(i) Database '{setupDbConfig.SqlApp.Database}' already exists on {rootConfig.Host}:{rootConfig.Port}.");
        bool dbHasCa = dbExists && CheckDatabase(rootConfig, setupDbConfig.SqlApp.Database);
        bool hasArtifacts = File.Exists(certPath) || File.Exists(trustPath) || dbExists;

        // 2. Confirm. Prompts only.
        if (hasArtifacts)
        {
            if (!ConfirmDestruction(certPath, trustPath, setupDbConfig, dbExists, dbHasCa, wipeAuditDatabase))
                return 1;
        }
        else
        {
            Console.WriteLine("(i) No existing artifacts found.");
        }

        // 3. Provision, fail-fast. 4. Only then delete the keystores. 5. Schema as the runtime roles.
        var databases = BootstrapDatabaseSetup.ProvisionAsync(
            rootConfig, setupDbConfig, wipeAuditDatabase,
            setupDbConfig.SqlApp.SslMode, setupDbConfig.SqlAudit.SslMode, Console.WriteLine).GetAwaiter().GetResult();
        DeleteArtifacts(certPath, trustPath);
        BootstrapDatabaseSetup.ApplySchemasAsync(databases, Console.WriteLine).GetAwaiter().GetResult();

        using var dbContext = CreateDbContext(PostgresConnection.Build(databases.App));

        // === Spaces (must precede CA and group creation) ===
        var orgSpace = EnsureBootstrapSpaces(
            dbContext, bootstrapConfig.CA.Subject.O ?? "Default", null);
        Console.WriteLine($"✓ Space '{orgSpace.Name}' ready.");

        // === Built-in Roles & System Groups (must precede user creation) ===
        BootstrapProfileSeeder.SeedBuiltInRoles(dbContext);
        BootstrapProfileSeeder.CreateSystemGroups(dbContext);

        // === OID Loading ===
        BootstrapProfileSeeder.LoadOidsToDb(dbContext, OIDConfig);

        // What the CA may put in the certificates it ISSUES. Kept at all six so that
        // "reissue infrastructure certificates" can rotate this CA's own OCSP responder and TSA
        // — see the signing-profile comment below.
        var allowedRootCaExtendedOids = new[] { "Server Authentication", "Client Authentication", "Code Signing", "Email Protection", "Time Stamping", "OCSP Signer" };

        // What the CA's own certificate asserts. This is a different question from the list above,
        // and conflating the two put both of the following in every bootstrap root:
        //
        // No EKU. RFC 5280 §4.2.1.12 makes an EKU on a CA constrain every certificate beneath it,
        // so a smartcardLogon or kdcAuthentication leaf under a root carrying the six-entry list
        // fails EKU-nesting in Windows CryptoAPI with CERT_E_WRONG_USAGE — the Windows smart-card
        // logon work cannot succeed under such a root. CA/B BR §7.1.2.1.2 forbids extKeyUsage on a
        // root outright.
        //
        // No keyEncipherment. RFC 5480 §3 forbids that bit for id-ecPublicKey and RFC 8410 §5 for
        // Ed25519, while config/bootstrap.yaml.example defaults to ECDSA P-384 — so the default
        // install asserted a bit the key type cannot carry. A CA key signs; it never encrypts.
        //
        // These three match what CaCreationService already emits for runtime-created CAs, which
        // were correct all along.
        var rootCaCertificateStandardOids = new[] { "Digital Signature", "Key Certificate Signing", "CRL Signing" };
        var rootCaCertificateExtendedOids = Array.Empty<string>();

        var RootCaStandardOidsJson = BootstrapProfileSeeder.SetupAllowedStandardOidsJson(rootCaCertificateStandardOids, dbContext);
        var RootCaExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(rootCaCertificateExtendedOids, dbContext);

        var KeyAlgorithms = new List<string> { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };
        var KeySizes = new List<string> { "2048", "3072", "4096", "7680", "8192", "P-256", "P-384", "P-521" };
        var SignatureAlgorithms = new List<string> { "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };

        var KeyAlgorithmsJson = JsonSerializer.Serialize(KeyAlgorithms);
        var KeySizesJson = JsonSerializer.Serialize(KeySizes);
        var SignatureAlgorithmsJson = JsonSerializer.Serialize(SignatureAlgorithms);

        // === CA Certificate Profile & Signing Profile ===
        // The CA cert profile governs CA certificates, so it takes the CA-certificate lists, not
        // the issuable-EKU list. This matters beyond the root: CaCreationService issues
        // INTERMEDIATE CAs through the normal issuance pipeline, which reads this profile's
        // KeyUsages and ExtendedKeyUsages straight into the certificate — so seeding it with the
        // six EKUs and keyEncipherment reproduced both defects one level down, on every
        // intermediate created from the default profile.
        BootstrapProfileSeeder.CreateCertProfile(dbContext, "Main CA Certificate Profile", "Default cert profile for self-signed CA certificates",
            rootCaCertificateStandardOids, rootCaCertificateExtendedOids, false, true,
            KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson, "P5Y", "P25Y");
        var caCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Main CA Certificate Profile");
        var allowedCertExtendedOids = new[] { "Server Authentication", "Client Authentication", "Email Protection" };
        // The SIGNING profile must permit the CA's OWN infrastructure EKUs, not just the leaf
        // ones. Built from the three-entry leaf list, the signing profile bound to the
        // bootstrap-created root allowed serverAuth/clientAuth/emailProtection only — and
        // "reissue infrastructure certificates" resolves the profile by
        // sp.IssuerId == caEntity.CertificateId, lands on exactly this profile, and
        // EnsureSigningProfilePermitsInfrastructureEkus then refuses for both OCSP signing and
        // time stamping. The primary CA's OCSP responder and TSA could never be rotated,
        // including after a key compromise. Invisible until the first reissue, because bootstrap
        // issues those two through BootstrapCertCreator, which hardcodes the EKU and bypasses
        // the profile. CaCreationService seeds all six for runtime-created CAs; this matches now.
        // allowedCertExtendedOids stays the leaf list and is still used for the non-CA profile.
        var CertExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(allowedRootCaExtendedOids, dbContext);
        var caCn = bootstrapConfig.CA.Subject.CN ?? "ModularCA";
        var signingProfileName = $"{caCn} Signing Profile";
        BootstrapProfileSeeder.CreateSigningProfile(dbContext, signingProfileName, $"Default signing profile for {caCn}",
            null, KeyAlgorithmsJson, CertExtendedOidsJson);
        var signingProfile = BootstrapProfileSeeder.GetSigningProfileFromDb(dbContext, signingProfileName);
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, caCertProfile, signingProfile);
        var theOUs = bootstrapConfig.CA.Subject.OU != null ? string.Join(",", bootstrapConfig.CA.Subject.OU) : string.Empty;

        // === Self-Signed CA Certificate ===
        // Only the CN is needed; the rest of the subject is optional, as in the setup wizard.
        var subject = bootstrapConfig.CA.Subject;
        var caCertRequest = BootstrapCertCreator.CreateCertificateRequest(caCn, subject.O ?? string.Empty, theOUs,
            subject.L ?? string.Empty, subject.ST ?? string.Empty, subject.C ?? string.Empty, bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(bootstrapConfig.CA.ValidityYears), signingProfile.Id, rootCaCertificateStandardOids, rootCaCertificateExtendedOids, dbContext);

        var (signedCaCert, caPrivKey, caPrivateKeyDer) = BootstrapCertCreator.CreateSelfSignedCertificate(caCertRequest);

        // === ModularCA System Signing CA ===
        var sysCertRequest = BootstrapCertCreator.CreateCertificateRequest("ModularCA System Signing CA", "ModularCA", string.Empty,
            subject.L ?? string.Empty, subject.ST ?? string.Empty, subject.C ?? string.Empty,
            bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(100), signingProfile.Id, rootCaCertificateStandardOids, rootCaCertificateExtendedOids, dbContext);
        var (signedSysCert, sysPrivKey, sysPrivateKeyDer) = BootstrapCertCreator.CreateSelfSignedCertificate(sysCertRequest);

        var caCertPem = KeystoreService.ExportCertificateToPem(signedCaCert);
        var sysCertPem = KeystoreService.ExportCertificateToPem(signedSysCert);

        // Never print raw CA private keys to stdout. Print the SPKI
        // SHA-256 fingerprint of each CA cert so the operator can verify the key pair
        // out-of-band without exposing the PEM encoding to scrollback / CI capture.
        var rootCaFingerprint = KeystoreService.ComputeSpkiSha256Hex(signedCaCert);
        var sysCaFingerprint = KeystoreService.ComputeSpkiSha256Hex(signedSysCert);

        Console.WriteLine("\nCA Certificate Bootstrap complete:");
        Console.WriteLine($" - Root CA subject       : {signedCaCert.SubjectDN}");
        Console.WriteLine($" - Root CA SPKI SHA-256  : {rootCaFingerprint}");
        Console.WriteLine($" - System CA subject     : {signedSysCert.SubjectDN}");
        Console.WriteLine($" - System CA SPKI SHA-256: {sysCaFingerprint}");
        Console.WriteLine("   (CA private keys are stored in the keystore files on disk — never printed.)");

        if (Directory.Exists(keystoreDir))
        {
            Console.WriteLine($"(i) Keystore directory already exists: {keystoreDir}");
        }
        else
        {
            Console.WriteLine($"(i) Creating keystore directory: {keystoreDir}");
            Directory.CreateDirectory(keystoreDir);
            Console.WriteLine($"✓ Keystore directory created: {keystoreDir}");
        }

        // === Modern Keystore Logic ===
        var keystorePasswords = new Dictionary<string, string>
        {
            { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
            { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
        };
        // Never print keystore passphrases to stdout. They are persisted
        // to config/keystore.yaml with owner-only ACLs by BootstrapKeystoreWriter, and the
        // operator is expected to migrate them into MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE
        // post-bootstrap.

        var keystoreFilePasswords = new Dictionary<string, string>
        {
            { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
            { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
        };

        var secondaryPasses = new Dictionary<string, string>
        {
            { "ca-certs.keystore", keystoreFilePasswords["ca-certs.keystore"] },
            { "ca-trust.keystore", keystoreFilePasswords["ca-trust.keystore"] }
        };

        Console.WriteLine("\n🎉 Keystore Bootstrap complete:");
        Console.WriteLine(" - CA cert keystore written to: " + certPath);
        Console.WriteLine(" - CA trust keystore written to: " + trustPath);

        // === TSA Certificate ===
        var tsaKeyGenParams = new ECKeyGenerationParameters(
            Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, new SecureRandom());
        var tsaKeyGen = new ECKeyPairGenerator();
        tsaKeyGen.Init(tsaKeyGenParams);
        var tsaKeyPair = tsaKeyGen.GenerateKeyPair();
        var tsaPrivateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(tsaKeyPair.Private).GetDerEncoded();
        var signedTsaCert = BootstrapCertCreator.SignTsaCertificate(tsaKeyPair, signedCaCert, caPrivKey);

        // OCSP responder key pair + cert (same algorithm as TSA — matches the CA)
        var ocspKeyGen = new ECKeyPairGenerator();
        ocspKeyGen.Init(tsaKeyGenParams);
        var ocspKeyPair = ocspKeyGen.GenerateKeyPair();
        var ocspPrivateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ocspKeyPair.Private).GetDerEncoded();
        var signedOcspCert = BootstrapCertCreator.SignOcspResponderCertificate(ocspKeyPair, signedCaCert, caPrivKey);

        var keystoreEntries = new List<AddKeystoreEntry>
        {
            new AddKeystoreEntry("ca-trust.keystore", signedCaCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-trust.keystore", signedSysCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-trust.keystore", signedTsaCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-trust.keystore", signedOcspCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", caPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", sysPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", tsaPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
            new AddKeystoreEntry("ca-certs.keystore", ocspPrivateKeyDer, secondaryPasses["ca-certs.keystore"])
        };

        // === Feature Flags ===
        var features = bootstrapConfig.Features;
        var defaultFlags = new List<FeatureFlagEntity>
        {
            new FeatureFlagEntity { Name = "CRL.Enabled", Enabled = features.CRL, Description = "Enable CRL generation and distribution" },
            new FeatureFlagEntity { Name = "OCSP.Enabled", Enabled = features.OCSP, Description = "Enable OCSP responder" },
            new FeatureFlagEntity { Name = "ACME.Enabled", Enabled = features.ACME, Description = "Enable ACME protocol endpoints" },
            new FeatureFlagEntity { Name = "EST.Enabled", Enabled = features.EST, Description = "Enable EST protocol endpoints" },
            new FeatureFlagEntity { Name = "SCEP.Enabled", Enabled = features.SCEP, Description = "Enable SCEP protocol endpoints" },
            new FeatureFlagEntity { Name = "CMP.Enabled", Enabled = features.CMP, Description = "Enable CMP protocol endpoints" },
            new FeatureFlagEntity { Name = "MSAE.Enabled", Enabled = features.MSAE, Description = "Enable Windows autoenrollment (MSAE) endpoints" },
            new FeatureFlagEntity { Name = "Syslog.Enabled", Enabled = true, Description = "Enable syslog (RFC 5424) log forwarding", RequiresRestart = true },
            new FeatureFlagEntity { Name = "EventLog.Enabled", Enabled = true, Description = "Enable Windows Event Log sink (Windows only)", RequiresRestart = true },
            new FeatureFlagEntity { Name = "Metrics.Enabled", Enabled = true, Description = "Enable Prometheus metrics endpoint at /metrics" },
        };

        // Pass the System Signing CA cert so its SPKI SHA-256 is stored on
        // the Keystores rows and future keystore loads pin-verify the file signature.
        BootstrapKeystoreWriter.WriteCertsToKeystore(keystorePasswords, secondaryPasses, keystoreEntries, sysPrivKey, dbContext, signedSysCert);

        // === Store Certificates in DB ===
        var kwPassphrase = System.Text.Encoding.UTF8.GetBytes(secondaryPasses["ca-certs.keystore"]);
        var rootCaEntry = BootstrapCertCreator.CreateCertificateEntry(dbContext, caCertPem, signedCaCert, caPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, signingProfile, kwPassphrase);
        // The system signing CA is issued by the root, so its
        // IssuerCertificateId FK points at rootCaEntry.CertificateId.
        BootstrapCertCreator.CreateCertificateEntry(dbContext, sysCertPem, signedSysCert, sysPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, signingProfile, kwPassphrase, issuerCertificateId: rootCaEntry.CertificateId);

        // Update signing profile issuer now that the root CA entry exists
        signingProfile.Issuer = rootCaEntry;
        signingProfile.IssuerId = rootCaEntry.CertificateId;
        dbContext.SaveChanges();

        // === Non-CA Certificate Profile ===
        var allowedCertStandardOids = new[] { "Digital Signature", "Key Encipherment" };
        BootstrapProfileSeeder.CreateCertProfile(dbContext, "Main Certificate Profile", "Default cert profile for non-CA certificates",
            allowedCertStandardOids, allowedCertExtendedOids, false, false,
            KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson, "P47D", "P397D");
        var nonCaCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Main Certificate Profile");
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, nonCaCertProfile, signingProfile);

        // Seed infrastructure cert profiles (TSA, OCSP) and link to signing profile
        BootstrapProfileSeeder.SeedInfrastructureCertProfiles(dbContext);
        var tsaCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "TSA Certificate Profile");
        var ocspCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "OCSP Responder Certificate Profile");
        var webTlsCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Web TLS Certificate Profile");
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, tsaCertProfile, signingProfile);
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, ocspCertProfile, signingProfile);
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, webTlsCertProfile, signingProfile);
        BootstrapProfileSeeder.SeedStandardCertProfiles(dbContext, signingProfile);

        BootstrapProfileSeeder.AddFeatureFlagsToDb(dbContext, defaultFlags);

        var caCertEntity = BootstrapCertCreator.GetCertificateFromDb(dbContext, signedCaCert.SubjectDN.ToString());
        var sysCertEntity = BootstrapCertCreator.GetCertificateFromDb(dbContext, signedSysCert.SubjectDN.ToString());

        BootstrapCertCreator.CreateCrlSchedule(dbContext, caCertEntity);
        BootstrapCertCreator.CreateCrlSchedule(dbContext, sysCertEntity);

        BootstrapKeystoreWriter.WriteKeystorePasswordsToFile(configDir, keystorePasswords, keystoreFilePasswords);

        // Generate backup encryption key
        var backupKeyPath = Path.Combine(configDir, "backup.key");
        if (!File.Exists(backupKeyPath))
        {
            var backupKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32); // 256-bit key
            File.WriteAllBytes(backupKeyPath, backupKey);
            FileSecurityUtil.SetOwnerOnly(backupKeyPath);
            Console.WriteLine("✓ Backup encryption key generated");
        }

        BootstrapCertCreator.CreateCertificateAuthority(dbContext, caCertEntity, type: "Root", isDefault: true, spaceId: orgSpace.Id);
        // The system signing CA is an instance CA: no space.
        BootstrapCertCreator.CreateCertificateAuthority(dbContext, sysCertEntity, type: "Root", isDefault: false, label: "system-signing-ca", spaceId: null);

        var caCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, caCertEntity.CertificateId);
        var sysCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, sysCertEntity.CertificateId);

        // === CA-Scoped Groups (must follow CA creation, precede admin user creation) ===
        BootstrapProfileSeeder.CreateCaGroups(dbContext, caCertCaEntity, orgSpace.Id);
        BootstrapProfileSeeder.CreateCaGroups(dbContext, sysCertCaEntity, null);

        // mTLS signing is a configured item — instance (system) groups never use mTLS, and
        // mTLS signing CAs must be non-Root issuing/intermediate CAs (Root CAs don't
        // sign end-entity certs directly). Clear legacy mTLS assignments on system groups;
        // admins attach an mTLS signing CA to a space group after they've created one.
        foreach (var systemGroup in dbContext.CaGroups.Where(g => g.IsSystemGroup && g.MtlsSigningCaId != null))
            systemGroup.MtlsSigningCaId = null;
        dbContext.SaveChanges();

        // === Seed request profiles and per-CA protocol configs ===
        var requestProfiles = BootstrapProfileSeeder.SeedDefaultRequestProfiles(dbContext);
        BootstrapProfileSeeder.SeedProtocolConfigs(dbContext, caCertCaEntity, signingProfile, nonCaCertProfile, requestProfiles,
            features.ACME && (bootstrapConfig.Acme?.AllowPrivateAddressValidation ?? false));
        // System CA: every protocol hardcoded disabled. Belt-and-suspenders alongside
        // ReservedCaLabelGuardMiddleware; even if the guard is lifted, the DB row says "off".
        BootstrapProfileSeeder.SeedSystemCaProtocolConfigs(dbContext, sysCertCaEntity);

        // Auto-generate service URLs (AIA/CDP) for the public CA. Shares its derivation with the
        // setup wizard — see BootstrapServiceUrlBuilder for what each path used to get wrong.
        var publicDomain = BootstrapServiceUrlBuilder.ResolvePublicDomain(
            bootstrapConfig.HttpsApi.PublicDomain, bootstrapConfig.HttpsApi.SANs);
        if (publicDomain == "localhost")
        {
            Console.WriteLine("[WARNING] No public name: bootstrap.yaml sets no HttpsApi.PublicDomain and HttpsApi.SANs has no");
            Console.WriteLine("          DNS name other than localhost. The instance will answer as localhost, and the URLs in");
            Console.WriteLine("          issued certificates will point there. Set HttpsApi.PublicDomain to the name clients use.");
        }
        else
            Console.WriteLine($"✓ Public name: {publicDomain}");
        var publicBaseUrl = BootstrapServiceUrlBuilder.Build(
            publicDomain: publicDomain,
            dnsSans: bootstrapConfig.HttpsApi.SANs,
            httpPort: bootstrapConfig.HttpsApi.HttpPort);

        if (publicBaseUrl == null)
        {
            Console.WriteLine("[WARNING] HttpsApi.HttpPort is 0, so plain HTTP is disabled and no CRL, OCSP");
            Console.WriteLine("          or AIA URL can be published. Certificates will be issued without a");
            Console.WriteLine("          distribution point. Set HttpsApi.HttpPort in bootstrap.yaml to publish one.");
        }
        else
        {
            BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, caCertEntity, publicBaseUrl, caCertCaEntity.Label ?? "default");
            BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, sysCertEntity, publicBaseUrl, sysCertCaEntity.Label ?? "system-signing-ca");
        }

        BootstrapProfileSeeder.SeedPasswordPolicy(dbContext);
        BootstrapProfileSeeder.SeedSecurityPolicy(dbContext);
        ApplyAdministratorChoice(dbContext, orgSpace, bootstrapConfig.Administration?.MultipleAdministrators);

        // === IP Whitelist defaults ===
        // This call was missing from the CLI path while the setup wizard has always made it,
        // and the two paths are otherwise seeded identically. The consequence was not a missing
        // convenience: with zero rows, WhitelistService finds no matching rule for any bucket
        // and every request resolves to NotCovered, which passes through. So a CLI-bootstrapped
        // install exposed its admin surface to every source address, while a wizard-bootstrapped
        // one restricted it to internal networks — same product, same version, silently
        // different security posture depending on how it was installed.
        //
        // SeedWhitelists is idempotent (it returns early when any row exists), so adding it here
        // is safe for installs that later gain rules by other means. No live reload is needed on
        // this path the way there is in BootstrapService: the CLI exits and the app starts fresh.
        BootstrapProfileSeeder.SeedWhitelists(dbContext);

        BootstrapProfileSeeder.SeedLdapPublisherPolicy(dbContext);
        BootstrapProfileSeeder.SeedProtocolRateLimits(dbContext);
        BootstrapProfileSeeder.SeedDefaultSshProfiles(dbContext);
        // NOTE: SSH CA keys are not created during bootstrap. They are generated at runtime
        // via SshCaService, which also creates the linked CertificateAuthorityEntity (with
        // IsSshCa = true) and its 4 CA-scoped groups. No backfill is needed here.
        BootstrapProfileSeeder.SeedNotificationPreferences(dbContext);
        BootstrapProfileSeeder.CreateInitialUser(dbContext);

        caCertEntity.CertificateAuthority = caCertCaEntity;
        sysCertEntity.CertificateAuthority = sysCertCaEntity;
        dbContext.SaveChanges();

        // === Store TSA signer certificate in DB ===
        BootstrapCertCreator.StoreTsaCertificate(signedTsaCert, tsaKeyPair, dbContext, signingProfile, nonCaCertProfile, caCertCaEntity);

        // === Store OCSP responder certificate in DB ===
        BootstrapCertCreator.StoreOcspResponderCertificate(signedOcspCert, ocspKeyPair, dbContext, signingProfile, nonCaCertProfile, caCertCaEntity);

        // === Build pending web TLS config for Stage 2 provisioning ===
        // The web TLS cert is NOT issued during bootstrap. Instead, the subject DN and SANs
        // are stored in config.yaml with Mode=Pending. On first runtime start,
        // WebTlsProvisioningService issues the cert through the standard CSR pipeline.
        var httpsApi = bootstrapConfig.HttpsApi;
        var pendingSubjectDn = !string.IsNullOrWhiteSpace(httpsApi.SubjectDn)
            ? httpsApi.SubjectDn
            : $"CN={httpsApi.CN}";
        var pendingSans = BootstrapServiceUrlBuilder.SansCovering(publicDomain, httpsApi.SANs);
        var pendingValidityDays = httpsApi.ValidityDays;

        // === Prove the ownership rule, then write config.yaml and db.yaml ===
        BootstrapDatabaseSetup.VerifyOwnershipAsync(databases, Console.WriteLine).GetAwaiter().GetResult();
        var (appUserPassword, auditUserPassword) = (databases.App.Password, databases.Audit.Password);
        BootstrapDatabaseSetup.WriteConfigFile(configDir, rootConfig, setupDbConfig, bootstrapConfig, appUserPassword, auditUserPassword,
            pfxPassword: "", // No PFX yet — Stage 2 generates it
            httpsPort: bootstrapConfig.HttpsApi.Port,
            // Was hardcoded 8080 while the AIA/CDP builder above pointed at the TLS port. Both now
            // read the same field, so the listener and the URLs in issued certificates agree.
            httpPort: bootstrapConfig.HttpsApi.HttpPort,
            // The node refuses to start with no Https.PublicDomain, which this path left empty.
            publicDomain: publicDomain,
            security: null,
            network: null,
            pendingSubjectDn: pendingSubjectDn,
            pendingSans: pendingSans,
            pendingValidityDays: pendingValidityDays);

        // === Write db.yaml with generated app credentials ===
        // The same instances bootstrap just connected with, TLS mode normalised by ProvisionAsync,
        // so db.yaml names exactly what was proved to work.
        var dbYamlPath = Path.Combine(configDir, "db.yaml");
        YamlDbConfigLoader.Write(dbYamlPath, new YamlDbConfigLoader.DbYamlConfig
        {
            App = new YamlDbConfigLoader.DbInstanceConfig
            {
                Host = databases.App.Host,
                Port = databases.App.Port,
                Database = databases.App.Database,
                Username = databases.App.Username,
                Password = appUserPassword,
                SslMode = databases.App.SslMode
            },
            Audit = new YamlDbConfigLoader.DbInstanceConfig
            {
                Host = databases.Audit.Host,
                Port = databases.Audit.Port,
                Database = databases.Audit.Database,
                Username = databases.Audit.Username,
                Password = auditUserPassword,
                SslMode = databases.Audit.SslMode
            }
        });
        Console.WriteLine($"✓ db.yaml written to {dbYamlPath}");

        // === Copy baseline policy files from examples if none exist ===
        SeedPolicyFiles(configDir);

        Console.WriteLine("\n----------------------------------------------------------------");
        Console.WriteLine("\nIMPORTANT: SUPERADMIN PASSWORD IS GENERATED ABOVE");
        Console.WriteLine("REMEMBER TO RECORD IT AND STORE IT SECURELY!");
        Console.WriteLine("THERE IS CURRENTLY NO WAY TO RECOVER IT IF LOST!");
        Console.WriteLine("\n----------------------------------------------------------------");

        // Delete setup-database.yaml — root credentials are no longer needed
        if (File.Exists(setupDbPath))
        {
            File.Delete(setupDbPath);
            Console.WriteLine("✓ setup-database.yaml deleted (root credentials removed)");
        }

        return 0;
    }

    /// <summary>
    /// Scrubs the SqlRoot.Password from BootstrapConfig.yaml after successful setup.
    /// Preserves the file structure for reference but removes the root DB credentials from disk.
    /// </summary>
    public static void ScrubRootPassword(string bootstrapConfigPath)
    {
        try
        {
            if (!File.Exists(bootstrapConfigPath))
                return;

            var lines = File.ReadAllLines(bootstrapConfigPath).ToList();
            bool inSqlRoot = false;

            for (int i = 0; i < lines.Count; i++)
            {
                var trimmed = lines[i].TrimStart();
                if (trimmed.StartsWith("SqlRoot:"))
                {
                    inSqlRoot = true;
                    continue;
                }
                // Exit SqlRoot section when we hit another top-level key
                if (inSqlRoot && !trimmed.StartsWith("#") && trimmed.Length > 0 && !char.IsWhiteSpace(lines[i][0]))
                {
                    inSqlRoot = false;
                }
                if (inSqlRoot && trimmed.StartsWith("Password:"))
                {
                    var indent = lines[i].Substring(0, lines[i].Length - trimmed.Length);
                    lines[i] = $"{indent}Password: \"\"  # Cleared after setup — re-enter to re-bootstrap";
                }
            }

            File.WriteAllLines(bootstrapConfigPath, lines);
            Console.WriteLine("✓ Root DB password scrubbed from BootstrapConfig.yaml");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Failed to scrub root password: {ex.Message}");
        }
    }

    /// <summary>
    /// Copies baseline policy YAML files from .yaml.example templates if the active files don't exist yet.
    /// Creates the policies directory if needed.
    /// </summary>
    private static void SeedPolicyFiles(string configDir)
    {
        var policiesDir = Path.Combine(configDir, "policies");
        Directory.CreateDirectory(policiesDir);

        var policyFiles = new[] { "cert-profiles.yaml", "signing-profiles.yaml", "request-profiles.yaml" };
        var seeded = 0;

        foreach (var fileName in policyFiles)
        {
            var targetPath = Path.Combine(policiesDir, fileName);
            if (File.Exists(targetPath))
                continue;

            // Look for the .yaml.example in the same directory or the app base
            var examplePath = Path.Combine(policiesDir, $"{fileName}.example");
            if (!File.Exists(examplePath))
                examplePath = Path.Combine(AppContext.BaseDirectory, "config", "policies", $"{fileName}.example");

            if (File.Exists(examplePath))
            {
                File.Copy(examplePath, targetPath);
                seeded++;
            }
        }

        if (seeded > 0)
            Console.WriteLine($"✓ Seeded {seeded} baseline policy file(s) in {policiesDir}");
        else
            Console.WriteLine($"✓ Policy files already exist in {policiesDir}");
    }

    /// <summary>
    /// Applies the setup answer to "Will more than one person administer this CA?", for both
    /// bootstrap paths, after the security policy is seeded. False turns the key ceremony
    /// requirement off for the instance policy and for <paramref name="firstSpace"/>, where a lone
    /// administrator could never get a ceremony approved; true sets both on. Null (the wizard
    /// field or the <c>Administration.MultipleAdministrators</c> key was absent) changes nothing,
    /// so both keep the entity default, on. An explicit answer is written to the bootstrap audit
    /// log (<see cref="BootstrapAuditLog.LogSetupDecision"/>).
    /// </summary>
    /// <returns>Whether key ceremonies are required after the call.</returns>
    public static bool ApplyAdministratorChoice(ModularCADbContext dbContext, SpaceEntity firstSpace, bool? multipleAdministrators)
    {
        var policy = dbContext.SecurityPolicies.FirstOrDefault()
            ?? throw new InvalidOperationException("The security policy must be seeded before the administrator choice is applied.");
        if (multipleAdministrators is not bool several)
            return policy.RequireKeyCeremony;

        var space = dbContext.Spaces.First(s => s.Id == firstSpace.Id);
        policy.RequireKeyCeremony = several;
        space.RequireKeyCeremony = several;
        dbContext.SaveChanges();

        // No property name here may contain "key": the audit scrubber would blank its value.
        BootstrapAuditLog.LogSetupDecision(
            ModularCA.Shared.Enums.AuditActionType.SecurityPolicyUpdated, "SecurityPolicy", "instance",
            new
            {
                SetupChoice = "MultipleAdministrators",
                MultipleAdministrators = several,
                CeremoniesRequired = several,
                CeremonyRequirementDisabled = !several,
                AppliedTo = new[] { "instance", $"space:{space.Slug}" },
                SpaceId = space.Id,
            });
        Console.WriteLine(several
            ? "✓ Several administrators: key ceremonies are required for the instance and the first space."
            : "✓ Single administrator: key ceremonies are off for the instance and the first space. Turn them on in Settings once a second administrator exists.");
        return several;
    }

    /// <summary>
    /// Ensures the first space, named after the organisation, exists with its space-level groups,
    /// for both bootstrap paths, and returns it. There is no system space: instance CAs and the
    /// system groups have no space. Idempotent: a second run finds it and creates nothing.
    /// It never creates a second space. Bootstrap seeds a database it has just reset, so a
    /// different space (enabled or disabled, not soft-deleted) means the reset did not happen: it
    /// throws <see cref="ModularCA.Shared.Errors.ConfigurationValidationException"/> with MCA-CFG-018.
    /// </summary>
    /// <param name="dbContext">The bootstrap context.</param>
    /// <param name="orgName">The organisation's name; its slug is derived from it.</param>
    /// <param name="orgDescription">A description, or null for the default.</param>
    public static SpaceEntity EnsureBootstrapSpaces(
        ModularCADbContext dbContext, string orgName, string? orgDescription)
    {
        var orgSlug = orgName.ToLowerInvariant().Replace(" ", "-").Replace(".", "-");
        var orgSpace = dbContext.Spaces.FirstOrDefault(t => t.Slug == orgSlug);
        if (orgSpace == null)
        {
            var existing = dbContext.Spaces
                .Where(t => !t.IsDeleted)
                .OrderBy(t => t.Name)
                .FirstOrDefault();
            if (existing is not null)
                throw new ModularCA.Shared.Errors.ConfigurationValidationException(
                    $"Bootstrap found space '{existing.Name}'{(existing.IsEnabled ? "" : " (disabled)")} "
                    + $"already in the database while creating '{orgName}'. Bootstrap only seeds a database it has "
                    + "just reset, so the reset did not happen.",
                    ModularCA.Shared.Errors.ErrorCodes.BootstrapDatabaseNotEmpty,
                    "The database was not reset. Fix the reset failure reported above and run bootstrap again.");

            orgSpace = new SpaceEntity
            {
                Name = orgName,
                Slug = orgSlug,
                Description = !string.IsNullOrWhiteSpace(orgDescription)
                    ? orgDescription
                    : $"Primary space for {orgName} certificate authorities",
                CanBeDeleted = false,
                IsEnabled = true,
            };
            dbContext.Spaces.Add(orgSpace);
            dbContext.SaveChanges();
        }
        CreateSpaceGroups(dbContext, orgSpace);

        return orgSpace;
    }

    /// <summary>
    /// Auto-generates the four space-level permission groups, <c>space-&lt;slug&gt;-admin</c>,
    /// <c>-operator</c>, <c>-auditor</c> and <c>-user</c> (display names <c>Space &lt;name&gt; Admin</c>
    /// and so on), for the given space. These groups have <c>CertificateAuthorityId = null</c> (not CA-scoped)
    /// and grant access to ALL CAs within the space.
    /// </summary>
    public static void CreateSpaceGroups(ModularCADbContext dbContext, SpaceEntity space)
    {
        var spaceRoles = new[]
        {
            ("Administrator", "admin", "Admin"),
            ("Operator", "operator", "Operator"),
            ("Auditor", "auditor", "Auditor"),
            ("Requester", "user", "User")
        };

        foreach (var (templateName, suffix, displaySuffix) in spaceRoles)
        {
            var groupName = $"space-{space.Slug}-{suffix}";
            if (!dbContext.CaGroups.Any(g => g.Name == groupName))
            {
                var group = new CaGroupEntity
                {
                    Name = groupName,
                    DisplayName = $"Space {space.Name} {displaySuffix}",
                    CertificateAuthorityId = null, // Space-wide, not CA-specific
                    TemplateName = templateName,
                    IsSystemGroup = false,
                    IsAutoGenerated = true,
                    SpaceId = space.Id,
                    RequiredQuorum = 1,
                };
                dbContext.CaGroups.Add(group);
                dbContext.SaveChanges();

                var capabilities = templateName switch
                {
                    "Administrator" => Capabilities.AdministratorTemplate,
                    "Operator" => Capabilities.OperatorTemplate,
                    "Auditor" => Capabilities.AuditorTemplate,
                    _ => Capabilities.RequesterTemplate,
                };
                foreach (var cap in capabilities)
                {
                    dbContext.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = cap });
                }
                dbContext.SaveChanges();
            }
        }
        Console.WriteLine($"✓ Space-level groups created for '{space.Name}'.");
    }

    /// <summary>
    /// Creates a <see cref="ModularCADbContext"/> from a raw connection string
    /// using <see cref="DbContextOptionsBuilder{T}"/>.
    /// </summary>
    /// <param name="connectionString">A PostgreSQL connection string.</param>
    /// <returns>An unopened context bound to that connection string.</returns>
    public static ModularCADbContext CreateDbContext(string connectionString)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ModularCADbContext>();
        optionsBuilder.UseNpgsql(connectionString);
        return new ModularCADbContext(optionsBuilder.Options);
    }

    /// <summary>
    /// Whether the application database exists in the cluster, read as SqlRoot from the
    /// maintenance database. Throws when the probe fails: an unanswered question must never
    /// read as "nothing there to destroy".
    /// </summary>
    /// <param name="setupDbConfig">Names the application database to look for.</param>
    /// <param name="rootConfig">Superuser credentials used for the probe.</param>
    /// <returns>True when the database exists.</returns>
    public static bool DatabaseExists(YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig, YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig)
    {
        using var conn = new NpgsqlConnection(BootstrapDatabaseSetup.AdminConnectionString(rootConfig));
        conn.Open();
        using var cmd = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @db", conn);
        cmd.Parameters.AddWithValue("db", setupDbConfig.SqlApp.Database);
        return cmd.ExecuteScalar() != null;
    }

    /// <summary>
    /// Whether the application database already holds CA certificate records, read as SqlRoot on
    /// a plain connection: no EF, no DDL, no migration. Errors propagate.
    /// </summary>
    /// <param name="rootConfig">Superuser credentials.</param>
    /// <param name="appDatabase">The application database, which must exist.</param>
    /// <returns>True when a row in Certificates is marked as a CA.</returns>
    public static bool CheckDatabase(YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig, string appDatabase)
    {
        var connectionString = new NpgsqlConnectionStringBuilder(BootstrapDatabaseSetup.AdminConnectionString(rootConfig))
        {
            Database = appDatabase,
            Pooling = false,
        }.ConnectionString;
        using var conn = new NpgsqlConnection(connectionString);
        conn.Open();
        using var cmd = new NpgsqlCommand(
            "SELECT CASE WHEN to_regclass('public.\"Certificates\"') IS NULL THEN 0 "
            + "ELSE (SELECT COUNT(*) FROM public.\"Certificates\" WHERE \"IsCa\" = TRUE) END", conn);
        return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
    }

    /// <summary>
    /// Asks the operator three times to confirm what bootstrap is about to destroy, and nothing
    /// else: no file is deleted and no database is touched here. Returns true to proceed, false
    /// when the operator aborted.
    /// </summary>
    /// <param name="certPath">The CA keystore file.</param>
    /// <param name="trustPath">The trust keystore file.</param>
    /// <param name="setupDbConfig">Names the databases.</param>
    /// <param name="appDatabaseExists">Whether the application database exists and will be dropped.</param>
    /// <param name="appDatabaseHasCa">Whether it holds CA certificates.</param>
    /// <param name="wipeAuditDatabase">Whether the audit database will be dropped rather than preserved.</param>
    public static bool ConfirmDestruction(
        string certPath, string trustPath, YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig,
        bool appDatabaseExists, bool appDatabaseHasCa, bool wipeAuditDatabase)
    {
        Console.WriteLine("⚠️  Existing CA artifacts detected. Bootstrap will destroy:");
        if (File.Exists(certPath) || File.Exists(trustPath))
            Console.WriteLine("   - the keystore files, holding the CA private keys");
        if (appDatabaseExists)
            Console.WriteLine($"   - the application database '{setupDbConfig.SqlApp.Database}'"
                + (appDatabaseHasCa ? ", which holds CA certificates" : ""));
        Console.WriteLine(wipeAuditDatabase
            ? $"   - the audit database '{setupDbConfig.SqlAudit.Database}' (--wipe-audit)"
            : $"   (the audit database '{setupDbConfig.SqlAudit.Database}' is preserved)");
        for (int i = 1; i <= 3; i++)
        {
            string prompt = i switch
            {
                1 => "[DESTROY]",
                2 => "[REALLY]",
                3 => "[YES]",
                _ => "[CONFIRM]"
            };
            Console.Write($"[{i}/3] Confirm destruction {prompt}: ");
            if (Console.ReadLine()?.Trim().ToUpperInvariant() != prompt.Trim('[', ']'))
            {
                Console.WriteLine("❌ Confirmation failed. Aborting bootstrap.");
                return false;
            }
        }
        Console.WriteLine("✅ Destruction confirmed. Proceeding...\n");
        return true;
    }

    /// <summary>
    /// Deletes the keystore files from disk: the CA keystore, the trust keystore and, beside the
    /// CA keystore, the SSH keystore (<c>ssh-ca.keystore</c>) with a file left by a creation of
    /// it that did not finish. Every caller replaces or drops the database that holds their
    /// <c>Keystores</c> rows, and an SSH keystore left behind without its row would leave the
    /// signer locked at the next start.
    /// </summary>
    public static void DeleteArtifacts(string certPath, string trustPath)
    {
        if (File.Exists(certPath))
            File.Delete(certPath);
        else
        {
            Console.WriteLine($"(i) {certPath} not found. Skipping deletion.");
        }

        if (File.Exists(trustPath))
            File.Delete(trustPath);
        else
        {
            Console.WriteLine($"(i) {trustPath} not found. Skipping deletion.");
        }

        var sshPath = Path.Combine(Path.GetDirectoryName(certPath) ?? string.Empty, ModularCA.Shared.Signing.KeyRef.SshKeystore);
        foreach (var path in new[] { sshPath, sshPath + CreatingSuffix })
        {
            if (!File.Exists(path))
                continue;
            File.Delete(path);
            Console.WriteLine($"✓ Deleted {Path.GetFileName(path)}");
        }
    }

    /// <summary>
    /// Removes the SSH CA key files a factory reset would otherwise leave on the host in
    /// plaintext, for SSH CAs that no longer exist: everything in the default key directory
    /// (<c>config/ssh-ca-keys</c>) and the directory itself, and each key file, with its
    /// <c>.pub</c>, that a key row named elsewhere. Every file is overwritten with zeros and
    /// flushed before it is deleted. A file outside the default directory is touched only when
    /// it is an OpenSSH private key file by its first line, so that a row cannot point the
    /// reset at some other file, and its directory is removed only when that leaves it empty.
    /// A file that cannot be removed is named and left; it does not fail the reset.
    /// </summary>
    /// <param name="configDir">The <c>config/</c> directory.</param>
    /// <param name="legacyKeyFiles">The key file paths the key rows gave, read before the tables were dropped.</param>
    internal static void DeleteLegacySshKeyFiles(string configDir, IEnumerable<string> legacyKeyFiles)
    {
        var defaultDir = Path.GetFullPath(Path.Combine(configDir, BackupWrappedSecrets.DefaultSshKeyDirectory));
        if (Directory.Exists(defaultDir))
        {
            try
            {
                foreach (var file in Directory.GetFiles(defaultDir, "*", SearchOption.AllDirectories))
                    ModularCA.Core.Services.SshKeyFileImport.EraseFile(file);
                Directory.Delete(defaultDir, recursive: true);
                Console.WriteLine($"✓ Deleted SSH CA key files: {defaultDir}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.WriteLine($"⚠ SSH CA key files under {defaultDir} could not all be removed ({ex.Message}). Remove them by hand: they are private keys in plaintext.");
            }
        }

        var baseDir = Path.GetDirectoryName(Path.GetFullPath(configDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) ?? configDir;
        foreach (var keyFile in legacyKeyFiles)
        {
            if (string.IsNullOrWhiteSpace(keyFile))
                continue;
            try
            {
                var full = Path.GetFullPath(Path.IsPathRooted(keyFile) ? keyFile : Path.Combine(baseDir, keyFile));
                if (BackupRestore.PathIsContainedIn(full, defaultDir) || !File.Exists(full))
                    continue;
                if (!ModularCA.Core.Services.SshKeyFileImport.LooksLikeKeyFile(full))
                {
                    Console.WriteLine($"(i) {full} was named as an SSH CA key file and is not one; left as it is.");
                    continue;
                }
                ModularCA.Core.Services.SshKeyFileImport.EraseFile(full);
                if (File.Exists(full + ".pub"))
                    File.Delete(full + ".pub");
                Console.WriteLine($"✓ Deleted SSH CA key file: {full}");
                var directory = Path.GetDirectoryName(full);
                if (directory != null && !Directory.EnumerateFileSystemEntries(directory).Any())
                    Directory.Delete(directory);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                Console.WriteLine($"⚠ The SSH CA key file {keyFile} could not be removed ({ex.Message}). Remove it by hand: it is a private key in plaintext.");
            }
        }
    }
}
