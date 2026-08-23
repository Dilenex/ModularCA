using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Utils;
using MySqlConnector;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Data;
using System.Text.Json;
using static ModularCA.Keystore.Services.KeystoreService;

namespace ModularCA.Bootstrap;

/// <summary>
/// Orchestrates initial CA setup: database creation, root CA generation, keystore creation, and configuration seeding.
/// Delegates to <see cref="BootstrapProfileSeeder"/>, <see cref="BootstrapCertCreator"/>,
/// <see cref="BootstrapKeystoreWriter"/>, and <see cref="BootstrapDatabaseSetup"/> for focused work.
/// </summary>
public class BootstrapModularCA
{

    /// <summary>
    /// Runs the full CA bootstrap procedure.
    /// Returns 0 on success, 1 on failure or user abort.
    /// </summary>
    /// <summary>
    /// Factory reset: drops all tables and recreates the schema, deletes keystores and policy files.
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
                // Honor SslMode stamped in db.yaml; clamp typos to Required.
                var dbCfgSslMode = Enum.TryParse<MySqlSslMode>(dbCfg.App.SslMode, ignoreCase: true, out var _dbCfgSsl)
                    ? _dbCfgSsl : MySqlSslMode.Required;
                var dbCfgConnBuilder = new MySqlConnectionStringBuilder
                {
                    Server = dbCfg.App.Host,
                    Port = (uint)dbCfg.App.Port,
                    UserID = dbCfg.App.Username,
                    Password = dbCfg.App.Password,
                    SslMode = dbCfgSslMode
                };
                connStr = dbCfgConnBuilder.ConnectionString;
                appDatabase = dbCfg.App.Database;
                auditDatabase = dbCfg.Audit.Database;
                Console.WriteLine($"Using db.yaml for DB connection ({dbCfg.App.Host}:{dbCfg.App.Port})");
            }
            else if (File.Exists(runtimeConfigPath))
            {
                var cfg = YamlConfigLoader.Load(runtimeConfigPath);
                // Honor SslMode from runtime config; clamp typos to Required.
                var cfgSslMode = Enum.TryParse<MySqlSslMode>(cfg.DB.App.SslMode, ignoreCase: true, out var _cfgSsl)
                    ? _cfgSsl : MySqlSslMode.Required;
                var cfgConnBuilder = new MySqlConnectionStringBuilder
                {
                    Server = cfg.DB.App.Host,
                    Port = (uint)cfg.DB.App.Port,
                    UserID = cfg.DB.App.Username,
                    Password = cfg.DB.App.Password,
                    SslMode = cfgSslMode
                };
                connStr = cfgConnBuilder.ConnectionString;
                appDatabase = cfg.DB.App.Database;
                auditDatabase = cfg.DB.Audit.Database;
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
            using var conn = new MySqlConnection(connStr);
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

            // Delete keystore files
            Console.WriteLine("\nDeleting keystore files...");
            DeleteArtifacts(certPath, trustPath);

            // Delete SSH CA key files
            if (Directory.Exists(keystoreDir))
            {
                foreach (var sshKey in Directory.GetFiles(keystoreDir, "ssh-ca-*"))
                {
                    File.Delete(sshKey);
                    Console.WriteLine($"✓ Deleted SSH key: {Path.GetFileName(sshKey)}");
                }
            }

            // Drop all tables (not the database itself) to preserve DB users/grants
            Console.WriteLine("\nDropping all tables...");

            // Check if app database exists before attempting to drop tables
            if (!string.IsNullOrWhiteSpace(appDatabase))
            {
                using var checkCmd = new MySqlCommand("SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = @schema", conn);
                checkCmd.Parameters.AddWithValue("@schema", appDatabase);
                var appDbExists = Convert.ToInt64(checkCmd.ExecuteScalar()) > 0;

                if (appDbExists)
                {
                    conn.ChangeDatabase(appDatabase);

                    using (var fkOff = new MySqlCommand("SET FOREIGN_KEY_CHECKS = 0;", conn))
                        fkOff.ExecuteNonQuery();

                    var tables = new List<string>();
                    using (var listCmd = new MySqlCommand("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = @schema AND TABLE_TYPE = 'BASE TABLE';", conn))
                    {
                        listCmd.Parameters.AddWithValue("@schema", appDatabase);
                        using var reader = listCmd.ExecuteReader();
                        while (reader.Read())
                            tables.Add(reader.GetString(0));
                    }

                    foreach (var table in tables)
                    {
                        using var dropCmd = new MySqlCommand($"DROP TABLE IF EXISTS `{appDatabase}`.`{table}`;", conn);
                        dropCmd.ExecuteNonQuery();
                    }
                    Console.WriteLine($"✓ Dropped {tables.Count} table(s) from {appDatabase}");

                    using (var fkOn = new MySqlCommand("SET FOREIGN_KEY_CHECKS = 1;", conn))
                        fkOn.ExecuteNonQuery();
                }
                else
                {
                    Console.WriteLine($"(i) App database '{appDatabase}' does not exist — skipping table drop.");
                }
            }

            // Audit database cleanup is deferred to the next setup run, which reconnects with root
            // credentials from setup-database.yaml and unconditionally drops/recreates the audit DB.
            // The runtime app and audit users are both scoped to their own databases and have no
            // privileges to drop audit tables here. Historical audit entries persist across resets
            // by design until the next root-credentialed bootstrap replaces the schema.
            if (!string.IsNullOrWhiteSpace(auditDatabase))
            {
                Console.WriteLine($"(i) Audit database '{auditDatabase}' cleanup deferred to next setup (requires root credentials).");
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

    /// <param name="wipeAuditDatabase">
    /// Passed through to <see cref="BootstrapDatabaseSetup.CreateDatabaseUsers"/>. False by
    /// default, so historical audit rows survive a reinstall — which is what the reset banner
    /// has always told operators, and what this code did not previously do.
    /// </param>
    public static int Run(bool wipeAuditDatabase = false)
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

        var setupDbPath = Path.Combine(configDir, "setup-database.yaml");
        var setupDbConfig = YamlSetupDatabaseLoader.Load(setupDbPath);
        if (setupDbConfig == null) { Console.WriteLine("❌ setup-database.yaml not found"); return 1; }

        // Use SqlRoot for admin operations; fall back to SqlApp if SqlRoot not configured
        var rootConfig = !string.IsNullOrWhiteSpace(setupDbConfig.SqlRoot.Password)
            ? setupDbConfig.SqlRoot
            : setupDbConfig.SqlApp;

        // Root-credential bootstrap connection honors the operator-selected
        // TLS mode now that setup-database.yaml round-trips SqlRoot.SslMode from the setup wizard.
        // Unparseable / missing values clamp back to Required so a typo can't silently disable TLS.
        var rootSslMode = Enum.TryParse<MySqlSslMode>(
            rootConfig.SslMode, ignoreCase: true, out var _rootSsl)
            ? _rootSsl : MySqlSslMode.Required;
        var rootConnBuilder = new MySqlConnectionStringBuilder
        {
            Server = rootConfig.Host,
            Port = (uint)rootConfig.Port,
            Database = setupDbConfig.SqlApp.Database,
            UserID = rootConfig.Username,
            Password = rootConfig.Password,
            SslMode = rootSslMode
        };
        var rootConnStr = rootConnBuilder.ConnectionString;

        bool dbExists = DatabaseExists(setupDbConfig, rootConfig);
        if (dbExists)
            Console.WriteLine($"(i) Database '{setupDbConfig.SqlApp.Database}' already exists on {rootConfig.Host}:{rootConfig.Port}.");

        var (dbContext, dbConnection) = CreateDatabaseConnection(rootConnStr);

        bool dbHasCa = CheckDatabase(dbConnection, setupDbConfig);
        bool hasArtifacts = File.Exists(certPath) || File.Exists(trustPath) || dbExists || dbHasCa;

        if (hasArtifacts)
        {
            if (!ConfirmDelete(true, certPath, trustPath, dbContext, dbConnection, setupDbConfig, wipeAuditDatabase))
                return 1;
        }
        else
        {
            // No existing artifacts — still ensure clean state (drop DBs/users if partially created)
            Console.WriteLine("(i) No existing artifacts found. Ensuring clean state...");
            DeleteArtifacts(certPath, trustPath);
            ReconstructDatabase(dbContext, dbConnection, setupDbConfig, wipeAuditDatabase);
        }

        // === Tenants (must precede CA and group creation) ===
        var systemTenant = dbContext.Tenants.FirstOrDefault(t => t.IsSystemTenant);
        if (systemTenant == null)
        {
            systemTenant = new TenantEntity
            {
                Name = "System",
                Slug = "system",
                Description = "Internal system tenant for infrastructure CAs and system groups",
                IsSystemTenant = true,
                CanBeDeleted = false,
                IsEnabled = true,
            };
            dbContext.Tenants.Add(systemTenant);
            dbContext.SaveChanges();
            Console.WriteLine("✓ System tenant created.");
        }

        // === Tenant-level permission groups for system tenant ===
        CreateTenantGroups(dbContext, systemTenant);

        var orgName = bootstrapConfig.CA.Subject.O ?? "Default";
        var orgSlug = orgName.ToLowerInvariant().Replace(" ", "-").Replace(".", "-");
        var orgTenant = dbContext.Tenants.FirstOrDefault(t => t.Slug == orgSlug);
        if (orgTenant == null)
        {
            orgTenant = new TenantEntity
            {
                Name = orgName,
                Slug = orgSlug,
                Description = $"Primary tenant for {orgName} certificate authorities",
                CanBeDeleted = false,
                IsEnabled = true,
            };
            dbContext.Tenants.Add(orgTenant);
            dbContext.SaveChanges();
            Console.WriteLine($"✓ Organization tenant '{orgName}' created.");
        }

        // === Tenant-level permission groups for org tenant ===
        CreateTenantGroups(dbContext, orgTenant);

        // === Built-in Roles & System Groups (must precede user creation) ===
        BootstrapProfileSeeder.SeedBuiltInRoles(dbContext);
        BootstrapProfileSeeder.CreateSystemGroups(dbContext, systemTenant.Id);

        // === OID Loading ===
        BootstrapProfileSeeder.LoadOidsToDb(dbContext, OIDConfig);

        var allowedRootCaStandardOids = new[] { "Digital Signature", "Key Encipherment", "Key Certificate Signing", "CRL Signing" };
        var allowedRootCaExtendedOids = new[] { "Server Authentication", "Client Authentication", "Code Signing", "Email Protection", "Time Stamping", "OCSP Signer" };

        var RootCaStandardOidsJson = BootstrapProfileSeeder.SetupAllowedStandardOidsJson(allowedRootCaStandardOids, dbContext);
        var RootCaExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(allowedRootCaExtendedOids, dbContext);

        var KeyAlgorithms = new List<string> { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };
        var KeySizes = new List<string> { "2048", "3072", "4096", "7680", "8192", "P-256", "P-384", "P-521" };
        var SignatureAlgorithms = new List<string> { "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };

        var KeyAlgorithmsJson = JsonSerializer.Serialize(KeyAlgorithms);
        var KeySizesJson = JsonSerializer.Serialize(KeySizes);
        var SignatureAlgorithmsJson = JsonSerializer.Serialize(SignatureAlgorithms);

        // === CA Certificate Profile & Signing Profile ===
        BootstrapProfileSeeder.CreateCertProfile(dbContext, "Main CA Certificate Profile", "Default cert profile for self-signed CA certificates",
            allowedRootCaStandardOids, allowedRootCaExtendedOids, false, true,
            KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson, "P5Y", "P25Y");
        var caCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Main CA Certificate Profile");
        var allowedCertExtendedOids = new[] { "Server Authentication", "Client Authentication", "Email Protection" };
        var CertExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(allowedCertExtendedOids, dbContext);
        var caCn = bootstrapConfig.CA.Subject.CN ?? "ModularCA";
        var signingProfileName = $"{caCn} Signing Profile";
        BootstrapProfileSeeder.CreateSigningProfile(dbContext, signingProfileName, $"Default signing profile for {caCn}",
            null, KeyAlgorithmsJson, CertExtendedOidsJson);
        var signingProfile = BootstrapProfileSeeder.GetSigningProfileFromDb(dbContext, signingProfileName);
        BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, caCertProfile, signingProfile);
        var theOUs = bootstrapConfig.CA.Subject.OU != null ? string.Join(",", bootstrapConfig.CA.Subject.OU) : string.Empty;

        // === Self-Signed CA Certificate ===
        var caCertRequest = BootstrapCertCreator.CreateCertificateRequest(bootstrapConfig.CA.Subject.CN ?? throw new Exception("The CA Subject CN was not found"), bootstrapConfig.CA.Subject.O ?? throw new Exception("The CA Subject O was not found"), theOUs,
            bootstrapConfig.CA.Subject.L ?? throw new Exception("The CA Subject L was not found"), bootstrapConfig.CA.Subject.ST ?? throw new Exception("The CA Subject ST was not found"), bootstrapConfig.CA.Subject.C ?? throw new Exception("The CA Subject C was not found"), bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(bootstrapConfig.CA.ValidityYears), signingProfile.Id, allowedRootCaStandardOids, allowedRootCaExtendedOids, dbContext);

        var (signedCaCert, caPrivKey, caPrivateKeyDer) = BootstrapCertCreator.CreateSelfSignedCertificate(caCertRequest);

        // === ModularCA System Signing CA ===
        var sysCertRequest = BootstrapCertCreator.CreateCertificateRequest("ModularCA System Signing CA", "ModularCA", string.Empty,
            bootstrapConfig.CA.Subject.L, bootstrapConfig.CA.Subject.ST, bootstrapConfig.CA.Subject.C,
            bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize,
            DateTime.UtcNow, DateTime.UtcNow.AddYears(100), signingProfile.Id, allowedRootCaStandardOids, allowedRootCaExtendedOids, dbContext);
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

        BootstrapCertCreator.CreateCertificateAuthority(dbContext, caCertEntity, type: "Root", isDefault: true, tenantId: orgTenant.Id);
        BootstrapCertCreator.CreateCertificateAuthority(dbContext, sysCertEntity, type: "Root", isDefault: false, label: "system-signing-ca", tenantId: systemTenant.Id);

        var caCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, caCertEntity.CertificateId);
        var sysCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, sysCertEntity.CertificateId);

        // === CA-Scoped Groups (must follow CA creation, precede admin user creation) ===
        BootstrapProfileSeeder.CreateCaGroups(dbContext, caCertCaEntity, orgTenant.Id);
        BootstrapProfileSeeder.CreateCaGroups(dbContext, sysCertCaEntity, systemTenant.Id);

        // === Backfill tenant IDs for any CAs/groups created without one ===
        var unassignedCas = dbContext.CertificateAuthorities
            .Where(ca => ca.TenantId == Guid.Empty)
            .ToList();
        foreach (var ca in unassignedCas)
        {
            ca.TenantId = ca.Label == "system-signing-ca" ? systemTenant.Id : orgTenant.Id;
        }
        if (unassignedCas.Count > 0)
        {
            dbContext.SaveChanges();
            Console.WriteLine($"✓ Backfilled TenantId on {unassignedCas.Count} CA(s).");
        }

        var unassignedGroups = dbContext.CaGroups
            .Where(g => g.TenantId == Guid.Empty)
            .ToList();
        foreach (var group in unassignedGroups)
        {
            if (group.IsSystemGroup)
            {
                group.TenantId = systemTenant.Id;
            }
            else if (group.CertificateAuthorityId != null)
            {
                var ownerCa = dbContext.CertificateAuthorities.FirstOrDefault(ca => ca.Id == group.CertificateAuthorityId);
                group.TenantId = ownerCa?.TenantId ?? orgTenant.Id;
            }
            else
            {
                group.TenantId = orgTenant.Id;
            }
        }
        if (unassignedGroups.Count > 0)
        {
            dbContext.SaveChanges();
            Console.WriteLine($"✓ Backfilled TenantId on {unassignedGroups.Count} group(s).");
        }

        // mTLS signing is a configured item — system-tenant groups never use mTLS, and
        // mTLS signing CAs must be non-Root issuing/intermediate CAs (Root CAs don't
        // sign end-entity certs directly). Clear legacy mTLS assignments on system groups;
        // admins attach an mTLS signing CA to an org group after they've created one.
        foreach (var systemGroup in dbContext.CaGroups.Where(g => g.IsSystemGroup && g.MtlsSigningCaId != null))
            systemGroup.MtlsSigningCaId = null;
        dbContext.SaveChanges();

        // === Seed request profiles and per-CA protocol configs ===
        var requestProfiles = BootstrapProfileSeeder.SeedDefaultRequestProfiles(dbContext);
        BootstrapProfileSeeder.SeedProtocolConfigs(dbContext, caCertCaEntity, signingProfile, nonCaCertProfile, requestProfiles);
        // System CA: every protocol hardcoded disabled. Belt-and-suspenders alongside
        // ReservedCaLabelGuardMiddleware; even if the guard is lifted, the DB row says "off".
        BootstrapProfileSeeder.SeedSystemCaProtocolConfigs(dbContext, sysCertCaEntity);

        // Auto-generate service URLs (AIA/CDP) for the public CA
        var publicBaseUrl = "http://localhost:" + bootstrapConfig.HttpsApi.Port;
        var firstDnsSan = bootstrapConfig.HttpsApi.SANs
            .Where(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Substring(4))
            .FirstOrDefault(s => s != "localhost");
        if (!string.IsNullOrEmpty(firstDnsSan))
            publicBaseUrl = $"http://{firstDnsSan}";

        BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, caCertEntity, publicBaseUrl, caCertCaEntity.Label ?? "default");
        BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, sysCertEntity, publicBaseUrl, sysCertCaEntity.Label ?? "system-signing-ca");

        BootstrapProfileSeeder.SeedPasswordPolicy(dbContext);
        BootstrapProfileSeeder.SeedSecurityPolicy(dbContext);

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

        if (dbConnection.State == ConnectionState.Open)
        {
            dbConnection.Close();
        }

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
        var pendingSans = httpsApi.SANs;
        var pendingValidityDays = httpsApi.ValidityDays;

        // === Create dedicated MySQL users and generate config.yaml ===
        var (appUserPassword, auditUserPassword) = BootstrapDatabaseSetup.CreateDatabaseUsers(rootConfig, setupDbConfig, wipeAuditDatabase);
        BootstrapDatabaseSetup.WriteConfigFile(configDir, rootConfig, setupDbConfig, bootstrapConfig, appUserPassword, auditUserPassword,
            pfxPassword: "", // No PFX yet — Stage 2 generates it
            httpsPort: bootstrapConfig.HttpsApi.Port,
            httpPort: 8080,
            security: null,
            network: null,
            pendingSubjectDn: pendingSubjectDn,
            pendingSans: pendingSans,
            pendingValidityDays: pendingValidityDays);

        // === Write db.yaml with generated app credentials ===
        var dbYamlPath = Path.Combine(configDir, "db.yaml");
        var (appUser, _) = BootstrapDatabaseSetup.ResolveMysqlUser(setupDbConfig.SqlApp.Username, rootConfig.Host);
        var (auditUser, _) = BootstrapDatabaseSetup.ResolveMysqlUser(setupDbConfig.SqlAudit.Username, rootConfig.Host);
        // Carry the operator-selected TLS mode (round-tripped through
        // setup-database.yaml) into db.yaml. Normalize via MySqlSslMode so unparseable values
        // land on Required instead of writing a typo that a later loader would clamp anyway.
        var appSslModeString = (Enum.TryParse<MySqlSslMode>(setupDbConfig.SqlApp.SslMode, ignoreCase: true, out var _appSsl)
            ? _appSsl : MySqlSslMode.Required).ToString();
        var auditSslModeString = (Enum.TryParse<MySqlSslMode>(setupDbConfig.SqlAudit.SslMode, ignoreCase: true, out var _auditSsl)
            ? _auditSsl : MySqlSslMode.Required).ToString();
        YamlDbConfigLoader.Write(dbYamlPath, new YamlDbConfigLoader.DbYamlConfig
        {
            App = new YamlDbConfigLoader.DbInstanceConfig
            {
                Host = rootConfig.Host,
                Port = rootConfig.Port,
                Database = setupDbConfig.SqlApp.Database,
                Username = appUser,
                Password = appUserPassword,
                SslMode = appSslModeString
            },
            Audit = new YamlDbConfigLoader.DbInstanceConfig
            {
                Host = rootConfig.Host,
                Port = rootConfig.Port,
                Database = setupDbConfig.SqlAudit.Database,
                Username = auditUser,
                Password = auditUserPassword,
                SslMode = auditSslModeString
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
    /// Auto-generates the four tenant-level permission groups (admin, operator, auditor, user)
    /// for the given tenant. These groups have <c>CertificateAuthorityId = null</c> (not CA-scoped)
    /// and grant access to ALL CAs within the tenant.
    /// </summary>
    public static void CreateTenantGroups(ModularCADbContext dbContext, TenantEntity tenant)
    {
        var tenantRoles = new[]
        {
            ("Administrator", "admin", "Admin"),
            ("Operator", "operator", "Operator"),
            ("Auditor", "auditor", "Auditor"),
            ("Requester", "user", "User")
        };

        foreach (var (templateName, suffix, displaySuffix) in tenantRoles)
        {
            var groupName = $"org-{tenant.Slug}-{suffix}";
            if (!dbContext.CaGroups.Any(g => g.Name == groupName))
            {
                var group = new CaGroupEntity
                {
                    Name = groupName,
                    DisplayName = $"Org {tenant.Name} {displaySuffix}",
                    CertificateAuthorityId = null, // Tenant-wide, not CA-specific
                    TemplateName = templateName,
                    IsSystemGroup = false,
                    IsAutoGenerated = true,
                    TenantId = tenant.Id,
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
        Console.WriteLine($"✓ Tenant-level groups created for '{tenant.Name}'.");
    }

    /// <summary>
    /// Creates a <see cref="ModularCADbContext"/> from a raw connection string
    /// using <see cref="DbContextOptionsBuilder{T}"/> and MySql auto-detection.
    /// </summary>
    public static ModularCADbContext CreateDbContext(string connectionString)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ModularCADbContext>();
        optionsBuilder.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
        return new ModularCADbContext(optionsBuilder.Options);
    }

    /// <summary>
    /// Creates a new database context and connection from the given connection string.
    /// Ensures the database schema is created.
    /// </summary>
    public static (ModularCADbContext, MySqlConnection dbConnect) CreateDatabaseConnection(string appConnStr)
    {
        var dbContext = CreateDbContext(appConnStr);
        var conn = new MySqlConnection(appConnStr);
        CreateDatabase(dbContext);
        conn.Open();
        return (dbContext, conn);
    }

    /// <summary>
    /// Ensures the database schema exists by applying EF Core migrations.
    /// <para>
    /// A failure is never "recovered" by dropping the database. This previously caught any
    /// exception and responded with <c>EnsureDeleted()</c> followed by a retry, on the theory
    /// that the failure meant a dirty schema left by a legacy <c>EnsureCreated</c> run. The catch
    /// was unqualified, so a lock-wait timeout or a connection drop mid-migration took the same
    /// branch — and <c>CreateDatabase</c> is reachable on every connection setup, including
    /// re-runs against a fully populated install.
    /// </para>
    /// <para>
    /// A destructive path already exists for the legacy case and is explicitly opted into by the
    /// operator: <c>--reset --force</c>. Pointing at it is strictly better than guessing.
    /// </para>
    /// </summary>
    public static void CreateDatabase(ModularCADbContext dbConnection)
    {
        try
        {
            dbConnection.Database.Migrate();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Migration failed: {ex.Message}");
            Console.WriteLine("    The database has NOT been modified.");
            Console.WriteLine("    If this is transient (lock timeout, connection drop), retry.");
            Console.WriteLine("    If the schema predates migrations and you intend to discard it,");
            Console.WriteLine("    run the reset explicitly:  --reset --force --confirm-db-name <database>");
            throw;
        }
    }

    /// <summary>
    /// Applies EF Core migrations to the audit database using root credentials.
    /// Called during setup to ensure the audit schema is created alongside the app schema.
    /// </summary>
    public static void CreateAuditDatabase(YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig, string auditDbName)
    {
        // Honor the operator-selected TLS mode; clamp typos to Required.
        var rootSslMode = Enum.TryParse<MySqlSslMode>(
            rootConfig.SslMode, ignoreCase: true, out var _rootSsl)
            ? _rootSsl : MySqlSslMode.Required;
        var connBuilder = new MySqlConnectionStringBuilder
        {
            Server = rootConfig.Host,
            Port = (uint)rootConfig.Port,
            UserID = rootConfig.Username,
            Password = rootConfig.Password,
            Database = auditDbName,
            SslMode = rootSslMode
        };
        CreateAuditDatabase(connBuilder.ConnectionString, auditDbName);
    }

    /// <summary>
    /// Applies EF Core migrations to the audit database using the provided connection string.
    /// </summary>
    public static void CreateAuditDatabase(string connectionString, string auditDbName)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AuditDbContext>();
        optionsBuilder.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
        using var auditDb = new AuditDbContext(optionsBuilder.Options);
        try
        {
            auditDb.Database.Migrate();
            Console.WriteLine($"✓ Audit database '{auditDbName}' schema applied via migrations.");
        }
        catch (Exception ex)
        {
            // Same reasoning as CreateDatabase: never drop on a failure we have not diagnosed.
            // The audit schema is evidence, so silently rebuilding it is the worst possible
            // response to a transient fault.
            Console.WriteLine($"(!) Audit migration failed: {ex.Message}");
            Console.WriteLine($"    Audit database '{auditDbName}' has NOT been modified.");
            Console.WriteLine("    Retry if transient; discard deliberately via --reset --force if not.");
            throw;
        }
    }

    /// <summary>
    /// Checks whether the target database already exists on the MySQL server.
    /// </summary>
    public static bool DatabaseExists(YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig, YamlSetupDatabaseLoader.SqlConnectionConfig rootConfig)
    {
        // Honor the operator-selected TLS mode for the existence probe;
        // clamp typos to Required so a misconfigured value can't silently disable TLS.
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
        var serverConnStr = serverConnBuilder.ConnectionString;
        try
        {
            using var conn = new MySqlConnection(serverConnStr);
            conn.Open();
            using var cmd = new MySqlCommand(
                "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = @db", conn);
            cmd.Parameters.AddWithValue("@db", setupDbConfig.SqlApp.Database);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(i) Could not check database existence — reason: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Checks whether the database already contains CA certificate records.
    /// </summary>
    public static bool CheckDatabase(MySqlConnection conn, YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig)
    {
        bool dbhasCa = false;

        try
        {

            using var cmd = new MySqlCommand(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = @db AND table_name = 'Certificates'", conn);
            cmd.Parameters.AddWithValue("@db", setupDbConfig.SqlApp.Database);

            var exists = Convert.ToInt32(cmd.ExecuteScalar()) > 0;
            if (exists)
            {
                using var checkCmd = new MySqlCommand("SELECT COUNT(*) FROM Certificates WHERE IsCa = 1", conn);
                dbhasCa = Convert.ToInt32(checkCmd.ExecuteScalar()) > 0;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(i) Skipping CA check — reason: {ex.Message}");
        }
        return dbhasCa;
    }

    /// <summary>
    /// Returns true if bootstrap should proceed, false if the user aborted.
    /// Prompts the user three times to confirm destruction of existing artifacts.
    /// </summary>
    public static bool ConfirmDelete(bool needsConfirm, string certPath, string trustPath, ModularCADbContext db, MySqlConnection conn, YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig, bool wipeAuditDatabase = false)
    {
        if (!needsConfirm)
            return true;

        Console.WriteLine("⚠️  Existing CA artifacts detected.");
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
        DeleteArtifacts(certPath, trustPath);
        ReconstructDatabase(db, conn, setupDbConfig, wipeAuditDatabase);
        return true;
    }

    /// <summary>
    /// Deletes existing keystore files from disk.
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
    }

    /// <summary>
    /// Drops and recreates both app and audit databases, and drops existing DB users
    /// so they can be cleanly recreated during bootstrap.
    /// </summary>
    /// <param name="wipeAuditDatabase">
    /// When true the audit database is dropped along with the app database. Default false.
    /// <para>
    /// This drop used to be unconditional, and it is the one that actually destroyed audit
    /// history on the CLI path — <c>Run</c> calls this before it ever reaches
    /// <c>CreateDatabaseUsers</c>, so making only that method conditional would have preserved
    /// nothing here. The point of a tamper-evident audit trail is that it outlives someone
    /// destroying the install, which is precisely what this method does.
    /// </para>
    /// </param>
    public static void ReconstructDatabase(ModularCADbContext db, MySqlConnection conn, YamlSetupDatabaseLoader.SetupDatabaseConfig setupDbConfig, bool wipeAuditDatabase = false)
    {
        // Validate all identifiers before any DROP/CREATE SQL
        BootstrapDatabaseSetup.ValidateIdentifier(setupDbConfig.SqlApp.Database, "app database name");
        if (!string.IsNullOrWhiteSpace(setupDbConfig.SqlAudit.Database))
            BootstrapDatabaseSetup.ValidateIdentifier(setupDbConfig.SqlAudit.Database, "audit database name");
        if (!string.IsNullOrWhiteSpace(setupDbConfig.SqlApp.Username))
            BootstrapDatabaseSetup.ValidateIdentifier(setupDbConfig.SqlApp.Username, "app username");
        if (!string.IsNullOrWhiteSpace(setupDbConfig.SqlAudit.Username))
            BootstrapDatabaseSetup.ValidateIdentifier(setupDbConfig.SqlAudit.Username, "audit username");

        // Drop app database
        try
        {
            using var dropAppCmd = new MySqlCommand($"DROP DATABASE IF EXISTS `{setupDbConfig.SqlApp.Database}`", conn);
            dropAppCmd.ExecuteNonQuery();
            Console.WriteLine($"✓ Dropped app database '{setupDbConfig.SqlApp.Database}'");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Failed to drop app database: {ex.Message}");
        }

        // Drop audit database — only when the operator explicitly asked to.
        try
        {
            var auditDbName = setupDbConfig.SqlAudit.Database;
            if (!wipeAuditDatabase)
            {
                Console.WriteLine($"(i) Audit database '{auditDbName}' preserved (pass --wipe-audit to discard).");
            }
            else if (!string.IsNullOrWhiteSpace(auditDbName))
            {
                using var dropAuditCmd = new MySqlCommand($"DROP DATABASE IF EXISTS `{auditDbName}`", conn);
                dropAuditCmd.ExecuteNonQuery();
                Console.WriteLine($"✓ Dropped audit database '{auditDbName}'");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Failed to drop audit database: {ex.Message}");
        }

        // Drop existing DB users (they'll be recreated by CreateDatabaseUsers)
        try
        {
            var appUser = setupDbConfig.SqlApp.Username;
            var auditUser = setupDbConfig.SqlAudit.Username;
            if (!string.IsNullOrWhiteSpace(appUser))
            {
                using var dropAppUser = new MySqlCommand($"DROP USER IF EXISTS '{appUser}'@'%'", conn);
                dropAppUser.ExecuteNonQuery();
                // Also try localhost variant
                using var dropAppUserLocal = new MySqlCommand($"DROP USER IF EXISTS '{appUser}'@'localhost'", conn);
                dropAppUserLocal.ExecuteNonQuery();
                Console.WriteLine($"✓ Dropped app DB user '{appUser}'");
            }
            if (!string.IsNullOrWhiteSpace(auditUser))
            {
                using var dropAuditUser = new MySqlCommand($"DROP USER IF EXISTS '{auditUser}'@'%'", conn);
                dropAuditUser.ExecuteNonQuery();
                using var dropAuditUserLocal = new MySqlCommand($"DROP USER IF EXISTS '{auditUser}'@'localhost'", conn);
                dropAuditUserLocal.ExecuteNonQuery();
                Console.WriteLine($"✓ Dropped audit DB user '{auditUser}'");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Failed to drop DB users: {ex.Message}");
        }

        // Recreate app database and apply schema via migrations (EnsureCreated fails with FK ordering)
        try
        {
            using var createCmd = new MySqlCommand($"CREATE DATABASE IF NOT EXISTS `{setupDbConfig.SqlApp.Database}`", conn);
            createCmd.ExecuteNonQuery();
            db.Database.Migrate();
            Console.WriteLine($"✓ App database '{setupDbConfig.SqlApp.Database}' recreated with schema via migrations");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!!) Failed to recreate app database: {ex.Message}");
        }

        // Recreate audit database if it doesn't exist (audit tables survive resets by design)
        try
        {
            var auditDbName = setupDbConfig.SqlAudit.Database;
            if (!string.IsNullOrWhiteSpace(auditDbName))
            {
                using var createAuditCmd = new MySqlCommand($"CREATE DATABASE IF NOT EXISTS `{auditDbName}`", conn);
                createAuditCmd.ExecuteNonQuery();

                // Apply any pending audit migrations (preserves existing audit data).
                // SslMode is inherited from the source conn.ConnectionString
                // (built upstream with TLS-Required), so no explicit SslMode assignment is needed here.
                var auditConnBuilder = new MySqlConnectionStringBuilder(conn.ConnectionString)
                {
                    Database = auditDbName
                };
                CreateAuditDatabase(auditConnBuilder.ConnectionString, auditDbName);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"(!) Failed to recreate audit database: {ex.Message}");
        }
    }
}
