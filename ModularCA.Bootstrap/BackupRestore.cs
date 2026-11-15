using System.Buffers.Binary;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Npgsql;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModularCA.Bootstrap;

/// <summary>
/// Filenames that must NEVER be carried inside a backup archive — these are KEKs, plaintext
/// secret material, or cryptographic material that would defeat the purpose of encrypting the
/// archive. Both Backup() and Restore() consult this list: Backup excludes them at write time,
/// and Restore refuses to extract any archive that still contains a denylisted file (defense in
/// depth against legacy archives or third-party generators).
/// </summary>
internal static class BackupSecretDenylist
{
    /// <summary>Lower-case file names (no path) that are forbidden inside the backup archive.</summary>
    public static readonly HashSet<string> DenyFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "backup.key",            // RandomKey-mode KEK
        "backup-password.key",   // StoredPassword-mode derived KEK
        "keystore.yaml",         // plaintext secondary keystore passphrases
        "db.yaml",               // app/audit DB credentials (now sourced from secret manager)
        "setup-database.yaml",   // superuser database credentials used during bootstrap
        "api-tls.pfx",           // Web TLS PFX (private key on disk)
    };

    /// <summary>True when the given file name must not appear in any backup archive.</summary>
    public static bool IsDenied(string fileName) => DenyFileNames.Contains(fileName);
}

/// <summary>
/// Provides full backup and restore of ModularCA databases, keystores, and configuration,
/// including schema version tracking to detect incompatible database changes.
/// </summary>
/// <remarks>
/// The keystore material in a backup comes from the signer and goes back through it: a backup
/// asks <see cref="ISigningService.ExportKeyAsync"/> for each keystore file under the backup
/// wrap, which returns the file as the signer keeps it, encrypted under the keystore
/// passphrases and signed by the pinned signer; a restore offers each file back through
/// <see cref="ISigningService.ImportKeyAsync"/> under the restore context, and the signer
/// verifies the signature against the pin before anything in place changes. Nothing here reads
/// a keystore file or touches key material. The archive layout is unchanged: the files sit
/// under <c>keystores/</c> by name, so an archive from before the signer restores the same way.
/// <para>
/// SSH CA keys travel in the signer's SSH keystore, <c>ssh-ca.keystore</c>, the third of those
/// files, which an install without an SSH CA does not have. A key that is still a plaintext
/// file on the node, awaiting its import into the signer, travels wrapped by the signer with
/// its directory, wherever under <c>config/</c> the key rows say that directory is, and never
/// in the config copy. A restore of an archive with no SSH keystore has the signer move a
/// live one aside (<see cref="ReconcileAbsentSshKeystoreAsync"/>), and the key files it
/// brings back are imported at the next start.
/// </para>
/// </remarks>
public static class BackupRestore
{
    /// <summary>
    /// Archive member holding the application database, produced by <c>pg_dump --format=custom</c>.
    /// Archives taken before the PostgreSQL move carry <c>db-app.sql</c> instead; see
    /// <see cref="IsPrePostgresArchive"/>.
    /// </summary>
    private const string AppDumpFileName = "db-app.dump";

    /// <summary>Archive member holding the audit database, in the same format.</summary>
    private const string AuditDumpFileName = "db-audit.dump";

    /// <summary>
    /// True when an extracted archive is one taken from a MySQL/MariaDB installation: it holds
    /// <c>db-app.sql</c>, a mysqldump script, and no <c>db-app.dump</c>.
    /// <para>
    /// This exists so a restore fails by name rather than by omission. Without it the restore
    /// would look for a file that is not there, skip the database entirely, and go on to report
    /// success — leaving an operator who believed they had a working backup with an empty
    /// database and no error to explain it.
    /// </para>
    /// </summary>
    /// <param name="restoreDir">Directory the archive was extracted into.</param>
    /// <returns>True when the archive predates the PostgreSQL move.</returns>
    private static bool IsPrePostgresArchive(string restoreDir) =>
        File.Exists(Path.Combine(restoreDir, "db-app.sql"))
        && !File.Exists(Path.Combine(restoreDir, AppDumpFileName));

    /// <summary>The caller a backup names at the signer.</summary>
    private const string BackupCaller = "backup";

    /// <summary>The caller a restore names at the signer.</summary>
    private const string RestoreCaller = "restore";

    /// <summary>
    /// Creates a compressed backup archive containing databases, keystores, and configuration files.
    /// The backup manifest includes a schema version derived from the current database table names,
    /// and, from 0.4.5, what identifies the instance (<see cref="ReadInstanceIdAsync"/>), the product
    /// version that took the backup and the newest migration of each database; the manifest lies
    /// inside the archive's encryption, and <c>--backup-manifest</c> prints it.
    /// Validates that the output path and encryption key path do not escape the application directory.
    /// The archived <c>config.yaml</c> never carries a <c>DB</c> section: the credentials stay in
    /// <c>db.yaml</c>, which no archive carries. A database that cannot be dumped ends the backup
    /// with no archive, and the encryption key is loaded before any plaintext archive exists; one
    /// left unencrypted by a later failure is deleted. Everything is staged in a fresh owner-only
    /// directory (<see cref="CreateBackupStagingDirectory"/>), removed when the backup ends; one
    /// that cannot be created owner-only ends the backup before anything is staged. The directory the
    /// archive goes in must be reachable by this account alone (<see cref="EnsureArchiveDirectory"/>):
    /// one others can reach is tightened when it is the backups' own, and otherwise ends the backup.
    /// </summary>
    /// <param name="outputPath">
    /// Optional explicit path for the output archive. When null, the archive goes to the configured
    /// <c>Backup.OutputPath</c> (default <c>backups/</c>; see <see cref="ResolveBackupDirectory"/>).
    /// Either way it must lie inside the application directory.
    /// </param>
    /// <param name="signerForAppDatabase">
    /// Resolves the signer the keystore files are exported through, given the application
    /// database's connection string; the node passes its own signer and ignores the argument,
    /// the command line builds a maintenance signer over it.
    /// </param>
    /// <returns>0 on success, non-zero on failure.</returns>
    public static async Task<int> Backup(string? outputPath, Func<string, ISigningService> signerForAppDatabase)
    {
        ArgumentNullException.ThrowIfNull(signerForAppDatabase);
        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var configPath = Path.Combine(configDir, "config.yaml");

        if (!File.Exists(configPath))
        {
            Console.WriteLine("❌ config.yaml not found. Cannot backup — has bootstrap been run?");
            return 1;
        }

        var config = YamlConfigLoader.Load(configPath);
        OverlayDbYaml(config, configDir);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var backupName = $"modularca-backup-{timestamp}";

        var archivePath = ResolveArchivePath(outputPath, AppContext.BaseDirectory, config.Backup?.OutputPath, backupName);
        if (!TryEnsureArchiveDirectory(Path.GetDirectoryName(archivePath)!, AppContext.BaseDirectory,
                ResolveBackupDirectory(AppContext.BaseDirectory, config.Backup?.OutputPath), "Backup"))
            return 1;

        // Plaintext keystores and config are copied in here before the archive is encrypted, so
        // a staging directory nobody else can read is a precondition, not a nicety: see
        // CreateBackupStagingDirectory. Without one the backup stops before writing anything.
        string backupDir;
        try
        {
            backupDir = CreateBackupStagingDirectory();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.WriteLine($"❌ Could not create a staging directory only this user can read: {ex.Message}");
            Console.WriteLine("   Backup stopped before anything was staged.");
            return 1;
        }
        string? plaintextArchive = null;

        try
        {
            Console.WriteLine($"📦 Creating backup: {backupName}");

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(config.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(config.DB.Audit.Database, "audit database name");

            // 0. The head of the signer's issuance journal, read before the database is dumped:
            // records the signer writes while the dump runs may then already be in the dump,
            // never the other way about, so a reader that starts at this head misses nothing.
            // The signer is made here for that reason and used again for the keystores below.
            var signer = signerForAppDatabase(AppConnectionString(config));
            var journalHead = await ReadJournalHeadAsync(signer, config);
            Console.WriteLine(journalHead == null
                ? "  Signer journal head: none (the signer keeps no journal, or it could not be read)"
                : $"  Signer journal head: sequence {journalHead.Seq}");

            // 1. Database dumps
            //
            // pg_dump in its custom format, not a plain SQL script. The custom format is
            // compressed, carries its own table of contents, and is what pg_restore needs in
            // order to restore inside a single transaction — so a restore that fails halfway
            // leaves the database as it was rather than half-replaced. The archive member is
            // therefore db-app.dump, not db-app.sql; see RestoreAsync for how an archive taken
            // before this change is recognised and refused rather than silently skipped.
            // A dump that fails ends the backup: an archive without its database restores nothing.
            var toolTimeoutMs = DatabaseToolTimeoutMs(config.Backup);
            var appDumpPath = Path.Combine(backupDir, AppDumpFileName);
            if (!await DumpDatabaseAsync("app", config.DB.App, appDumpPath, toolTimeoutMs))
                return 1;

            if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database)
                && !await DumpDatabaseAsync("audit", config.DB.Audit, Path.Combine(backupDir, AuditDumpFileName), toolTimeoutMs))
                return 1;

            // 2. Keystores, through the signer. Each file arrives as the signer keeps it, already
            // encrypted and signed, and is written under keystores/ by name as before.
            var backupKeystores = Path.Combine(backupDir, "keystores");
            Console.Write("  Exporting keystores...");
            var exported = await ExportKeystoresAsync(signer, BackupCaller);
            if (exported.Count > 0)
            {
                Directory.CreateDirectory(backupKeystores);
                foreach (var (name, bytes) in exported)
                    File.WriteAllBytes(Path.Combine(backupKeystores, name), bytes);
            }
            Console.WriteLine($" ✓ ({exported.Count} file(s))");

            // 3. The Data Protection key ring travels wrapped by the signer, never in the clear:
            // with the database dump it opens every DP-protected column. So does every SSH CA
            // key that is still a file on this node. Where those files are is read from the key
            // rows, since no setting names their directory any more; a backup that cannot read
            // them is not written, because it could not tell which files to keep out.
            IReadOnlyList<string> legacyKeyFiles;
            try
            {
                legacyKeyFiles = await LegacySshKeyFilesAsync(AppConnectionString(config));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ The SSH CA key rows could not be read ({ex.GetType().Name}: {ex.Message}).");
                Console.WriteLine("   A backup is not written without knowing where SSH CA key files lie: they are never copied");
                Console.WriteLine("   into an archive in the clear.");
                return 1;
            }
            var wrappedTargets = BackupWrappedSecrets.Targets(configDir, legacyKeyFiles);
            var looseKeyFiles = BackupWrappedSecrets.LooseLegacyKeyFiles(configDir, legacyKeyFiles);
            Console.Write("  Wrapping configuration secrets...");
            IReadOnlyList<string> wrapped;
            try
            {
                wrapped = await BackupWrappedSecrets.WrapAsync(signer, configDir, wrappedTargets,
                    Path.Combine(backupDir, BackupWrappedSecrets.ArchiveDirectory), BackupCaller);
            }
            catch (SigningRefusedException ex)
            {
                Console.WriteLine();
                Console.WriteLine($"❌ The signer refused to wrap the configuration secrets: {ex.Message}");
                Console.WriteLine("   The Data Protection key ring is never written to a backup in the clear. Take the backup");
                Console.WriteLine("   from the console or the scheduler while the signer is unlocked, or run --backup on the");
                Console.WriteLine("   host that holds the keystore and keystore.yaml.");
                return 1;
            }
            Console.WriteLine(wrapped.Count > 0 ? $" ✓ ({string.Join(", ", wrapped)})" : " (none present)");

            // 4. Copy config — explicit deny-list to keep KEKs and secret-bearing
            // files OUT of the archive that they protect. Anything matching the denylist is
            // skipped and announced so operators can see what was excluded; the wrapped
            // directories are left out because their wrapped copies are already in the archive.
            var backupConfig = Path.Combine(backupDir, "config");
            Console.Write("  Copying config...");
            CopyDirectoryFiltered(configDir, backupConfig, wrappedTargets, out var skippedDenied, looseKeyFiles);
            if (looseKeyFiles.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"  ⚠ SSH CA key file(s) lie directly in config/ and are left out of the archive: {string.Join(", ", looseKeyFiles)}.");
                Console.WriteLine("    They await their import into the signer; once imported, the keys travel in the signer's SSH keystore.");
            }
            // A config.yaml saved by an earlier build can carry the db.yaml credentials under DB:.
            var archivedConfigYaml = Path.Combine(backupConfig, "config.yaml");
            if (File.Exists(archivedConfigYaml))
                File.WriteAllText(archivedConfigYaml, ConfigYamlWriter.WithoutDbSection(File.ReadAllText(archivedConfigYaml)));
            Console.WriteLine(" ✓");
            if (skippedDenied.Count > 0)
            {
                Console.WriteLine($"  Excluded {skippedDenied.Count} secret-bearing file(s) from archive: {string.Join(", ", skippedDenied)}");
            }

            // 5. Compute schema version from database table list
            Console.Write("  Computing schema version...");
            var schemaVersion = await ComputeSchemaVersionAsync(config);
            Console.WriteLine($" {schemaVersion}");

            // 6. Collect entity counts for manifest
            Console.Write("  Collecting entity counts...");
            var (caCount, certCount, userCount) = await CountEntitiesAsync(config);
            Console.WriteLine($" CAs={caCount}, Certs={certCount}, Users={userCount}");

            // What identifies this instance, the build that took the backup and the newest
            // migration of each database, so that an archive can say what it is before anyone
            // restores it (--backup-manifest). They lie inside the archive's encryption.
            var instanceId = await ReadInstanceIdAsync(AppConnectionString(config));
            var productVersion = BackupManifestCommand.ProductVersion();
            var latestMigration = await ReadLatestMigrationAsync(AppConnectionString(config));
            var latestAuditMigration = string.IsNullOrWhiteSpace(config.DB.Audit.Database) ? null
                : await ReadLatestMigrationAsync(ModularCA.Shared.Utils.PostgresConnection.Build(config.DB.Audit));

            // 7. Check integrity indicators
            var keystoreIntegrity = exported.Count > 0;
            var dbIntegrity = File.Exists(appDumpPath) && new FileInfo(appDumpPath).Length > 0;

            // 8. Write manifest (includes schema version and extended metadata)
            var manifest = new
            {
                Version = "1.0",
                Timestamp = DateTime.UtcNow,
                AppDatabase = config.DB.App.Database,
                AuditDatabase = config.DB.Audit.Database,
                MachineName = Environment.MachineName,
                InstanceId = instanceId,
                ProductVersion = productVersion,
                LatestMigration = latestMigration,
                LatestAuditMigration = latestAuditMigration,
                SchemaVersion = schemaVersion,
                CaCount = caCount,
                CertCount = certCount,
                UserCount = userCount,
                KeystoreIntegrity = keystoreIntegrity,
                DbIntegrity = dbIntegrity,
                WrappedSecrets = wrapped,
                JournalHead = journalHead,
                BackupSizeBytes = 0L // placeholder, updated after archive creation
            };
            var manifestPath = Path.Combine(backupDir, "manifest.json");
            File.WriteAllText(manifestPath,
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

            // 9. The encryption key, before any plaintext archive exists: a missing key ends the
            // backup with nothing written.
            var mode = BackupKeyManager.ParseMode(config.Backup?.EncryptionMode);

            // Resolve RandomKey path (containment check uses GetRelativePath helper).
            var keyRelativePath = config.Backup?.EncryptionKeyPath ?? "config/backup.key";
            if (keyRelativePath.Contains("..") || Path.IsPathRooted(keyRelativePath))
                throw new InvalidOperationException("Invalid backup encryption key path — must be relative without '..' sequences.");
            var randomKeyPath = Path.Combine(AppContext.BaseDirectory, keyRelativePath);
            if (!PathIsContainedIn(randomKeyPath, AppContext.BaseDirectory))
                throw new InvalidOperationException("Backup encryption key path escapes application directory.");

            // Resolve StoredPassword path
            var passwordRelativePath = config.Backup?.PasswordFilePath ?? "config/backup-password.key";
            if (passwordRelativePath.Contains("..") || Path.IsPathRooted(passwordRelativePath))
                throw new InvalidOperationException("Invalid backup password file path — must be relative without '..' sequences.");
            var passwordKeyPath = Path.Combine(AppContext.BaseDirectory, passwordRelativePath);
            if (!PathIsContainedIn(passwordKeyPath, AppContext.BaseDirectory))
                throw new InvalidOperationException("Backup password file path escapes application directory.");

            // Load the KEK + scrypt params. FileNotFoundException bubbles up as-is.
            var (key, saltOrNull, scryptN, scryptR, scryptP) =
                BackupKeyManager.LoadEncryptionKey(mode, randomKeyPath, passwordKeyPath);
            if (mode == BackupEncryptionMode.StoredPassword && BackupKeyManager.IsBelowDefaultCost(scryptN, scryptR))
            {
                Console.WriteLine($"  ⚠ The stored backup password was derived with scrypt N={scryptN}, r={scryptR}, below this build's");
                Console.WriteLine($"    N={BackupKeyManager.DefaultScryptN}, r={BackupKeyManager.DefaultScryptR}. Set the backup password again to raise it for new archives.");
            }

            // 10. Create archive (its path was resolved and contained above).
            Console.Write($"  Creating archive...");
            // Refuse to silently overwrite an existing archive.
            if (File.Exists(archivePath))
            {
                BackupKeyManager.ZeroKey(key);
                throw new InvalidOperationException(
                    $"Backup archive already exists at '{archivePath}'. Refusing to overwrite — choose a different output path or delete the existing file.");
            }
            plaintextArchive = archivePath;
            // The plaintext archive holds the database dumps and config/. It is a new owner-only
            // file from the moment it exists, not one zipped at default permissions and
            // restricted afterwards.
            FileSecurityUtil.CreateOwnerOnly(archivePath, stream => ZipFile.CreateFromDirectory(backupDir, stream));
            Console.WriteLine(" ✓");

            // 11. Update manifest with final archive size and rewrite into the archive
            var archiveSize = new FileInfo(archivePath).Length;
            var updatedManifest = new
            {
                Version = "1.0",
                Timestamp = manifest.Timestamp,
                AppDatabase = config.DB.App.Database,
                AuditDatabase = config.DB.Audit.Database,
                MachineName = Environment.MachineName,
                InstanceId = instanceId,
                ProductVersion = productVersion,
                LatestMigration = latestMigration,
                LatestAuditMigration = latestAuditMigration,
                SchemaVersion = schemaVersion,
                CaCount = caCount,
                CertCount = certCount,
                UserCount = userCount,
                KeystoreIntegrity = keystoreIntegrity,
                DbIntegrity = dbIntegrity,
                WrappedSecrets = wrapped,
                JournalHead = journalHead,
                BackupSizeBytes = archiveSize
            };
            using (var zipStream = new FileStream(archivePath, FileMode.Open, FileAccess.ReadWrite))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Update))
            {
                var entry = archive.GetEntry("manifest.json");
                entry?.Delete();
                var newEntry = archive.CreateEntry("manifest.json");
                using var writer = new StreamWriter(newEntry.Open());
                writer.Write(JsonSerializer.Serialize(updatedManifest, new JsonSerializerOptions { WriteIndented = true }));
            }

            // Encrypt the backup archive using the configured mode
            byte[]? plaintext = null;
            byte[]? ciphertext = null;
            try
            {
                // Defense-in-depth: verify key length even though LoadEncryptionKey already checks it.
                if (key.Length != BackupKeyManager.KeySize)
                    throw new InvalidOperationException(
                        $"Backup encryption key must be {BackupKeyManager.KeySize} bytes, got {key.Length}.");

                plaintext = File.ReadAllBytes(archivePath);
                var nonce = RandomNumberGenerator.GetBytes(BackupKeyManager.NonceSize);
                ciphertext = new byte[plaintext.Length];
                var tag = new byte[BackupKeyManager.TagSize];

                using (var aes = new AesGcm(key, BackupKeyManager.TagSize))
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag);
                }

                // Write new-format encrypted archive:
                // [4 magic][1 version][1 mode][16 salt][8 N][4 r][4 p][12 nonce][16 tag][ciphertext]
                var encPath = archivePath.Replace(".zip", ".enc");
                FileSecurityUtil.CreateOwnerOnly(encPath, fs =>
                {
                    fs.Write(BackupKeyManager.MagicBytes);
                    fs.WriteByte(BackupKeyManager.FormatVersion);
                    fs.WriteByte((byte)mode);

                    // Salt (16 bytes): real salt in StoredPassword mode, zero-filled in RandomKey mode.
                    var saltBytes = saltOrNull ?? new byte[BackupKeyManager.SaltSize];
                    if (saltBytes.Length != BackupKeyManager.SaltSize)
                        throw new InvalidOperationException($"Unexpected salt length {saltBytes.Length}.");
                    fs.Write(saltBytes);

                    // Scrypt params (16 bytes total): 8 N + 4 r + 4 p, little-endian.
                    var nBuf = new byte[8];
                    var rBuf = new byte[4];
                    var pBuf = new byte[4];
                    BinaryPrimitives.WriteInt64LittleEndian(nBuf, scryptN);
                    BinaryPrimitives.WriteInt32LittleEndian(rBuf, scryptR);
                    BinaryPrimitives.WriteInt32LittleEndian(pBuf, scryptP);
                    fs.Write(nBuf);
                    fs.Write(rBuf);
                    fs.Write(pBuf);

                    // Nonce, tag, ciphertext
                    fs.Write(nonce);
                    fs.Write(tag);
                    fs.Write(ciphertext);
                }, replaceExisting: true);

                File.Delete(archivePath); // Remove plaintext ZIP
                plaintextArchive = null;
                archiveSize = new FileInfo(encPath).Length;
                Console.WriteLine($"✓ Encrypted backup archive: {encPath} (mode: {mode})");
                archivePath = encPath;
            }
            finally
            {
                // Zero sensitive data from memory
                if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
                if (ciphertext != null) CryptographicOperations.ZeroMemory(ciphertext);
                BackupKeyManager.ZeroKey(key);
            }

            Console.WriteLine($"\n✅ Backup complete: {archivePath}");
            Console.WriteLine($"   Size: {archiveSize / 1024}KB");
            return 0;
        }
        finally
        {
            try { Directory.Delete(backupDir, true); } catch { }
            // An archive that was never encrypted holds both database dumps in the clear.
            if (plaintextArchive != null)
                try { File.Delete(plaintextArchive); } catch { }
        }
    }

    /// <summary>
    /// Dumps one database with <c>pg_dump</c> in custom format, as its runtime role, and says
    /// whether the dump is usable: the tool exited 0 and wrote a file that is not empty.
    /// </summary>
    /// <param name="label">How the database is named to the operator.</param>
    /// <param name="instance">The database and the role that dumps it.</param>
    /// <param name="dumpPath">Where the dump is written.</param>
    /// <param name="timeoutMs">How long the tool may run.</param>
    /// <returns>True when the dump can go into an archive.</returns>
    private static async Task<bool> DumpDatabaseAsync(string label, ModularCA.Shared.Models.Config.DbInstance instance, string dumpPath, int timeoutMs)
    {
        Console.Write($"  Dumping {label} database...");
        var passFile = WritePgPassFile(instance.Host, instance.Port, instance.Database, instance.Username, instance.Password);
        int exit;
        string stderr;
        try
        {
            (exit, _, stderr) = await RunPostgresToolAsync("pg_dump", new[]
            {
                "--host", instance.Host,
                "--port", instance.Port.ToString(),
                "--username", instance.Username,
                "--no-password",
                "--format=custom",
                "--file", dumpPath,
                instance.Database,
            }, passFile, timeoutMs);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            (exit, stderr) = (-1, $"pg_dump could not be started ({ex.Message}). It must be on the PATH of the account that runs ModularCA.");
        }
        finally
        {
            try { File.Delete(passFile); } catch { }
        }

        if (exit == 0 && File.Exists(dumpPath) && new FileInfo(dumpPath).Length > 0)
        {
            Console.WriteLine(" ✓");
            return true;
        }

        Console.WriteLine();
        Console.WriteLine($"❌ The {label} database '{instance.Database}' could not be dumped (exit {exit}): {stderr.Trim()}");
        Console.WriteLine("   No archive was written. A pg_dump older than the server is refused by pg_dump itself:");
        Console.WriteLine("   install the client tools of the server's major version or newer.");
        return false;
    }

    /// <summary>The time one <c>pg_dump</c> or <c>pg_restore</c> run may take, from <c>Backup.DatabaseTimeoutMinutes</c>.</summary>
    /// <param name="backup">The backup settings, or null for the default.</param>
    internal static int DatabaseToolTimeoutMs(ModularCA.Shared.Models.Config.BackupConfig? backup)
    {
        var minutes = Math.Max(1, backup?.DatabaseTimeoutMinutes ?? 60);
        return (int)Math.Min(int.MaxValue, minutes * 60_000L);
    }

    /// <summary>
    /// Restores databases, keystores, and configuration from a backup archive.
    /// Validates the schema version in the manifest against the current database before restoring,
    /// captures a pre-restore snapshot of the live state for rollback in the backup directory
    /// (<see cref="PreRestoreSnapshotPath"/>; a backup directory others can reach and that cannot be
    /// restricted ends the restore, see <see cref="EnsureArchiveDirectory"/>), and refuses
    /// archives that contain secret-bearing files on the deny-list.
    /// The databases are restored into the ones this host's own <c>config/db.yaml</c> names, with
    /// its credentials (<see cref="LoadRestoreTargetDatabases"/>); a host without one is refused
    /// before anything changes. Restored config files keep the access of the files they replace
    /// (<see cref="RestoreConfigFile"/>).
    /// An archive with no application database is refused before anything changes, and a
    /// database that cannot be restored ends the restore before a keystore or a config file is
    /// replaced. The CRL counters are raised and every CRL configuration made due
    /// (<see cref="CrlNumberFloor"/>), this machine's incarnation is stored in the restored
    /// database (<see cref="StoreIncarnationAfterRestoreAsync"/>) so the next start does not
    /// report the restore as a rollback, and this host's self-issued Web TLS certificate file is
    /// removed: the node issues a new one at its next start.
    /// The audit database is left as it is unless <paramref name="restoreAudit"/> asks for the
    /// archive's audit trail: audit history survives a restore, as it survives a reset, unless
    /// the operator deliberately replaces it.
    /// Supports both the new <c>.enc</c> format (magic "MCAB" + mode marker + scrypt header) and
    /// the legacy format (<c>[nonce][tag][ciphertext]</c>) for backward compatibility; which one a
    /// file is comes from its first bytes (<see cref="BackupArchiveFile.ReadZip"/>).
    /// An archive taken by a newer build is refused before anything changes
    /// (<see cref="RefuseNewerSchemaAsync"/>), and a database that cannot be reached is told apart
    /// from a refusal (<see cref="ProbeRestoreTargetAsync"/>).
    /// The archive is only read, so it may lie on a read-only mount. The last line written is the
    /// verdict of <see cref="RestoreWithVerdictAsync"/>, which this wraps.
    /// </summary>
    /// <param name="archivePath">Path to the backup archive: encrypted, or a plain ZIP.</param>
    /// <param name="restoreAudit">
    /// Whether the archive's audit database replaces this host's (<c>--restore-audit</c>). False,
    /// the default, keeps the live audit history and records the restore in it; true is for
    /// rebuilding a host whose own audit database is empty or lost.
    /// </param>
    /// <param name="skipSchemaCheck">When true, bypasses schema version validation (use with caution).</param>
    /// <param name="providedPassword">
    /// Optional plain-text password for disaster-recovery restoration of a StoredPassword-mode archive
    /// when the local <c>backup-password.key</c> file is missing or mismatched. When non-null, this
    /// password is used to re-derive the KEK via scrypt using the parameters stored in the archive header.
    /// </param>
    /// <param name="signerForAppDatabase">
    /// Resolves the signer the keystore files are imported through, given the connection
    /// string of the application database the archive is restored into; the node passes its
    /// own signer and ignores the argument, the command line builds a maintenance signer over it.
    /// </param>
    /// <param name="interactive">
    /// When true (CLI path), prompts on stdin for the literal "RESTORE" confirmation before any
    /// destructive action. When false (API path), the caller is expected to have enforced its own
    /// confirmation (step-up MFA + single-use restore token) and the prompt is skipped.
    /// </param>
    /// <param name="exclusion">
    /// How the restore gets the application database to itself (<see cref="RestoreOptions.Exclusion"/>);
    /// null takes the restore lock on a connection of its own, as the command line does.
    /// </param>
    /// <returns>
    /// A status from <see cref="RestoreExit"/>: 0 done, 3 refused with nothing changed, 4 failed
    /// after something was changed, 75 a database could not be reached and nothing was changed.
    /// </returns>
    public static async Task<int> Restore(string archivePath, Func<string, ISigningService> signerForAppDatabase, bool skipSchemaCheck = false, string? providedPassword = null, bool interactive = true, bool restoreAudit = false, ModularCA.Database.IRestoreExclusion? exclusion = null)
    {
        var result = await RestoreWithVerdictAsync(archivePath, signerForAppDatabase, new RestoreOptions
        {
            SkipSchemaCheck = skipSchemaCheck,
            Interactive = interactive,
            RestoreAudit = restoreAudit,
            Keys = new BackupKeySource(Password: providedPassword),
            Exclusion = exclusion,
        });
        Console.WriteLine(result.Verdict);
        return result.ExitCode;
    }

    /// <summary>Whether a restore has changed anything yet; see <see cref="RestoreWithVerdictAsync"/>.</summary>
    private sealed class RestoreProgress
    {
        /// <summary>
        /// True from the moment a database restore committed, or ended without its outcome known.
        /// Every failure while this is false leaves both databases, the keystores and the config
        /// directory as they were.
        /// </summary>
        public bool Changed;
    }

    /// <summary>
    /// The restore behind <see cref="Restore"/>, <c>--restore</c> and the console: the same steps,
    /// returning how it ended as an exit status and the line that names it
    /// (<see cref="RestoreExit"/>). It never throws and never asks for anything but the
    /// confirmation <see cref="RestoreOptions.Interactive"/> turns on. The caller prints
    /// <see cref="RestoreResult.Verdict"/> as its last line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Where "nothing was changed" ends.</b> Everything up to the first database restore only
    /// reads this host: the archive (which may lie on a read-only mount), the key file,
    /// <c>db.yaml</c>, the databases and the live keystores. What it writes goes elsewhere: the
    /// extracted archive into an owner-only directory under the temporary directory, removed when
    /// the restore ends, and the pre-restore snapshot into the backup directory (which is made
    /// owner-only when others could reach it). One thing is written to a database before the
    /// boundary: reading the live keystores for that snapshot goes through the signer, which
    /// records each read as a row in <c>SignerAudit</c> in the application database. Those rows
    /// are a record of the attempt, as the node's signer writes them all day, and are not counted
    /// as a change. A failure there is <see cref="RestoreExit.Refused"/>, or
    /// <see cref="RestoreExit.Unreachable"/> when it is a database that could not be reached.
    /// </para>
    /// <para>
    /// <b>The restore lock.</b> Once the databases have answered, and before the confirmation or
    /// the snapshot, the restore takes the application database for itself
    /// (<see cref="TakeExclusionAsync"/>, <see cref="ModularCA.Database.RestoreLock"/>) and keeps
    /// it until it ends. While a node serves from that database, the signer service runs on it,
    /// or another restore runs, it is refused: <see cref="RestoreExit.Refused"/> with
    /// <see cref="RestoreResult.DatabaseInUse"/>, saying what must be stopped. While it holds the
    /// lock no node starts. The lock is looked at again just before the first database restore.
    /// </para>
    /// <para>
    /// The first statement that changes anything is the <c>pg_restore --single-transaction</c> of
    /// the first database restored (<see cref="RestoreDumpFileAsync"/>): the audit database with
    /// <see cref="RestoreOptions.RestoreAudit"/>, otherwise the application database. A
    /// <c>pg_restore</c> that exits with an error never sent its <c>COMMIT</c>, so that database
    /// is as it was: still <see cref="RestoreExit.Refused"/> while no other database was restored
    /// before it. One that was killed for running past its time limit, or failed in a way this
    /// process cannot read, may have committed: <see cref="RestoreExit.FailedAfterChanges"/>.
    /// Once one database has been restored, every later failure is
    /// <see cref="RestoreExit.FailedAfterChanges"/>: the second database, the CRL numbers, a
    /// keystore the signer refuses, a config file that cannot be written, or any exception.
    /// </para>
    /// </remarks>
    /// <param name="archivePath">The archive; a ZIP, or one encrypted by a backup.</param>
    /// <param name="signerForAppDatabase">Resolves the signer the keystore files go through; see <see cref="Restore"/>.</param>
    /// <param name="options">What was asked for.</param>
    public static async Task<RestoreResult> RestoreWithVerdictAsync(string archivePath, Func<string, ISigningService> signerForAppDatabase, RestoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(signerForAppDatabase);
        ArgumentNullException.ThrowIfNull(options);
        var progress = new RestoreProgress();
        try
        {
            return await RestoreCoreAsync(archivePath, signerForAppDatabase, options, progress);
        }
        catch (BackupArchiveException ex) when (!progress.Changed)
        {
            Console.WriteLine($"❌ {ex.Message}");
            return RestoreResult.Refused(ex.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ The restore stopped: {ex.GetType().Name}: {ex.Message}");
            return progress.Changed
                ? RestoreResult.FailedAfterChanges($"{ex.GetType().Name}: {ex.Message}")
                : RestoreResult.Refused($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>The steps of <see cref="RestoreWithVerdictAsync"/>; what it throws is turned into a verdict there.</summary>
    private static async Task<RestoreResult> RestoreCoreAsync(string archivePath, Func<string, ISigningService> signerForAppDatabase, RestoreOptions options, RestoreProgress progress)
    {
        var restoreAudit = options.RestoreAudit;
        if (string.IsNullOrWhiteSpace(archivePath) || !File.Exists(archivePath))
        {
            var unreadable = !string.IsNullOrWhiteSpace(archivePath) && ModularCA.Shared.Utils.FileAccessProbe.IsUnreadable(archivePath);
            Console.WriteLine("❌ " + (unreadable
                ? ModularCA.Shared.Utils.FileAccessProbe.Describe("Backup archive", archivePath)
                : $"Backup archive not found: {archivePath}"));
            return RestoreResult.Refused(unreadable ? "the backup archive cannot be read by this account" : "the backup archive was not found");
        }

        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var archiveName = Path.GetFileName(archivePath);
        // Created owner-only just before extraction (CreateRestoreStagingDirectory), never at a
        // predictable path and never beside the archive; null until then, so the cleanup below
        // has nothing to remove.
        string? restoreDir = null;
        // The restore lock, held from the moment the databases are known to answer until the
        // restore ends, however it ends.
        ModularCA.Database.IRestoreExclusionHold? exclusion = null;

        try
        {
            Console.WriteLine($"📦 Restoring from: {archivePath}");

            // The archive is read where it lies and decrypted in memory: nothing is written
            // beside it, and the decrypted ZIP, which holds every keystore and both database
            // dumps, never reaches a disk as one file.
            var zip = BackupArchiveFile.ReadZip(archivePath, options.Keys, AppContext.BaseDirectory, out var encryption);
            try
            {
                if (encryption != BackupArchiveFile.NotEncrypted)
                    Console.WriteLine($"  Archive opened (encryption: {encryption}).");

                // The archive is expanded into a directory of its own, so from extraction onward
                // that directory holds the keystore files and the database dumps. A directory only
                // this user can reach is a precondition, not a nicety: without one the restore
                // stops before extracting anything.
                try
                {
                    restoreDir = CreateRestoreStagingDirectory();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
                {
                    Console.WriteLine($"❌ Could not create a staging directory only this user can read: {ex.Message}");
                    Console.WriteLine("   Restore stopped before anything was extracted or changed.");
                    return RestoreResult.Refused("no staging directory only this user can read could be created under the temporary directory");
                }

                // Extract with per-entry path validation to prevent zip slip.
                // Every entry must resolve to a path inside restoreDir; absolute paths, ADS
                // markers, null bytes, and parent-traversal sequences are rejected.
                try
                {
                    using var archive = new ZipArchive(new MemoryStream(zip, writable: false), ZipArchiveMode.Read);
                    SafeExtractZip(archive, restoreDir);
                }
                catch (InvalidDataException ex)
                {
                    throw new BackupArchiveException($"The backup archive could not be extracted: {ex.Message}");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(zip);
            }

            // Validate manifest
            var manifestPath = Path.Combine(restoreDir, "manifest.json");
            if (!File.Exists(manifestPath))
            {
                Console.WriteLine("❌ Invalid backup archive: manifest.json not found");
                return RestoreResult.Refused("the archive holds no manifest.json: it is not a ModularCA backup archive");
            }
            var manifestJson = File.ReadAllText(manifestPath);
            Console.WriteLine($"  Manifest: {manifestJson}");

            // Defense-in-depth — refuse to extract any archive that still carries
            // secret-bearing files on the deny-list (covers legacy archives or third-party generators).
            var deniedFound = ScanForDeniedFiles(restoreDir);
            if (deniedFound.Count > 0)
            {
                Console.WriteLine("❌ Refusing to restore: archive contains denylisted secret-bearing files:");
                foreach (var d in deniedFound) Console.WriteLine($"     - {d}");
                Console.WriteLine("   These files must NOT be carried inside a backup archive (they are KEKs or plaintext secrets).");
                return RestoreResult.Refused($"the archive carries secret-bearing files no backup may hold ({string.Join(", ", deniedFound)})");
            }

            // An archive taken before the PostgreSQL move contains db-app.sql: a mysqldump
            // script, full of backticks and ENGINE=InnoDB, that no PostgreSQL tool can read.
            // Refused by name, and before anything changes.
            if (IsPrePostgresArchive(restoreDir))
            {
                Console.WriteLine("❌ This archive was taken from a MySQL/MariaDB installation (it contains db-app.sql).");
                Console.WriteLine("   PostgreSQL cannot read a mysqldump script, so there is nothing this build can restore from it.");
                Console.WriteLine();
                Console.WriteLine("   To recover data from it: restore it with a 0.3.0 build onto MariaDB, then run the");
                Console.WriteLine("   migration helper against that database. See docs/architecture/postgresql-migration.md.");
                return RestoreResult.Refused("the archive was taken from a MySQL/MariaDB installation, which this build cannot restore");
            }

            // An archive with no application database would put back keys and settings over a
            // database they do not belong to.
            var appDump = Path.Combine(restoreDir, AppDumpFileName);
            if (!File.Exists(appDump) || new FileInfo(appDump).Length == 0)
            {
                Console.WriteLine($"❌ This archive holds no application database ({AppDumpFileName} is missing or empty).");
                Console.WriteLine("   The backup that wrote it could not dump the database. Nothing was changed; restore an");
                Console.WriteLine("   earlier archive.");
                return RestoreResult.Refused($"the archive holds no application database ({AppDumpFileName} is missing or empty)");
            }

            // The backup's config, for the settings it carries; never for database credentials.
            var backupConfigPath = Path.Combine(restoreDir, "config", "config.yaml");
            if (!File.Exists(backupConfigPath))
            {
                Console.WriteLine("❌ Backup config.yaml not found in archive");
                return RestoreResult.Refused("the archive holds no config/config.yaml");
            }
            var backupConfig = YamlConfigLoader.Load(backupConfigPath);
            var toolTimeoutMs = DatabaseToolTimeoutMs(backupConfig.Backup);
            var auditDump = Path.Combine(restoreDir, AuditDumpFileName);
            var replacesAudit = restoreAudit && File.Exists(auditDump);

            // The databases restored into are this host's own, named by its config/db.yaml. The
            // archive carries no credentials, and a DB: section in an older archive's config.yaml
            // names the host the backup was taken on, which may still be serving.
            var target = LoadRestoreTargetDatabases(configDir, out var targetProblem);
            if (target == null)
            {
                Console.WriteLine($"❌ {targetProblem}");
                Console.WriteLine("   A restore writes into the databases this host's config/db.yaml names, with its credentials.");
                Console.WriteLine("   On a new host, set up the databases first (the setup wizard, or the roles and databases by");
                Console.WriteLine("   hand with db.yaml written from db.yaml.example), then run the restore again.");
                return RestoreResult.Refused(targetProblem ?? "this host names no database to restore into");
            }
            ReportRestoreTarget(target, manifestJson);

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(target.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(target.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(target.DB.Audit.Database, "audit database name");

            // Every database the restore writes into must answer now, as its runtime role. A
            // server that is down is told apart from a refusal: the caller tries again.
            if (await ProbeRestoreTargetAsync("application", target.DB.App) is { } appUnreachable)
                return appUnreachable;
            if (replacesAudit && await ProbeRestoreTargetAsync("audit", target.DB.Audit) is { } auditUnreachable)
                return auditUnreachable;

            // The application database must be this restore's alone from here to the end: a
            // node serving from it, the signer service or another restore holds the restore
            // lock, and then this one is refused, before anything is asked or changed. While
            // this restore holds it, no node starts.
            var (taken, notTaken) = await TakeExclusionAsync(options.Exclusion ?? ModularCA.Database.RestoreLock.OwnConnection, target.DB.App);
            if (notTaken != null)
                return notTaken;
            exclusion = taken;

            // Schema version check
            if (!options.SkipSchemaCheck)
            {
                // An archive taken by a newer build holds migrations this build does not have. It
                // would restore, and the node would then refuse to start on it.
                if (await RefuseNewerSchemaAsync("application", appDump, audit: false, toolTimeoutMs) is { } newerApp)
                    return newerApp;
                if (replacesAudit && await RefuseNewerSchemaAsync("audit", auditDump, audit: true, toolTimeoutMs) is { } newerAudit)
                    return newerAudit;

                if (await ValidateSchemaVersionAsync(manifestJson) is { } mismatch)
                    return mismatch;
            }

            // Confirmation — only consume stdin when running interactively (CLI path). A caller
            // that turned it off has confirmed already: --unattended on the command line, or
            // the console's step-up and single-use restore token.
            if (options.Interactive)
            {
                Console.Write(restoreAudit
                    ? "\n⚠️  This will OVERWRITE current config, keystores, the application database AND the audit database. Type [RESTORE] to confirm: "
                    : "\n⚠️  This will OVERWRITE current config, keystores and the application database (the audit database is kept). Type [RESTORE] to confirm: ");
                var typed = Console.ReadLine();
                if (typed?.Trim() != "RESTORE")
                {
                    Console.WriteLine();
                    Console.WriteLine(typed == null
                        ? "❌ Restore cancelled: standard input is closed, so nobody could confirm. Run it with --unattended when no one is at the terminal."
                        : "❌ Restore cancelled.");
                    return RestoreResult.Refused(typed == null
                        ? "not confirmed: standard input is closed; use --unattended to restore with nobody at the terminal"
                        : "not confirmed: the word RESTORE was not typed");
                }
            }
            else
            {
                Console.WriteLine("(i) No confirmation prompt: the caller confirmed (--unattended, or the console's restore token).");
            }

            // An archive from before the key ring travelled wrapped carries it, and the SSH CA
            // keys, in the clear under config/. It still restores: dropping the ring would leave
            // every DP-protected column unreadable. The operator is told to replace the archive.
            // The archive's SSH CA key files are found by what they are, not by where a row or a
            // setting says they lie: its rows name paths on the host it was taken on.
            var archiveConfigDir = Path.Combine(restoreDir, "config");
            var plaintextSecrets = BackupWrappedSecrets.PlaintextTargetsIn(archiveConfigDir, BackupWrappedSecrets.Targets(archiveConfigDir, null))
                .Union(BackupWrappedSecrets.PlaintextSshKeyDirectoriesIn(archiveConfigDir).Select(d => d == "." ? "SSH CA key files in config/" : d), StringComparer.Ordinal)
                .ToList();
            if (plaintextSecrets.Count > 0)
            {
                Console.WriteLine($"⚠  This archive carries {string.Join(", ", plaintextSecrets)} in plaintext (taken before these travelled wrapped).");
                Console.WriteLine("   They are restored as before. Take a new backup once the restore is done and destroy this archive:");
                Console.WriteLine("   anyone holding it and its key can read every TOTP secret, held key and stored credential, and every");
                Console.WriteLine("   SSH CA key it carries. The next start imports restored SSH CA key files into the signer and deletes them.");
            }

            // The signer the keystore files go back through, over the database the archive is
            // restored into. It is also what takes the pre-restore snapshot of the live files.
            var signer = signerForAppDatabase(AppConnectionString(target));

            // Capture a pre-restore snapshot of the LIVE keystores + config before any
            // destructive write. If the snapshot fails, abort the restore — operators must not
            // lose the only copy of the current state to a botched restore. The live keystore
            // files come from the signer; they are kept in memory too, to put back if the
            // restore of the keystores fails part way. It goes to the backup directory: the
            // program files around config/ are root's and read-only to the service.
            string snapshotPath;
            IReadOnlyList<(string Name, byte[] Bytes)> liveKeystores;
            try
            {
                snapshotPath = PreRestoreSnapshotPath(AppContext.BaseDirectory, configDir, DateTime.UtcNow);
                // The snapshot always goes in the backup directory, so that is the directory checked
                // (and tightened, when it is the backups' own); one others can reach ends the restore here.
                var snapshotDir = Path.GetDirectoryName(snapshotPath)!;
                if (EnsureArchiveDirectory(snapshotDir, AppContext.BaseDirectory, snapshotDir))
                    Console.WriteLine($"🔒 {snapshotDir} could be reached by other local users; it is now restricted to this account.");
                liveKeystores = await ExportKeystoresAsync(signer, RestoreCaller);
                CreatePreRestoreSnapshot(snapshotPath, configDir, liveKeystores);
                Console.WriteLine($"  ✓ Pre-restore snapshot saved to: {snapshotPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Pre-restore snapshot failed: {ex.Message}");
                Console.WriteLine("   Aborting restore — refusing to destroy live state without a rollback safety net.");
                return RestoreResult.Refused($"the pre-restore snapshot could not be taken: {ex.Message}");
            }

            // 1. Restore databases. Each is one transaction, so one that fails is left as it was;
            // either failure ends the restore before a keystore or a config file is replaced.
            // The audit database is replaced only when asked (--restore-audit), and then goes
            // first: when it fails, nothing at all has changed. Otherwise the live audit history
            // stays, and the restore is recorded in it below.
            //
            // THIS IS WHERE "NOTHING WAS CHANGED" ENDS. Up to here the restore has read this host
            // and written only its own staging directory and the pre-restore snapshot. The first
            // pg_restore below is the first statement that changes a database; progress.Changed is
            // set the moment one has committed or may have.
            //
            // The restore lock is looked at once more first: if the connection that holds it
            // dropped while the archive was checked, a node may have started since.
            if (!await exclusion!.StillHeldAsync())
            {
                Console.WriteLine("❌ The restore's lock on the application database was lost: the connection that held it dropped.");
                Console.WriteLine("   A node may have started meanwhile, so the restore stops here. Nothing was changed; run it again.");
                return RestoreResult.Refused("the restore's lock on the application database was lost before anything was changed (its connection dropped); run the restore again");
            }
            var auditRestored = false;
            if (!restoreAudit)
            {
                Console.WriteLine(File.Exists(auditDump)
                    ? "  (i) Keeping this host's audit database: the archive's audit trail is not restored (--restore-audit replaces it)."
                    : "  (i) Keeping this host's audit database; the archive holds no audit trail.");
            }
            else if (!replacesAudit)
            {
                Console.WriteLine("  ⚠ --restore-audit was given, but the archive holds no audit database; this host's audit database is kept.");
            }
            else
            {
                switch (await RestoreDatabaseAsync("audit", target.DB.Audit, auditDump, ensureCitext: false, toolTimeoutMs))
                {
                    case DatabaseRestore.RolledBack:
                        Console.WriteLine("   Nothing was changed: both databases, the keystores and config/ are as they were.");
                        return RestoreResult.Refused("the audit database could not be restored; its one transaction was rolled back");
                    case DatabaseRestore.Unknown:
                        progress.Changed = true;
                        Console.WriteLine("   Whether the audit database was replaced is not known. The application database, the keystores");
                        Console.WriteLine("   and config/ are as they were.");
                        return RestoreResult.FailedAfterChanges("the restore of the audit database ended without its outcome known; it may hold the archive's audit trail");
                }
                progress.Changed = true;
                auditRestored = true;
            }

            switch (await RestoreDatabaseAsync("app", target.DB.App, appDump, ensureCitext: true, toolTimeoutMs))
            {
                case DatabaseRestore.RolledBack when !auditRestored:
                    Console.WriteLine("   Nothing was changed: the application database, the keystores and config/ are as they were.");
                    return RestoreResult.Refused("the application database could not be restored; its one transaction was rolled back");
                case DatabaseRestore.RolledBack:
                    Console.WriteLine("   The audit database now holds the archive's audit trail; the application database, the keystores");
                    Console.WriteLine("   and config/ are as they were. Fix the cause and run the restore again before starting the node.");
                    return RestoreResult.FailedAfterChanges("the audit database was replaced, then the application database could not be restored");
                case DatabaseRestore.Unknown:
                    progress.Changed = true;
                    Console.WriteLine("   Whether the application database was replaced is not known. The keystores and config/ are as they were.");
                    return RestoreResult.FailedAfterChanges("the restore of the application database ended without its outcome known; it may hold the archive's contents");
            }
            progress.Changed = true;

            // CRLs published after this backup was taken carried higher numbers than the restored
            // counters; raise every counter past them before anything can generate a CRL.
            var crlFloorFailed = !await RaiseCrlNumbersAfterRestoreAsync(target, archiveName);

            // The restored database holds the incarnation of the machine and moment the backup
            // was taken. This restore has just made the repairs a changed incarnation calls for,
            // so it stores this machine's incarnation itself and the next start reports nothing.
            // A failure here does not fail the restore; the last line says so.
            var incarnationStored = await StoreIncarnationAfterRestoreAsync(AppConnectionString(target));

            // The signer's journal is never written or removed by a restore. What a restore
            // leaves for it is one fact in the restored database's queue: that this restore
            // ran, with what the archive's manifest says of itself. The node offers it to the
            // signer at its next start, and the signer writes the RestoreMarker.
            await QueueRestoreMarkerAsync(AppConnectionString(target), archiveName, manifestJson);

            // 2. Restore keystores, through the signer. Each file from the archive is offered
            // under the restore context; the signer verifies its signature against the pinned
            // signer in the just-restored app database before it replaces the file in place, and
            // keeps the previous file beside it. A file that does not verify is refused and
            // nothing of it lands. If a later file fails after an earlier one was replaced, the
            // earlier ones are put back from the pre-restore snapshot through the same door.
            var backupKeystores = Path.Combine(restoreDir, "keystores");
            if (Directory.Exists(backupKeystores))
            {
                Console.Write("  Restoring keystores...");
                var restoreContext = new SigningContext(RestoreCaller, SigningPurpose.Restore, null, null);
                var restored = new List<string>();
                string? failure = null;
                foreach (var path in Directory.GetFiles(backupKeystores, "*.keystore", SearchOption.TopDirectoryOnly).OrderBy(p => p, StringComparer.Ordinal))
                {
                    var name = Path.GetFileName(path);
                    try
                    {
                        await signer.ImportKeyAsync(new KeyMaterial(File.ReadAllBytes(path), KeyMaterial.KeystoreFile, Guid.Empty, name), restoreContext);
                        restored.Add(name);
                    }
                    catch (Exception ex)
                    {
                        failure = $"{name}: {ex.Message}";
                        break;
                    }
                }

                if (failure == null)
                {
                    Console.WriteLine($" ✓ ({restored.Count} file(s) verified and in place)");
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine($"  ❌ Restored keystore refused by the signer: {failure}");
                    foreach (var name in restored)
                    {
                        var live = liveKeystores.FirstOrDefault(k => k.Name == name);
                        if (live.Bytes == null)
                            continue;
                        try
                        {
                            await signer.ImportKeyAsync(new KeyMaterial(live.Bytes, KeyMaterial.KeystoreFile, Guid.Empty, name), restoreContext);
                            Console.WriteLine($"     {name}: previous file put back.");
                        }
                        catch (Exception rollbackEx)
                        {
                            Console.WriteLine($"     {name}: the previous file could not be put back ({rollbackEx.Message}); " +
                                              $"it is kept beside the live file as {name}.bak.<timestamp>, and the pre-restore snapshot holds a copy.");
                        }
                    }
                    Console.WriteLine("     Pre-restore keystore state restored where possible; the restore is aborted.");
                    Console.WriteLine("     The application database already holds the archive's contents.");
                    return RestoreResult.FailedAfterChanges($"the application database was replaced, then the signer refused a keystore from the archive ({failure})");
                }
            }

            // An archive from before the SSH keystore, or from an install with no SSH CA, has no
            // ssh-ca.keystore and no Keystores row for one. A live file would then have no row.
            // Only a signer that kept one is asked; the pre-restore snapshot holds that file too.
            if (liveKeystores.Any(k => k.Name == KeyRef.SshKeystore))
            {
                var sshKeystoreLine = await ReconcileAbsentSshKeystoreAsync(signer, restoreDir);
                if (sshKeystoreLine != null)
                    Console.WriteLine(sshKeystoreLine);
            }

            // 3. Restore config
            var backupConfigDir = Path.Combine(restoreDir, "config");
            if (Directory.Exists(backupConfigDir))
            {
                Console.Write("  Restoring config...");
                // Don't delete existing config dir entirely — merge files
                foreach (var file in Directory.GetFiles(backupConfigDir, "*", SearchOption.AllDirectories))
                {
                    var relativePath = Path.GetRelativePath(backupConfigDir, file);
                    var destPath = Path.Combine(configDir, relativePath);

                    // Deny-list guard plus consistent path traversal validation.
                    if (BackupSecretDenylist.IsDenied(Path.GetFileName(destPath)))
                        throw new InvalidOperationException($"Refusing to restore denylisted file from backup: {relativePath}");
                    if (!PathIsContainedIn(destPath, configDir))
                        throw new InvalidOperationException($"Path traversal detected in backup: {relativePath}");

                    Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                    RestoreConfigFile(file, destPath);
                }
                Console.WriteLine(" ✓");
            }

            // This host's own Web TLS certificate file belongs to the installation the restore
            // replaced, and opens with a password the restored config.yaml does not hold. The
            // node issues a new one at its next start; the pre-restore snapshot keeps this one.
            var replacedWebCertificate = Path.Combine(configDir, "api-tls.pfx");
            if (File.Exists(replacedWebCertificate)
                && !string.Equals(backupConfig.Https?.Mode?.Trim(), "Custom", StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(replacedWebCertificate);
                Console.WriteLine("  ✓ This host's Web TLS certificate file removed; the node issues a new one when it starts.");
            }

            // 4. The wrapped configuration secrets wait under config/restore-pending/ until the
            // node next starts: only then does the signer hold the restored keystore whose key
            // wrapped them, and only then is it certain nothing has read the key ring yet.
            var staged = BackupWrappedSecrets.StagePending(restoreDir, configDir);
            if (staged > 0)
                Console.WriteLine($"  ✓ {staged} wrapped configuration secret(s) staged; the signer unwraps them at the next start.");

            if (crlFloorFailed)
            {
                Console.WriteLine("\n❌ Restore applied, but the CRL number counters could NOT be raised (see above).");
                Console.WriteLine("   Do not start the CA until they are: the next CRL would reuse a number already published.");
                return RestoreResult.FailedAfterChanges("the restore was applied, but the CRL number counters could not be raised; do not start the CA until they are");
            }

            // The lock was this restore's guard against a node starting under it. If its
            // connection dropped on the way, the restore is still done, and the operator is told
            // to look before starting anything.
            if (!await exclusion.StillHeldAsync())
            {
                Console.WriteLine("  ⚠ The restore's lock on the application database was lost while it ran (its connection dropped).");
                Console.WriteLine("    A node that started meanwhile ran beside the restore: check that none did, and restart any that is running.");
            }

            Console.WriteLine("\n✅ Restore complete. Restart the application to apply changes.");
            return RestoreResult.Done(auditKept: !auditRestored, incarnationStored);
        }
        finally
        {
            if (exclusion != null)
                try { await exclusion.DisposeAsync(); } catch { }
            if (restoreDir != null)
                try { Directory.Delete(restoreDir, true); } catch { }
        }
    }

    /// <summary>
    /// Takes the restore lock (<see cref="ModularCA.Database.RestoreLock"/>) through
    /// <paramref name="exclusion"/>. Returns the hold, or the verdict when it could not be had:
    /// <see cref="RestoreResult.InUse"/> when a node, the signer service or another restore is
    /// using the application database, <see cref="RestoreExit.Unreachable"/> when the server did
    /// not answer, <see cref="RestoreExit.Refused"/> for anything else. Nothing has been changed
    /// in any of those cases.
    /// </summary>
    /// <param name="exclusion">The command line's own connection, or the console's node.</param>
    /// <param name="app">The application database the restore writes into.</param>
    internal static async Task<(ModularCA.Database.IRestoreExclusionHold? Hold, RestoreResult? Verdict)> TakeExclusionAsync(
        ModularCA.Database.IRestoreExclusion exclusion, ModularCA.Shared.Models.Config.DbInstance app)
    {
        try
        {
            var attempt = await exclusion.TryTakeAsync(PostgresConnection.Build(app));
            if (attempt.Hold != null)
            {
                Console.WriteLine("  ✓ Restore lock taken: no node is serving from the application database, and none starts while this restore runs.");
                return (attempt.Hold, null);
            }
            var reason = attempt.Refusal ?? ModularCA.Database.RestoreLock.NodeInUse;
            Console.WriteLine($"❌ The application database '{app.Database}' on {app.Host}:{app.Port} is in use: {reason}.");
            Console.WriteLine("   A restore replaces that database, so it runs only when nothing else is running on it. Nothing was changed.");
            return (null, RestoreResult.InUse(reason));
        }
        catch (Exception ex)
        {
            var failure = ex as ModularCA.Database.SchemaConnectException ?? new ModularCA.Database.SchemaConnectException(ex);
            var described = ModularCA.Database.SchemaFailure.Describe(failure);
            if (ModularCA.Database.SchemaFailure.Classify(failure) == ModularCA.Database.SchemaFailureKind.Unreachable)
            {
                Console.WriteLine($"❌ The restore lock could not be taken: the application database could not be reached: {described}");
                Console.WriteLine("   Nothing was changed. Try again when the database server answers.");
                return (null, RestoreResult.Unreachable($"the application database could not be reached to take the restore lock: {described}"));
            }
            Console.WriteLine($"❌ The restore lock could not be taken in the application database: {described}");
            Console.WriteLine("   Nothing was changed.");
            return (null, RestoreResult.Refused($"the restore lock could not be taken in the application database: {described}"));
        }
    }

    /// <summary>How the restore of one database ended.</summary>
    private enum DatabaseRestore
    {
        /// <summary><c>pg_restore</c> exited 0: its one transaction committed and the database holds the dump.</summary>
        Restored,

        /// <summary>
        /// The database is as it was: <c>pg_restore</c> could not be started, or exited with an
        /// error. With <c>--single-transaction</c> it sends <c>COMMIT</c> only after every statement
        /// succeeded and exits non-zero without sending it otherwise, and the server rolls back a
        /// transaction whose connection closes uncommitted.
        /// </summary>
        RolledBack,

        /// <summary>
        /// Not known: <c>pg_restore</c> was killed for running past its time limit, or this
        /// process failed while waiting for it, so a <c>COMMIT</c> may have been sent.
        /// </summary>
        Unknown,
    }

    /// <summary>
    /// Opens one connection to a database the restore writes into, as its runtime role, and
    /// returns null when it answers. Otherwise the verdict: <see cref="RestoreExit.Unreachable"/>
    /// when the server could not be reached or is not accepting connections yet, which passes on
    /// its own, and <see cref="RestoreExit.Refused"/> for anything the operator must fix (the
    /// database is missing, the login is refused, TLS fails). Nothing has been changed either way.
    /// </summary>
    /// <param name="label">How the database is named to the operator.</param>
    /// <param name="instance">The database and its runtime role.</param>
    private static async Task<RestoreResult?> ProbeRestoreTargetAsync(string label, ModularCA.Shared.Models.Config.DbInstance instance)
    {
        try
        {
            await using var conn = new NpgsqlConnection(
                new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand("SELECT 1", conn);
            await cmd.ExecuteScalarAsync();
            return null;
        }
        catch (Exception ex)
        {
            var failure = new ModularCA.Database.SchemaConnectException(ex);
            var described = ModularCA.Database.SchemaFailure.Describe(failure);
            if (ModularCA.Database.SchemaFailure.Classify(failure) == ModularCA.Database.SchemaFailureKind.Unreachable)
            {
                Console.WriteLine($"❌ The {label} database '{instance.Database}' on {instance.Host}:{instance.Port} could not be reached: {described}");
                Console.WriteLine("   Nothing was changed. Try again when the database server answers.");
                return RestoreResult.Unreachable($"the {label} database could not be reached: {described}");
            }
            Console.WriteLine($"❌ The {label} database '{instance.Database}' on {instance.Host}:{instance.Port} refused the role '{instance.Username}' of config/db.yaml: {described}");
            Console.WriteLine("   Nothing was changed. A restore writes into databases that exist, as the roles db.yaml names.");
            return RestoreResult.Refused($"the {label} database cannot be used as config/db.yaml names it: {described}");
        }
    }

    /// <summary>
    /// Refuses a dump taken by a newer build: one whose migration history
    /// (<see cref="ReadDumpMigrationsAsync"/>) holds a migration this build does not have. Such a
    /// database would restore, and the node would then refuse to start on it. Returns null when
    /// the dump may be restored: every migration in it is known, or it carries no history at all
    /// (which is said, and not refused). Nothing has been changed either way.
    /// </summary>
    /// <param name="label">How the database is named to the operator.</param>
    /// <param name="dumpFile">The dump, extracted from the archive.</param>
    /// <param name="audit">True for the audit database's migrations.</param>
    /// <param name="timeoutMs">How long <c>pg_restore</c> may take to read the dump.</param>
    private static async Task<RestoreResult?> RefuseNewerSchemaAsync(string label, string dumpFile, bool audit, int timeoutMs)
    {
        var (migrations, problem) = await ReadDumpMigrationsAsync(dumpFile, timeoutMs);
        if (migrations == null)
        {
            Console.WriteLine($"❌ The {label} database in the archive could not be read by pg_restore: {problem}");
            Console.WriteLine("   Nothing was changed. pg_restore must be on the PATH of the account that runs ModularCA, at the");
            Console.WriteLine("   major version of the pg_dump that wrote the archive or newer.");
            return RestoreResult.Refused($"the {label} database in the archive could not be read by pg_restore: {problem}");
        }
        if (migrations.Count == 0)
        {
            Console.WriteLine($"  ⚠ The {label} database in the archive carries no migration history; it cannot be compared with this build.");
            return null;
        }

        var known = BackupManifestCommand.KnownMigrations(audit);
        var unknown = migrations.Where(id => !known.Contains(id)).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (unknown.Count == 0)
        {
            Console.WriteLine($"  The {label} database in the archive is at {migrations.Max(StringComparer.Ordinal)}, which this build has.");
            return null;
        }

        var build = BackupManifestCommand.ProductVersion();
        Console.WriteLine($"❌ The {label} database in this archive was taken by a newer build than this one ({build}).");
        Console.WriteLine($"   It holds {unknown.Count} migration(s) this build does not have: {string.Join(", ", unknown.Take(5))}{(unknown.Count > 5 ? ", ..." : "")}");
        Console.WriteLine("   Nothing was changed. Restore it with the build that took it, or a newer one: this build would");
        Console.WriteLine("   refuse to start on the restored database.");
        return RestoreResult.Refused($"the archive's {label} schema is newer than this build ({build}): it holds migration {unknown[^1]}, which this build does not have");
    }

    /// <summary>
    /// The migration ids a custom-format dump carries in its <c>__EFMigrationsHistory</c> table,
    /// read with <c>pg_restore --data-only --table</c> writing to standard output: no database is
    /// contacted and nothing is written. An empty list means the dump has no such table or no
    /// rows in it; null, with the reason, means <c>pg_restore</c> could not read the dump.
    /// </summary>
    /// <param name="dumpFile">The dump.</param>
    /// <param name="timeoutMs">How long <c>pg_restore</c> may run.</param>
    internal static async Task<(IReadOnlyList<string>? Migrations, string? Problem)> ReadDumpMigrationsAsync(string dumpFile, int timeoutMs)
    {
        int exit;
        string stdout, stderr;
        try
        {
            (exit, stdout, stderr) = await RunPostgresToolAsync("pg_restore",
                ["--data-only", "--table=__EFMigrationsHistory", "--file=-", dumpFile], pgPassFile: null, timeoutMs);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return (null, $"pg_restore could not be started ({ex.Message})");
        }
        if (exit != 0)
            return (null, $"exit {exit}: {stderr.Trim()}");
        return (ParseCopiedMigrations(stdout), null);
    }

    /// <summary>
    /// The first column of every row of the <c>COPY ... "__EFMigrationsHistory" ... FROM stdin;</c>
    /// block in a script <c>pg_restore</c> printed: the migration ids.
    /// </summary>
    /// <param name="script">The script.</param>
    internal static IReadOnlyList<string> ParseCopiedMigrations(string script)
    {
        var ids = new List<string>();
        var inBlock = false;
        foreach (var raw in script.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (!inBlock)
            {
                inBlock = line.StartsWith("COPY ", StringComparison.Ordinal)
                    && line.Contains("__EFMigrationsHistory", StringComparison.Ordinal)
                    && line.TrimEnd().EndsWith("FROM stdin;", StringComparison.Ordinal);
                continue;
            }
            if (line == "\\.")
            {
                inBlock = false;
                continue;
            }
            var id = line.Split('\t')[0];
            if (id.Length > 0)
                ids.Add(id);
        }
        return ids;
    }

    /// <summary>
    /// What identifies the instance a database belongs to, as a backup's manifest records it and
    /// the hub's <c>hello</c> answers it: the identifier stored with the instance's data
    /// (<see cref="ModularCA.Core.Services.Settings.InstanceIdentity"/>), which the first start of
    /// a build that keeps it wrote once and nothing changes afterwards. It travels with the
    /// database, so it is the same on every host the instance is restored onto and differs
    /// between two installs. Only while nothing is stored (a database no such build has started
    /// on yet) is it derived: the SHA-256 of the public key of the system signing CA, as the
    /// <c>Keystores</c> rows pin it (<c>SigningCaSpkiSha256</c>, 64 hex digits), which is also
    /// the value that start stores. It is not a secret. Null when nothing is stored and no row
    /// carries a pin (an install from before the pin that was never backfilled), when the stored
    /// row holds no usable value, or when the database cannot be read. Runs over a connection of
    /// its own, for the host commands that have no service container.
    /// </summary>
    /// <param name="appConnectionString">The application database.</param>
    public static async Task<string?> ReadInstanceIdAsync(string appConnectionString)
        => (await ModularCA.Core.Services.Settings.InstanceIdentity.ReadAsync(appConnectionString)).Id;

    /// <summary>The newest migration a database's history names, or null when it has none or cannot be read.</summary>
    /// <param name="connectionString">The database.</param>
    private static async Task<string?> ReadLatestMigrationAsync(string connectionString)
    {
        try
        {
            await using var conn = new NpgsqlConnection(connectionString);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                """SELECT "MigrationId" FROM "__EFMigrationsHistory" ORDER BY "MigrationId" DESC LIMIT 1""", conn);
            return await cmd.ExecuteScalarAsync() as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Raises every CRL configuration's counter in the restored application database to the
    /// time-derived floor of <see cref="CrlNumberFloor"/>, so no CRL number published after the
    /// backup is used again, and records it in the restored audit trail. Returns false when the
    /// counters could not be raised; a failure to write the audit record is reported but does
    /// not undo the floor.
    /// </summary>
    /// <param name="config">The configuration the databases were restored with.</param>
    /// <param name="archiveName">The archive's file name, for the audit record.</param>
    private static async Task<bool> RaiseCrlNumbersAfterRestoreAsync(ModularCA.Shared.Models.Config.SystemConfig config, string archiveName)
    {
        var floor = CrlNumberFloor.FloorAt(DateTimeOffset.UtcNow);
        IReadOnlyList<CrlNumberFloor.Raised> raised;
        try
        {
            using var db = new ModularCA.Database.ModularCADbContext(
                new DbContextOptionsBuilder<ModularCA.Database.ModularCADbContext>().UseNpgsql(AppConnectionString(config)).Options);
            raised = await CrlNumberFloor.ApplyAsync(db, floor);
            Console.WriteLine($"  ✓ CRL numbers: {raised.Count} configuration(s) raised to at least {floor}.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ❌ CRL numbers could not be raised: {ex.Message}");
            Console.WriteLine($"     Run: UPDATE \"CrlConfigurations\" SET \"LastCrlNumber\" = GREATEST(\"LastCrlNumber\", {floor});");
            return false;
        }

        try
        {
            if (string.IsNullOrWhiteSpace(config.DB.Audit.Database))
                throw new InvalidOperationException("no audit database is configured");
            using var auditDb = new ModularCA.Database.AuditDbContext(
                new DbContextOptionsBuilder<ModularCA.Database.AuditDbContext>().UseNpgsql(ModularCA.Shared.Utils.PostgresConnection.Build(config.DB.Audit)).Options);
            await new AuditHashChainService().AppendAsync(auditDb, new ModularCA.Shared.Entities.AuditLogEntity
            {
                ActionType = ModularCA.Shared.Enums.AuditActionType.CrlNumbersRaisedOnRestore,
                ActorUsername = RestoreCaller,
                TargetEntityType = "CrlConfiguration",
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(new
                {
                    Archive = archiveName,
                    Floor = floor,
                    Raised = raised.Select(r => new { r.TaskId, r.IssuerDn, r.IsDelta, r.Before, r.After }),
                    Host = Environment.MachineName,
                }),
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ⚠ The CRL number floor was applied but not audited ({ex.GetType().Name}: {ex.Message}).");
        }
        return true;
    }

    /// <summary>
    /// Stores this machine's incarnation in the application database just restored
    /// (<see cref="ModularCA.Core.Services.Continuity.InstanceContinuity.StoreIncarnationAsync"/>),
    /// so the first start after the restore finds the same timeline and does not report the
    /// restore a second time as a rollback. A failed attempt is made again after each wait of
    /// <see cref="IncarnationStoreRetryDelays"/> (four attempts over seven seconds), on a new
    /// connection each time, so a database that is still settling after the restore does not
    /// cost a notice. When every attempt failed it is reported and does not fail the restore:
    /// the next start then reports an incarnation change, which costs a notice to acknowledge
    /// and nothing else, the CRL numbers having been raised already. The restore's last line
    /// says so (<see cref="RestoreResult.Done"/>).
    /// </summary>
    /// <param name="appConnectionString">The restored application database.</param>
    /// <param name="reading">What this machine reports; read from the default sources when null.</param>
    /// <param name="retryDelays">The wait before each further attempt; <see cref="IncarnationStoreRetryDelays"/> when null.</param>
    /// <param name="store">
    /// What stores the reading, given the attempt's number from 1; null stores it in the database.
    /// For tests that make the store fail.
    /// </param>
    /// <returns>True when the incarnation was stored.</returns>
    internal static async Task<bool> StoreIncarnationAfterRestoreAsync(string appConnectionString,
        ModularCA.Core.Services.Continuity.IncarnationReading? reading = null,
        IReadOnlyList<TimeSpan>? retryDelays = null,
        Func<int, ModularCA.Core.Services.Continuity.IncarnationReading, Task>? store = null)
    {
        retryDelays ??= IncarnationStoreRetryDelays;
        store ??= async (_, r) =>
        {
            using var db = new ModularCA.Database.ModularCADbContext(
                new DbContextOptionsBuilder<ModularCA.Database.ModularCADbContext>().UseNpgsql(appConnectionString).Options)
            {
                // The restored database may be from before the journal's fact queue, and the
                // restore's own marker says what happened here; no fact rides on this save.
                SuppressSignerFacts = true,
            };
            await ModularCA.Core.Services.Continuity.InstanceContinuity.StoreIncarnationAsync(db, r, RestoreCaller);
        };

        Exception? last = null;
        for (var attempt = 1; attempt <= retryDelays.Count + 1; attempt++)
        {
            try
            {
                reading ??= ModularCA.Core.Services.Continuity.IncarnationSources.Read();
                await store(attempt, reading);
                Console.WriteLine($"  ✓ Incarnation stored (source: {reading.Source}{(attempt > 1 ? $", attempt {attempt}" : "")}); the next start will not report this restore as a rollback.");
                return true;
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt <= retryDelays.Count)
                {
                    Console.WriteLine($"  … The incarnation could not be stored ({ex.GetType().Name}: {ex.GetBaseException().Message}); trying again in {retryDelays[attempt - 1].TotalSeconds:0.#} s.");
                    await Task.Delay(retryDelays[attempt - 1]);
                }
            }
        }
        Console.WriteLine($"  ⚠ The incarnation could not be stored after {retryDelays.Count + 1} attempt(s) ({last!.GetType().Name}: {last.GetBaseException().Message}). The restore is done; the next start shows a notice that the instance runs from an earlier state. Acknowledge it.");
        return false;
    }

    /// <summary>
    /// The waits between the attempts of <see cref="StoreIncarnationAfterRestoreAsync"/>: 1 s,
    /// 2 s and 4 s, so four attempts over seven seconds.
    /// </summary>
    internal static readonly IReadOnlyList<TimeSpan> IncarnationStoreRetryDelays =
        [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)];

    /// <summary>
    /// Computes a schema version string fingerprinting both the live table list AND the EF
    /// migration history. Column-level changes shipped via an EF migration
    /// invalidate the fingerprint even when the table-name set is unchanged, so a backup
    /// taken at a different migration level is rejected by <see cref="ValidateSchemaVersionAsync"/>.
    /// </summary>
    /// <param name="config">The system configuration containing database connection details.</param>
    /// <returns>A string in the format "tables:N:sha256-hash:migrations:M:sha256-hash".</returns>
    public static async Task<string> ComputeSchemaVersionAsync(ModularCA.Shared.Models.Config.SystemConfig config)
    {
        var tableNames = new List<string>();
        var migrationIds = new List<string>();
        try
        {
            // MySQL exposed information_schema as a database you could connect to and then
            // filter by TABLE_SCHEMA. PostgreSQL scopes a session to one database and pg_tables
            // already shows only that database, so the probe connects to the application
            // database itself and filters by schema name instead.
            using var schemaConn = new NpgsqlConnection(AppConnectionString(config));
            await schemaConn.OpenAsync();
            using var listCmd = new NpgsqlCommand(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename", schemaConn);
            using var reader = await listCmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                tableNames.Add(reader.GetString(0));
        }
        catch
        {
            // If we cannot query the DB, fall back to a count-only marker
        }

        // Include the EF migration history in the fingerprint so column/index
        // drift inside known tables is caught by the schema check on restore.
        if (tableNames.Contains("__EFMigrationsHistory", StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                // Honor the configured SslMode for the __EFMigrationsHistory probe. The table
                // and column names are quoted: EF created them with that exact casing, and
                // PostgreSQL folds an unquoted identifier to lower case.
                using var appConn = new NpgsqlConnection(AppConnectionString(config));
                await appConn.OpenAsync();
                using var migCmd = new NpgsqlCommand(
                    """
                    SELECT "MigrationId" FROM "__EFMigrationsHistory" ORDER BY "MigrationId"
                    """, appConn);
                using var migReader = await migCmd.ExecuteReaderAsync();
                while (await migReader.ReadAsync())
                    migrationIds.Add(migReader.GetString(0));
            }
            catch
            {
                // Best effort — leave migration list empty if unreadable.
            }
        }

        var tableCount = tableNames.Count;
        var joined = string.Join("|", tableNames);
        var tableHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(joined)))[..16].ToLowerInvariant();

        var migCount = migrationIds.Count;
        var migJoined = string.Join("|", migrationIds);
        var migHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(migJoined)))[..16].ToLowerInvariant();

        return $"tables:{tableCount}:{tableHash}:migrations:{migCount}:{migHash}";
    }

    /// <summary>
    /// Validates the schema version stored in a backup manifest against the current database.
    /// If the current config.yaml is available, computes the live schema version and compares.
    /// </summary>
    /// <param name="manifestJson">The raw JSON content of the backup manifest.</param>
    /// <returns>Null when the versions match or cannot be compared; the refusal when they differ. Nothing has been changed either way.</returns>
    private static async Task<RestoreResult?> ValidateSchemaVersionAsync(string manifestJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            if (!doc.RootElement.TryGetProperty("SchemaVersion", out var backupSchemaEl))
            {
                Console.WriteLine("  ⚠ Backup manifest has no SchemaVersion — skipping schema check.");
                return null;
            }

            var backupSchema = backupSchemaEl.GetString();
            var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
            if (!File.Exists(configPath))
            {
                Console.WriteLine("  ⚠ No local config.yaml — cannot verify schema version.");
                return null;
            }

            var config = YamlConfigLoader.Load(configPath);
            OverlayDbYaml(config, Path.GetDirectoryName(configPath)!);
            var currentSchema = await ComputeSchemaVersionAsync(config);

            if (!string.Equals(backupSchema, currentSchema, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  ❌ Schema version mismatch!");
                Console.WriteLine($"     Backup:  {backupSchema}");
                Console.WriteLine($"     Current: {currentSchema}");
                Console.WriteLine("     The database schema has changed since this backup was created.");
                Console.WriteLine("     Restoring may cause data loss or corruption. Aborting.");
                return RestoreResult.Refused($"the archive's schema ({backupSchema}) is not the schema of this host's database ({currentSchema}); restore with the build the archive was taken with, onto a database at that version");
            }

            Console.WriteLine($"  Schema version OK: {currentSchema}");
        }
        catch (JsonException)
        {
            Console.WriteLine("  ⚠ Could not parse manifest for schema check — skipping.");
        }

        return null;
    }

    /// <summary>
    /// Queries the application database for entity counts (CAs, certificates, users) used in the backup manifest.
    /// Returns zeros if the database is unreachable.
    /// </summary>
    /// <param name="config">The system configuration containing database connection details.</param>
    /// <returns>A tuple of (caCount, certCount, userCount).</returns>
    private static async Task<(int caCount, int certCount, int userCount)> CountEntitiesAsync(ModularCA.Shared.Models.Config.SystemConfig config)
    {
        // This used to shell out to the `mysql` client and parse tab-separated stdout. There is
        // no reason to launch a process to run one query: the driver is already referenced here,
        // and going through it removes a client-binary dependency, a temporary credentials file
        // and a text-parsing step from the backup path at once.
        try
        {
            BootstrapDatabaseSetup.ValidateIdentifier(config.DB.App.Database, "app database name");
            using var conn = new NpgsqlConnection(AppConnectionString(config));
            await conn.OpenAsync();
            using var cmd = new NpgsqlCommand(
                """
                SELECT (SELECT COUNT(*) FROM "CertificateAuthorities"),
                       (SELECT COUNT(*) FROM "Certificates"),
                       (SELECT COUNT(*) FROM "Users")
                """, conn);
            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
                return ((int)reader.GetInt64(0), (int)reader.GetInt64(1), (int)reader.GetInt64(2));
        }
        catch
        {
            // Best effort — return zeros if the database is unreachable
        }
        return (0, 0, 0);
    }

    /// <summary>
    /// Restores a pg_dump custom-format archive into a PostgreSQL database.
    /// <para>
    /// Every argument is passed as its own token, so nothing in a database or user name can
    /// become a second argument, and the password never appears on the command line or in the
    /// process environment — it is read by the tool from the pgpass file this is given.
    /// </para>
    /// <para>
    /// The flags are what make a restore safe to repeat: <c>--clean --if-exists</c> drops what
    /// it is about to replace without failing on what is not there, <c>--no-owner
    /// --no-privileges</c> keep the dump's ownership and grants from overwriting the roles this
    /// installation actually uses, and <c>--single-transaction</c> makes the whole restore
    /// atomic — a failure halfway leaves the database exactly as it was. The MySQL version had
    /// none of these properties: it piped a script into the client statement by statement.
    /// </para>
    /// <para>
    /// Everything runs as the runtime role that owns the database, never as a superuser. The
    /// dump's extension entries are left out of the restore (<c>pg_restore --list</c>, filtered,
    /// then <c>--use-list</c>): with <c>--clean</c> they would drop and recreate <c>citext</c>,
    /// which fails for any role but the extension's owner, and on a repaired pre-0.4.0 install the
    /// owner is the superuser that bootstrapped it. For the application database the extension is
    /// instead ensured first, as the runtime role.
    /// </para>
    /// <para>
    /// <b>What a failure leaves.</b> Nothing here changes the database before the last
    /// <c>pg_restore</c> except the <c>citext</c> extension, created only when the database has
    /// none; when the restore then does not go through, that extension is dropped again, so a
    /// database reported as <see cref="DatabaseRestore.RolledBack"/> is as it was found. The
    /// table of contents is read and filtered without a connection.
    /// </para>
    /// </summary>
    /// <param name="pgPassFile">Path to the pgpass file holding the credentials.</param>
    /// <param name="instance">The database and runtime role to restore into (name pre-validated).</param>
    /// <param name="dumpFile">Path to the custom-format archive to restore.</param>
    /// <param name="ensureCitext">Create <c>citext</c> as the runtime role first, if it is missing.</param>
    /// <param name="timeoutMs">How long each <c>pg_restore</c> run may take.</param>
    /// <returns>How it ended, and for a failure the tool's own message.</returns>
    private static async Task<(DatabaseRestore Outcome, string Detail)> RestoreDumpFileAsync(
        string pgPassFile, ModularCA.Shared.Models.Config.DbInstance instance, string dumpFile, bool ensureCitext, int timeoutMs)
    {
        var createdCitext = false;

        // A restore that does not go through leaves the database as it was: the extension this
        // call created is dropped again. One that cannot be dropped is the one change left.
        async Task<(DatabaseRestore, string)> NotRestoredAsync(string detail)
        {
            if (!createdCitext)
                return (DatabaseRestore.RolledBack, detail);
            try
            {
                await using var conn = new NpgsqlConnection(PostgresConnection.Build(instance));
                await conn.OpenAsync();
                await using var cmd = new NpgsqlCommand($"DROP EXTENSION IF EXISTS {ModularCA.Database.Conventions.TextCaseSensitivity.Extension}", conn);
                await cmd.ExecuteNonQueryAsync();
                return (DatabaseRestore.RolledBack, detail);
            }
            catch (Exception ex)
            {
                return (DatabaseRestore.Unknown,
                    $"{detail} The {ModularCA.Database.Conventions.TextCaseSensitivity.Extension} extension this restore created in the database could not be removed again ({ex.Message}).");
            }
        }

        if (ensureCitext)
        {
            try
            {
                await using var conn = new NpgsqlConnection(PostgresConnection.Build(instance));
                await conn.OpenAsync();
                bool present;
                await using (var probe = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = @name)", conn))
                {
                    probe.Parameters.AddWithValue("name", ModularCA.Database.Conventions.TextCaseSensitivity.Extension);
                    present = (bool)(await probe.ExecuteScalarAsync())!;
                }
                if (!present)
                {
                    // Set first: a statement whose answer is lost may still have run.
                    createdCitext = true;
                    await using var cmd = new NpgsqlCommand(ModularCA.Database.PostgresRoleLayout.ExtensionSql, conn);
                    await cmd.ExecuteNonQueryAsync();
                    // In a database that was empty the extension is new, and this process has
                    // already read the type list without it: every citext column would be unreadable.
                    await conn.ReloadTypesAsync();
                }
            }
            catch (Exception ex)
            {
                return await NotRestoredAsync($"could not ensure the citext extension as '{instance.Username}': {ex.Message}");
            }
        }

        string listFile;
        try
        {
            var (listExit, listing, listErr) = await RunPostgresToolAsync("pg_restore", new[] { "--list", dumpFile }, pgPassFile, timeoutMs);
            if (listExit != 0)
                return await NotRestoredAsync($"pg_restore --list exited {listExit}: {listErr.Trim()}");
            listFile = dumpFile + ".list";
            await File.WriteAllLinesAsync(listFile, WithoutExtensionEntries(listing));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            return await NotRestoredAsync(ex is System.ComponentModel.Win32Exception
                ? $"pg_restore could not be started ({ex.Message}). It must be on the PATH of the account that runs ModularCA."
                : $"the dump's table of contents could not be staged: {ex.Message}");
        }

        // From this call on the database may change. It is one transaction: an exit with an
        // error means COMMIT was never sent; a kill or a failure of this process to follow the
        // tool means it may have been.
        int exit;
        string stderr;
        try
        {
            (exit, _, stderr) = await RunPostgresToolAsync("pg_restore", new[]
            {
                "--host", instance.Host,
                "--port", instance.Port.ToString(),
                "--username", instance.Username,
                "--no-password",
                "--dbname", instance.Database,
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--use-list", listFile,
                dumpFile,
            }, pgPassFile, timeoutMs);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return await NotRestoredAsync($"pg_restore could not be started ({ex.Message}). It must be on the PATH of the account that runs ModularCA.");
        }
        catch (Exception ex)
        {
            return (DatabaseRestore.Unknown, $"pg_restore was started and could not be followed to its end ({ex.GetType().Name}: {ex.Message}).");
        }

        if (exit == 0)
            return (DatabaseRestore.Restored, string.Empty);
        if (exit == ToolTimedOut)
            return (DatabaseRestore.Unknown, $"{stderr.Trim()}; it was stopped, and whether its transaction had committed is not known. Raise Backup.DatabaseTimeoutMinutes.");
        return await NotRestoredAsync($"pg_restore exited {exit}: {stderr.Trim()}");
    }

    /// <summary>
    /// Restores one database from its dump as its runtime role
    /// (<see cref="RestoreDumpFileAsync"/>) and says how it ended. A failure is printed with the
    /// tool's own message, and with whether the database is as it was.
    /// </summary>
    /// <param name="label">How the database is named to the operator.</param>
    /// <param name="instance">The database and runtime role to restore into.</param>
    /// <param name="dumpFile">The custom-format dump from the archive.</param>
    /// <param name="ensureCitext">Create <c>citext</c> as the runtime role first, if it is missing.</param>
    /// <param name="timeoutMs">How long each <c>pg_restore</c> run may take.</param>
    /// <returns>Whether the database now holds the dump, is as it was, or may be either.</returns>
    private static async Task<DatabaseRestore> RestoreDatabaseAsync(
        string label, ModularCA.Shared.Models.Config.DbInstance instance, string dumpFile, bool ensureCitext, int timeoutMs)
    {
        Console.Write($"  Restoring {label} database...");
        var passFile = WritePgPassFile(instance.Host, instance.Port, instance.Database, instance.Username, instance.Password);
        DatabaseRestore outcome;
        string detail;
        try
        {
            (outcome, detail) = await RestoreDumpFileAsync(passFile, instance, dumpFile, ensureCitext, timeoutMs);
        }
        finally
        {
            try { File.Delete(passFile); } catch { }
        }

        if (outcome == DatabaseRestore.Restored)
        {
            Console.WriteLine(" ✓");
            return outcome;
        }

        Console.WriteLine();
        Console.WriteLine($"❌ The {label} database '{instance.Database}' could not be restored: {detail}");
        if (outcome == DatabaseRestore.RolledBack)
            Console.WriteLine($"   The {label} database is as it was: the restore is one transaction, and it did not commit.");
        return outcome;
    }

    /// <summary>
    /// The lines of a <c>pg_restore --list</c> table of contents without its <c>EXTENSION</c> and
    /// <c>COMMENT - EXTENSION</c> entries, which only the extension's owner may drop or recreate.
    /// </summary>
    /// <param name="listing">The table of contents as <c>pg_restore --list</c> prints it.</param>
    internal static IEnumerable<string> WithoutExtensionEntries(string listing) =>
        listing.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => !ExtensionTocEntry.IsMatch(line));

    private static readonly System.Text.RegularExpressions.Regex ExtensionTocEntry =
        new(@"^\s*\d+;\s*\d+\s+\d+\s+(?:EXTENSION|COMMENT - EXTENSION)\s", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>The exit code <see cref="RunPostgresToolAsync"/> reports for a tool it killed for running past its time limit.</summary>
    private const int ToolTimedOut = -1;

    /// <summary>
    /// Runs one of the PostgreSQL command-line tools with the credentials supplied through a
    /// pgpass file rather than through the command line or the environment.
    /// <para>
    /// <c>PGPASSFILE</c> is set on the child process only. Putting the password in
    /// <c>PGPASSWORD</c> instead would be shorter and is what most examples do; it also makes
    /// the password readable to anything that can list the process environment, which on a
    /// machine holding CA private keys is not a trade worth making.
    /// </para>
    /// </summary>
    /// <param name="tool">The executable name, e.g. <c>pg_dump</c> or <c>pg_restore</c>.</param>
    /// <param name="arguments">Arguments, each passed as exactly one token.</param>
    /// <param name="pgPassFile">Path to the pgpass file to point PGPASSFILE at; null for a run that contacts no database.</param>
    /// <param name="timeoutMs">How long to wait before killing the process.</param>
    /// <returns>A tuple of (exitCode, stdout, stderr); the exit code is <see cref="ToolTimedOut"/> when the process was killed for running past the limit.</returns>
    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunPostgresToolAsync(
        string tool, IReadOnlyList<string> arguments, string? pgPassFile, int timeoutMs)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = tool,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        if (pgPassFile != null)
            startInfo.Environment["PGPASSFILE"] = pgPassFile;

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        var completed = await Task.Run(() => process.WaitForExit(timeoutMs));
        if (!completed)
        {
            process.Kill(entireProcessTree: true);
            return (ToolTimedOut, string.Empty, $"Process '{tool}' timed out after {timeoutMs}ms");
        }

        return (process.ExitCode, await stdoutTask, await stderrTask);
    }

    /// <summary>
    /// The backup directory as an absolute path: <c>Backup.OutputPath</c> (default
    /// <c>backups</c>), relative to <paramref name="baseDirectory"/> unless rooted. The console,
    /// the command-line <c>--backup</c> default and the pre-restore snapshot all use it; it is one
    /// of the four runtime directories the service may write.
    /// </summary>
    /// <param name="baseDirectory">The application directory.</param>
    /// <param name="configuredOutputPath">The configured <c>Backup.OutputPath</c>, or null for the default.</param>
    /// <returns>The absolute directory path.</returns>
    public static string ResolveBackupDirectory(string baseDirectory, string? configuredOutputPath)
    {
        var path = string.IsNullOrWhiteSpace(configuredOutputPath) ? "backups" : configuredOutputPath;
        return Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(baseDirectory, path));
    }

    /// <summary>
    /// Creates the directory a backup stages its database dumps, keystores and configuration in
    /// before they are zipped and encrypted, and returns its path: a new directory under the
    /// temporary directory with an unpredictable name, owner-only from the moment it exists
    /// (<see cref="FileSecurityUtil.CreateOwnerOnlyTempDirectory"/>). Throws when it cannot be
    /// created or restricted, which ends the backup.
    /// <para>
    /// It used to be <c>/tmp/modularca-backup-&lt;timestamp&gt;</c>, a name any local user could
    /// predict and create first, and a failure to restrict it was only a warning, so the
    /// plaintext could be staged in a directory another user owned or could read.
    /// </para>
    /// </summary>
    /// <returns>The full path of the new, empty staging directory.</returns>
    /// <exception cref="IOException">The directory could not be created or restricted to its owner.</exception>
    /// <exception cref="UnauthorizedAccessException">The directory's permissions could not be read or set.</exception>
    internal static string CreateBackupStagingDirectory()
        => FileSecurityUtil.CreateOwnerOnlyTempDirectory("modularca-backup-");

    /// <summary>
    /// Creates the directory a restore extracts the archive into, plaintext keystores and
    /// configuration included, and returns its path: a new directory under the temporary
    /// directory with an unpredictable name, owner-only from the moment it exists
    /// (<see cref="FileSecurityUtil.CreateOwnerOnlyTempDirectory"/>). Throws when it cannot be
    /// created or restricted, which ends the restore before anything is extracted.
    /// <para>
    /// It used to be created at <c>modularca-restore-&lt;guid&gt;</c> and then chmodded, with a
    /// failure to restrict it only a warning, so the archive could be expanded into a directory
    /// other local users could read.
    /// </para>
    /// </summary>
    /// <returns>The full path of the new, empty staging directory.</returns>
    /// <exception cref="IOException">The directory could not be created or restricted to its owner.</exception>
    /// <exception cref="UnauthorizedAccessException">The directory's permissions could not be read or set.</exception>
    internal static string CreateRestoreStagingDirectory()
        => FileSecurityUtil.CreateOwnerOnlyTempDirectory("modularca-restore-");

    /// <summary>
    /// Creates the directory the pre-restore snapshot stages the live configuration and the
    /// live keystores in before they are zipped, and returns its path, under the same rules as
    /// <see cref="CreateRestoreStagingDirectory"/>. Throws when it cannot be created or
    /// restricted; the snapshot then fails, and a restore without its snapshot does not go ahead.
    /// </summary>
    /// <returns>The full path of the new, empty staging directory.</returns>
    /// <exception cref="IOException">The directory could not be created or restricted to its owner.</exception>
    /// <exception cref="UnauthorizedAccessException">The directory's permissions could not be read or set.</exception>
    internal static string CreatePreRestoreStagingDirectory()
        => FileSecurityUtil.CreateOwnerOnlyTempDirectory("modularca-pre-restore-");

    /// <summary>
    /// The absolute path a backup archive is written to: <paramref name="outputPath"/> when one
    /// is given, otherwise <c>&lt;backupName&gt;.zip</c> in the backup directory
    /// (<see cref="ResolveBackupDirectory"/>), never beside the binary, whose directory is root's
    /// and read-only to the service. Either way it must lie inside
    /// <paramref name="baseDirectory"/>.
    /// </summary>
    /// <param name="outputPath">The explicit archive path, or null for the default.</param>
    /// <param name="baseDirectory">The application directory.</param>
    /// <param name="configuredOutputPath">The configured <c>Backup.OutputPath</c>, or null.</param>
    /// <param name="backupName">The archive's name without extension.</param>
    /// <returns>The absolute archive path.</returns>
    /// <exception cref="InvalidOperationException">The path lies outside the application directory.</exception>
    internal static string ResolveArchivePath(string? outputPath, string baseDirectory, string? configuredOutputPath, string backupName)
    {
        var archivePath = Path.GetFullPath(outputPath
            ?? Path.Combine(ResolveBackupDirectory(baseDirectory, configuredOutputPath), $"{backupName}.zip"));
        if (!PathIsContainedIn(archivePath, baseDirectory))
        {
            throw new InvalidOperationException(
                $"Backup output path '{archivePath}' must be within the application directory '{baseDirectory}'.");
        }
        return archivePath;
    }

    /// <summary>
    /// Where a restore writes its pre-restore snapshot: <c>pre-restore-&lt;timestamp&gt;.zip</c> in
    /// the backup directory this host's <c>config.yaml</c> names, or <c>backups/</c> when there is
    /// no readable <c>config.yaml</c> yet (a new host).
    /// </summary>
    /// <param name="baseDirectory">The application directory.</param>
    /// <param name="liveConfigDir">This host's <c>config/</c> directory.</param>
    /// <param name="now">The time to stamp the snapshot with.</param>
    /// <returns>The absolute snapshot path.</returns>
    internal static string PreRestoreSnapshotPath(string baseDirectory, string liveConfigDir, DateTime now)
    {
        string? configured = null;
        var liveConfigPath = Path.Combine(liveConfigDir, "config.yaml");
        if (File.Exists(liveConfigPath))
        {
            try { configured = YamlConfigLoader.Load(liveConfigPath, _ => { }).Backup?.OutputPath; }
            catch (Exception) { configured = null; }
        }
        return Path.Combine(ResolveBackupDirectory(baseDirectory, configured), $"pre-restore-{now:yyyyMMdd-HHmmss}.zip");
    }

    /// <summary>
    /// Makes sure the directory a backup archive or a pre-restore snapshot is written to exists
    /// and is reachable by its owner alone, or throws
    /// (<see cref="FileSecurityUtil.EnsureOwnerOnlyDirectory"/>). A missing one is created
    /// owner-only.
    /// <para>
    /// An existing one that others can reach is restricted to its owner when it is the backup
    /// directory (<paramref name="backupDirectory"/>) and that is the backups' own: neither the
    /// application directory nor one holding <c>config/</c>, <c>keystores/</c>, <c>logs/</c> or
    /// <c>signer/</c>, whose accounts and groups a restriction would lock out. That covers an
    /// upgraded install whose <c>backups/</c> was created readable by others (the container image
    /// made it 0750, and the console created it with the default mode). Any other directory others
    /// can reach, such as one an explicit output path names, is refused with what to do.
    /// </para>
    /// <para>
    /// It used to leave an existing directory exactly as it was, and a new one that could not be
    /// restricted was only a warning.
    /// </para>
    /// </summary>
    /// <param name="directory">The directory the archive or snapshot goes in.</param>
    /// <param name="baseDirectory">The application directory.</param>
    /// <param name="backupDirectory">The backup directory (<see cref="ResolveBackupDirectory"/>).</param>
    /// <returns>True when an existing directory's permissions were tightened.</returns>
    /// <exception cref="IOException">The directory could not be created or restricted to its owner, or others can reach it and it may not be tightened.</exception>
    internal static bool EnsureArchiveDirectory(string directory, string baseDirectory, string backupDirectory)
    {
        static string Normalized(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

        var full = Normalized(directory);
        var tighten = string.Equals(full, Normalized(backupDirectory), StringComparison.Ordinal)
            && !new[] { "", "config", "keystores", "logs", "signer" }
                .Select(d => Path.Combine(baseDirectory, d))
                .Any(shared => PathIsContainedIn(shared, full));
        return FileSecurityUtil.EnsureOwnerOnlyDirectory(full, tighten);
    }

    /// <summary>
    /// <see cref="EnsureArchiveDirectory"/> for the console: prints that an existing directory was
    /// tightened, or why it could not be used, and returns false in that case.
    /// </summary>
    /// <param name="directory">The directory the archive or snapshot goes in.</param>
    /// <param name="baseDirectory">The application directory.</param>
    /// <param name="backupDirectory">The backup directory (<see cref="ResolveBackupDirectory"/>).</param>
    /// <param name="refusal">What the operation that was refused is called, for the message.</param>
    /// <returns>True when the directory is ready to write into.</returns>
    private static bool TryEnsureArchiveDirectory(string directory, string baseDirectory, string backupDirectory, string refusal)
    {
        try
        {
            if (EnsureArchiveDirectory(directory, baseDirectory, backupDirectory))
                Console.WriteLine($"🔒 {directory} could be reached by other local users; it is now restricted to this account.");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.WriteLine($"❌ {ex.Message}");
            Console.WriteLine($"   {refusal} refused: backup archives are only written to a directory only this account can reach.");
            return false;
        }
    }

    /// <summary>
    /// The databases a restore writes into and the credentials it uses: this host's own
    /// <c>config/db.yaml</c>, with the environment overrides the service applies at start
    /// (<see cref="EnvVarConfigOverlay"/>). Never the archive's: archives carry no
    /// <c>db.yaml</c>, and the <c>DB</c> section an older archive's <c>config.yaml</c> may carry
    /// names the host the backup was taken on. Returns null, with the reason, when this host has
    /// no usable <c>db.yaml</c>.
    /// </summary>
    /// <param name="liveConfigDir">This host's <c>config/</c> directory.</param>
    /// <param name="problem">Why there is no target, when there is none.</param>
    /// <returns>A configuration whose <c>DB</c> section is this host's, or null.</returns>
    internal static ModularCA.Shared.Models.Config.SystemConfig? LoadRestoreTargetDatabases(string liveConfigDir, out string? problem)
    {
        var dbYamlPath = Path.Combine(liveConfigDir, "db.yaml");
        if (!File.Exists(dbYamlPath))
        {
            problem = $"This host has no {dbYamlPath}, so there is no database to restore into.";
            return null;
        }

        var config = new ModularCA.Shared.Models.Config.SystemConfig();
        try
        {
            OverlayDbYaml(config, liveConfigDir);
        }
        catch (Exception ex)
        {
            problem = $"{dbYamlPath} could not be read: {ex.Message}";
            return null;
        }
        new EnvVarConfigOverlay().Apply(config);

        if (string.IsNullOrWhiteSpace(config.DB.App.Database) || string.IsNullOrWhiteSpace(config.DB.App.Username))
        {
            problem = $"{dbYamlPath} names no application database or role.";
            return null;
        }

        problem = null;
        return config;
    }

    /// <summary>
    /// Says which databases the restore writes into, and when the archive was taken from
    /// databases of other names, says that too.
    /// </summary>
    private static void ReportRestoreTarget(ModularCA.Shared.Models.Config.SystemConfig target, string manifestJson)
    {
        Console.WriteLine($"  Restoring into this host's databases (config/db.yaml): app '{target.DB.App.Database}' on " +
                          $"{target.DB.App.Host}:{target.DB.App.Port}, audit '{target.DB.Audit.Database}' on {target.DB.Audit.Host}:{target.DB.Audit.Port}.");
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            var archivedApp = doc.RootElement.TryGetProperty("AppDatabase", out var a) ? a.GetString() : null;
            var archivedAudit = doc.RootElement.TryGetProperty("AuditDatabase", out var b) ? b.GetString() : null;
            if ((archivedApp != null && archivedApp != target.DB.App.Database)
                || (archivedAudit != null && archivedAudit != target.DB.Audit.Database))
            {
                Console.WriteLine($"  (i) The archive was taken from app '{archivedApp}' and audit '{archivedAudit}'.");
            }
        }
        catch (JsonException)
        {
        }
    }

    /// <summary>
    /// Writes one file from an archive's <c>config/</c> over this host's. A file that exists is
    /// rewritten in place, so it keeps its owner, group and mode (on a split install
    /// <c>config.yaml</c> keeps the signer's group read); a new one is created owner-only.
    /// <c>config.yaml</c> loses any <c>DB</c> section an older archive carries: this host's
    /// <c>db.yaml</c> owns the credentials.
    /// </summary>
    /// <param name="source">The extracted archive file.</param>
    /// <param name="destination">The path under this host's <c>config/</c>.</param>
    internal static void RestoreConfigFile(string source, string destination)
    {
        if (string.Equals(Path.GetFileName(destination), "config.yaml", StringComparison.OrdinalIgnoreCase))
        {
            ConfigYamlWriter.WriteKeepingAccess(destination, ConfigYamlWriter.WithoutDbSection(File.ReadAllText(source)));
            return;
        }

        var bytes = File.ReadAllBytes(source);
        try
        {
            if (File.Exists(destination))
            {
                File.WriteAllBytes(destination, bytes);
                return;
            }

            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(destination, options))
                stream.Write(bytes);
            FileSecurityUtil.SetOwnerOnly(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Overlays runtime DB credentials from <c>db.yaml</c> onto the given config. Post-refactor,
    /// <c>config.yaml</c> no longer carries <c>DB.App.*</c> / <c>DB.Audit.*</c> secrets — they
    /// live in <c>db.yaml</c> alongside, and every tool that opens the app DB must apply this
    /// overlay after loading config.yaml or the connection string ends up with an empty user.
    /// </summary>
    private static void OverlayDbYaml(ModularCA.Shared.Models.Config.SystemConfig config, string configDir)
    {
        var dbYamlPath = Path.Combine(configDir, "db.yaml");
        var dbYaml = ModularCA.Shared.Utils.YamlDbConfigLoader.Load(dbYamlPath);
        if (dbYaml == null) return;

        config.DB.App.Host = dbYaml.App.Host;
        config.DB.App.Port = dbYaml.App.Port;
        config.DB.App.Database = dbYaml.App.Database;
        config.DB.App.Username = dbYaml.App.Username;
        config.DB.App.Password = dbYaml.App.Password;
        // Carry SslMode across the overlay so the strict-by-default
        // setting written into db.yaml isn't silently erased when config.yaml is loaded first.
        config.DB.App.SslMode = dbYaml.App.SslMode;

        config.DB.Audit.Host = dbYaml.Audit.Host;
        config.DB.Audit.Port = dbYaml.Audit.Port;
        config.DB.Audit.Database = dbYaml.Audit.Database;
        config.DB.Audit.Username = dbYaml.Audit.Username;
        config.DB.Audit.Password = dbYaml.Audit.Password;
        config.DB.Audit.SslMode = dbYaml.Audit.SslMode;
    }

    /// <summary>
    /// Creates a temporary PostgreSQL password file (<c>pgpass</c>) containing connection
    /// credentials. The caller must delete this file when done (use a finally block).
    /// </summary>
    /// <remarks>
    /// On POSIX systems the file is opened with explicit
    /// <see cref="UnixFileMode.UserRead"/>+<see cref="UnixFileMode.UserWrite"/> at create time
    /// (no race window between create and chmod). On Windows the file is created in the
    /// per-user temp directory and immediately ACL-tightened via
    /// <see cref="FileSecurityUtil.SetOwnerOnly"/>. Both matter more here than they did for the
    /// MySQL option file: libpq <em>refuses to read</em> a pgpass file that is group- or
    /// world-readable, so a permissive file does not leak the password, it silently produces an
    /// authentication failure instead.
    /// </remarks>
    /// <remarks>
    /// Escaping: a pgpass line is five colon-separated fields, and a literal colon or backslash
    /// inside any field is escaped with a backslash. That is the whole grammar — there is no
    /// quoting, and no comment character to be truncated at, which removes the <c>#</c> trap the
    /// MySQL option file had. <see cref="PasswordUtil.Generate"/>'s symbol set can produce both
    /// escaped characters, so this is a real failure mode rather than a theoretical one.
    /// </remarks>
    /// <param name="host">Server hostname, matched literally by libpq.</param>
    /// <param name="port">Server port.</param>
    /// <param name="database">Database name the entry applies to.</param>
    /// <param name="username">Role the entry applies to.</param>
    /// <param name="password">The password to supply.</param>
    /// <returns>The path of the temporary file, which the caller must delete.</returns>
    internal static string WritePgPassFile(string host, int port, string database, string username, string password)
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"modularca-pgpass-{Guid.NewGuid():N}.conf");
        static string Field(string value) => value.Replace("\\", "\\\\").Replace(":", "\\:");
        var content = $"{Field(host)}:{port}:{Field(database)}:{Field(username)}:{Field(password)}\n";
        var bytes = Encoding.UTF8.GetBytes(content);

        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.None,
        };

        if (!OperatingSystem.IsWindows())
        {
            // .NET 7+: set the unix mode at creation, eliminating the race window.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using (var fs = new FileStream(tempPath, options))
        {
            fs.Write(bytes, 0, bytes.Length);
        }
        // Tighten Windows ACL (no-op on POSIX where UnixCreateMode already applied).
        FileSecurityUtil.SetOwnerOnly(tempPath);
        return tempPath;
    }

    /// <summary>
    /// Recursively copies a directory and all its contents to a new location.
    /// </summary>
    /// <param name="source">The source directory path.</param>
    /// <param name="destination">The destination directory path.</param>
    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true);
        foreach (var dir in Directory.GetDirectories(source))
            CopyDirectory(dir, Path.Combine(destination, Path.GetFileName(dir)));
    }

    /// <summary>
    /// Recursively copies a directory while skipping any file whose name matches
    /// <see cref="BackupSecretDenylist"/>. Used by Backup() to keep KEKs and
    /// secret-bearing files OUT of the archive that they protect.
    /// </summary>
    /// <param name="source">Source directory.</param>
    /// <param name="destination">Destination directory (created if missing).</param>
    /// <param name="excludedDirectories">Directories, relative to <paramref name="source"/> with forward slashes, left out whole.</param>
    /// <param name="skipped">Receives the list of denied file names that were skipped (relative paths).</param>
    /// <param name="excludedRootFiles">Names of files directly in <paramref name="source"/> that are left out: SSH CA key files that lie in no directory of their own.</param>
    internal static void CopyDirectoryFiltered(string source, string destination, IEnumerable<string> excludedDirectories, out List<string> skipped,
        IEnumerable<string>? excludedRootFiles = null)
    {
        skipped = new List<string>();
        var excluded = new HashSet<string>(excludedDirectories.Select(d => d.Replace('\\', '/').Trim('/')), StringComparer.Ordinal);
        var excludedFiles = new HashSet<string>(excludedRootFiles ?? [], StringComparer.Ordinal);
        CopyDirectoryFilteredImpl(source, destination, source, excluded, excludedFiles, skipped);
    }

    /// <summary>The recursion behind <see cref="CopyDirectoryFiltered"/>.</summary>
    private static void CopyDirectoryFilteredImpl(string source, string destination, string root, HashSet<string> excluded, HashSet<string> excludedRootFiles, List<string> skipped)
    {
        Directory.CreateDirectory(destination);
        var atRoot = string.Equals(Path.GetFullPath(source), Path.GetFullPath(root), StringComparison.Ordinal);
        foreach (var file in Directory.GetFiles(source))
        {
            var fileName = Path.GetFileName(file);
            if (BackupSecretDenylist.IsDenied(fileName))
            {
                skipped.Add(Path.GetRelativePath(root, file));
                continue;
            }
            if (atRoot && excludedRootFiles.Contains(fileName))
                continue;
            File.Copy(file, Path.Combine(destination, fileName), true);
        }
        foreach (var dir in Directory.GetDirectories(source))
        {
            if (excluded.Contains(Path.GetRelativePath(root, dir).Replace('\\', '/')))
                continue;
            var dirName = Path.GetFileName(dir);
            CopyDirectoryFilteredImpl(dir, Path.Combine(destination, dirName), root, excluded, excludedRootFiles, skipped);
        }
    }

    /// <summary>
    /// The key file paths of the SSH CA keys that are, or may still be, plaintext files on the
    /// node, as the application database records them: the path of every key row that has one
    /// (a row has a path exactly while its key awaits its import into the signer), and the path
    /// of every imported key whose file has not been removed yet. A database without the SSH
    /// tables has none. This is where a backup learns which directories hold SSH CA key files;
    /// it throws what the driver throws when the rows cannot be read.
    /// </summary>
    /// <param name="appConnectionString">The application database.</param>
    internal static async Task<IReadOnlyList<string>> LegacySshKeyFilesAsync(string appConnectionString)
    {
        var files = new List<string>();
        await using var conn = new NpgsqlConnection(appConnectionString);
        await conn.OpenAsync();

        bool hasKeys, hasImports;
        await using (var probe = new NpgsqlCommand(
            """SELECT to_regclass('"SshCaKeys"') IS NOT NULL, to_regclass('"SshKeyImports"') IS NOT NULL""", conn))
        await using (var reader = await probe.ExecuteReaderAsync())
        {
            await reader.ReadAsync();
            hasKeys = reader.GetBoolean(0);
            hasImports = reader.GetBoolean(1);
        }

        if (hasKeys)
        {
            await using var cmd = new NpgsqlCommand(
                """SELECT "PrivateKeyPath" FROM "SshCaKeys" WHERE "PrivateKeyPath" IS NOT NULL AND "PrivateKeyPath" <> '' """, conn);
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                files.Add(reader.GetString(0));
        }
        if (hasImports)
        {
            await using var cmd = new NpgsqlCommand(
                """SELECT "FilePath" FROM "SshKeyImports" WHERE "FileRemovedAt" IS NULL""", conn);
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                files.Add(reader.GetString(0));
        }
        return files;
    }

    /// <summary>
    /// Makes the signer's SSH keystore agree with a restored state that has none: when the
    /// extracted archive in <paramref name="restoreDir"/> carries no <c>ssh-ca.keystore</c>, the
    /// signer is told so (<see cref="KeyMaterial.KeystoreFileAbsent"/>) and moves a file it still
    /// keeps under that name aside, as <c>ssh-ca.keystore.bak.&lt;timestamp&gt;</c>. The restored
    /// database has no <c>Keystores</c> row for it, and a file without its row leaves the signer
    /// locked at the next start. With the file out of the way, the next start imports the SSH CA
    /// key files the archive brought back. Returns the line to print, or null when the archive
    /// carries the keystore and nothing was asked of the signer. A signer that refuses, because it
    /// predates this or because the restored database does have a row for the keystore, is
    /// reported in that line and does not fail the restore.
    /// </summary>
    /// <param name="signer">The signer the keystore files go back through.</param>
    /// <param name="restoreDir">The directory the archive was extracted into.</param>
    internal static async Task<string?> ReconcileAbsentSshKeystoreAsync(ISigningService signer, string restoreDir)
    {
        if (File.Exists(Path.Combine(restoreDir, "keystores", KeyRef.SshKeystore)))
            return null;
        var restoreContext = new SigningContext(RestoreCaller, SigningPurpose.Restore, null, null);
        try
        {
            await signer.ImportKeyAsync(new KeyMaterial(Array.Empty<byte>(), KeyMaterial.KeystoreFileAbsent, Guid.Empty, KeyRef.SshKeystore), restoreContext);
            return $"  ✓ The archive carries no {KeyRef.SshKeystore}; the signer's own was moved aside as {KeyRef.SshKeystore}.bak.<timestamp>.";
        }
        catch (Exception ex)
        {
            return $"  ⚠ The archive carries no {KeyRef.SshKeystore}, and the signer did not move a live one aside ({ex.Message})." + Environment.NewLine
                + $"    If the signer's keystore directory holds a {KeyRef.SshKeystore}, move it aside by hand before the next start: with no" + Environment.NewLine
                + "    Keystores row for it in the restored database, it would leave the signer locked.";
        }
    }

    /// <summary>
    /// Scans a recursively-extracted directory for any file whose name appears in
    /// <see cref="BackupSecretDenylist"/>. Defense-in-depth used by Restore() to
    /// refuse legacy or third-party archives that still bundle secret-bearing files.
    /// </summary>
    /// <param name="root">Extracted archive root directory.</param>
    /// <returns>List of relative paths matching the deny-list (empty when none found).</returns>
    private static List<string> ScanForDeniedFiles(string root)
    {
        var found = new List<string>();
        if (!Directory.Exists(root)) return found;
        foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(file);
            if (BackupSecretDenylist.IsDenied(name))
                found.Add(Path.GetRelativePath(root, file));
        }
        return found;
    }

    /// <summary>
    /// Returns true when <paramref name="candidate"/>, after full-path normalization, lies inside
    /// (or equals) <paramref name="container"/>. Applies the trailing-separator
    /// pattern uniformly so a sibling directory with a shared prefix
    /// (e.g. <c>C:\opt\modularca</c> vs <c>C:\opt\modularca-backups</c>) cannot pass.
    /// </summary>
    /// <param name="candidate">Path being validated.</param>
    /// <param name="container">Directory that must contain the candidate path.</param>
    public static bool PathIsContainedIn(string candidate, string container)
    {
        var fullCandidate = Path.GetFullPath(candidate);
        var fullContainer = Path.GetFullPath(container);
        if (fullCandidate.Equals(fullContainer, StringComparison.Ordinal))
            return true;
        var withSep = fullContainer.EndsWith(Path.DirectorySeparatorChar)
            ? fullContainer
            : fullContainer + Path.DirectorySeparatorChar;
        return fullCandidate.StartsWith(withSep, StringComparison.Ordinal);
    }

    /// <summary>
    /// Captures a pre-restore snapshot of the live config directory and the live keystore
    /// files, as the signer exported them, into a timestamped ZIP file, providing a manual
    /// rollback path if the restore corrupts state. The snapshot intentionally includes the
    /// secret-bearing config files (it is local-only, is owned by the operator, and is never
    /// uploaded). The snapshot is the operator's last line of defense and must not be sanitised.
    /// The files are staged in a directory only this user can reach
    /// (<see cref="CreatePreRestoreStagingDirectory"/>); when one cannot be made the snapshot
    /// throws, and the restore stops.
    /// </summary>
    /// <param name="destinationZip">Absolute path where the snapshot ZIP is written.</param>
    /// <param name="configDir">Absolute path to the live <c>config/</c> directory.</param>
    /// <param name="keystores">The live keystore files by name, as the signer exported them.</param>
    private static void CreatePreRestoreSnapshot(string destinationZip, string configDir, IReadOnlyList<(string Name, byte[] Bytes)> keystores)
    {
        var stagingDir = CreatePreRestoreStagingDirectory();
        try
        {
            if (Directory.Exists(configDir))
                CopyDirectory(configDir, Path.Combine(stagingDir, "config"));
            if (keystores.Count > 0)
            {
                var keystoreStaging = Path.Combine(stagingDir, "keystores");
                Directory.CreateDirectory(keystoreStaging);
                foreach (var (name, bytes) in keystores)
                    File.WriteAllBytes(Path.Combine(keystoreStaging, name), bytes);
            }

            if (File.Exists(destinationZip))
                throw new InvalidOperationException($"Snapshot path '{destinationZip}' already exists.");
            // The snapshot holds config/ in the clear: owner-only from creation, not zipped at
            // default permissions and restricted afterwards.
            FileSecurityUtil.CreateOwnerOnly(destinationZip, stream => ZipFile.CreateFromDirectory(stagingDir, stream));
        }
        finally
        {
            try { Directory.Delete(stagingDir, true); } catch { }
        }
    }

    /// <summary>The head of the signer's journal as a backup's manifest carries it: the sequence and the hash of the last record.</summary>
    /// <param name="Seq">The sequence.</param>
    /// <param name="Hash">The hash, lower-case hex.</param>
    public sealed record ManifestJournalHead(ulong Seq, string Hash);

    /// <summary>
    /// Reads the head of the signer's issuance journal for a backup's manifest: from the signer
    /// when it keeps a journal and answers, otherwise from the journal's files when this host
    /// has them, which is the case of the command-line backup, whose own signer keeps none.
    /// Null when neither gives one; a backup is taken all the same.
    /// </summary>
    internal static async Task<ManifestJournalHead?> ReadJournalHeadAsync(ISigningService signer, ModularCA.Shared.Models.Config.SystemConfig config)
    {
        try
        {
            if (await signer.JournalInfoAsync() is { Seq: > 0 } info)
                return new ManifestJournalHead(info.Seq, info.Hash);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A signer that cannot say: the files are tried next.
        }
        try
        {
            var home = ModularCA.Shared.Models.Config.SignerPaths.Shared(AppContext.BaseDirectory).JournalDirectory(config.Signer);
            var head = ModularCA.Journal.JournalHead.Read(ModularCA.Journal.JournalLayout.ReadDirectory(home));
            if (head.ExitCode == ModularCA.Journal.JournalHead.ExitOk && head.Verification?.Head is { } state)
                return new ManifestJournalHead(state.Seq, Convert.ToHexStringLower(state.Hash));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // No readable journal on this host.
        }
        return null;
    }

    /// <summary>
    /// Queues, in the database a restore has just restored, the fact that the restore ran: the
    /// archive's file name and, from its manifest, its instance identifier, its creation time
    /// and the journal head it carries, if any. The node offers the fact to the signer at its
    /// next start. A database from before the queue has no table for it; the restore then says
    /// so and goes on, as it does for anything else here that fails.
    /// </summary>
    internal static async Task<bool> QueueRestoreMarkerAsync(string appConnectionString, string archiveName, string manifestJson)
    {
        try
        {
            var payload = RestoreMarkerPayload(archiveName, manifestJson, DateTimeOffset.UtcNow);
            await using var connection = new Npgsql.NpgsqlConnection(appConnectionString);
            await connection.OpenAsync();
            await using (var exists = new Npgsql.NpgsqlCommand("""SELECT to_regclass('"SignerFactQueue"') IS NOT NULL""", connection))
            {
                if (await exists.ExecuteScalarAsync() is not true)
                {
                    Console.WriteLine("  (i) The restored database is from before the signer's journal: no restore marker is queued for it.");
                    return false;
                }
            }
            await using var insert = new Npgsql.NpgsqlCommand(
                """INSERT INTO "SignerFactQueue" ("Type", "Payload", "CreatedAt", "Attempts") VALUES (@type, @payload, @now, 0)""", connection);
            insert.Parameters.AddWithValue("type", (int)ModularCA.Journal.RecordType.RestoreMarker);
            insert.Parameters.AddWithValue("payload", payload);
            insert.Parameters.AddWithValue("now", DateTime.UtcNow);
            await insert.ExecuteNonQueryAsync();
            Console.WriteLine("  ✓ Restore marker queued for the signer's journal; the node hands it over at its next start.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ⚠ The restore marker for the signer's journal could not be queued ({ex.GetType().Name}: {ex.Message}). The restore goes on.");
            return false;
        }
    }

    /// <summary>The <c>RestoreMarker</c> fact for a restore of <paramref name="archiveName"/>, from what its manifest says.</summary>
    internal static byte[] RestoreMarkerPayload(string archiveName, string manifestJson, DateTimeOffset now)
    {
        string? instanceId = null;
        long? createdAt = null;
        ModularCA.Journal.HeadRef? head = null;
        try
        {
            using var manifest = JsonDocument.Parse(manifestJson);
            var root = manifest.RootElement;
            if (root.TryGetProperty("InstanceId", out var id) && id.ValueKind == JsonValueKind.String)
                instanceId = id.GetString();
            if (root.TryGetProperty("Timestamp", out var taken) && taken.ValueKind == JsonValueKind.String && taken.TryGetDateTimeOffset(out var at))
                createdAt = ModularCA.Journal.JournalFormat.ToMicros(at);
            if (root.TryGetProperty("JournalHead", out var journal) && journal.ValueKind == JsonValueKind.Object
                && journal.TryGetProperty("Seq", out var seq) && seq.TryGetUInt64(out var sequence)
                && journal.TryGetProperty("Hash", out var hash) && hash.ValueKind == JsonValueKind.String)
                head = new ModularCA.Journal.HeadRef(sequence, Convert.FromHexString(hash.GetString()!));
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            // A manifest this cannot read still names its archive.
        }
        return new ModularCA.Journal.RestoreMarkerPayload(archiveName, instanceId, createdAt, head, ModularCA.Journal.JournalFormat.ToMicros(now)).Encode();
    }

    /// <summary>
    /// Exports every keystore file a backup carries through the signer under the backup wrap,
    /// by name. A keystore the signer does not keep is skipped, since a node that has never
    /// been bootstrapped has none and an install with no SSH CA has no SSH keystore; any other
    /// refusal propagates, because a backup that silently lacks its keystores is worse than none.
    /// </summary>
    private static async Task<IReadOnlyList<(string Name, byte[] Bytes)>> ExportKeystoresAsync(ISigningService signer, string caller)
    {
        var context = new SigningContext(caller, SigningPurpose.Backup, null, null);
        var files = new List<(string, byte[])>();
        foreach (var name in KeyRef.BackupKeystores)
        {
            try
            {
                files.Add((name, await signer.ExportKeyAsync(KeyRef.ForKeystore(name), ExportWrap.ForKeystoreFile(), context)));
            }
            catch (SigningRefusedException ex) when (ex.Reason == SigningRefusalReason.UnknownKey)
            {
                // Not kept: nothing to carry.
            }
        }
        return files;
    }

    /// <summary>
    /// The application database's connection string as the configuration names it, honouring
    /// the configured SSL mode. Used for the signer and the schema probes alike.
    /// </summary>
    private static string AppConnectionString(ModularCA.Shared.Models.Config.SystemConfig config)
    {
        return ModularCA.Shared.Utils.PostgresConnection.Build(config.DB.App);
    }

    /// <summary>
    /// Safely extract an open ZIP archive into <paramref name="destinationDir"/>, rejecting
    /// any entry whose resolved full path falls outside the destination root. Also rejects
    /// absolute entry paths, NUL bytes, and ADS markers (<c>:</c>). This replaces
    /// <c>ZipFile.ExtractToDirectory</c>, which is susceptible to zip-slip when the archive
    /// is attacker-influenced.
    /// </summary>
    /// <param name="archive">The ZIP archive, opened for reading.</param>
    /// <param name="destinationDir">Absolute path where entries will be extracted.</param>
    private static void SafeExtractZip(ZipArchive archive, string destinationDir)
    {
        var fullDest = Path.GetFullPath(destinationDir);
        var destWithSep = fullDest.EndsWith(Path.DirectorySeparatorChar)
            ? fullDest
            : fullDest + Path.DirectorySeparatorChar;

        foreach (var entry in archive.Entries)
        {
            var rawName = entry.FullName;
            if (string.IsNullOrEmpty(rawName))
                continue;

            // Reject NUL bytes anywhere in the entry name.
            if (rawName.IndexOf('\0') >= 0)
                throw new InvalidDataException($"Refusing zip entry with NUL byte in name: '{rawName}'.");

            // Normalize separators so the downstream check never trips on mixed slashes.
            var normalized = rawName.Replace('\\', '/');

            // Reject absolute paths outright. On Windows this includes drive-qualified paths
            // like "C:\evil" or UNC "\\server\share"; on POSIX any leading "/".
            if (Path.IsPathRooted(normalized))
                throw new InvalidDataException($"Refusing zip entry with absolute path: '{rawName}'.");

            // Reject ADS markers (e.g. "file.txt:evil"). A ':' is never valid inside a ZIP
            // entry name for our use case, so block on all platforms.
            if (normalized.IndexOf(':') >= 0)
                throw new InvalidDataException($"Refusing zip entry with ':' in name (ADS marker): '{rawName}'.");

            // Directory entries (trailing '/') — create the directory after path validation.
            var isDirEntry = normalized.EndsWith('/');

            var combined = Path.Combine(fullDest, normalized.Replace('/', Path.DirectorySeparatorChar));
            var resolved = Path.GetFullPath(combined);

            if (!(resolved.Equals(fullDest, StringComparison.Ordinal) ||
                  resolved.StartsWith(destWithSep, StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    $"Refusing zip entry that escapes restore directory: '{rawName}' -> '{resolved}'.");
            }

            if (isDirEntry)
            {
                Directory.CreateDirectory(resolved);
                continue;
            }

            var parent = Path.GetDirectoryName(resolved);
            if (!string.IsNullOrEmpty(parent))
                Directory.CreateDirectory(parent);

            // overwrite: false — the restore dir is a fresh temp dir, so collisions would
            // indicate a crafted archive with duplicate entries.
            entry.ExtractToFile(resolved, overwrite: false);
        }
    }
}
