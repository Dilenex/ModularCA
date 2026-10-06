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
    /// The backup manifest includes a schema version derived from the current database table names.
    /// Validates that the output path and encryption key path do not escape the application directory.
    /// The archived <c>config.yaml</c> never carries a <c>DB</c> section: the credentials stay in
    /// <c>db.yaml</c>, which no archive carries. A database that cannot be dumped ends the backup
    /// with no archive, and the encryption key is loaded before any plaintext archive exists; one
    /// left unencrypted by a later failure is deleted.
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
        EnsureOwnerOnlyDirectory(Path.GetDirectoryName(archivePath)!);

        var backupDir = Path.Combine(Path.GetTempPath(), backupName);
        Directory.CreateDirectory(backupDir);
        // Plaintext keystores and config are copied in here before the archive is encrypted.
        // GetTempPath is /tmp on Linux, which is world-readable, so without this every local
        // user can read the CA private keys for the duration of the backup. Hardening only the
        // finished archive (further down) does nothing for the plaintext staged beside it.
        FileSecurityUtil.SetDirectoryOwnerOnly(backupDir);
        string? plaintextArchive = null;

        try
        {
            Console.WriteLine($"📦 Creating backup: {backupName}");

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(config.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(config.DB.Audit.Database, "audit database name");

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
            var signer = signerForAppDatabase(AppConnectionString(config));
            var exported = await ExportKeystoresAsync(signer, BackupCaller);
            if (exported.Count > 0)
            {
                Directory.CreateDirectory(backupKeystores);
                foreach (var (name, bytes) in exported)
                    File.WriteAllBytes(Path.Combine(backupKeystores, name), bytes);
            }
            Console.WriteLine($" ✓ ({exported.Count} file(s))");

            // 3. The Data Protection key ring and the SSH CA keys travel wrapped by the signer,
            // never in the clear: with the database dump the ring opens every DP-protected column.
            var wrappedTargets = BackupWrappedSecrets.Targets(configDir, config.SshCa?.KeyStoragePath);
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
            CopyDirectoryFiltered(configDir, backupConfig, wrappedTargets, out var skippedDenied);
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
                SchemaVersion = schemaVersion,
                CaCount = caCount,
                CertCount = certCount,
                UserCount = userCount,
                KeystoreIntegrity = keystoreIntegrity,
                DbIntegrity = dbIntegrity,
                WrappedSecrets = wrapped,
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
            ZipFile.CreateFromDirectory(backupDir, archivePath);
            FileSecurityUtil.SetOwnerOnly(archivePath);
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
                SchemaVersion = schemaVersion,
                CaCount = caCount,
                CertCount = certCount,
                UserCount = userCount,
                KeystoreIntegrity = keystoreIntegrity,
                DbIntegrity = dbIntegrity,
                WrappedSecrets = wrapped,
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
                using (var fs = File.Create(encPath))
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
                }

                File.Delete(archivePath); // Remove plaintext ZIP
                plaintextArchive = null;
                FileSecurityUtil.SetOwnerOnly(encPath);
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
    /// (<see cref="PreRestoreSnapshotPath"/>), and refuses
    /// archives that contain secret-bearing files on the deny-list.
    /// The databases are restored into the ones this host's own <c>config/db.yaml</c> names, with
    /// its credentials (<see cref="LoadRestoreTargetDatabases"/>); a host without one is refused
    /// before anything changes. Restored config files keep the access of the files they replace
    /// (<see cref="RestoreConfigFile"/>).
    /// An archive with no application database is refused before anything changes, and a
    /// database that cannot be restored ends the restore before a keystore or a config file is
    /// replaced. The CRL counters are raised and every CRL configuration made due
    /// (<see cref="CrlNumberFloor"/>), and this host's self-issued Web TLS certificate file is
    /// removed: the node issues a new one at its next start.
    /// Supports both the new <c>.enc</c> format (magic "MCAB" + mode marker + scrypt header) and
    /// the legacy format (<c>[nonce][tag][ciphertext]</c>) for backward compatibility.
    /// </summary>
    /// <param name="archivePath">Path to the backup .zip or .enc (encrypted) archive.</param>
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
    /// <returns>0 on success, non-zero on failure.</returns>
    public static async Task<int> Restore(string archivePath, Func<string, ISigningService> signerForAppDatabase, bool skipSchemaCheck = false, string? providedPassword = null, bool interactive = true)
    {
        ArgumentNullException.ThrowIfNull(signerForAppDatabase);
        if (!File.Exists(archivePath))
        {
            Console.WriteLine($"❌ Backup archive not found: {archivePath}");
            return 1;
        }

        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var archiveName = Path.GetFileName(archivePath);
        var restoreDir = Path.Combine(Path.GetTempPath(), $"modularca-restore-{Guid.NewGuid():N}");
        string? tempDecryptedZip = null;

        try
        {
            Console.WriteLine($"📦 Restoring from: {archivePath}");

            // If archive is encrypted (.enc), decrypt first
            if (archivePath.EndsWith(".enc"))
            {
                // Resolve RandomKey path (containment check uses GetRelativePath helper).
                var restoreKeyRelativePath = "config/backup.key";
                if (restoreKeyRelativePath.Contains("..") || Path.IsPathRooted(restoreKeyRelativePath))
                    throw new InvalidOperationException("Invalid backup encryption key path — must be relative without '..' sequences.");
                var randomKeyPath = Path.Combine(AppContext.BaseDirectory, restoreKeyRelativePath);
                if (!PathIsContainedIn(randomKeyPath, AppContext.BaseDirectory))
                    throw new InvalidOperationException("Backup encryption key path escapes application directory.");

                // Resolve StoredPassword path
                var passwordRelativePath = "config/backup-password.key";
                if (passwordRelativePath.Contains("..") || Path.IsPathRooted(passwordRelativePath))
                    throw new InvalidOperationException("Invalid backup password file path — must be relative without '..' sequences.");
                var passwordKeyPath = Path.Combine(AppContext.BaseDirectory, passwordRelativePath);
                if (!PathIsContainedIn(passwordKeyPath, AppContext.BaseDirectory))
                    throw new InvalidOperationException("Backup password file path escapes application directory.");

                var encrypted = await File.ReadAllBytesAsync(archivePath);
                byte[]? key = null;
                byte[]? derivedKey = null;
                byte[]? plaintext = null;
                byte[]? ciphertext = null;
                try
                {
                    // Detect new vs legacy format via magic bytes.
                    bool isNewFormat = encrypted.Length >= BackupKeyManager.MagicBytes.Length
                        && encrypted.AsSpan(0, BackupKeyManager.MagicBytes.Length).SequenceEqual(BackupKeyManager.MagicBytes);

                    byte[] nonce;
                    byte[] tag;
                    BackupEncryptionMode archiveMode;

                    if (isNewFormat)
                    {
                        // New header is 66 bytes: 4 magic + 1 version + 1 mode + 16 salt + 8 N + 4 r + 4 p + 12 nonce + 16 tag
                        if (encrypted.Length < 66)
                            throw new InvalidDataException("Backup archive header is truncated.");
                        var version = encrypted[4];
                        if (version != BackupKeyManager.FormatVersion)
                            throw new InvalidDataException($"Unsupported backup archive version: {version}");
                        archiveMode = (BackupEncryptionMode)encrypted[5];
                        var salt = encrypted.AsSpan(6, BackupKeyManager.SaltSize).ToArray();
                        var n = BinaryPrimitives.ReadInt64LittleEndian(encrypted.AsSpan(22, 8));
                        var r = BinaryPrimitives.ReadInt32LittleEndian(encrypted.AsSpan(30, 4));
                        var p = BinaryPrimitives.ReadInt32LittleEndian(encrypted.AsSpan(34, 4));
                        nonce = encrypted.AsSpan(38, BackupKeyManager.NonceSize).ToArray();
                        tag = encrypted.AsSpan(50, BackupKeyManager.TagSize).ToArray();
                        ciphertext = encrypted.AsSpan(66).ToArray();

                        if (archiveMode == BackupEncryptionMode.RandomKey)
                        {
                            if (!File.Exists(randomKeyPath))
                                throw new InvalidOperationException("Backup encryption key not found. Cannot decrypt backup.");
                            key = File.ReadAllBytes(randomKeyPath);
                            if (key.Length != BackupKeyManager.KeySize)
                                throw new InvalidOperationException(
                                    $"Backup encryption key must be 256 bits, got {key.Length * 8}.");
                        }
                        else if (archiveMode == BackupEncryptionMode.StoredPassword)
                        {
                            // Priority 1: explicit operator-supplied password (disaster recovery).
                            if (!string.IsNullOrEmpty(providedPassword))
                            {
                                derivedKey = BackupKeyManager.DeriveKey(providedPassword, salt, n, r, p);
                                key = derivedKey;
                            }
                            // Priority 2: stored KEK file, but only if its salt matches this archive.
                            else if (File.Exists(passwordKeyPath))
                            {
                                var (storedKek, storedSalt, _, _, _) = BackupKeyManager.ReadPasswordKeyFile(passwordKeyPath);
                                if (storedSalt.AsSpan().SequenceEqual(salt))
                                {
                                    key = storedKek;
                                }
                                else
                                {
                                    BackupKeyManager.ZeroKey(storedKek);
                                    throw new InvalidOperationException(
                                        "This archive was encrypted with an older password and cannot be decrypted using the current stored password file. " +
                                        "Re-run the restore with the original password supplied via the API.");
                                }
                            }
                            else
                            {
                                throw new FileNotFoundException(
                                    $"Password file '{passwordKeyPath}' not found and no password was supplied. " +
                                    "Provide the original backup password via the restore API to recover this archive.");
                            }
                        }
                        else
                        {
                            throw new InvalidDataException($"Unknown backup encryption mode: {archiveMode}");
                        }
                    }
                    else
                    {
                        // Legacy format: [12 nonce][16 tag][ciphertext] — always RandomKey mode.
                        if (encrypted.Length < BackupKeyManager.NonceSize + BackupKeyManager.TagSize)
                            throw new InvalidDataException("Legacy backup archive is truncated.");
                        archiveMode = BackupEncryptionMode.RandomKey;
                        nonce = encrypted.AsSpan(0, BackupKeyManager.NonceSize).ToArray();
                        tag = encrypted.AsSpan(BackupKeyManager.NonceSize, BackupKeyManager.TagSize).ToArray();
                        ciphertext = encrypted.AsSpan(BackupKeyManager.NonceSize + BackupKeyManager.TagSize).ToArray();
                        if (!File.Exists(randomKeyPath))
                            throw new InvalidOperationException("Backup encryption key not found. Cannot decrypt backup.");
                        key = File.ReadAllBytes(randomKeyPath);
                        if (key.Length != BackupKeyManager.KeySize)
                            throw new InvalidOperationException(
                                $"Backup encryption key must be 256 bits, got {key.Length * 8}.");
                        Console.WriteLine("(i) Restoring from legacy backup format (no mode marker).");
                    }

                    plaintext = new byte[ciphertext.Length];
                    using (var aes = new AesGcm(key, BackupKeyManager.TagSize))
                    {
                        try { aes.Decrypt(nonce, ciphertext, tag, plaintext); }
                        catch (CryptographicException ex)
                        {
                            throw new InvalidOperationException("Backup decryption failed. File may be corrupted or encrypted with a different key.", ex);
                        }
                    }

                    // Write decrypted ZIP to temp location
                    tempDecryptedZip = Path.GetTempFileName() + ".zip";
                    File.WriteAllBytes(tempDecryptedZip, plaintext);
                    // The decrypted archive contains every CA private key in the install.
                    FileSecurityUtil.SetOwnerOnly(tempDecryptedZip);
                    archivePath = tempDecryptedZip; // Use decrypted ZIP for rest of restore
                }
                finally
                {
                    if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
                    if (ciphertext != null) CryptographicOperations.ZeroMemory(ciphertext);
                    if (key != null && !ReferenceEquals(key, derivedKey)) BackupKeyManager.ZeroKey(key);
                    if (derivedKey != null) BackupKeyManager.ZeroKey(derivedKey);
                }
            }

            // Extract with per-entry path validation to prevent zip slip.
            // Every entry must resolve to a path inside restoreDir; absolute paths, ADS
            // markers, null bytes, and parent-traversal sequences are rejected.
            Directory.CreateDirectory(restoreDir);
            // Harden BEFORE extracting: the archive is expanded in place, so from the next line
            // onward this directory holds every CA private key in plaintext. Under a
            // world-readable /tmp that is readable by any local user until the restore finishes.
            FileSecurityUtil.SetDirectoryOwnerOnly(restoreDir);
            SafeExtractZip(archivePath, restoreDir);

            // Validate manifest
            var manifestPath = Path.Combine(restoreDir, "manifest.json");
            if (!File.Exists(manifestPath))
            {
                Console.WriteLine("❌ Invalid backup archive: manifest.json not found");
                return 1;
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
                return 1;
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
                return 1;
            }

            // An archive with no application database would put back keys and settings over a
            // database they do not belong to.
            var appDump = Path.Combine(restoreDir, AppDumpFileName);
            if (!File.Exists(appDump) || new FileInfo(appDump).Length == 0)
            {
                Console.WriteLine($"❌ This archive holds no application database ({AppDumpFileName} is missing or empty).");
                Console.WriteLine("   The backup that wrote it could not dump the database. Nothing was changed; restore an");
                Console.WriteLine("   earlier archive.");
                return 1;
            }

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
                return 1;
            }
            ReportRestoreTarget(target, manifestJson);

            // Schema version check
            if (!skipSchemaCheck)
            {
                var schemaCheckResult = await ValidateSchemaVersionAsync(manifestJson);
                if (schemaCheckResult != 0)
                    return schemaCheckResult;
            }

            // Confirmation — only consume stdin when running interactively (CLI path).
            // The API path (interactive=false) is expected to gate the call with step-up MFA
            // and a single-use restore token before reaching this point.
            if (interactive)
            {
                Console.Write("\n⚠️  This will OVERWRITE current config, keystores, and databases. Type [RESTORE] to confirm: ");
                if (Console.ReadLine()?.Trim() != "RESTORE")
                {
                    Console.WriteLine("❌ Restore cancelled.");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("(i) Non-interactive restore — confirmation enforced upstream by API.");
            }

            // The backup's config, for the settings it carries; never for database credentials.
            var backupConfigPath = Path.Combine(restoreDir, "config", "config.yaml");
            if (!File.Exists(backupConfigPath))
            {
                Console.WriteLine("❌ Backup config.yaml not found in archive");
                return 1;
            }
            var backupConfig = YamlConfigLoader.Load(backupConfigPath);

            // An archive from before the key ring travelled wrapped carries it, and the SSH CA
            // keys, in the clear under config/. It still restores: dropping the ring would leave
            // every DP-protected column unreadable. The operator is told to replace the archive.
            var archiveConfigDir = Path.Combine(restoreDir, "config");
            var plaintextSecrets = BackupWrappedSecrets.PlaintextTargetsIn(archiveConfigDir,
                BackupWrappedSecrets.Targets(archiveConfigDir, backupConfig.SshCa?.KeyStoragePath));
            if (plaintextSecrets.Count > 0)
            {
                Console.WriteLine($"⚠  This archive carries {string.Join(", ", plaintextSecrets)} in plaintext (taken before these travelled wrapped).");
                Console.WriteLine("   They are restored as before. Take a new backup once the restore is done and destroy this archive:");
                Console.WriteLine("   anyone holding it and its key can read every TOTP secret, held key and stored credential.");
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
                EnsureOwnerOnlyDirectory(Path.GetDirectoryName(snapshotPath)!);
                liveKeystores = await ExportKeystoresAsync(signer, RestoreCaller);
                CreatePreRestoreSnapshot(snapshotPath, configDir, liveKeystores);
                Console.WriteLine($"  ✓ Pre-restore snapshot saved to: {snapshotPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Pre-restore snapshot failed: {ex.Message}");
                Console.WriteLine("   Aborting restore — refusing to destroy live state without a rollback safety net.");
                return 1;
            }

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(target.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(target.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(target.DB.Audit.Database, "audit database name");

            // 1. Restore databases. Each is one transaction, so one that fails is left as it was;
            // either failure ends the restore before a keystore or a config file is replaced.
            // The audit database goes first: when it fails, nothing at all has changed.
            var toolTimeoutMs = DatabaseToolTimeoutMs(backupConfig.Backup);
            var auditDump = Path.Combine(restoreDir, AuditDumpFileName);
            var auditRestored = false;
            if (File.Exists(auditDump))
            {
                if (!await RestoreDatabaseAsync("audit", target.DB.Audit, auditDump, ensureCitext: false, toolTimeoutMs))
                {
                    Console.WriteLine("   Nothing was changed: both databases, the keystores and config/ are as they were.");
                    return 1;
                }
                auditRestored = true;
            }

            if (!await RestoreDatabaseAsync("app", target.DB.App, appDump, ensureCitext: true, toolTimeoutMs))
            {
                Console.WriteLine(auditRestored
                    ? "   The audit database now holds the archive's audit trail; the application database, the keystores"
                    : "   Nothing was changed: the application database, the keystores");
                Console.WriteLine(auditRestored
                    ? "   and config/ are as they were. Fix the cause and run the restore again before starting the node."
                    : "   and config/ are as they were.");
                return 1;
            }

            // CRLs published after this backup was taken carried higher numbers than the restored
            // counters; raise every counter past them before anything can generate a CRL.
            var crlFloorFailed = !await RaiseCrlNumbersAfterRestoreAsync(target, archiveName);

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
                    return 1;
                }
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
                return 2;
            }

            Console.WriteLine("\n✅ Restore complete. Restart the application to apply changes.");
            return 0;
        }
        finally
        {
            try { Directory.Delete(restoreDir, true); } catch { }
            if (tempDecryptedZip != null)
                try { File.Delete(tempDecryptedZip); } catch { }
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
    /// <returns>0 if versions match or cannot be checked, 1 if there is a mismatch and restore should abort.</returns>
    private static async Task<int> ValidateSchemaVersionAsync(string manifestJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            if (!doc.RootElement.TryGetProperty("SchemaVersion", out var backupSchemaEl))
            {
                Console.WriteLine("  ⚠ Backup manifest has no SchemaVersion — skipping schema check.");
                return 0;
            }

            var backupSchema = backupSchemaEl.GetString();
            var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
            if (!File.Exists(configPath))
            {
                Console.WriteLine("  ⚠ No local config.yaml — cannot verify schema version.");
                return 0;
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
                return 1;
            }

            Console.WriteLine($"  Schema version OK: {currentSchema}");
        }
        catch (JsonException)
        {
            Console.WriteLine("  ⚠ Could not parse manifest for schema check — skipping.");
        }

        return 0;
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
    /// </summary>
    /// <param name="pgPassFile">Path to the pgpass file holding the credentials.</param>
    /// <param name="instance">The database and runtime role to restore into (name pre-validated).</param>
    /// <param name="dumpFile">Path to the custom-format archive to restore.</param>
    /// <param name="ensureCitext">Create <c>citext</c> as the runtime role first, if it is missing.</param>
    /// <param name="timeoutMs">How long each <c>pg_restore</c> run may take.</param>
    /// <returns>A tuple of (exitCode, errorOutput).</returns>
    private static async Task<(int ExitCode, string Stderr)> RestoreDumpFileAsync(
        string pgPassFile, ModularCA.Shared.Models.Config.DbInstance instance, string dumpFile, bool ensureCitext, int timeoutMs)
    {
        if (ensureCitext)
        {
            try
            {
                await using var conn = new NpgsqlConnection(PostgresConnection.Build(instance));
                await conn.OpenAsync();
                await using var cmd = new NpgsqlCommand(ModularCA.Database.PostgresRoleLayout.ExtensionSql, conn);
                await cmd.ExecuteNonQueryAsync();
                // In a database that was empty the extension is new, and this process has
                // already read the type list without it: every citext column would be unreadable.
                await conn.ReloadTypesAsync();
            }
            catch (Exception ex)
            {
                return (1, $"could not ensure the citext extension as '{instance.Username}': {ex.Message}");
            }
        }

        var (listExit, listing, listErr) = await RunPostgresToolAsync("pg_restore", new[] { "--list", dumpFile }, pgPassFile, timeoutMs);
        if (listExit != 0)
            return (listExit, listErr);
        var listFile = dumpFile + ".list";
        await File.WriteAllLinesAsync(listFile, WithoutExtensionEntries(listing));

        var (exit, _, stderr) = await RunPostgresToolAsync("pg_restore", new[]
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
        return (exit, stderr);
    }

    /// <summary>
    /// Restores one database from its dump as its runtime role
    /// (<see cref="RestoreDumpFileAsync"/>) and says whether it succeeded. A failure is printed
    /// with the tool's own message; the database is then as it was, the restore being one
    /// transaction.
    /// </summary>
    /// <param name="label">How the database is named to the operator.</param>
    /// <param name="instance">The database and runtime role to restore into.</param>
    /// <param name="dumpFile">The custom-format dump from the archive.</param>
    /// <param name="ensureCitext">Create <c>citext</c> as the runtime role first, if it is missing.</param>
    /// <param name="timeoutMs">How long each <c>pg_restore</c> run may take.</param>
    /// <returns>True when the database now holds the dump.</returns>
    private static async Task<bool> RestoreDatabaseAsync(
        string label, ModularCA.Shared.Models.Config.DbInstance instance, string dumpFile, bool ensureCitext, int timeoutMs)
    {
        Console.Write($"  Restoring {label} database...");
        var passFile = WritePgPassFile(instance.Host, instance.Port, instance.Database, instance.Username, instance.Password);
        int exit;
        string stderr;
        try
        {
            (exit, stderr) = await RestoreDumpFileAsync(passFile, instance, dumpFile, ensureCitext, timeoutMs);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            (exit, stderr) = (-1, $"pg_restore could not be started ({ex.Message}). It must be on the PATH of the account that runs ModularCA.");
        }
        finally
        {
            try { File.Delete(passFile); } catch { }
        }

        if (exit == 0)
        {
            Console.WriteLine(" ✓");
            return true;
        }

        Console.WriteLine();
        Console.WriteLine($"❌ The {label} database '{instance.Database}' could not be restored (exit {exit}): {stderr.Trim()}");
        return false;
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
    /// <param name="pgPassFile">Path to the pgpass file to point PGPASSFILE at.</param>
    /// <param name="timeoutMs">How long to wait before killing the process.</param>
    /// <returns>A tuple of (exitCode, stdout, stderr).</returns>
    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunPostgresToolAsync(
        string tool, IReadOnlyList<string> arguments, string pgPassFile, int timeoutMs)
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
        startInfo.Environment["PGPASSFILE"] = pgPassFile;

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        var completed = await Task.Run(() => process.WaitForExit(timeoutMs));
        if (!completed)
        {
            process.Kill(entireProcessTree: true);
            return (-1, string.Empty, $"Process '{tool}' timed out after {timeoutMs}ms");
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
    /// Creates <paramref name="directory"/> owner-only when it does not exist; an existing one is
    /// left exactly as it is.
    /// </summary>
    private static void EnsureOwnerOnlyDirectory(string directory)
    {
        if (Directory.Exists(directory))
            return;
        Directory.CreateDirectory(directory);
        FileSecurityUtil.SetDirectoryOwnerOnly(directory);
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
    internal static void CopyDirectoryFiltered(string source, string destination, IEnumerable<string> excludedDirectories, out List<string> skipped)
    {
        skipped = new List<string>();
        var excluded = new HashSet<string>(excludedDirectories.Select(d => d.Replace('\\', '/').Trim('/')), StringComparer.Ordinal);
        CopyDirectoryFilteredImpl(source, destination, source, excluded, skipped);
    }

    /// <summary>The recursion behind <see cref="CopyDirectoryFiltered"/>.</summary>
    private static void CopyDirectoryFilteredImpl(string source, string destination, string root, HashSet<string> excluded, List<string> skipped)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source))
        {
            var fileName = Path.GetFileName(file);
            if (BackupSecretDenylist.IsDenied(fileName))
            {
                skipped.Add(Path.GetRelativePath(root, file));
                continue;
            }
            File.Copy(file, Path.Combine(destination, fileName), true);
        }
        foreach (var dir in Directory.GetDirectories(source))
        {
            if (excluded.Contains(Path.GetRelativePath(root, dir).Replace('\\', '/')))
                continue;
            var dirName = Path.GetFileName(dir);
            CopyDirectoryFilteredImpl(dir, Path.Combine(destination, dirName), root, excluded, skipped);
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
    /// </summary>
    /// <param name="destinationZip">Absolute path where the snapshot ZIP is written.</param>
    /// <param name="configDir">Absolute path to the live <c>config/</c> directory.</param>
    /// <param name="keystores">The live keystore files by name, as the signer exported them.</param>
    private static void CreatePreRestoreSnapshot(string destinationZip, string configDir, IReadOnlyList<(string Name, byte[] Bytes)> keystores)
    {
        var stagingDir = Path.Combine(Path.GetTempPath(), $"modularca-pre-restore-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(stagingDir);
            FileSecurityUtil.SetDirectoryOwnerOnly(stagingDir);
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
            ZipFile.CreateFromDirectory(stagingDir, destinationZip);
            FileSecurityUtil.SetOwnerOnly(destinationZip);
        }
        finally
        {
            try { Directory.Delete(stagingDir, true); } catch { }
        }
    }

    /// <summary>
    /// Exports every keystore file a backup carries through the signer under the backup wrap,
    /// by name. A keystore the signer does not keep is skipped, since a node that has never
    /// been bootstrapped has none; any other refusal propagates, because a backup that silently
    /// lacks its keystores is worse than none.
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
    /// Safely extract a ZIP archive into <paramref name="destinationDir"/>, rejecting
    /// any entry whose resolved full path falls outside the destination root. Also rejects
    /// absolute entry paths, NUL bytes, and ADS markers (<c>:</c>). This replaces
    /// <c>ZipFile.ExtractToDirectory</c>, which is susceptible to zip-slip when the archive
    /// is attacker-influenced.
    /// </summary>
    /// <param name="archivePath">Absolute path to the ZIP archive.</param>
    /// <param name="destinationDir">Absolute path where entries will be extracted.</param>
    private static void SafeExtractZip(string archivePath, string destinationDir)
    {
        var fullDest = Path.GetFullPath(destinationDir);
        var destWithSep = fullDest.EndsWith(Path.DirectorySeparatorChar)
            ? fullDest
            : fullDest + Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(archivePath);
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
