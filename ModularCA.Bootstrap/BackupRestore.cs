using System.Buffers.Binary;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Core.Helpers;
using ModularCA.Shared.Utils;
using MySqlConnector;
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
        "setup-database.yaml",   // root MySQL credentials used during bootstrap
        "api-tls.pfx",           // Web TLS PFX (private key on disk)
    };

    /// <summary>True when the given file name must not appear in any backup archive.</summary>
    public static bool IsDenied(string fileName) => DenyFileNames.Contains(fileName);
}

/// <summary>
/// Provides full backup and restore of ModularCA databases, keystores, and configuration,
/// including schema version tracking to detect incompatible database changes.
/// </summary>
public static class BackupRestore
{
    /// <summary>
    /// Creates a compressed backup archive containing databases, keystores, and configuration files.
    /// The backup manifest includes a schema version derived from the current database table names.
    /// Validates that the output path and encryption key path do not escape the application directory.
    /// </summary>
    /// <param name="outputPath">Optional explicit path for the output archive. When null, defaults to the application base directory.</param>
    /// <returns>0 on success, non-zero on failure.</returns>
    public static async Task<int> Backup(string? outputPath)
    {
        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
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
        var backupDir = Path.Combine(Path.GetTempPath(), backupName);
        Directory.CreateDirectory(backupDir);
        // Plaintext keystores and config are copied in here before the archive is encrypted.
        // GetTempPath is /tmp on Linux, which is world-readable, so without this every local
        // user can read the CA private keys for the duration of the backup. Hardening only the
        // finished archive (further down) does nothing for the plaintext staged beside it.
        FileSecurityUtil.SetDirectoryOwnerOnly(backupDir);

        try
        {
            Console.WriteLine($"📦 Creating backup: {backupName}");

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(config.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(config.DB.Audit.Database, "audit database name");

            // 1. Database dumps
            Console.Write("  Dumping app database...");
            var appDumpPath = Path.Combine(backupDir, "db-app.sql");
            var dumpFlags = "--single-transaction --skip-lock-tables";
            var appDefaultsFile = WriteMysqlDefaultsFile(config.DB.App.Host, config.DB.App.Port, config.DB.App.Username, config.DB.App.Password);
            try
            {
                var (appExit, _, appErr) = await ProcessRunner.RunAsync("mysqldump",
                    $"--defaults-extra-file=\"{appDefaultsFile}\" {dumpFlags} --result-file=\"{appDumpPath}\" {config.DB.App.Database}", 120000);
                Console.WriteLine(appExit == 0 ? " ✓" : $" ⚠ (exit {appExit}: {appErr})");
            }
            finally
            {
                try { File.Delete(appDefaultsFile); } catch { }
            }

            if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
            {
                Console.Write("  Dumping audit database...");
                var auditDumpPath = Path.Combine(backupDir, "db-audit.sql");
                var auditDefaultsFile = WriteMysqlDefaultsFile(config.DB.Audit.Host, config.DB.Audit.Port, config.DB.Audit.Username, config.DB.Audit.Password);
                try
                {
                    var auditConnStr = $"--defaults-extra-file=\"{auditDefaultsFile}\" {dumpFlags} --result-file=\"{auditDumpPath}\" {config.DB.Audit.Database}";
                    var (auditExit, _, _) = await ProcessRunner.RunAsync("mysqldump", auditConnStr, 120000);
                    Console.WriteLine(auditExit == 0 ? " ✓" : $" ⚠ (mysqldump exit {auditExit})");
                }
                finally
                {
                    try { File.Delete(auditDefaultsFile); } catch { }
                }
            }

            // 2. Copy keystores
            var backupKeystores = Path.Combine(backupDir, "keystores");
            if (Directory.Exists(keystoreDir))
            {
                Console.Write("  Copying keystores...");
                CopyDirectory(keystoreDir, backupKeystores);
                Console.WriteLine(" ✓");
            }

            // 3. Copy config — explicit deny-list to keep KEKs and secret-bearing
            // files OUT of the archive that they protect. Anything matching the denylist is
            // skipped and announced so operators can see what was excluded.
            var backupConfig = Path.Combine(backupDir, "config");
            Console.Write("  Copying config...");
            CopyDirectoryFiltered(configDir, backupConfig, out var skippedDenied);
            Console.WriteLine(" ✓");
            if (skippedDenied.Count > 0)
            {
                Console.WriteLine($"  Excluded {skippedDenied.Count} secret-bearing file(s) from archive: {string.Join(", ", skippedDenied)}");
            }

            // 4. Compute schema version from database table list
            Console.Write("  Computing schema version...");
            var schemaVersion = await ComputeSchemaVersionAsync(config);
            Console.WriteLine($" {schemaVersion}");

            // 5. Collect entity counts for manifest
            Console.Write("  Collecting entity counts...");
            var (caCount, certCount, userCount) = await CountEntitiesAsync(config);
            Console.WriteLine($" CAs={caCount}, Certs={certCount}, Users={userCount}");

            // 6. Check integrity indicators
            var keystoreIntegrity = Directory.Exists(backupKeystores) &&
                Directory.GetFiles(backupKeystores, "*", SearchOption.AllDirectories).Length > 0;
            var dbIntegrity = File.Exists(appDumpPath) && new FileInfo(appDumpPath).Length > 0;

            // 7. Write manifest (includes schema version and extended metadata)
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
                BackupSizeBytes = 0L // placeholder, updated after archive creation
            };
            var manifestPath = Path.Combine(backupDir, "manifest.json");
            File.WriteAllText(manifestPath,
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

            // 8. Create archive — validate output path does not escape the application directory
            // (trailing-separator check via PathIsContainedIn).
            if (outputPath != null && !PathIsContainedIn(outputPath, AppContext.BaseDirectory))
            {
                throw new InvalidOperationException("Backup output path must be within the application directory.");
            }
            var archivePath = outputPath ?? Path.Combine(AppContext.BaseDirectory, $"{backupName}.zip");
            Console.Write($"  Creating archive...");
            // Refuse to silently overwrite an existing archive.
            if (File.Exists(archivePath))
            {
                throw new InvalidOperationException(
                    $"Backup archive already exists at '{archivePath}'. Refusing to overwrite — choose a different output path or delete the existing file.");
            }
            ZipFile.CreateFromDirectory(backupDir, archivePath);
            FileSecurityUtil.SetOwnerOnly(archivePath);
            Console.WriteLine(" ✓");

            // 9. Update manifest with final archive size and rewrite into the archive
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
        }
    }

    /// <summary>
    /// Restores databases, keystores, and configuration from a backup archive.
    /// Validates the schema version in the manifest against the current database before restoring,
    /// captures a pre-restore snapshot of the live state for rollback, and refuses
    /// archives that contain secret-bearing files on the deny-list.
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
    /// <param name="interactive">
    /// When true (CLI path), prompts on stdin for the literal "RESTORE" confirmation before any
    /// destructive action. When false (API path), the caller is expected to have enforced its own
    /// confirmation (step-up MFA + single-use restore token) and the prompt is skipped.
    /// </param>
    /// <returns>0 on success, non-zero on failure.</returns>
    public static async Task<int> Restore(string archivePath, bool skipSchemaCheck = false, string? providedPassword = null, bool interactive = true)
    {
        if (!File.Exists(archivePath))
        {
            Console.WriteLine($"❌ Backup archive not found: {archivePath}");
            return 1;
        }

        var configDir = Path.Combine(AppContext.BaseDirectory, "config");
        var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
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

            // Capture a pre-restore snapshot of the LIVE keystores + DB before any
            // destructive write. If the snapshot fails, abort the restore — operators must not
            // lose the only copy of the current state to a botched restore.
            var snapshotPath = Path.Combine(
                AppContext.BaseDirectory,
                $"pre-restore-{DateTime.UtcNow:yyyyMMdd-HHmmss}.zip");
            try
            {
                CreatePreRestoreSnapshot(snapshotPath, configDir, keystoreDir);
                Console.WriteLine($"  ✓ Pre-restore snapshot saved to: {snapshotPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Pre-restore snapshot failed: {ex.Message}");
                Console.WriteLine("   Aborting restore — refusing to destroy live state without a rollback safety net.");
                return 1;
            }

            // Load the backup's config to get DB credentials
            var backupConfigPath = Path.Combine(restoreDir, "config", "config.yaml");
            if (!File.Exists(backupConfigPath))
            {
                Console.WriteLine("❌ Backup config.yaml not found in archive");
                return 1;
            }
            var backupConfig = YamlConfigLoader.Load(backupConfigPath);
            OverlayDbYaml(backupConfig, Path.GetDirectoryName(backupConfigPath)!);

            // Validate database name identifiers before use in command args
            BootstrapDatabaseSetup.ValidateIdentifier(backupConfig.DB.App.Database, "app database name");
            if (!string.IsNullOrWhiteSpace(backupConfig.DB.Audit.Database))
                BootstrapDatabaseSetup.ValidateIdentifier(backupConfig.DB.Audit.Database, "audit database name");

            // 1. Restore databases
            var appDump = Path.Combine(restoreDir, "db-app.sql");
            if (File.Exists(appDump))
            {
                Console.Write("  Restoring app database...");
                var restoreAppDefaults = WriteMysqlDefaultsFile(backupConfig.DB.App.Host, backupConfig.DB.App.Port, backupConfig.DB.App.Username, backupConfig.DB.App.Password);
                try
                {
                    var (exit, err) = await RestoreSqlFileAsync(restoreAppDefaults, backupConfig.DB.App.Database, appDump);
                    Console.WriteLine(exit == 0 ? " ✓" : $" ⚠ ({err})");
                }
                finally
                {
                    try { File.Delete(restoreAppDefaults); } catch { }
                }
            }

            var auditDump = Path.Combine(restoreDir, "db-audit.sql");
            if (File.Exists(auditDump))
            {
                Console.Write("  Restoring audit database...");
                var restoreAuditDefaults = WriteMysqlDefaultsFile(backupConfig.DB.Audit.Host, backupConfig.DB.Audit.Port, backupConfig.DB.Audit.Username, backupConfig.DB.Audit.Password);
                try
                {
                    var (exit, err) = await RestoreSqlFileAsync(restoreAuditDefaults, backupConfig.DB.Audit.Database, auditDump);
                    Console.WriteLine(exit == 0 ? " ✓" : $" ⚠ ({err})");
                }
                finally
                {
                    try { File.Delete(restoreAuditDefaults); } catch { }
                }
            }

            // 2. Restore keystores
            //
            // The previous implementation unconditionally deleted the
            // live keystore directory before any validation, so a corrupted or tampered
            // archive could destroy the operator's only copy. We now:
            //   (a) rename the live directory to keystoreDir.bak.<timestamp> BEFORE the
            //       destructive copy, so a failure at any later step leaves the pre-image
            //       in place for manual recovery;
            //   (b) copy the archive's keystores into place;
            //   (c) parse every restored *.keystore file and call
            //       KeystoreService.VerifyKeystoreFileSignature against the (just-restored)
            //       app database's pinned signing CA; if ANY restored keystore fails
            //       verification we delete the new dir, rename the .bak back into place,
            //       and abort the restore with a non-zero exit code.
            //
            // This closes the cases where restore overwrote without verifying and where there was no
            // pre-restore rollback for the keystore dir itself (the snapshot covers
            // the archive-level rollback but not in-place swap safety).
            var backupKeystores = Path.Combine(restoreDir, "keystores");
            string? keystoreBakDir = null;
            if (Directory.Exists(backupKeystores))
            {
                Console.Write("  Restoring keystores...");
                if (Directory.Exists(keystoreDir))
                {
                    keystoreBakDir = $"{keystoreDir}.bak.{DateTime.UtcNow:yyyyMMdd-HHmmss}";
                    Directory.Move(keystoreDir, keystoreBakDir);
                }
                try
                {
                    CopyDirectory(backupKeystores, keystoreDir);
                }
                catch
                {
                    // Copy failed before we touched the live dir further — roll the .bak back into place.
                    if (keystoreBakDir != null && Directory.Exists(keystoreBakDir))
                    {
                        try { if (Directory.Exists(keystoreDir)) Directory.Delete(keystoreDir, true); } catch { }
                        Directory.Move(keystoreBakDir, keystoreDir);
                    }
                    throw;
                }
                Console.WriteLine(" ✓");

                // Verify every restored keystore file against the just-restored
                // app database's pinned signing CA before completing the restore. We open a
                // short-lived DbContext directly against backupConfig's app DB credentials
                // (since config hasn't been copied into place yet). Any failure triggers the
                // rollback of the keystore directory.
                try
                {
                    VerifyRestoredKeystoresOrThrow(keystoreDir, backupConfig);
                    Console.WriteLine("  ✓ Restored keystores passed signature verification.");
                }
                catch (Exception verifyEx)
                {
                    Console.WriteLine($"  ❌ Restored keystore signature verification failed: {verifyEx.Message}");
                    // Roll the .bak directory back into place so the operator still has the
                    // previous keystore state on disk.
                    try { if (Directory.Exists(keystoreDir)) Directory.Delete(keystoreDir, true); } catch { }
                    if (keystoreBakDir != null && Directory.Exists(keystoreBakDir))
                    {
                        Directory.Move(keystoreBakDir, keystoreDir);
                        keystoreBakDir = null;
                    }
                    Console.WriteLine("     Pre-restore keystore directory rolled back.");
                    return 1;
                }

                // Verification succeeded — drop the .bak dir now that the new files are proven.
                if (keystoreBakDir != null && Directory.Exists(keystoreBakDir))
                {
                    try { Directory.Delete(keystoreBakDir, true); } catch { }
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
                    File.Copy(file, destPath, overwrite: true);
                }
                Console.WriteLine(" ✓");
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
            // Reuse the app SslMode setting for the information_schema probe.
            var schemaSslMode = Enum.TryParse<MySqlSslMode>(config.DB.App.SslMode, ignoreCase: true, out var _schemaSsl)
                ? _schemaSsl : MySqlSslMode.Required;
            var schemaConnBuilder = new MySqlConnectionStringBuilder
            {
                Server = config.DB.App.Host,
                Port = (uint)config.DB.App.Port,
                UserID = config.DB.App.Username,
                Password = config.DB.App.Password,
                Database = "information_schema",
                SslMode = schemaSslMode
            };
            var schemaConnStr = schemaConnBuilder.ConnectionString;
            using var schemaConn = new MySqlConnection(schemaConnStr);
            await schemaConn.OpenAsync();
            using var listCmd = new MySqlCommand("SELECT TABLE_NAME FROM TABLES WHERE TABLE_SCHEMA = @schema ORDER BY TABLE_NAME", schemaConn);
            listCmd.Parameters.AddWithValue("@schema", config.DB.App.Database);
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
                // Honor the configured SslMode for the __EFMigrationsHistory probe.
                var appSslMode = Enum.TryParse<MySqlSslMode>(config.DB.App.SslMode, ignoreCase: true, out var _appSsl)
                    ? _appSsl : MySqlSslMode.Required;
                var appConnBuilder = new MySqlConnectionStringBuilder
                {
                    Server = config.DB.App.Host,
                    Port = (uint)config.DB.App.Port,
                    UserID = config.DB.App.Username,
                    Password = config.DB.App.Password,
                    Database = config.DB.App.Database,
                    SslMode = appSslMode
                };
                using var appConn = new MySqlConnection(appConnBuilder.ConnectionString);
                await appConn.OpenAsync();
                using var migCmd = new MySqlCommand("SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId", appConn);
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
    /// Verifies every <c>*.keystore</c> file under <paramref name="keystoreDir"/>
    /// against the just-restored app database's pinned signing CA. Opens a short-lived
    /// <see cref="ModularCA.Database.ModularCADbContext"/> from the backup's own config
    /// (since the live config hasn't been written yet at this point in the restore flow)
    /// and calls <see cref="ModularCA.Keystore.Services.KeystoreService.VerifyKeystoreFileSignature"/>
    /// for each file. Throws on any verification failure so the caller can roll back the
    /// restore before the operator reboots into a tamper-signed keystore.
    /// <para>
    /// The pin itself is authenticated first via
    /// <see cref="ModularCA.Keystore.Services.KeystoreService.LoadVerifiedPinnedSpki"/>. Verifying
    /// a file signature against a pin nobody checked only proves the file matches whatever the DB
    /// says — which is worthless if the DB is what the attacker wrote to, and the DB here has just
    /// been restored from an archive. When the secondary passphrase cannot be resolved the check
    /// degrades to a warning rather than failing the restore; see
    /// <see cref="TryLoadSecondaryPassphrase"/>.
    /// </para>
    /// </summary>
    private static void VerifyRestoredKeystoresOrThrow(
        string keystoreDir,
        ModularCA.Shared.Models.Config.SystemConfig backupConfig)
    {
        var files = Directory.GetFiles(keystoreDir, "*.keystore", SearchOption.TopDirectoryOnly);
        if (files.Length == 0)
            return;

        // Opened against the backup's own config (not the live
        // config.yaml), so use the SslMode that was stamped into the backup. Default to
        // Required on parse failure.
        var restoreSslMode = Enum.TryParse<MySqlSslMode>(backupConfig.DB.App.SslMode, ignoreCase: true, out var _restoreSsl)
            ? _restoreSsl : MySqlSslMode.Required;
        var appCsb = new MySqlConnectionStringBuilder
        {
            Server = backupConfig.DB.App.Host,
            Port = (uint)backupConfig.DB.App.Port,
            Database = backupConfig.DB.App.Database,
            UserID = backupConfig.DB.App.Username,
            Password = backupConfig.DB.App.Password,
            SslMode = restoreSslMode,
        };
        var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<ModularCA.Database.ModularCADbContext>()
            .UseMySql(appCsb.ConnectionString, Microsoft.EntityFrameworkCore.ServerVersion.AutoDetect(appCsb.ConnectionString))
            .Options;
        using var db = new ModularCA.Database.ModularCADbContext(options);

        foreach (var path in files)
        {
            var name = Path.GetFileName(path);

            // Authenticate the pin before verifying anything against it. GetPinnedSignerSpki,
            // used here previously, returns the pin WITHOUT checking the MAC that protects it —
            // so an attacker who could write to the app DB could swap the pin and have their own
            // CA accepted as the keystore signer, which is precisely what this step exists to
            // catch. The runtime loader (KeystoreService.LoadCertKeysInner) has always done the
            // MAC check; this was the sibling that missed it.
            var secondary = TryLoadSecondaryPassphrase(name, out var whyNot);
            string? pinned;
            if (secondary != null)
            {
                // Throws on a MAC mismatch, which the caller turns into a rollback. A mismatch
                // means either the pin was tampered with or the secondary passphrase changed
                // since the backup — and in the latter case the restored keystores could not
                // have been decrypted at first boot anyway, so failing here surfaces the problem
                // while the rollback is still available.
                pinned = ModularCA.Keystore.Services.KeystoreService.LoadVerifiedPinnedSpki(db, name, secondary);
            }
            else
            {
                Console.WriteLine(
                    $"  [WARNING] Could not resolve the secondary passphrase for '{name}' ({whyNot}), " +
                    "so its SPKI pin could not be authenticated. Signature verification proceeds " +
                    "against an UNVERIFIED pin. Set MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE or " +
                    "restore config/keystore.yaml before re-running to close this gap.");
                pinned = ModularCA.Keystore.Services.KeystoreService.GetPinnedSignerSpki(db, name);
            }

            // If the row has no pin at all, the legacy fallback in KeystoreService.FindValidSigner
            // still runs but emits a warning. After restoring from an install with signer pinning the
            // pin should always be present.
            ModularCA.Keystore.Services.KeystoreService.VerifyKeystoreFileSignature(path, db, pinned);
        }
    }

    /// <summary>
    /// Resolves the secondary keystore passphrase for pin authentication during a restore, or
    /// null when no source has it.
    /// <para>
    /// Deliberately reads the LIVE <c>config/keystore.yaml</c> rather than the archive's copy:
    /// <see cref="BackupSecretDenylist"/> keeps <c>keystore.yaml</c> out of every backup, so the
    /// archive has no copy to read and the on-disk file is untouched by the restore. That is also
    /// the correct secret — the restored keystore files can only be opened with the secondary
    /// passphrase currently in effect on this host.
    /// </para>
    /// <para>
    /// Returns null rather than throwing for ANY resolution failure — absent file, missing entry,
    /// blank value, malformed YAML. A missing file is a legitimate state part-way through a
    /// disaster recovery, and the rest are operator problems that should not abort a restore that
    /// would otherwise succeed. Failing open here is safe precisely because the caller falls back
    /// to the behaviour that shipped before this check existed, and says so loudly;
    /// <paramref name="reason"/> carries the detail into that warning.
    /// </para>
    /// </summary>
    private static string? TryLoadSecondaryPassphrase(string keystoreName, out string reason)
    {
        try
        {
            var yamlPath = Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml");
            var value = ModularCA.Keystore.Config.KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystoreName);
            reason = string.Empty;
            return value;
        }
        catch (Exception ex)
        {
            reason = ex.Message;
            return null;
        }
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
        var countDefaultsFile = WriteMysqlDefaultsFile(config.DB.App.Host, config.DB.App.Port, config.DB.App.Username, config.DB.App.Password);
        try
        {
            BootstrapDatabaseSetup.ValidateIdentifier(config.DB.App.Database, "app database name");
            var connArgs = $"--defaults-extra-file=\"{countDefaultsFile}\" -N -e \"SELECT (SELECT COUNT(*) FROM CertificateAuthorities), (SELECT COUNT(*) FROM Certificates), (SELECT COUNT(*) FROM Users);\" {config.DB.App.Database}";
            var (exit, stdout, _) = await ProcessRunner.RunAsync("mysql", connArgs, 30000);
            if (exit == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                var parts = stdout.Trim().Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length >= 3 &&
                    int.TryParse(parts[0], out var ca) &&
                    int.TryParse(parts[1], out var cert) &&
                    int.TryParse(parts[2], out var user))
                {
                    return (ca, cert, user);
                }
            }
        }
        catch
        {
            // Best effort — return zeros if the database is unreachable
        }
        finally
        {
            try { File.Delete(countDefaultsFile); } catch { }
        }
        return (0, 0, 0);
    }

    /// <summary>
    /// Restores a SQL dump file into a MySQL database by piping it via standard input,
    /// avoiding shell redirection operators that could allow command injection.
    /// </summary>
    /// <param name="defaultsFile">Path to the MySQL defaults-extra-file with credentials.</param>
    /// <param name="database">The target database name (must be pre-validated).</param>
    /// <param name="sqlFile">Path to the SQL dump file to restore.</param>
    /// <returns>A tuple of (exitCode, errorOutput).</returns>
    private static async Task<(int ExitCode, string Stderr)> RestoreSqlFileAsync(string defaultsFile, string database, string sqlFile)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "mysql",
                Arguments = $"--defaults-extra-file=\"{defaultsFile}\" {database}",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.Start();

        var stderrTask = process.StandardError.ReadToEndAsync();

        await using (var fileStream = File.OpenRead(sqlFile))
        {
            await fileStream.CopyToAsync(process.StandardInput.BaseStream);
        }
        process.StandardInput.Close();

        var completed = await Task.Run(() => process.WaitForExit(120000));
        if (!completed)
        {
            process.Kill(entireProcessTree: true);
            return (-1, "Process timed out after 120 seconds");
        }

        var stderr = await stderrTask;
        return (process.ExitCode, stderr);
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
    /// Creates a temporary MySQL defaults-extra-file containing connection credentials.
    /// The caller must delete this file when done (use a finally block).
    /// </summary>
    /// <remarks>
    /// On POSIX systems the file is opened with explicit
    /// <see cref="UnixFileMode.UserRead"/>+<see cref="UnixFileMode.UserWrite"/> at create time
    /// (no race window between create and chmod). On Windows the file is created in the
    /// per-user temp directory and immediately ACL-tightened via
    /// <see cref="FileSecurityUtil.SetOwnerOnly"/>.
    /// <para>
    /// Password handling: my.cnf treats <c>#</c> as a comment delimiter even mid-line, so an
    /// unquoted password containing <c>#</c> would be silently truncated at that character —
    /// producing a confusing <c>Access denied (using password: YES)</c> when the truncated
    /// fragment fails to authenticate. <see cref="PasswordUtil.Generate"/>'s symbol set
    /// includes <c>#</c>, so this is a real (intermittent) failure mode. We wrap the password
    /// in double quotes and escape <c>\</c> and <c>"</c> per MySQL's option-file parsing rules
    /// so any character is preserved verbatim.
    /// </para>
    /// </remarks>
    internal static string WriteMysqlDefaultsFile(string host, int port, string username, string password)
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"modularca-mysql-{Guid.NewGuid():N}.cnf");
        var escapedPassword = password.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var content = $"[client]\nuser={username}\npassword=\"{escapedPassword}\"\nhost={host}\nport={port}\n";
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
    /// <param name="skipped">Receives the list of denied file names that were skipped (relative paths).</param>
    private static void CopyDirectoryFiltered(string source, string destination, out List<string> skipped)
    {
        skipped = new List<string>();
        CopyDirectoryFilteredImpl(source, destination, source, skipped);
    }

    private static void CopyDirectoryFilteredImpl(string source, string destination, string root, List<string> skipped)
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
            var dirName = Path.GetFileName(dir);
            CopyDirectoryFilteredImpl(dir, Path.Combine(destination, dirName), root, skipped);
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
    /// Captures a pre-restore snapshot of the live keystores and config directories into a
    /// timestamped ZIP file, providing a manual rollback path if the restore corrupts state.
    /// The snapshot intentionally includes the secret-bearing files (it is local-only,
    /// is owned by the operator, and is never uploaded). The snapshot is the operator's last line
    /// of defense and must not be sanitised.
    /// </summary>
    /// <param name="destinationZip">Absolute path where the snapshot ZIP is written.</param>
    /// <param name="configDir">Absolute path to the live <c>config/</c> directory.</param>
    /// <param name="keystoreDir">Absolute path to the live <c>keystores/</c> directory.</param>
    private static void CreatePreRestoreSnapshot(string destinationZip, string configDir, string keystoreDir)
    {
        var stagingDir = Path.Combine(Path.GetTempPath(), $"modularca-pre-restore-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(stagingDir);
            FileSecurityUtil.SetDirectoryOwnerOnly(stagingDir);
            if (Directory.Exists(configDir))
                CopyDirectory(configDir, Path.Combine(stagingDir, "config"));
            if (Directory.Exists(keystoreDir))
                CopyDirectory(keystoreDir, Path.Combine(stagingDir, "keystores"));

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
