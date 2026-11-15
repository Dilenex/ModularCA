using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// Where the key of a backup archive is read from. Every member names a file, or is a password a
/// person typed: no key and no password is ever read from an environment variable.
/// </summary>
/// <param name="KeyFilePath">
/// The key file for the archive, given explicitly (<c>--key-file</c>): the 32-byte
/// <c>backup.key</c> for an archive made in RandomKey mode, the 64-byte
/// <c>backup-password.key</c> for one made in StoredPassword mode. Null reads the file this host's
/// configuration names, <c>config/backup.key</c> or <c>config/backup-password.key</c> by default.
/// </param>
/// <param name="Password">
/// The backup password of a StoredPassword archive, when the stored key file is missing or was
/// made for another password: read from a file (<c>--password-file</c>), typed at the prompt, or
/// sent by the console. Ignored for a RandomKey archive.
/// </param>
public sealed record BackupKeySource(string? KeyFilePath = null, string? Password = null)
{
    /// <summary>
    /// Reads a backup password from a file: the file's text without the line break an editor or
    /// <c>echo</c> leaves at its end. Nothing else is trimmed, so a password may begin or end with
    /// a space.
    /// </summary>
    /// <param name="path">The file holding the password.</param>
    /// <exception cref="BackupArchiveException">The file is missing, unreadable or empty.</exception>
    public static string ReadPasswordFile(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            throw new BackupArchiveException($"The password file '{path}' could not be read: {ex.Message}");
        }
        text = text.TrimEnd('\r', '\n');
        if (text.Length == 0)
            throw new BackupArchiveException($"The password file '{path}' is empty.");
        return text;
    }
}

/// <summary>
/// An archive that cannot be read: it is missing, is not a ModularCA backup archive, or does not
/// open with the key given. Nothing has been changed when this is thrown.
/// </summary>
/// <param name="message">What is wrong, for a person.</param>
public sealed class BackupArchiveException(string message) : Exception(message);

/// <summary>
/// Reads a backup archive without writing anything: the archive may lie on a read-only mount, and
/// what is decrypted stays in memory. A restore and <c>--backup-manifest</c> open an archive
/// through this one door.
/// </summary>
public static class BackupArchiveFile
{
    /// <summary>What <see cref="ReadZip"/> says of an archive that was not encrypted.</summary>
    public const string NotEncrypted = "none";

    private static readonly byte[] ZipMagic = [0x50, 0x4B];

    /// <summary>
    /// The key files a backup or a restore on this host uses when none is given explicitly:
    /// <c>Backup.EncryptionKeyPath</c> and <c>Backup.PasswordFilePath</c> from this host's
    /// <c>config.yaml</c> when it has one and names them, otherwise <c>config/backup.key</c> and
    /// <c>config/backup-password.key</c>. Both are relative to the application directory and must
    /// lie inside it.
    /// </summary>
    /// <param name="baseDirectory">The application directory.</param>
    /// <returns>The absolute paths of the random key file and of the password key file.</returns>
    /// <exception cref="BackupArchiveException">A configured path is rooted, holds <c>..</c> or leaves the application directory.</exception>
    public static (string RandomKeyPath, string PasswordKeyPath) DefaultKeyPaths(string baseDirectory)
    {
        string? configuredKey = null, configuredPassword = null;
        var configPath = Path.Combine(baseDirectory, "config", "config.yaml");
        if (File.Exists(configPath))
        {
            try
            {
                var backup = YamlConfigLoader.Load(configPath, _ => { }).Backup;
                (configuredKey, configuredPassword) = (backup?.EncryptionKeyPath, backup?.PasswordFilePath);
            }
            catch (Exception)
            {
                // A config.yaml this build cannot read names no key file: the defaults apply.
            }
        }

        string Resolve(string? configured, string fallback, string what)
        {
            var relative = string.IsNullOrWhiteSpace(configured) ? fallback : configured;
            if (relative.Contains("..") || Path.IsPathRooted(relative))
                throw new BackupArchiveException($"Invalid {what} path '{relative}': it must be relative to the application directory, without '..'.");
            var full = Path.Combine(baseDirectory, relative);
            if (!BackupRestore.PathIsContainedIn(full, baseDirectory))
                throw new BackupArchiveException($"The {what} path '{relative}' leaves the application directory.");
            return full;
        }

        return (Resolve(configuredKey, "config/backup.key", "backup encryption key"),
            Resolve(configuredPassword, "config/backup-password.key", "backup password file"));
    }

    /// <summary>
    /// Returns the archive's ZIP in memory, decrypted when the archive is encrypted. What kind of
    /// file it is comes from its first bytes, never from its name: a ZIP is taken as it is, the
    /// current encrypted format starts with <c>MCAB</c> and names its own mode, and anything else
    /// is tried as the legacy format (<c>[nonce][tag][ciphertext]</c>, RandomKey). Only the archive
    /// and the key file are read; nothing is written. The caller zeroes the result when done.
    /// </summary>
    /// <param name="archivePath">The archive.</param>
    /// <param name="keys">Where its key comes from; null reads this host's key files.</param>
    /// <param name="baseDirectory">The application directory, for the default key files.</param>
    /// <param name="encryption"><c>RandomKey</c>, <c>StoredPassword</c>, or <see cref="NotEncrypted"/>.</param>
    /// <exception cref="BackupArchiveException">The archive is missing or cannot be opened; the message says why.</exception>
    public static byte[] ReadZip(string archivePath, BackupKeySource? keys, string baseDirectory, out string encryption)
    {
        keys ??= new BackupKeySource();
        byte[] file;
        try
        {
            if (!File.Exists(archivePath))
                throw new BackupArchiveException($"Backup archive not found: {archivePath}");
            file = File.ReadAllBytes(archivePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            throw new BackupArchiveException($"The backup archive '{archivePath}' could not be read: {ex.Message}");
        }

        if (file.AsSpan().StartsWith(ZipMagic))
        {
            encryption = NotEncrypted;
            return file;
        }

        byte[]? key = null;
        try
        {
            var isNewFormat = file.AsSpan().StartsWith(BackupKeyManager.MagicBytes);
            ReadOnlySpan<byte> nonce, tag, ciphertext;
            var mode = BackupEncryptionMode.RandomKey;
            if (isNewFormat)
            {
                // 66 bytes: 4 magic + 1 version + 1 mode + 16 salt + 8 N + 4 r + 4 p + 12 nonce + 16 tag.
                if (file.Length < 66)
                    throw new BackupArchiveException("The backup archive's header is truncated.");
                if (file[4] != BackupKeyManager.FormatVersion)
                    throw new BackupArchiveException($"Unsupported backup archive version {file[4]}: it was written by a build this one cannot read.");
                mode = (BackupEncryptionMode)file[5];
                var salt = file.AsSpan(6, BackupKeyManager.SaltSize).ToArray();
                var n = BinaryPrimitives.ReadInt64LittleEndian(file.AsSpan(22, 8));
                var r = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(30, 4));
                var p = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(34, 4));
                nonce = file.AsSpan(38, BackupKeyManager.NonceSize);
                tag = file.AsSpan(50, BackupKeyManager.TagSize);
                ciphertext = file.AsSpan(66);
                key = mode switch
                {
                    BackupEncryptionMode.RandomKey => ReadRandomKey(keys.KeyFilePath ?? DefaultKeyPaths(baseDirectory).RandomKeyPath),
                    BackupEncryptionMode.StoredPassword => ReadPasswordKey(keys, baseDirectory, salt, n, r, p),
                    _ => throw new BackupArchiveException($"Unknown backup encryption mode {(byte)mode}."),
                };
            }
            else
            {
                if (file.Length < BackupKeyManager.NonceSize + BackupKeyManager.TagSize + 4)
                    throw new BackupArchiveException("The file is not a ModularCA backup archive: it is too short to be one.");
                nonce = file.AsSpan(0, BackupKeyManager.NonceSize);
                tag = file.AsSpan(BackupKeyManager.NonceSize, BackupKeyManager.TagSize);
                ciphertext = file.AsSpan(BackupKeyManager.NonceSize + BackupKeyManager.TagSize);
                key = ReadRandomKey(keys.KeyFilePath ?? DefaultKeyPaths(baseDirectory).RandomKeyPath);
            }

            var plaintext = new byte[ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, BackupKeyManager.TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new BackupArchiveException(isNewFormat
                    ? mode == BackupEncryptionMode.StoredPassword
                        ? "The backup archive does not open with this password: the password is wrong, or the file is damaged."
                        : "The backup archive does not open with this key: it was encrypted with another backup key, or the file is damaged."
                    : "The file is not a ModularCA backup archive, or it is one in the legacy format encrypted with another backup key.");
            }

            if (!plaintext.AsSpan().StartsWith(ZipMagic))
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new BackupArchiveException("The backup archive decrypts to something that is not a ZIP: it is not a ModularCA backup archive.");
            }
            encryption = mode.ToString();
            return plaintext;
        }
        finally
        {
            if (key != null) BackupKeyManager.ZeroKey(key);
        }
    }

    /// <summary>The text of <c>manifest.json</c> in an archive's ZIP, or null when the ZIP holds none.</summary>
    /// <param name="zip">The ZIP, from <see cref="ReadZip"/>.</param>
    /// <param name="hasAuditDump">Whether the ZIP holds an audit database.</param>
    /// <exception cref="BackupArchiveException">The bytes are not a readable ZIP.</exception>
    public static string? ReadManifest(byte[] zip, out bool hasAuditDump)
    {
        try
        {
            using var archive = new ZipArchive(new MemoryStream(zip, writable: false), ZipArchiveMode.Read);
            hasAuditDump = archive.GetEntry("db-audit.dump") is { Length: > 0 };
            if (archive.GetEntry("manifest.json") is not { } entry)
                return null;
            using var reader = new StreamReader(entry.Open());
            return reader.ReadToEnd();
        }
        catch (InvalidDataException ex)
        {
            throw new BackupArchiveException($"The backup archive is not a readable ZIP: {ex.Message}");
        }
    }

    /// <summary>The 32-byte key of a RandomKey archive.</summary>
    private static byte[] ReadRandomKey(string path)
    {
        byte[] key;
        try
        {
            if (!File.Exists(path))
                throw new BackupArchiveException($"The backup encryption key file '{path}' was not found. Put the backup key this archive was made with there, or name it with --key-file.");
            key = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            throw new BackupArchiveException($"The backup encryption key file '{path}' could not be read: {ex.Message}");
        }
        if (key.Length != BackupKeyManager.KeySize)
        {
            var length = key.Length;
            CryptographicOperations.ZeroMemory(key);
            throw new BackupArchiveException($"The backup encryption key file '{path}' is not a backup key: it holds {length} bytes, a key is {BackupKeyManager.KeySize}.");
        }
        return key;
    }

    /// <summary>
    /// The key of a StoredPassword archive: derived from the password when one was given,
    /// otherwise the stored key file, which fits only when it was made with the archive's salt.
    /// </summary>
    private static byte[] ReadPasswordKey(BackupKeySource keys, string baseDirectory, byte[] salt, long n, int r, int p)
    {
        try
        {
            if (!string.IsNullOrEmpty(keys.Password))
                return BackupKeyManager.DeriveKey(keys.Password, salt, n, r, p);

            var path = keys.KeyFilePath ?? DefaultKeyPaths(baseDirectory).PasswordKeyPath;
            if (!File.Exists(path))
                throw new BackupArchiveException($"The backup password key file '{path}' was not found and no password was given. "
                    + "This archive is protected by a backup password: give it in a file with --password-file, or name the stored key file with --key-file.");
            var (kek, storedSalt, _, _, _) = BackupKeyManager.ReadPasswordKeyFile(path);
            if (storedSalt.AsSpan().SequenceEqual(salt))
                return kek;
            BackupKeyManager.ZeroKey(kek);
            throw new BackupArchiveException($"This archive was encrypted under another backup password than the one '{path}' was made for. "
                + "Give the password the archive was made with, in a file, with --password-file.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or InvalidOperationException)
        {
            throw new BackupArchiveException($"The backup password key could not be used: {ex.Message}");
        }
    }
}
