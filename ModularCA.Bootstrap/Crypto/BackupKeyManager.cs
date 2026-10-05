using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto.Generators;

namespace ModularCA.Bootstrap.Crypto;

/// <summary>
/// Backup encryption mode selector.
/// </summary>
public enum BackupEncryptionMode
{
    /// <summary>Encrypt backups with a random 32-byte key stored on disk.</summary>
    RandomKey = 0,

    /// <summary>Encrypt backups with a scrypt-derived KEK from an admin-supplied password.</summary>
    StoredPassword = 1
}

/// <summary>
/// Centralizes backup key operations for both RandomKey and StoredPassword modes.
/// Used by <c>BackupRestore</c> and the admin backup API to load, derive, read, and write
/// encryption keys, and to parse/validate user input for the password-based mode.
/// </summary>
public static class BackupKeyManager
{
    /// <summary>Magic bytes ("MCAB") that prefix every ModularCA encrypted backup archive.</summary>
    public static readonly byte[] MagicBytes = new byte[] { 0x4D, 0x43, 0x41, 0x42 };

    /// <summary>Current .enc file format version.</summary>
    public const byte FormatVersion = 0x01;

    /// <summary>Scrypt salt size in bytes.</summary>
    public const int SaltSize = 16;

    /// <summary>AES-GCM nonce size in bytes.</summary>
    public const int NonceSize = 12;

    /// <summary>AES-GCM authentication tag size in bytes.</summary>
    public const int TagSize = 16;

    /// <summary>AES-256 key size in bytes.</summary>
    public const int KeySize = 32;

    /// <summary>
    /// Default scrypt cost parameter N for a newly set password: 2^17 = 131072, which with r = 8
    /// takes 128 MiB and roughly half a second per guess on a current server core. A password
    /// archive is the one artefact an attacker can take offline and guess at without limit, so
    /// the cost is set for that, not for interactive use. Archives and key files written with an
    /// older N carry it in their header and are still read.
    /// </summary>
    public const long DefaultScryptN = 1L << 17;

    /// <summary>The smallest scrypt N accepted from an archive header or key file (2^14).</summary>
    public const long MinScryptN = 1L << 14;

    /// <summary>The largest scrypt N accepted from an archive header or key file (2^20).</summary>
    public const long MaxScryptN = 1L << 20;

    /// <summary>The largest scrypt r accepted from an archive header or key file.</summary>
    public const int MaxScryptR = 32;

    /// <summary>The largest scrypt p accepted from an archive header or key file.</summary>
    public const int MaxScryptP = 4;

    /// <summary>The most memory a header may ask scrypt for (128 * N * r bytes): 1 GiB.</summary>
    public const long MaxScryptMemoryBytes = 1L << 30;

    /// <summary>The shortest password accepted for a new password-mode archive.</summary>
    public const int MinPasswordLength = 16;

    /// <summary>The fewest distinct characters a new backup password may contain.</summary>
    public const int MinDistinctPasswordCharacters = 8;

    /// <summary>Default scrypt block-size parameter r.</summary>
    public const int DefaultScryptR = 8;

    /// <summary>Default scrypt parallelization parameter p.</summary>
    public const int DefaultScryptP = 1;

    /// <summary>
    /// Total size in bytes of the password-derived KEK file.
    /// Layout: [16-byte salt][8-byte N (uint64 LE)][4-byte r (uint32 LE)][4-byte p (uint32 LE)][32-byte derived KEK].
    /// </summary>
    public const int PasswordFileSize = 64;

    /// <summary>
    /// Lightweight archive inspection result returned by <see cref="PeekArchiveInfo(string)"/>.
    /// Lets callers decide whether an operator password is required before calling
    /// the full decryption path, without reading or decrypting the ciphertext.
    /// </summary>
    public sealed record ArchiveHeaderInfo(bool IsLegacyFormat, BackupEncryptionMode Mode, byte[]? Salt);

    /// <summary>
    /// Reads just the archive header (first ~38 bytes at most) to determine whether the archive is
    /// in the new format and, if so, which encryption mode it was created with. Returns
    /// <c>IsLegacyFormat = true</c> for files whose first 4 bytes don't match the "MCAB" magic —
    /// those are always RandomKey and have no embedded salt. For new-format StoredPassword archives,
    /// the 16-byte scrypt salt is returned so the caller can compare it against a locally-stored
    /// password key and decide whether the stored KEK will decrypt this particular archive.
    /// </summary>
    /// <param name="archivePath">Absolute path to a candidate .enc file.</param>
    /// <exception cref="FileNotFoundException">Thrown when the archive file does not exist.</exception>
    /// <exception cref="InvalidDataException">Thrown when the file is shorter than the minimum header size or carries an unsupported version byte.</exception>
    public static ArchiveHeaderInfo PeekArchiveInfo(string archivePath)
    {
        if (!File.Exists(archivePath))
            throw new FileNotFoundException("Backup archive not found.", archivePath);

        using var fs = File.OpenRead(archivePath);
        if (fs.Length < MagicBytes.Length)
            throw new InvalidDataException("Backup archive is truncated — shorter than the magic bytes header.");

        Span<byte> magic = stackalloc byte[4];
        fs.ReadExactly(magic);
        bool isNewFormat = magic.SequenceEqual(MagicBytes);
        if (!isNewFormat)
            return new ArchiveHeaderInfo(IsLegacyFormat: true, Mode: BackupEncryptionMode.RandomKey, Salt: null);

        // New format: read version + mode + salt. (Scrypt params live after the salt but aren't needed for mode detection.)
        if (fs.Length < 6 + SaltSize)
            throw new InvalidDataException("Backup archive header is truncated.");

        Span<byte> versionByte = stackalloc byte[1];
        fs.ReadExactly(versionByte);
        if (versionByte[0] != FormatVersion)
            throw new InvalidDataException($"Unsupported backup archive version: 0x{versionByte[0]:X2}.");

        Span<byte> modeByte = stackalloc byte[1];
        fs.ReadExactly(modeByte);
        var mode = (BackupEncryptionMode)modeByte[0];

        var salt = new byte[SaltSize];
        fs.ReadExactly(salt);

        return new ArchiveHeaderInfo(IsLegacyFormat: false, Mode: mode, Salt: salt);
    }

    /// <summary>
    /// Refuses scrypt parameters outside what this build writes or has ever written: N a power of
    /// two in [<see cref="MinScryptN"/>, <see cref="MaxScryptN"/>], r in [1, <see cref="MaxScryptR"/>],
    /// p in [1, <see cref="MaxScryptP"/>], and no more than <see cref="MaxScryptMemoryBytes"/> of
    /// memory. The parameters come from an archive header, which an attacker can write, so an
    /// unbounded N would turn a restore into an out-of-memory crash.
    /// </summary>
    /// <exception cref="InvalidDataException">The parameters are out of range.</exception>
    public static void ValidateScryptParameters(long N, int r, int p)
    {
        if (N < MinScryptN || N > MaxScryptN || (N & (N - 1)) != 0)
            throw new InvalidDataException($"Backup scrypt N={N} is out of range (a power of two in [{MinScryptN}, {MaxScryptN}]).");
        if (r < 1 || r > MaxScryptR)
            throw new InvalidDataException($"Backup scrypt r={r} is out of range (1..{MaxScryptR}).");
        if (p < 1 || p > MaxScryptP)
            throw new InvalidDataException($"Backup scrypt p={p} is out of range (1..{MaxScryptP}).");
        if (128L * N * r > MaxScryptMemoryBytes)
            throw new InvalidDataException($"Backup scrypt parameters N={N}, r={r} need more than {MaxScryptMemoryBytes / (1 << 20)} MiB.");
    }

    /// <summary>
    /// True when a stored password key file was derived with less work than this build's default,
    /// so new archives under it are weaker than a freshly set password would make them.
    /// </summary>
    public static bool IsBelowDefaultCost(long N, int r) => N * r < DefaultScryptN * DefaultScryptR;

    /// <summary>
    /// Derives a 32-byte AES-256 KEK from a password and salt using scrypt with the supplied
    /// parameters, after <see cref="ValidateScryptParameters"/> accepts them.
    /// </summary>
    /// <param name="password">Plain-text password supplied by the admin.</param>
    /// <param name="salt">Scrypt salt (typically 16 bytes of cryptographically random data).</param>
    /// <param name="N">Scrypt cost parameter (literal cost, not the exponent).</param>
    /// <param name="r">Scrypt block-size parameter.</param>
    /// <param name="p">Scrypt parallelization parameter.</param>
    /// <returns>A 32-byte key suitable for AES-256-GCM.</returns>
    public static byte[] DeriveKey(string password, byte[] salt, long N, int r, int p)
    {
        ValidateScryptParameters(N, r, p);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return SCrypt.Generate(passwordBytes, salt, (int)N, r, p, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>
    /// Writes the password-derived KEK file atomically with owner-only permissions.
    /// Generates a fresh 16-byte salt, runs scrypt with the default parameters, and writes
    /// [salt][N][r][p][KEK] to <paramref name="path"/>. The derived KEK buffer is zeroed after write.
    /// </summary>
    /// <param name="path">Destination path for the password-derived KEK file (typically <c>config/backup-password.key</c>).</param>
    /// <param name="password">Plain-text password supplied by the admin.</param>
    public static void WritePasswordKeyFile(string path, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var kek = DeriveKey(password, salt, DefaultScryptN, DefaultScryptR, DefaultScryptP);
        try
        {
            var buffer = new byte[PasswordFileSize];
            Buffer.BlockCopy(salt, 0, buffer, 0, SaltSize);
            BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(SaltSize, 8), DefaultScryptN);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(SaltSize + 8, 4), DefaultScryptR);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(SaltSize + 12, 4), DefaultScryptP);
            Buffer.BlockCopy(kek, 0, buffer, SaltSize + 16, KeySize);

            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = path + ".tmp";
            File.WriteAllBytes(tempPath, buffer);
            File.Move(tempPath, path, overwrite: true);
            FileSecurityUtil.SetOwnerOnly(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Reads the password-derived KEK file and returns its components.
    /// </summary>
    /// <param name="path">Path to the password-derived KEK file.</param>
    /// <returns>A tuple of (KEK, salt, N, r, p) parsed from the file.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    /// <exception cref="InvalidDataException">Thrown when the file length is not exactly <see cref="PasswordFileSize"/> bytes.</exception>
    public static (byte[] Kek, byte[] Salt, long N, int r, int p) ReadPasswordKeyFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Backup password key file not found at '{path}'. Set a backup password via the admin API before running encrypted backups.",
                path);
        }

        var bytes = File.ReadAllBytes(path);
        if (bytes.Length != PasswordFileSize)
        {
            throw new InvalidDataException(
                $"Backup password key file '{path}' is malformed: expected {PasswordFileSize} bytes, got {bytes.Length}.");
        }

        var salt = new byte[SaltSize];
        Buffer.BlockCopy(bytes, 0, salt, 0, SaltSize);
        var n = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(SaltSize, 8));
        var r = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(SaltSize + 8, 4));
        var p = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(SaltSize + 12, 4));
        var kek = new byte[KeySize];
        Buffer.BlockCopy(bytes, SaltSize + 16, kek, 0, KeySize);

        CryptographicOperations.ZeroMemory(bytes);
        return (kek, salt, n, r, p);
    }

    /// <summary>
    /// Parses the mode from a config string. Defaults to <see cref="BackupEncryptionMode.RandomKey"/>
    /// when the value is null, empty, or unrecognized (fail-safe).
    /// </summary>
    /// <param name="configValue">Raw config string (typically <c>BackupConfig.EncryptionMode</c>).</param>
    /// <returns>The parsed <see cref="BackupEncryptionMode"/>.</returns>
    public static BackupEncryptionMode ParseMode(string? configValue)
    {
        if (!string.IsNullOrWhiteSpace(configValue) &&
            string.Equals(configValue, "StoredPassword", StringComparison.OrdinalIgnoreCase))
        {
            return BackupEncryptionMode.StoredPassword;
        }

        return BackupEncryptionMode.RandomKey;
    }

    /// <summary>
    /// Loads the KEK for encrypting a new backup, according to the current mode.
    /// In <see cref="BackupEncryptionMode.RandomKey"/> mode, reads the 32-byte file at <paramref name="randomKeyPath"/>
    /// and returns (kek, null, 0, 0, 0). In <see cref="BackupEncryptionMode.StoredPassword"/> mode, reads
    /// <paramref name="passwordKeyPath"/> and returns the derived KEK along with the scrypt parameters
    /// (salt, N, r, p) so they can be written into the archive header.
    /// </summary>
    /// <param name="mode">Current backup encryption mode.</param>
    /// <param name="randomKeyPath">Path to the random key file (used in RandomKey mode).</param>
    /// <param name="passwordKeyPath">Path to the password-derived KEK file (used in StoredPassword mode).</param>
    /// <returns>A tuple of (KEK, salt, N, r, p). Salt is null and N/r/p are 0 in RandomKey mode.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the required key file does not exist.</exception>
    /// <exception cref="InvalidDataException">Thrown when the key file is malformed.</exception>
    public static (byte[] Kek, byte[]? Salt, long N, int r, int p) LoadEncryptionKey(
        BackupEncryptionMode mode, string randomKeyPath, string passwordKeyPath)
    {
        if (mode == BackupEncryptionMode.StoredPassword)
        {
            var (kek, salt, n, r, p) = ReadPasswordKeyFile(passwordKeyPath);
            return (kek, salt, n, r, p);
        }

        if (!File.Exists(randomKeyPath))
        {
            throw new FileNotFoundException(
                $"Backup encryption key file not found at '{randomKeyPath}'. Run bootstrap to generate it, or switch to StoredPassword mode.",
                randomKeyPath);
        }

        var keyBytes = File.ReadAllBytes(randomKeyPath);
        if (keyBytes.Length != KeySize)
        {
            throw new InvalidDataException(
                $"Backup encryption key file '{randomKeyPath}' is malformed: expected {KeySize} bytes, got {keyBytes.Length}.");
        }

        return (keyBytes, null, 0, 0, 0);
    }

    /// <summary>
    /// Validates a new backup password: at least <see cref="MinPasswordLength"/> characters, at
    /// least <see cref="MinDistinctPasswordCharacters"/> distinct characters, at least one letter,
    /// and at least one digit or symbol (a space counts, so a passphrase of words qualifies). An
    /// archive under this password can be guessed at offline without limit, so length is the
    /// requirement that matters. Applies to setting a password only; a restore accepts whatever
    /// password an existing archive was made with.
    /// </summary>
    /// <param name="password">Plain-text password to validate.</param>
    /// <returns><c>null</c> if the password is acceptable, otherwise a human-readable failure reason.</returns>
    public static string? ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
        {
            return $"Password must be at least {MinPasswordLength} characters; a passphrase of several words is easiest.";
        }

        if (password.Distinct().Count() < MinDistinctPasswordCharacters)
        {
            return $"Password must contain at least {MinDistinctPasswordCharacters} different characters.";
        }

        if (!password.Any(char.IsLetter))
        {
            return "Password must contain at least one letter.";
        }

        if (!password.Any(c => char.IsDigit(c) || !char.IsLetterOrDigit(c)))
        {
            return "Password must contain at least one digit or symbol.";
        }

        return null;
    }

    /// <summary>
    /// Zeros a byte array in place using <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>.
    /// Safe to call with a null reference (no-op).
    /// </summary>
    /// <param name="key">The byte array to zero. No-op if null.</param>
    public static void ZeroKey(byte[] key)
    {
        if (key is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(key);
    }
}
