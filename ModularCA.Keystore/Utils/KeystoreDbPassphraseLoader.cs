using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Shared.Utils;
using System.Text;

namespace ModularCA.Keystore.Utils
{
    /// <summary>
    /// Retrieves encrypted keystore passphrases from the database and decrypts them for use at startup.
    /// </summary>
    /// <remarks>
    /// This is the single canonical loader (the duplicate at
    /// <c>ModularCA.API/Startup/KeystoreDbPassphraseLoader.cs</c> was removed). DB connection
    /// strings are built via <see cref="ModularCA.Shared.Utils.PostgresConnection"/> so a password containing
    /// <c>;</c>, <c>"</c>, or <c>=</c> cannot inject extra connection-string options. The literal
    /// <c>"ModularCA:PassWrap"</c> passed to <see cref="ScryptKeyDeriver.DeriveFileKey"/> is a
    /// domain-separation tag, not a secret — its purpose is to bind the derivation to this code
    /// path so a leaked main-keystore-passphrase scrypt input cannot be replayed in another context.
    /// The actual secrecy comes from the secondary passphrase, which is sourced from
    /// <c>MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE</c> at runtime (see
    /// <see cref="KeystoreYamlLoader.LoadSecondaryPassphrase"/>).
    /// </remarks>
    public static class KeystoreDbPassphraseLoader
    {
        // Mirrors KeystoreFileParser's bounds for the same fields; kept in step deliberately.
        private const int MinScryptN = 1 << 14;
        private const int MaxScryptN = 1 << 20;
        private const int MaxScryptR = 32;
        private const int MaxScryptP = 32;

        /// <summary>
        /// Loads the encrypted main passphrase of the named keystore from the database the caller
        /// already has open, decrypts it with a KEK derived from <paramref name="secondaryPassphrase"/>,
        /// and returns it as the raw UTF-8 bytes that came out of AES-GCM, so the caller can zero
        /// them with <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span{byte})"/>
        /// after use. Reads no file: the connection and the secondary passphrase come from the
        /// caller, which on the signer role took them from the signer's own files.
        /// </summary>
        /// <param name="db">The application database the keystore rows live in.</param>
        /// <param name="name">The keystore name, e.g. <c>ca-certs.keystore</c>.</param>
        /// <param name="secondaryPassphrase">The keystore's secondary passphrase.</param>
        public static byte[] RetrieveFromDatabase(ModularCADbContext db, string name, string secondaryPassphrase)
        {
            ArgumentNullException.ThrowIfNull(db);
            var entry = db.Keystores.AsNoTracking().FirstOrDefault(k => k.Name == name)
                ?? throw new Exception($"❌ Keystore '{name}' not found in database.");
            var secondaryPass = secondaryPassphrase;

            // Bound the KDF parameters exactly as KeystoreFileParser does for the same values
            // when they arrive from a file. These come from a DB row, which was trusted
            // implicitly — so a single UPDATE setting ScryptN to 2^30 turned every startup and
            // every LoadCertKeys into a multi-hundred-gigabyte allocation, an unrecoverable
            // outage that survives restart. Validate rather than clamp: silently weakening a KDF
            // is worse than refusing to start with a diagnosable error.
            if (entry.ScryptN < MinScryptN || entry.ScryptN > MaxScryptN || (entry.ScryptN & (entry.ScryptN - 1)) != 0)
                throw new InvalidDataException(
                    $"Keystore '{name}' has an out-of-range scrypt N={entry.ScryptN} (expected a power of two in [{MinScryptN}, {MaxScryptN}]).");
            if (entry.ScryptR < 1 || entry.ScryptR > MaxScryptR)
                throw new InvalidDataException($"Keystore '{name}' has an out-of-range scrypt r={entry.ScryptR} (expected 1..{MaxScryptR}).");
            if (entry.ScryptP < 1 || entry.ScryptP > MaxScryptP)
                throw new InvalidDataException($"Keystore '{name}' has an out-of-range scrypt p={entry.ScryptP} (expected 1..{MaxScryptP}).");

            // nonce(12) + tag(16) + at least one ciphertext byte.
            if (entry.Passblob == null || entry.Passblob.Length < 29)
                throw new InvalidDataException(
                    $"Keystore '{name}' has a truncated wrapped passphrase ({entry.Passblob?.Length ?? 0} bytes).");

            var file = new KeystoreFile
            {
                ScryptN = entry.ScryptN,
                ScryptR = entry.ScryptR,
                ScryptP = entry.ScryptP,
                ScryptSalt = entry.Salt,
            };

            // "ModularCA:PassWrap" is a fixed domain-separation tag, not a secret. See class remarks.
            var kek = ScryptKeyDeriver.DeriveFileKey(KeystorePasswordWrapping.WrapDomainTag, secondaryPass, file);

            var nonce = entry.Passblob[..12];
            var ciphertext = entry.Passblob[12..^16];
            var tag = entry.Passblob[^16..];

            // Zero the wrapping KEK once we're done decrypting.
            byte[] decryptedBytes;
            try
            {
                decryptedBytes = AesGcmDecryptor.Decrypt(nonce, ciphertext, tag, kek);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(kek);
            }
            // Caller owns decryptedBytes; caller must zero it after use.
            return decryptedBytes;
        }
    }

    /// <summary>
    /// Constants used to wrap the keystore main passphrase under a KEK derived from the
    /// secondary passphrase. The tag is a fixed string and provides domain separation only —
    /// it is not a secret and may appear in source control.
    /// </summary>
    public static class KeystorePasswordWrapping
    {
        /// <summary>
        /// Domain-separation tag prepended to the secondary passphrase before scrypt derivation.
        /// Not a secret; documents the intent of the derivation.
        /// </summary>
        public const string WrapDomainTag = "ModularCA:PassWrap";
    }
}
