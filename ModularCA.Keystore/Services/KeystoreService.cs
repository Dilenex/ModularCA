using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Enums;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Collections.Concurrent;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Keystore.Services;

/// <summary>
/// Manages encrypted keystore files including creation, saving, re-encryption, loading, and signature verification.
/// Uses a single system CA signer for all keystore signatures.
/// </summary>
public class KeystoreService : IDisposable
{
    private readonly List<AddKeystoreEntry> _entries = new();
    private readonly string _keystorePath;
    // Main passphrase is held as raw UTF-8 bytes so it can be zeroed
    // deterministically on Dispose. The secondary remains a string (it comes from
    // yaml / env var as a managed string at the source).
    private readonly byte[] _mainPasswordBytes;
    private readonly string _secondaryPassword;
    private readonly AsymmetricKeyParameter _signer; // system CA
    private bool _disposed;

    /// <summary>
    /// Byte-array main passphrase constructor — preferred entry point. Callers
    /// responsible for providing a fresh copy of the main passphrase bytes; the
    /// service takes ownership and zeros them on <see cref="Dispose"/>.
    /// </summary>
    public KeystoreService(string keystorePath, byte[] mainPasswordBytes, string secondaryPassword, AsymmetricKeyParameter signer)
    {
        _keystorePath = keystorePath;
        _mainPasswordBytes = mainPasswordBytes ?? throw new ArgumentNullException(nameof(mainPasswordBytes));
        _secondaryPassword = secondaryPassword;
        _signer = signer;
    }

    /// <summary>
    /// Legacy string-based constructor. Converts the passphrase to a fresh
    /// <c>byte[]</c> on entry; the caller's original string is unchanged and still
    /// subject to managed-heap pinning. Prefer the <c>byte[]</c> overload.
    /// </summary>
    public KeystoreService(string keystorePath, string mainPassword, string secondaryPassword, AsymmetricKeyParameter signer)
        : this(keystorePath, System.Text.Encoding.UTF8.GetBytes(mainPassword ?? string.Empty), secondaryPassword, signer)
    {
    }

    /// <summary>
    /// Zeros the in-memory main passphrase. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_mainPasswordBytes);
        GC.SuppressFinalize(this);
    }

    // Process-wide keystore-path locks so two concurrent AppendEntry calls
    // can't race on the same file. The lock map is keyed by the absolute, case-insensitive
    // path (Windows filesystems are case-insensitive; Linux treats the distinction as the
    // operator's problem to avoid). This is PROCESS-LOCAL: multi-instance HA deployments
    // must coordinate keystore writes out-of-band. Each path gets its own SemaphoreSlim with a capacity of 1.
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _keystoreFileLocks =
        new(StringComparer.OrdinalIgnoreCase);

    private static SemaphoreSlim GetFileLock(string keystorePath)
    {
        var absolute = Path.GetFullPath(keystorePath);
        return _keystoreFileLocks.GetOrAdd(absolute, _ => new SemaphoreSlim(1, 1));
    }

    /// <summary>
    /// Adds an encrypted entry to the keystore with a per-entry secondary password.
    /// </summary>
    public void AddEntry(byte[] payload, string secondaryPassword)
    {
        _entries.Add(new AddKeystoreEntry(_keystorePath, payload, secondaryPassword));
    }

    // Default scrypt cost used when no explicit params are supplied. Callers
    // that want to track the operator's SecurityPolicy.KeystoreScryptN/R/P values should
    // read the policy and pass the clamped triple via <see cref="SetTargetScryptParams"/>
    // before calling Save(). Defaults kept at the prior pinned constants so legacy behavior
    // is byte-identical when no override is supplied.
    public const int DefaultScryptN = 1 << 16; // 65536
    public const int DefaultScryptR = 8;
    public const int DefaultScryptP = 1;
    private const int ScryptSaltLength = 16;

    private int _targetScryptN = DefaultScryptN;
    private int _targetScryptR = DefaultScryptR;
    private int _targetScryptP = DefaultScryptP;

    /// <summary>
    /// Overrides the default scrypt cost parameters used by <see cref="Save"/>. Values
    /// are clamped: N to [2^14, 2^20], r to [1, 32], p to [1, 16].
    /// </summary>
    public void SetTargetScryptParams(int n, int r, int p)
    {
        _targetScryptN = Math.Clamp(n, 1 << 14, 1 << 20);
        _targetScryptR = Math.Clamp(r, 1, 32);
        _targetScryptP = Math.Clamp(p, 1, 16);
    }

    /// <summary>
    /// Encrypts all entries, signs each with the system CA signer, and writes the complete keystore file to disk.
    /// </summary>
    public KeystoreSaveResult Save()
    {
        if (!_entries.Any())
            throw new InvalidOperationException("Keystore is empty. No entries to write.");

        // Generate a fresh random salt each Save() call.
        var salt = CryptoUtils.GenerateSalt(ScryptSaltLength);
        var scrypt = new KeystoreFileWriter.ScryptParams(_targetScryptN, _targetScryptR, _targetScryptP);
        var encryptedEntries = new List<KeystoreFileWriter.EncryptedEntry>();

        // v4 derives a single file master key and HKDFs per-entry keys from it,
        // and signs (index, nonce, ciphertext, tag) so entry reordering invalidates the sigs.
        // The master key is zeroed in the finally below.
        var fileSeed = new KeystoreFile
        {
            ScryptSalt = Convert.ToBase64String(salt),
            ScryptN = scrypt.N,
            ScryptR = scrypt.R,
            ScryptP = scrypt.P,
            FormatVersion = KeystoreFileWriter.CurrentFormatVersion,
        };
        byte[]? masterKey = null;
        try
        {
            masterKey = ScryptKeyDeriver.DeriveFileKey(_mainPasswordBytes, _secondaryPassword, fileSeed);

            for (int i = 0; i < _entries.Count; i++)
            {
                var entry = _entries[i];
                byte[]? entryKey = null;
                try
                {
                    entryKey = DeriveEntryKey(masterKey, i);
                    var (nonce, ciphertext, tag) = AesGcmEncryptor.Encrypt(entry.Payload, entryKey);
                    var dataToSign = SerializeEntryForSig(i, nonce, ciphertext, tag);
                    var sig = SignData(dataToSign, _signer);
                    encryptedEntries.Add(new KeystoreFileWriter.EncryptedEntry(nonce, ciphertext, tag, sig));
                }
                finally
                {
                    if (entryKey != null) CryptographicOperations.ZeroMemory(entryKey);
                }
            }

            var fileBytesToSign = SerializeKeystoreData(salt, scrypt, encryptedEntries, KeystoreFileWriter.CurrentFormatVersion);
            var fileSig = SignData(fileBytesToSign, _signer);

            KeystoreFileWriter.WriteEntireKeystore(_keystorePath, salt, scrypt, encryptedEntries, fileSig);
            ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(_keystorePath);

            Console.WriteLine($"Keystore written to {_keystorePath} with {_entries.Count} entries (v{KeystoreFileWriter.CurrentFormatVersion}).");

            return new KeystoreSaveResult(salt, scrypt);
        }
        finally
        {
            if (masterKey != null) CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    /// <summary>
    /// HKDF-Expand(masterKey, info = "ModularCA:Keystore:entry" || u32be(index)) → 32 bytes.
    /// Gives every entry its own AES-256-GCM key while binding that key to the entry's
    /// position in the file. Reordering invalidates decryption because the wrong entry
    /// index produces the wrong key.
    /// </summary>
    private const string EntryKeyDomainTag = "ModularCA:Keystore:entry";
    private static byte[] DeriveEntryKey(byte[] masterKey, int index)
    {
        var tag = Encoding.ASCII.GetBytes(EntryKeyDomainTag);
        var info = new byte[tag.Length + 4];
        Buffer.BlockCopy(tag, 0, info, 0, tag.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(tag.Length, 4), (uint)index);
        return HKDF.Expand(HashAlgorithmName.SHA256, masterKey, 32, info);
    }

    /// <summary>
    /// Serializes entry data WITH the entry index as the first field, for v4 entry
    /// signature input. Prepending the u32be index means two entries with identical
    /// ciphertext bodies at different positions produce different signing inputs, so an
    /// attacker with file-write access cannot swap entries without breaking the sigs.
    /// </summary>
    private static byte[] SerializeEntryForSig(int index, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        writer.Write(index);
        writer.Write(nonce.Length);
        writer.Write(nonce);
        writer.Write(ciphertext.Length);
        writer.Write(ciphertext);
        writer.Write(tag.Length);
        writer.Write(tag);
        return ms.ToArray();
    }

    /// <summary>
    /// Loads and verifies private keys from the CA certificates keystore, returning decrypted key objects.
    /// File-level and per-entry signature verification is pinned to the
    /// System Signing CA via <see cref="KeystoreEntryEntity.SigningCaSpkiSha256"/>.
    /// Every decrypted PKCS#8 DER buffer is zeroed immediately after it is
    /// handed to <see cref="PrivateKeyFactory.CreateKey"/>, and the derived file key is
    /// zeroed in the outer finally so the raw key material does not linger on the managed
    /// heap past this call.
    /// </summary>
    public static List<CertKey> LoadCertKeys(string keystorePath, string yamlPath, ModularCADbContext db)
    {
        const string keystoreName = "ca-certs.keystore";
        try
        {
            return LoadCertKeysInner(keystorePath, yamlPath, db, keystoreName);
        }
        catch (SecurityException ex)
        {
            // Distinguish pin-MAC failure from file/entry signature failure in the audit trail.
            var action = ex.Message.Contains("SPKI pin MAC", StringComparison.OrdinalIgnoreCase)
                ? AuditActionType.KeystorePinMacFailed
                : AuditActionType.KeystoreSignatureFailed;
            EmitKeystoreAudit(action, keystoreName, success: false, detail: ex.Message);
            throw;
        }
    }

    private static List<CertKey> LoadCertKeysInner(string keystorePath, string yamlPath, ModularCADbContext db, string keystoreName)
    {
        var secondary = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystoreName);
        var (pinnedSpki, pinMac) = LoadPinnedSignerSpkiWithMac(db, keystoreName);
        VerifySpkiPinMac(pinnedSpki, pinMac, secondary, keystoreName);
        var keystore = KeystoreFileParser.Parse(keystorePath);
        VerifyFileSignature(keystore, db, pinnedSpki);
        var mainBytes = LoadMainPassphraseBytes(keystoreName);
        byte[]? key = null;
        try
        {
            key = ScryptKeyDeriver.DeriveFileKey(mainBytes, secondary, keystore);

            var verified = new List<CertKey>();
            for (int i = 0; i < keystore.Entries.Count; i++)
            {
                var entry = keystore.Entries[i];
                DecryptAndVerifyEntry(keystore.FormatVersion, i, entry, key, db, pinnedSpki, decrypted =>
                {
                    verified.Add(new CertKey(PrivateKeyFactory.CreateKey(decrypted)));
                });
            }
            EmitKeystoreAudit(AuditActionType.KeystoreLoaded, keystoreName, success: true,
                detail: $"entries={verified.Count} format=v{keystore.FormatVersion}");
            return verified;
        }
        finally
        {
            if (key != null) CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(mainBytes);
        }
    }

    /// <summary>
    /// Loads and verifies trusted CA certificates from the trust keystore.
    /// Signatures are pinned to the System Signing CA identity recorded in
    /// <see cref="KeystoreEntryEntity.SigningCaSpkiSha256"/>.
    /// </summary>
    public static List<X509Certificate> LoadTrustedCerts(string keystorePath, string yamlPath, ModularCADbContext db)
    {
        const string keystoreName = "ca-trust.keystore";
        try
        {
            return LoadTrustedCertsInner(keystorePath, yamlPath, db, keystoreName);
        }
        catch (SecurityException ex)
        {
            var action = ex.Message.Contains("SPKI pin MAC", StringComparison.OrdinalIgnoreCase)
                ? AuditActionType.KeystorePinMacFailed
                : AuditActionType.KeystoreSignatureFailed;
            EmitKeystoreAudit(action, keystoreName, success: false, detail: ex.Message);
            throw;
        }
    }

    private static List<X509Certificate> LoadTrustedCertsInner(string keystorePath, string yamlPath, ModularCADbContext db, string keystoreName)
    {
        var secondary = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystoreName);
        var (pinnedSpki, pinMac) = LoadPinnedSignerSpkiWithMac(db, keystoreName);
        VerifySpkiPinMac(pinnedSpki, pinMac, secondary, keystoreName);
        var keystore = KeystoreFileParser.Parse(keystorePath);
        VerifyFileSignature(keystore, db, pinnedSpki);
        var mainBytes = LoadMainPassphraseBytes(keystoreName);
        byte[]? key = null;
        try
        {
            key = ScryptKeyDeriver.DeriveFileKey(mainBytes, secondary, keystore);

            var verified = new List<X509Certificate>();
            for (int i = 0; i < keystore.Entries.Count; i++)
            {
                var entry = keystore.Entries[i];
                DecryptAndVerifyEntry(keystore.FormatVersion, i, entry, key, db, pinnedSpki, decrypted =>
                {
                    verified.Add(new X509Certificate(decrypted));
                });
            }
            EmitKeystoreAudit(AuditActionType.KeystoreLoaded, keystoreName, success: true,
                detail: $"entries={verified.Count} format=v{keystore.FormatVersion}");
            return verified;
        }
        finally
        {
            if (key != null) CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(mainBytes);
        }
    }

    /// <summary>
    /// Shared entry-verify-and-decrypt helper. v4 uses HKDF per-entry keys and index-prefixed
    /// signatures; v3 and earlier use the flat file key + unprefixed sig. <paramref name="consume"/>
    /// is invoked once with the decrypted plaintext and gets a guarantee of zeroing afterwards.
    /// <para>
    /// This is the ONLY place that decides how a keystore entry is decrypted. The Unlocker used
    /// to carry its own loop that passed the file master key straight to AES-GCM; that silently
    /// stopped working at v4, when entries moved to per-entry HKDF keys, so the break-glass tool
    /// could not read any keystore the product writes. Both paths now come through here.
    /// </para>
    /// </summary>
    /// <param name="verifySignature">
    /// When false, the per-entry signature check is skipped and <paramref name="db"/> may be null.
    /// Reserved for offline disaster recovery, where the app database is unavailable and the
    /// operator has explicitly accepted that entries are decrypted unverified.
    /// </param>
    private static void DecryptAndVerifyEntry(
        int formatVersion,
        int index,
        KeystoreFile.KeystoreEntry entry,
        byte[] fileKey,
        ModularCADbContext? db,
        string? pinnedSpki,
        Action<byte[]> consume,
        bool verifySignature = true)
    {
        // Verify the entry signature first so we never decrypt unverified data.
        if (verifySignature)
        {
            if (db == null)
                throw new ArgumentNullException(nameof(db), "Signature verification requires a database context.");
            if (entry.Signature == null)
                throw new SecurityException($"Entry {index} carries no signature.");

            var sigInput = formatVersion >= 4
                ? SerializeEntryForSig(index, entry.Nonce, entry.Ciphertext, entry.Tag)
                : SerializeEntryWithoutSignatures(entry.Nonce, entry.Ciphertext, entry.Tag);
            if (FindValidSigner(sigInput, entry.Signature, db, pinnedSpki) == null)
                throw new SecurityException($"Entry signature failed for entry {index}");
        }

        byte[]? entryKey = null;
        byte[]? decrypted = null;
        try
        {
            entryKey = formatVersion >= 4
                ? DeriveEntryKey(fileKey, index)
                : fileKey; // legacy: entries share the flat file key
            decrypted = AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, entryKey);
            consume(decrypted);
        }
        finally
        {
            if (decrypted != null) CryptographicOperations.ZeroMemory(decrypted);
            // Only zero the key we allocated; the caller owns fileKey.
            if (entryKey != null && formatVersion >= 4) CryptographicOperations.ZeroMemory(entryKey);
        }
    }


    /// <summary>
    /// Decrypts every entry of an already-parsed keystore, honouring the file's format version.
    /// <para>
    /// Exists so the Unlocker can reuse the runtime's decrypt path instead of reimplementing it.
    /// The reimplementation is what broke: it applied the file master key directly to AES-GCM,
    /// which is correct only up to v3. From v4 each entry is encrypted under
    /// <c>HKDF-Expand(masterKey, "ModularCA:Keystore:entry" || u32be(index))</c>, so every
    /// decryption failed the authentication tag and the tool was unusable against any keystore
    /// the product had written.
    /// </para>
    /// </summary>
    /// <param name="keystore">Parsed keystore, supplying both entries and format version.</param>
    /// <param name="fileMasterKey">
    /// scrypt output from <see cref="ScryptKeyDeriver.DeriveFileKey(byte[], string, KeystoreFile)"/>.
    /// The caller retains ownership and is responsible for zeroing it.
    /// </param>
    /// <param name="db">App database used to resolve entry signers. May be null only when
    /// <paramref name="verifyEntrySignatures"/> is false.</param>
    /// <param name="pinnedSpki">Pinned signer SPKI, ideally from
    /// <see cref="LoadVerifiedPinnedSpki"/> so the pin's own MAC has been checked.</param>
    /// <param name="verifyEntrySignatures">
    /// False only for explicitly-acknowledged offline recovery. Entry plaintext is then
    /// unauthenticated beyond the AES-GCM tag, which proves the passphrases but says nothing
    /// about who wrote the file.
    /// </param>
    /// <param name="consume">
    /// Receives (entry index, plaintext) for each entry. The buffer is zeroed as soon as this
    /// returns, so a consumer that needs the bytes afterwards must copy them.
    /// </param>
    public static void DecryptEntries(
        KeystoreFile keystore,
        byte[] fileMasterKey,
        ModularCADbContext? db,
        string? pinnedSpki,
        bool verifyEntrySignatures,
        Action<int, byte[]> consume)
    {
        ArgumentNullException.ThrowIfNull(keystore);
        ArgumentNullException.ThrowIfNull(fileMasterKey);
        ArgumentNullException.ThrowIfNull(consume);

        for (int i = 0; i < keystore.Entries.Count; i++)
        {
            var index = i;
            DecryptAndVerifyEntry(
                keystore.FormatVersion,
                index,
                keystore.Entries[index],
                fileMasterKey,
                db,
                pinnedSpki,
                decrypted => consume(index, decrypted),
                verifyEntrySignatures);
        }
    }

    /// <summary>
    /// Returns the pinned signer SPKI for a keystore only after verifying the MAC that protects
    /// it, matching what <c>LoadCertKeysInner</c> does before trusting a pin.
    /// <para>
    /// <see cref="GetPinnedSignerSpki"/> skips that check. The Unlocker used it, so a
    /// DB-write-only compromise could swap the pin and the tool would happily verify a keystore
    /// against an attacker's CA. A legacy row with no stored MAC still warns and proceeds — the
    /// MAC is populated on the next keystore rewrite — but a MAC that is present and wrong is a
    /// hard failure.
    /// </para>
    /// </summary>
    public static string? LoadVerifiedPinnedSpki(ModularCADbContext db, string keystoreName, string secondaryPassphrase)
    {
        var (pinnedSpki, pinMac) = LoadPinnedSignerSpkiWithMac(db, keystoreName);
        VerifySpkiPinMac(pinnedSpki, pinMac, secondaryPassphrase, keystoreName);
        return pinnedSpki;
    }

    /// <summary>
    /// Returns the main passphrase as its raw UTF-8 bytes so the caller
    /// can <see cref="CryptographicOperations.ZeroMemory"/> it in a finally block.
    /// Prevents the secret from being pinned in the GC as a managed <c>string</c>.
    /// </summary>
    private static byte[] LoadMainPassphraseBytes(string keystore)
    {
        var bytes = KeystoreDbPassphraseLoader.RetrieveFromDatabase(keystore);
        if (bytes == null || bytes.Length == 0)
            throw new InvalidOperationException("Main passphrase is not set in the keystore configuration.");
        return bytes;
    }

    /// <summary>
    /// Searches for the CA certificate whose public key verifies the given signature,
    /// constrained to the pinned signer stored in <see cref="KeystoreEntryEntity.SigningCaSpkiSha256"/>
    /// for the named keystore. If a pin is present, only that exact certificate is accepted —
    /// creating a new CA in the database can no longer forge a valid file signature by re-signing
    /// the keystore, because verification refuses anything whose SPKI hash doesn't match the pin.
    /// If no pin is stored (legacy rows), the method falls back to the previous
    /// "any CA in the DB" behaviour for backwards compatibility with existing deployments, and
    /// the caller is responsible for scheduling a bootstrap re-issue to populate the pin.
    /// </summary>
    private static int _legacyFallbackWarningLogged;

    /// <summary>
    /// Reports how many times the legacy fallback has been exercised so operators
    /// and monitoring can flag installs that still have unpinned keystore rows. The counter is
    /// incremented every time <see cref="FindValidSigner"/> runs without an
    /// <c>expectedSpkiSha256Hex</c> pin supplied.
    /// </summary>
    private static long _legacyFallbackInvocations;

    /// <summary>
    /// Total number of times the legacy unpinned fallback has been taken since
    /// process start. Exposed for operator diagnostics — a non-zero value means at least one
    /// keystore row lacks <c>Keystores.SigningCaSpkiSha256</c> and should be backfilled via
    /// <see cref="BackfillPinnedSpkiAsync"/>.
    /// </summary>
    public static long LegacyFallbackInvocationCount => System.Threading.Interlocked.Read(ref _legacyFallbackInvocations);

    private static X509Certificate? FindValidSigner(byte[] data, byte[] signature, ModularCADbContext db, string? expectedSpkiSha256Hex = null)
    {
        IEnumerable<ModularCA.Shared.Entities.CertificateEntity> candidates;
        if (!string.IsNullOrEmpty(expectedSpkiSha256Hex))
        {
            // Pinned mode: pull every CA and filter in-memory by SPKI hash so we pick the one
            // cert the pin refers to. We could store the SPKI on CertificateEntity to make this
            // a DB filter, but for now the CA set is small and per-request cost is negligible.
            candidates = db.Certificates.Where(c => c.IsCA == true).AsEnumerable()
                .Where(c =>
                {
                    try
                    {
                        var cert = new X509Certificate(c.RawCertificate);
                        var spkiHex = ComputeSpkiSha256Hex(cert);
                        return string.Equals(spkiHex, expectedSpkiSha256Hex, StringComparison.OrdinalIgnoreCase);
                    }
                    catch { return false; }
                });
        }
        else
        {
            // Taking the "any IsCA row in DB" path is a security-relevant fallback
            // that lets a freshly-inserted CA verify a forged keystore. We log once per process
            // at Warning level so the operator notices, and increment a counter every time the
            // fallback is exercised so monitoring can alert on unpinned installs. Operators are
            // expected to run BackfillPinnedSpkiAsync once after upgrade and then this branch
            // should never execute again.
            System.Threading.Interlocked.Increment(ref _legacyFallbackInvocations);
            if (System.Threading.Interlocked.Exchange(ref _legacyFallbackWarningLogged, 1) == 0)
            {
                Console.Error.WriteLine(
                    "[WARNING] KeystoreService.FindValidSigner: pinned SPKI is not set for this keystore row. " +
                    "Falling back to legacy \"any IsCA cert verifies\" behaviour — this is a security regression. " +
                    "Run KeystoreService.BackfillPinnedSpkiAsync (or re-bootstrap the keystore) to pin the signing CA.");
            }
            candidates = db.Certificates.Where(c => c.IsCA == true);
        }

        foreach (var cert in candidates)
        {
            var ca = new X509Certificate(cert.RawCertificate);
            try
            {
                var publicKey = ca.GetPublicKey();

                // Skip RSA CAs whose key size doesn't match the signature length
                if (publicKey is RsaKeyParameters rsaKey)
                {
                    int keySizeBytes = (rsaKey.Modulus.BitLength + 7) / 8;
                    if (signature.Length != keySizeBytes)
                        continue;
                }

                var verifier = CreateSignerForKey(publicKey);
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data, 0, data.Length);

                if (verifier.VerifySignature(signature))
                    return ca;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to verify with {ca.SubjectDN}: {ex.Message}");
            }
        }
        return null;
    }

    /// <summary>
    /// SHA-256 hex of the DER-encoded SubjectPublicKeyInfo. Lowercase for stable
    /// comparison against the value in <c>KeystoreEntryEntity.SigningCaSpkiSha256</c>.
    /// Called from bootstrap and anywhere else that needs to pin a CA cert to its SPKI.
    /// </summary>
    public static string ComputeSpkiSha256Hex(X509Certificate cert)
    {
        var spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(cert.GetPublicKey())
            .GetDerEncoded();
        var hash = System.Security.Cryptography.SHA256.HashData(spki);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Load the pinned keystore-signing CA fingerprint from the
    /// <c>Keystores</c> table for a given keystore name. Returns null if no row exists
    /// (legacy install) or if the pin was never populated.
    /// </summary>
    private static string? LoadPinnedSignerSpki(ModularCADbContext db, string keystoreName)
    {
        try
        {
            return db.Keystores
                .Where(k => k.Name == keystoreName)
                .Select(k => k.SigningCaSpkiSha256)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Load the pinned SPKI hex AND the MAC protecting it. The caller is responsible
    /// for verifying the MAC against the secondary passphrase via
    /// <see cref="VerifySpkiPinMac"/> before trusting the pin.
    /// </summary>
    private static (string? spkiHex, byte[]? mac) LoadPinnedSignerSpkiWithMac(ModularCADbContext db, string keystoreName)
    {
        try
        {
            var row = db.Keystores
                .Where(k => k.Name == keystoreName)
                .Select(k => new { k.SigningCaSpkiSha256, k.SigningCaSpkiSha256Mac })
                .FirstOrDefault();
            if (row == null) return (null, null);
            return (row.SigningCaSpkiSha256, row.SigningCaSpkiSha256Mac);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Domain-separated MAC key derivation for the SPKI pin.
    /// HKDF-SHA256 over the secondary passphrase bytes, info=domain tag.
    /// The salt is intentionally empty: the secondary passphrase is already high-entropy
    /// (generated at bootstrap) and scrypt-protected where it's at rest; HKDF is used
    /// here purely for domain separation from the scrypt wrapping KEK.
    /// </summary>
    private const string SpkiPinMacDomainTag = "ModularCA:SpkiPinMac";
    private static byte[] DeriveSpkiPinMacKey(byte[] secondaryUtf8Bytes)
    {
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: secondaryUtf8Bytes,
            outputLength: 32,
            salt: Array.Empty<byte>(),
            info: Encoding.UTF8.GetBytes(SpkiPinMacDomainTag));
    }

    /// <summary>
    /// HMAC-SHA256 over the lowercase hex pin, keyed by the HKDF-derived MAC key.
    /// Produces a deterministic 32-byte tag comparable to whatever was stored during
    /// the last rewrite.
    /// </summary>
    // Keystore operations run before DI is ready (startup) and inside
    // static service paths (append), so we can't inject IAuditService. Write events to the
    // same bootstrap-audit-{date}.jsonl file that BootstrapAuditReplayService drains into
    // the audit DB on first successful DB connection. This gives us a structured trail
    // that survives restarts and keystore-load failures.
    private static readonly object _auditLogLock = new();
    private static readonly string _auditInstanceId = Guid.NewGuid().ToString("N");
    private static void EmitKeystoreAudit(string action, string keystoreName, bool success, string? detail = null)
    {
        try
        {
            var logsDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logsDir);
            var filePath = Path.Combine(logsDir, $"bootstrap-audit-{DateTime.UtcNow:yyyyMMdd}.jsonl");
            var line = System.Text.Json.JsonSerializer.Serialize(new
            {
                timestamp = DateTime.UtcNow.ToString("o"),
                action,
                keystoreName,
                success,
                detail,
                instanceId = _auditInstanceId,
            });
            lock (_auditLogLock)
            {
                File.AppendAllText(filePath, line + Environment.NewLine);
                try { ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(filePath); } catch { /* best-effort */ }
            }
        }
        catch
        {
            // Audit write failure must never fail the keystore operation itself.
        }
    }

    public static byte[] ComputeSpkiPinMac(string spkiHex, string secondary)
    {
        var secBytes = Encoding.UTF8.GetBytes(secondary ?? string.Empty);
        try
        {
            var key = DeriveSpkiPinMacKey(secBytes);
            try
            {
                return HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(spkiHex.ToLowerInvariant()));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secBytes);
        }
    }

    /// <summary>
    /// Verifies the stored MAC against the expected value computed from the secondary
    /// passphrase. When <paramref name="storedMac"/> is null this is a legacy row —
    /// we emit a one-time warning and accept the pin (the operator needs to re-save
    /// the keystore once to populate the MAC). Any non-null MAC that fails to match
    /// is a hard error.
    /// </summary>
    private static int _missingMacWarningLogged;
    private static void VerifySpkiPinMac(string? spkiHex, byte[]? storedMac, string secondary, string keystoreName)
    {
        if (string.IsNullOrEmpty(spkiHex)) return; // no pin at all — legacy, handled elsewhere
        if (storedMac == null || storedMac.Length == 0)
        {
            if (System.Threading.Interlocked.Exchange(ref _missingMacWarningLogged, 1) == 0)
            {
                Console.Error.WriteLine(
                    $"[WARNING] Keystore '{keystoreName}' has an unprotected SPKI pin (no MAC stored). " +
                    "DB-write-only compromise could swap the pin undetected. The MAC is populated " +
                    "automatically on the next keystore rewrite — append an entry or run " +
                    "BackfillPinnedSpkiAsync to trigger one.");
            }
            return;
        }

        var expected = ComputeSpkiPinMac(spkiHex, secondary);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, storedMac))
                throw new SecurityException(
                    $"Keystore '{keystoreName}': SPKI pin MAC mismatch. The stored pin has been tampered " +
                    "with or the secondary passphrase has changed since the last rewrite. Refusing to " +
                    "load the keystore.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }


    /// <summary>
    /// Matches private keys with their corresponding public certificates by comparing public key material.
    /// </summary>
    public static List<CertWithKey> MatchCertsWithKeys(List<CertKey> privateKeys, List<X509Certificate> publicCerts)
    {
        var matches = new List<CertWithKey>();

        foreach (var cert in publicCerts)
        {
            var certPublicKey = cert.GetPublicKey();

            foreach (var key in privateKeys)
            {
                try
                {
                    var derivedPublic = GetPublicFromPrivate(key.PrivateKey);

                    if (certPublicKey.Equals(derivedPublic))
                    {
                        matches.Add(new CertWithKey(cert, key.PrivateKey));
                        break;
                    }
                }
                catch { /* key type mismatch – skip */ }
            }
        }

        return matches;
    }

    /// <summary>
    /// Derives the public key from a private key for supported algorithm types.
    /// </summary>
    private static AsymmetricKeyParameter GetPublicFromPrivate(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Key is not a private key");

        return privateKey switch
        {
            RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
            ECPrivateKeyParameters ec => new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D), ec.Parameters),
            Ed25519PrivateKeyParameters ed25519 => ed25519.GeneratePublicKey(),
            Ed448PrivateKeyParameters ed448 => ed448.GeneratePublicKey(),
            MLDsaPrivateKeyParameters mlDsa => mlDsa.GetPublicKey(),
            SlhDsaPrivateKeyParameters slhDsa => slhDsa.GetPublicKey(),
            _ => throw new NotSupportedException($"Unsupported key type: {privateKey.GetType().Name}")
        };
    }

    /// <summary>
    /// Exports an X.509 certificate to PEM format.
    /// </summary>
    public static string ExportCertificateToPem(X509Certificate cert)
    {
        using var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();
        return sw.ToString();
    }

    /// <summary>
    /// Exports a private key to PEM format.
    /// </summary>
    public static string ExportPrivateKeyToPem(AsymmetricKeyParameter privateKey)
    {
        using var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();
        return sw.ToString();
    }

    /// <summary>
    /// Verifies the single file-level signature. When a pinned signer SPKI is supplied,
    /// only that exact CA is accepted — new CAs in the database cannot
    /// silently become valid keystore signers. Legacy mode (no pin) falls back to the
    /// previous "any IsCA row in the DB" behaviour for backwards compatibility.
    /// </summary>
    private static void VerifyFileSignature(KeystoreFile keystore, ModularCADbContext db, string? expectedSpkiSha256Hex = null)
    {
        var data = SerializeKeystoreData(
            Convert.FromBase64String(keystore.ScryptSalt),
            new KeystoreFileWriter.ScryptParams(keystore.ScryptN, keystore.ScryptR, keystore.ScryptP),
            keystore.Entries.Select(e =>
                new KeystoreFileWriter.EncryptedEntry(e.Nonce, e.Ciphertext, e.Tag, e.Signature)
            ).ToList(),
            keystore.FormatVersion
        );

        if (FindValidSigner(data, keystore.FileSignature!, db, expectedSpkiSha256Hex) == null)
            throw new SecurityException("File signature is invalid for the pinned keystore-signing CA");

        Console.WriteLine("Keystore file-level signature verified.");
    }

    /// <summary>
    /// Public entry point for callers that need to parse+verify a
    /// keystore file against the pinned signing CA (or the legacy any-CA fallback). Used by
    /// the Unlocker CLI and the backup-restore flow to reject substituted or unsigned files
    /// before any plaintext key material is exposed. When <paramref name="expectedSpkiSha256Hex"/>
    /// is supplied, only that exact SPKI is accepted as a valid signer.
    /// </summary>
    /// <param name="keystorePath">Absolute path to the keystore file.</param>
    /// <param name="db">Database context used to look up candidate CA certificates.</param>
    /// <param name="expectedSpkiSha256Hex">Optional pinned SPKI hex; when null the legacy
    /// fallback behaviour applies (still logs a loud warning — see <see cref="FindValidSigner"/>).</param>
    /// <exception cref="SecurityException">Thrown if no valid signer is found.</exception>
    public static void VerifyKeystoreFileSignature(
        string keystorePath,
        ModularCADbContext db,
        string? expectedSpkiSha256Hex = null)
    {
        var keystore = KeystoreFileParser.Parse(keystorePath);
        VerifyFileSignature(keystore, db, expectedSpkiSha256Hex);
    }

    /// <summary>
    /// Public wrapper around <see cref="LoadPinnedSignerSpki"/> so callers outside
    /// this class (Unlocker, backup restore) can fetch the pinned SPKI hex for a keystore name.
    /// Returns null when the row is missing or the column was never populated — the caller is
    /// responsible for deciding whether the legacy fallback is acceptable or the verification
    /// should be refused.
    /// </summary>
    public static string? GetPinnedSignerSpki(ModularCADbContext db, string keystoreName)
    {
        return LoadPinnedSignerSpki(db, keystoreName);
    }

    /// <summary>
    /// Backfill the <c>Keystores.SigningCaSpkiSha256</c> column for legacy rows
    /// whose pin was never populated. Iterates every Keystores row with a null pin, parses
    /// the matching keystore file from <paramref name="keystoresDir"/>, finds the CA whose
    /// public key validates the file-level signature (using the legacy unpinned path), and
    /// writes that CA's SPKI SHA-256 back to the row. After this completes successfully the
    /// legacy fallback in <see cref="FindValidSigner"/> should never execute again and the
    /// operator can treat a new fallback invocation as a tamper signal.
    /// </summary>
    /// <param name="db">Database context for reading/updating <c>Keystores</c>.</param>
    /// <param name="keystoresDir">Directory containing the keystore files by name.</param>
    /// <returns>A report describing which rows were backfilled, skipped, or failed.</returns>
    public static KeystoreBackfillReport BackfillPinnedSpki(ModularCADbContext db, string keystoresDir, bool persist = true)
    {
        var report = new KeystoreBackfillReport();
        var rows = db.Keystores.Where(k => k.SigningCaSpkiSha256 == null || k.SigningCaSpkiSha256 == string.Empty).ToList();
        foreach (var row in rows)
        {
            try
            {
                var path = Path.Combine(keystoresDir, row.Name);
                if (!File.Exists(path))
                {
                    report.Skipped.Add($"{row.Name} (file not found at {path})");
                    continue;
                }
                var keystore = KeystoreFileParser.Parse(path);
                var data = SerializeKeystoreData(
                    Convert.FromBase64String(keystore.ScryptSalt),
                    new KeystoreFileWriter.ScryptParams(keystore.ScryptN, keystore.ScryptR, keystore.ScryptP),
                    keystore.Entries.Select(e =>
                        new KeystoreFileWriter.EncryptedEntry(e.Nonce, e.Ciphertext, e.Tag, e.Signature)
                    ).ToList(),
                    keystore.FormatVersion
                );

                // Use the unpinned path deliberately — that's exactly what we need in order to
                // discover which CA actually signed this legacy file.
                var signer = FindValidSigner(data, keystore.FileSignature!, db, expectedSpkiSha256Hex: null);
                if (signer == null)
                {
                    report.Failed.Add($"{row.Name} (no CA in DB validates file signature)");
                    continue;
                }
                var spkiHex = ComputeSpkiSha256Hex(signer);
                row.SigningCaSpkiSha256 = spkiHex;
                report.Backfilled.Add($"{row.Name} -> {spkiHex}");
            }
            catch (Exception ex)
            {
                report.Failed.Add($"{row.Name} ({ex.GetType().Name}: {ex.Message})");
            }
        }

        if (report.Backfilled.Count > 0 && persist)
            db.SaveChanges();
        return report;
    }

    /// <summary>
    /// Result of a <see cref="BackfillPinnedSpki"/> run. Exposed to the caller so
    /// admin tooling and startup diagnostics can print a human-readable summary.
    /// </summary>
    public sealed class KeystoreBackfillReport
    {
        public List<string> Backfilled { get; } = new();
        public List<string> Skipped { get; } = new();
        public List<string> Failed { get; } = new();
    }

    /// <summary>
    /// Serializes the keystore header, scrypt parameters, and all encrypted entries (including per-entry signatures)
    /// into a byte array suitable for computing the file-level signature.
    /// The format-version byte in the serialized magic must match the version
    /// on disk so signature verification lines up across v2 and v3 keystores.
    /// </summary>
    private static byte[] SerializeKeystoreData(byte[] salt, KeystoreFileWriter.ScryptParams scrypt, List<KeystoreFileWriter.EncryptedEntry> entries, int formatVersion = KeystoreFileWriter.CurrentFormatVersion)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        var magic = formatVersion switch
        {
            2 => "MCAKSTR\x02",
            3 => "MCAKSTR\x03",
            4 => "MCAKSTR\x04",
            _ => throw new InvalidOperationException($"Unsupported keystore format version {formatVersion}")
        };
        writer.Write(Encoding.ASCII.GetBytes(magic));
        writer.Write((ushort)salt.Length);
        writer.Write(salt);
        writer.Write(scrypt.N);
        writer.Write(scrypt.R);
        writer.Write(scrypt.P);
        writer.Write(entries.Count);

        foreach (var entry in entries)
        {
            writer.Write(entry.Nonce.Length);
            writer.Write(entry.Nonce);
            writer.Write(entry.Ciphertext.Length);
            writer.Write(entry.Ciphertext);
            writer.Write(entry.Tag.Length);
            writer.Write(entry.Tag);
            KeystoreSignatureBlock.Write(writer, entry.Signature);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Signs the given data using the specified private key, selecting the appropriate signature algorithm.
    /// </summary>
    private static byte[] SignData(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = CreateSignerForKey(privateKey);
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    /// Creates the appropriate ISigner instance for the given key type (RSA-PSS, ECDSA, Ed25519, Ed448, ML-DSA, SLH-DSA).
    /// </summary>
    private static ISigner CreateSignerForKey(AsymmetricKeyParameter key)
    {
        return key switch
        {
            RsaPrivateCrtKeyParameters or RsaKeyParameters =>
                new PssSigner(new RsaEngine(), new Sha256Digest(), 20),
            ECPrivateKeyParameters or ECPublicKeyParameters =>
                new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest()),
            Ed25519PrivateKeyParameters or Ed25519PublicKeyParameters =>
                new Ed25519Signer(),
            Ed448PrivateKeyParameters or Ed448PublicKeyParameters =>
                new Ed448Signer([]),
            MLDsaKeyParameters mlDsa =>
                new MLDsaSigner(mlDsa.Parameters, false),
            SlhDsaKeyParameters slhDsa =>
                new SlhDsaSigner(slhDsa.Parameters, false),
            _ => throw new NotSupportedException($"Unsupported key type for signing: {key.GetType().Name}")
        };
    }

    /// <summary>
    /// Serializes entry data (nonce, ciphertext, tag) without signatures for use as the signing input.
    /// </summary>
    private static byte[] SerializeEntryWithoutSignatures(byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Match the format in WriteEntireKeystore
        writer.Write(nonce.Length);
        writer.Write(nonce);

        writer.Write(ciphertext.Length);
        writer.Write(ciphertext);

        writer.Write(tag.Length);
        writer.Write(tag);

        return ms.ToArray();
    }



    /// <summary>
    /// Appends a new entry to an existing keystore file at runtime. Delegates to
    /// <see cref="AppendEntries"/> with a one-element batch.
    /// </summary>
    public static KeystoreSaveResult AppendEntry(
        string keystorePath,
        string yamlPath,
        string keystoreName,
        byte[] newPayload,
        AsymmetricKeyParameter signer,
        ModularCADbContext db)
    {
        return AppendEntries(keystorePath, yamlPath, keystoreName, new[] { newPayload }, signer, db);
    }

    /// <summary>
    /// Appends one or more new entries to an existing keystore file at runtime. Loads the existing file,
    /// decrypts all entries, adds the new ones, and rewrites the entire file with fresh signatures.
    /// Acquires a process-wide <see cref="SemaphoreSlim"/> keyed on the absolute keystore
    /// path so concurrent callers serialize cleanly; zeros the decrypted plaintext buffers with
    /// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> before returning; writes via
    /// the atomic-rename path in <see cref="KeystoreFileWriter.WriteEntireKeystore"/> so a crash
    /// mid-write preserves the prior <c>.bak</c> file for recovery. Also verifies the new file
    /// parses and its file-level signature validates before the lock is released.
    /// </summary>
    public static KeystoreSaveResult AppendEntries(
        string keystorePath,
        string yamlPath,
        string keystoreName,
        IReadOnlyCollection<byte[]> newPayloads,
        AsymmetricKeyParameter signer,
        ModularCADbContext db)
    {
        if (newPayloads == null || newPayloads.Count == 0)
            throw new ArgumentException("At least one payload must be supplied.", nameof(newPayloads));

        var fileLock = GetFileLock(keystorePath);
        fileLock.Wait();
        try
        {
            try
            {
                return AppendEntriesInner(keystorePath, yamlPath, keystoreName, newPayloads, signer, db);
            }
            catch (SecurityException ex)
            {
                var action = ex.Message.Contains("SPKI pin MAC", StringComparison.OrdinalIgnoreCase)
                    ? AuditActionType.KeystorePinMacFailed
                    : AuditActionType.KeystoreSignatureFailed;
                EmitKeystoreAudit(action, keystoreName, success: false, detail: ex.Message);
                throw;
            }
        }
        finally
        {
            fileLock.Release();
        }
    }

    private static KeystoreSaveResult AppendEntriesInner(
        string keystorePath,
        string yamlPath,
        string keystoreName,
        IReadOnlyCollection<byte[]> newPayloads,
        AsymmetricKeyParameter signer,
        ModularCADbContext db)
    {
        {
            // Load existing keystore. Verify the SPKI-pin MAC
            // against the secondary passphrase before trusting the pin at all.
            var secondary = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystoreName);
            var (pinnedSpki, pinMac) = LoadPinnedSignerSpkiWithMac(db, keystoreName);
            VerifySpkiPinMac(pinnedSpki, pinMac, secondary, keystoreName);
            var keystore = KeystoreFileParser.Parse(keystorePath);
            VerifyFileSignature(keystore, db, pinnedSpki);

            var mainBytes = LoadMainPassphraseBytes(keystoreName);
            byte[]? fileKey = null;
            var existingPayloads = new List<byte[]>(keystore.Entries.Count);
            try
            {
                fileKey = ScryptKeyDeriver.DeriveFileKey(mainBytes, secondary, keystore);

                // Decrypt existing entries to get their raw payloads. v4 entries need HKDF-derived
                // per-entry keys; v3 and earlier use the flat file key. Payload buffers are
                // zeroed in the outer finally regardless of success or failure.
                for (int i = 0; i < keystore.Entries.Count; i++)
                {
                    var entry = keystore.Entries[i];
                    byte[]? entryKey = null;
                    try
                    {
                        entryKey = keystore.FormatVersion >= 4 ? DeriveEntryKey(fileKey, i) : fileKey;
                        var decrypted = AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, entryKey);
                        existingPayloads.Add(decrypted);
                    }
                    finally
                    {
                        if (entryKey != null && keystore.FormatVersion >= 4)
                            CryptographicOperations.ZeroMemory(entryKey);
                    }
                }

                // Create a new keystore service with all entries (existing + new). The service
                // takes ownership of a copy of the main bytes and zeros them on Dispose so the
                // passphrase doesn't outlive the critical section.
                using var service = new KeystoreService(keystorePath, (byte[])mainBytes.Clone(), secondary, signer);

                // Honor the operator's configured scrypt cost if a SecurityPolicy
                // row is available. Falls back to the pinned defaults if the table isn't
                // populated yet (legacy installs pre-migration).
                try
                {
                    var policy = db.SecurityPolicies.AsNoTracking().FirstOrDefault();
                    if (policy != null)
                        service.SetTargetScryptParams(policy.KeystoreScryptN, policy.KeystoreScryptR, policy.KeystoreScryptP);
                }
                catch { /* leave defaults */ }

                foreach (var payload in existingPayloads)
                    service.AddEntry(payload, secondary);
                foreach (var payload in newPayloads)
                    service.AddEntry(payload, secondary);

                var result = service.Save();

                // Sanity-check the freshly written file — if it doesn't parse,
                // the previous content is still available at {path}.bak and callers can recover.
                var verify = KeystoreFileParser.Parse(keystorePath);
                VerifyFileSignature(verify, db, pinnedSpki);

                // Refresh the SPKI pin MAC on every successful rewrite.
                if (!string.IsNullOrEmpty(pinnedSpki))
                {
                    var keystoreRow = db.Keystores.FirstOrDefault(k => k.Name == keystoreName);
                    if (keystoreRow != null)
                    {
                        keystoreRow.SigningCaSpkiSha256Mac = ComputeSpkiPinMac(pinnedSpki, secondary);
                        db.SaveChanges();
                    }
                }

                EmitKeystoreAudit(AuditActionType.KeystoreAppended, keystoreName, success: true,
                    detail: $"added={newPayloads.Count} total={existingPayloads.Count + newPayloads.Count}");

                return result;
            }
            finally
            {
                // Zero every decrypted plaintext buffer before letting it escape to the GC.
                foreach (var buf in existingPayloads)
                {
                    if (buf != null && buf.Length > 0)
                        CryptographicOperations.ZeroMemory(buf);
                }
                if (fileKey != null && fileKey.Length > 0)
                    CryptographicOperations.ZeroMemory(fileKey);
                // Zero the main passphrase bytes before returning.
                CryptographicOperations.ZeroMemory(mainBytes);
            }
        }
    }

    /// <summary>
    /// Result of saving a keystore, containing the scrypt salt and parameters used.
    /// </summary>
    public record KeystoreSaveResult(byte[] Salt, KeystoreFileWriter.ScryptParams Params);

    /// <summary>
    /// A pending keystore entry with its target keystore, payload, and secondary password.
    /// </summary>
    public record AddKeystoreEntry(string Keystore, byte[] Payload, string SecondaryPass);

    /// <summary>
    /// Wraps a decrypted private key loaded from the keystore.
    /// </summary>
    public record CertKey(AsymmetricKeyParameter PrivateKey);

    /// <summary>
    /// Pairs an X.509 certificate with its corresponding private key.
    /// </summary>
    public record CertWithKey(X509Certificate Cert, AsymmetricKeyParameter PrivateKey);
}
