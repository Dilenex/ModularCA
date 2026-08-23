using System.Security.Cryptography;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Keystore;

/// <summary>
/// Round-trips a keystore written by <see cref="KeystoreService.Save"/> back through
/// <see cref="KeystoreService.DecryptEntries"/> — the path the Unlocker break-glass tool now
/// takes.
/// <para>
/// The Unlocker previously ran its own decrypt loop that handed the file master key straight to
/// AES-GCM. That is correct only up to MCAKSTR v3. From v4 every entry is encrypted under
/// <c>HKDF-Expand(masterKey, "ModularCA:Keystore:entry" || u32be(index))</c>, and since v4 is
/// what <see cref="KeystoreFileWriter.CurrentFormatVersion"/> emits, the tool could not read a
/// single keystore the product had ever written. Nothing caught it: the writer and the runtime
/// loader agreed with each other, and the third implementation was only ever exercised by hand
/// during a disaster.
/// </para>
/// <para>
/// These tests pin both halves — that the shared path round-trips, and that the old shortcut
/// genuinely fails — so a future format bump cannot quietly strand the recovery tool again.
/// </para>
/// </summary>
public class KeystoreUnlockRoundTripTests : IDisposable
{
    private const string MainPass = "main-passphrase-for-test";
    private const string SecondaryPass = "secondary-passphrase-for-test";

    // Lowest cost SetTargetScryptParams will accept. The production default is 2^16, which is
    // ~64 MB and about a second per derivation; this exercises identical code at a cost the
    // suite can absorb.
    private const int TestScryptN = 1 << 14;

    private readonly string _dir;

    public KeystoreUnlockRoundTripTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "modularca-keystore-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Writes a keystore holding <paramref name="payloads"/> and returns its path.
    /// </summary>
    private string WriteKeystore(string name, params byte[][] payloads)
    {
        var path = Path.Combine(_dir, name);
        var signer = TestCaMaterial.CreateCa("CN=Keystore Test Signer, O=ModularCA");

        using var service = new KeystoreService(path, MainPass, SecondaryPass, signer.KeyPair.Private);
        service.SetTargetScryptParams(TestScryptN, KeystoreService.DefaultScryptR, KeystoreService.DefaultScryptP);
        foreach (var payload in payloads)
            service.AddEntry(payload, SecondaryPass);
        service.Save();

        return path;
    }

    private static byte[] Payload(byte seed, int length = 96)
    {
        var buffer = new byte[length];
        for (int i = 0; i < length; i++) buffer[i] = (byte)(seed + i);
        return buffer;
    }

    [Fact]
    public void Save_emits_the_current_format_version()
    {
        // If this ever fails, the rest of these tests are asserting against the wrong format and
        // the Unlocker's version handling needs revisiting before the bump ships.
        var path = WriteKeystore("format.keystore", Payload(1));

        var keystore = KeystoreFileParser.Parse(path);

        Assert.Equal(KeystoreFileWriter.CurrentFormatVersion, keystore.FormatVersion);
        Assert.True(keystore.FormatVersion >= 4, "v4 introduced per-entry HKDF keys.");
    }

    [Fact]
    public void DecryptEntries_round_trips_every_entry()
    {
        var first = Payload(0x10);
        var second = Payload(0x40);
        var third = Payload(0x70);
        var path = WriteKeystore("roundtrip.keystore", first, second, third);

        var keystore = KeystoreFileParser.Parse(path);
        var key = ScryptKeyDeriver.DeriveFileKey(MainPass, SecondaryPass, keystore);

        var recovered = new Dictionary<int, byte[]>();
        try
        {
            // verifyEntrySignatures: false is the --insecure-no-verify path — the only one
            // available without an app database, and the case an operator hits when the DB is
            // exactly what they have lost.
            KeystoreService.DecryptEntries(
                keystore, key, db: null, pinnedSpki: null, verifyEntrySignatures: false,
                (index, plaintext) => recovered[index] = plaintext.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        Assert.Equal(3, recovered.Count);
        Assert.Equal(first, recovered[0]);
        Assert.Equal(second, recovered[1]);
        Assert.Equal(third, recovered[2]);
    }

    [Fact]
    public void Raw_file_key_cannot_decrypt_a_v4_entry()
    {
        // This is the Unlocker's old loop, verbatim in effect: derive the file key, then hand it
        // to AES-GCM per entry. It must fail, or the bug this suite exists for was never real.
        var path = WriteKeystore("rawkey.keystore", Payload(0x20));

        var keystore = KeystoreFileParser.Parse(path);
        var key = ScryptKeyDeriver.DeriveFileKey(MainPass, SecondaryPass, keystore);
        try
        {
            var entry = keystore.Entries[0];
            Assert.ThrowsAny<CryptographicException>(
                () => AesGcmDecryptor.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, key));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void Entry_keys_are_bound_to_entry_position()
    {
        // The HKDF info carries the entry index, so an attacker with file-write access cannot
        // reorder entries and still have them decrypt. Proven by decrypting the file with its
        // entries swapped and requiring failure — a plain "each entry decrypts" assertion would
        // pass even if the index were dropped from the derivation.
        var path = WriteKeystore("ordering.keystore", Payload(0x30), Payload(0x60));

        var keystore = KeystoreFileParser.Parse(path);
        var key = ScryptKeyDeriver.DeriveFileKey(MainPass, SecondaryPass, keystore);
        try
        {
            (keystore.Entries[0], keystore.Entries[1]) = (keystore.Entries[1], keystore.Entries[0]);

            Assert.ThrowsAny<CryptographicException>(() =>
                KeystoreService.DecryptEntries(
                    keystore, key, db: null, pinnedSpki: null, verifyEntrySignatures: false,
                    (_, _) => { }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void Wrong_secondary_passphrase_fails_to_decrypt()
    {
        // The secondary passphrase lives in config/keystore.yaml. Recovering with a stale copy of
        // that file is a realistic disaster-recovery mistake, and it must fail loudly rather than
        // yield garbage plaintext.
        var path = WriteKeystore("wrongpass.keystore", Payload(0x50));

        var keystore = KeystoreFileParser.Parse(path);
        var key = ScryptKeyDeriver.DeriveFileKey(MainPass, "not-the-secondary-passphrase", keystore);
        try
        {
            Assert.ThrowsAny<CryptographicException>(() =>
                KeystoreService.DecryptEntries(
                    keystore, key, db: null, pinnedSpki: null, verifyEntrySignatures: false,
                    (_, _) => { }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void DecryptEntries_refuses_signature_verification_without_a_database()
    {
        // Guards the branch the Unlocker relies on: asking for verification with no database is a
        // programming error, not a silent downgrade to unverified decryption.
        var path = WriteKeystore("nodb.keystore", Payload(0x80));

        var keystore = KeystoreFileParser.Parse(path);
        var key = ScryptKeyDeriver.DeriveFileKey(MainPass, SecondaryPass, keystore);
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                KeystoreService.DecryptEntries(
                    keystore, key, db: null, pinnedSpki: null, verifyEntrySignatures: true,
                    (_, _) => { }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
