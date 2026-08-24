using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the field mapping between wrapping a private key and storing it on a certificate.
/// <para>
/// <c>EncryptPrivateKey</c> returns <c>(aesKeyEncrypted, iv, encryptedPrivateKey)</c>. Issuance
/// deconstructed that tuple POSITIONALLY into <c>(certIv, certEncryptedAes, ...)</c>, so the
/// wrapped AES key was stored in the IV column and the 12-byte nonce in the AES key column.
/// Tuple element names do not protect a positional deconstruction, and nothing failed at
/// issuance — the swap surfaced much later, as an ArgumentOutOfRangeException inside the unwrap,
/// the first time anyone exported a PFX.
/// </para>
/// </summary>
public class KeyWrapRoundTripTests
{
    private static AsymmetricCipherKeyPair RsaKeyPair()
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return generator.GenerateKeyPair();
    }

    private static readonly byte[] Passphrase = "test-secondary-passphrase"u8.ToArray();

    [Fact]
    public void A_key_wrapped_for_a_certificate_can_be_unwrapped_again()
    {
        // Walks the exact mapping the issuance path uses: wrap, store onto the model the way
        // BuildCertModel does, then read it back the way CertificateExportService does.
        var encryptor = RsaKeyPair();
        var subjectKey = RsaKeyPair();

        var wrapped = KeyEncryptionUtil.EncryptPrivateKey(encryptor.Public, subjectKey.Private, Passphrase);

        var stored = new CertificateInfoModel
        {
            Iv = wrapped.iv,
            EncryptedAesKey = wrapped.aesKeyEncrypted,
            EncryptedPrivateKey = wrapped.encryptedPrivateKey,
        };

        var recovered = KeyEncryptionUtil.DecryptPrivateKey(
            stored.EncryptedAesKey!, stored.Iv!, stored.EncryptedPrivateKey!,
            encryptor.Private, encryptor.Public, Passphrase);

        Assert.NotNull(recovered);
        Assert.True(recovered.IsPrivate);
        Assert.Equal(
            ((RsaPrivateCrtKeyParameters)subjectKey.Private).Modulus,
            ((RsaPrivateCrtKeyParameters)recovered).Modulus);
    }

    [Fact]
    public void Storing_the_iv_and_wrapped_key_the_wrong_way_round_cannot_be_unwrapped()
    {
        // The regression itself. Without this, the round-trip test above would still pass if
        // someone reintroduced the swap on BOTH sides consistently — and real stored data would
        // silently stop matching what the exporter expects.
        var encryptor = RsaKeyPair();
        var subjectKey = RsaKeyPair();

        var wrapped = KeyEncryptionUtil.EncryptPrivateKey(encryptor.Public, subjectKey.Private, Passphrase);

        Assert.ThrowsAny<Exception>(() => KeyEncryptionUtil.DecryptPrivateKey(
            wrapped.iv,               // <- swapped: the 12-byte nonce where the wrapped key belongs
            wrapped.aesKeyEncrypted,  // <- swapped
            wrapped.encryptedPrivateKey,
            encryptor.Private, encryptor.Public, Passphrase));
    }

    [Fact]
    public void The_iv_is_twelve_bytes_and_the_wrapped_key_never_is()
    {
        // This is exactly the discriminator RepairSwappedCertKeyWrapColumns uses to find
        // corrupted rows. If either invariant stops holding, that migration's predicate becomes
        // unsafe — so it is pinned here rather than left as an assumption in SQL.
        var encryptor = RsaKeyPair();
        var subjectKey = RsaKeyPair();

        var wrapped = KeyEncryptionUtil.EncryptPrivateKey(encryptor.Public, subjectKey.Private, Passphrase);

        Assert.Equal(12, wrapped.iv.Length);
        Assert.NotEqual(12, wrapped.aesKeyEncrypted.Length);
    }
}
