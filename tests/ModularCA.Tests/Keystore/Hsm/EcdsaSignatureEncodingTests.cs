using System.Security.Cryptography;
using ModularCA.Keystore.Hsm;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace ModularCA.Tests.Keystore.Hsm;

/// <summary>
/// The raw <c>r || s</c> a PKCS#11 token returns for <c>CKM_ECDSA</c> becomes the DER
/// <c>SEQUENCE { INTEGER r, INTEGER s }</c> X.509 carries. Known vectors cover the encodings
/// that go wrong: a half whose top bit is set (needs a zero byte), halves with leading zero
/// bytes (dropped), and both together; converted signatures made with real keys verify.
/// </summary>
public sealed class EcdsaSignatureEncodingTests
{
    /// <summary>A 32-byte half: <paramref name="prefix"/> then <paramref name="fill"/> to the end.</summary>
    private static byte[] Half(byte[] prefix, byte fill = 0x11)
    {
        var half = Enumerable.Repeat(fill, 32).ToArray();
        prefix.CopyTo(half, 0);
        return half;
    }

    /// <summary>A DER INTEGER with the given content bytes, written out by hand.</summary>
    private static byte[] Integer(byte[] content) => [0x02, (byte)content.Length, .. content];

    [Fact]
    public void A_half_with_the_top_bit_set_gains_a_zero_byte()
    {
        var r = Half([0x80]);
        var s = Half([0x7F]);

        var der = EcdsaSignatureEncoding.RawToDer([.. r, .. s], 32);

        byte[] body = [.. Integer([0x00, .. r]), .. Integer(s)];
        Assert.Equal([0x30, (byte)body.Length, .. body], der);
    }

    [Fact]
    public void Leading_zero_bytes_are_dropped()
    {
        var r = Half([0x00, 0x00, 0x7F]);
        var s = Half([0x00, 0x01]);

        var der = EcdsaSignatureEncoding.RawToDer([.. r, .. s], 32);

        byte[] body = [.. Integer(r[2..]), .. Integer(s[1..])];
        Assert.Equal([0x30, (byte)body.Length, .. body], der);
    }

    [Fact]
    public void A_leading_zero_before_a_set_top_bit_is_kept_as_the_sign_byte()
    {
        var r = Half([0x00, 0x00, 0x80]);
        var s = Half([0xFF]);

        var der = EcdsaSignatureEncoding.RawToDer([.. r, .. s], 32);

        byte[] body = [.. Integer(r[1..]), .. Integer([0x00, .. s])];
        Assert.Equal([0x30, (byte)body.Length, .. body], der);
    }

    [Fact]
    public void A_signature_of_the_wrong_length_for_the_curve_is_refused()
    {
        Assert.Throws<CryptographicException>(() => EcdsaSignatureEncoding.RawToDer(new byte[63], 32));
        Assert.Throws<CryptographicException>(() => EcdsaSignatureEncoding.RawToDer(new byte[96], 32));
    }

    [Fact]
    public void A_zero_component_is_refused()
    {
        Assert.Throws<CryptographicException>(() => EcdsaSignatureEncoding.RawToDer([.. new byte[32], .. Half([0x01])], 32));
    }

    [Theory]
    [InlineData("P-256", 32)]
    [InlineData("P-384", 48)]
    [InlineData("P-521", 66)]
    public void The_component_length_is_the_byte_length_of_the_curve_order(string curve, int expected)
    {
        var oid = curve switch { "P-256" => HsmTestKeys.P256, "P-384" => HsmTestKeys.P384, _ => HsmTestKeys.P521 };
        Assert.Equal(expected, EcdsaSignatureEncoding.ComponentLength(HsmTestKeys.Ec(oid).Public));
        Assert.Null(EcdsaSignatureEncoding.ComponentLength(HsmTestKeys.Rsa().Public));
    }

    [Theory]
    [InlineData("P-256", "SHA256withECDSA")]
    [InlineData("P-384", "SHA384withECDSA")]
    [InlineData("P-521", "SHA512withECDSA")]
    public void A_converted_raw_signature_verifies_against_the_public_key(string curve, string algorithm)
    {
        var oid = curve switch { "P-256" => HsmTestKeys.P256, "P-384" => HsmTestKeys.P384, _ => HsmTestKeys.P521 };
        var keys = HsmTestKeys.Ec(oid);
        var length = EcdsaSignatureEncoding.ComponentLength(keys.Public)!.Value;
        var data = System.Text.Encoding.ASCII.GetBytes("to-be-signed");

        // Many signatures, so halves with leading zeros and set top bits both turn up.
        for (var i = 0; i < 32; i++)
        {
            var raw = FakeEcdsaToken.SignRaw((ECPrivateKeyParameters)keys.Private, algorithm, data);
            var der = EcdsaSignatureEncoding.RawToDer(raw, length);

            var verifier = SignerUtilities.GetSigner(algorithm);
            verifier.Init(false, keys.Public);
            verifier.BlockUpdate(data, 0, data.Length);
            Assert.True(verifier.VerifySignature(der));
            Assert.IsAssignableFrom<Asn1Sequence>(Asn1Object.FromByteArray(der));
        }
    }
}

/// <summary>Makes the raw <c>r || s</c> a PKCS#11 token returns for <c>CKM_ECDSA_SHAxxx</c>, with a software key.</summary>
internal static class FakeEcdsaToken
{
    /// <summary>Hashes <paramref name="data"/> as <paramref name="algorithm"/> names and signs it, returning fixed-width r || s.</summary>
    public static byte[] SignRaw(ECPrivateKeyParameters key, string algorithm, byte[] data)
    {
        var digestName = algorithm[..algorithm.IndexOf("with", StringComparison.OrdinalIgnoreCase)];
        var hash = DigestUtilities.CalculateDigest(digestName, data);
        var signer = new ECDsaSigner();
        signer.Init(true, new ParametersWithRandom(key, new SecureRandom()));
        var rs = signer.GenerateSignature(hash);
        var length = (key.Parameters.N.BitLength + 7) / 8;
        return [.. Fixed(rs[0], length), .. Fixed(rs[1], length)];
    }

    private static byte[] Fixed(BigInteger value, int length) => value.ToByteArrayUnsigned() is var b && b.Length == length
        ? b
        : [.. new byte[length - b.Length], .. b];
}
