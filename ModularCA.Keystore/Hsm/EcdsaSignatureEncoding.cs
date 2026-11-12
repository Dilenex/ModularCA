using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// Converts the ECDSA signature a PKCS#11 token returns into the one X.509 needs. <c>CKM_ECDSA</c>
/// and its hashing variants return <c>r || s</c>, each half the byte length of the curve order;
/// certificates, CRLs, OCSP responses and CMS carry the DER <c>SEQUENCE { INTEGER r, INTEGER s }</c>
/// of RFC 3279, which is what the software keys (BouncyCastle) return and what every verifier
/// expects.
/// </summary>
public static class EcdsaSignatureEncoding
{
    /// <summary>
    /// The DER <c>SEQUENCE { INTEGER r, INTEGER s }</c> for the fixed-width <c>r || s</c> in
    /// <paramref name="raw"/>. Each half is read as an unsigned big-endian integer, so leading
    /// zero bytes are dropped and a half whose top bit is set gains the zero byte that keeps the
    /// DER INTEGER positive.
    /// </summary>
    /// <param name="raw">The token's signature: <c>r</c> then <c>s</c>, <paramref name="componentLength"/> bytes each.</param>
    /// <param name="componentLength">The byte length of the curve order: 32 for P-256, 48 for P-384, 66 for P-521.</param>
    /// <exception cref="CryptographicException">The signature is not <c>2 × componentLength</c> bytes, or r or s is zero.</exception>
    public static byte[] RawToDer(ReadOnlySpan<byte> raw, int componentLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(componentLength);
        if (raw.Length != 2 * componentLength)
            throw new CryptographicException(
                $"An ECDSA signature from the token should be {2 * componentLength} bytes of r || s for this key's curve; it was {raw.Length}.");

        var r = new BigInteger(1, raw[..componentLength].ToArray());
        var s = new BigInteger(1, raw[componentLength..].ToArray());
        if (r.SignValue == 0 || s.SignValue == 0)
            throw new CryptographicException("The ECDSA signature from the token has a zero component.");
        return new DerSequence(new DerInteger(r), new DerInteger(s)).GetEncoded(Asn1Encodable.Der);
    }

    /// <summary>
    /// The byte length of each half of a raw ECDSA signature by <paramref name="publicKey"/>'s
    /// private half: the byte length of the curve order. Null for a key that is not an EC key.
    /// </summary>
    /// <param name="publicKey">The key's public half, from its certificate.</param>
    public static int? ComponentLength(AsymmetricKeyParameter publicKey)
        => publicKey is ECPublicKeyParameters ec ? (ec.Parameters.N.BitLength + 7) / 8 : null;
}
