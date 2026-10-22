using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ModularCA.Ssh;

/// <summary>The shape a signer returns an ECDSA signature in.</summary>
public enum EcdsaSignatureFormat
{
    /// <summary>A DER <c>SEQUENCE { r INTEGER, s INTEGER }</c>, as software keys return it.</summary>
    Der,

    /// <summary>Fixed-width <c>r || s</c>, as PKCS#11 tokens return it.</summary>
    Raw,
}

/// <summary>A decoded SSH signature blob: the algorithm name and the algorithm-specific bytes.</summary>
/// <param name="Algorithm">The signature algorithm, for example <c>rsa-sha2-512</c>.</param>
/// <param name="Data">
/// The signature bytes: 64 bytes for Ed25519, the PKCS#1 signature for RSA, and for ECDSA the
/// encoded <c>mpint r, mpint s</c> pair.
/// </param>
public sealed record SshSignatureBlob(string Algorithm, byte[] Data);

/// <summary>
/// Formats, parses, verifies and (for software keys) creates SSH signature blobs:
/// <c>string algorithm, string signature</c>.
/// </summary>
public static class SshSignature
{
    /// <summary>
    /// Builds an SSH signature blob from a signer's output for <paramref name="algorithm"/>.
    /// ECDSA output is converted from <paramref name="ecdsaFormat"/> to the SSH <c>mpint r, mpint s</c> pair.
    /// </summary>
    /// <exception cref="ArgumentException">The output does not have the shape the algorithm requires.</exception>
    public static byte[] Encode(string algorithm, byte[] signerOutput, EcdsaSignatureFormat ecdsaFormat = EcdsaSignatureFormat.Der)
    {
        ArgumentNullException.ThrowIfNull(signerOutput);
        byte[] data;
        switch (algorithm)
        {
            case SshSignatureAlgorithms.Ed25519:
                if (signerOutput.Length != Ed25519PrivateKeyParameters.SignatureSize)
                    throw new ArgumentException("An Ed25519 signature is 64 bytes.", nameof(signerOutput));
                data = signerOutput;
                break;
            case SshSignatureAlgorithms.RsaSha256 or SshSignatureAlgorithms.RsaSha512:
                if (signerOutput.Length == 0)
                    throw new ArgumentException("The RSA signature is empty.", nameof(signerOutput));
                data = signerOutput;
                break;
            case SshSignatureAlgorithms.EcdsaP256 or SshSignatureAlgorithms.EcdsaP384 or SshSignatureAlgorithms.EcdsaP521:
                var (r, s) = ecdsaFormat == EcdsaSignatureFormat.Der
                    ? FromDer(signerOutput)
                    : FromRaw(signerOutput, (SshPublicKey.Domain(algorithm).Curve.FieldSize + 7) / 8);
                data = new SshWriter().MPInt(r).MPInt(s).ToArray();
                break;
            default:
                throw new ArgumentException($"Unsupported SSH signature algorithm '{algorithm}'.", nameof(algorithm));
        }
        return new SshWriter().String(algorithm).String(data).ToArray();
    }

    /// <summary>Splits a signature blob into its algorithm and data, refusing trailing bytes.</summary>
    /// <exception cref="FormatException">The blob is malformed.</exception>
    public static SshSignatureBlob Decode(byte[] blob)
    {
        var reader = new SshReader(blob);
        var algorithm = reader.Utf8String();
        var data = reader.String();
        reader.EnsureEnd("signature");
        return new SshSignatureBlob(algorithm, data);
    }

    /// <summary>
    /// Verifies <paramref name="signatureBlob"/> over <paramref name="data"/> with <paramref name="key"/>.
    /// False for a malformed blob, an algorithm the key does not sign with, or SHA-1 <c>ssh-rsa</c>.
    /// </summary>
    public static bool Verify(SshPublicKey key, byte[] data, byte[] signatureBlob)
    {
        ArgumentNullException.ThrowIfNull(key);
        SshSignatureBlob decoded;
        try
        {
            decoded = Decode(signatureBlob);
        }
        catch (FormatException)
        {
            return false;
        }
        if (!SshSignatureAlgorithms.IsCompatible(decoded.Algorithm, key.KeyType))
            return false;

        var verifier = SignerUtilities.GetSigner(SshSignatureAlgorithms.SignerAlgorithmName(decoded.Algorithm));
        verifier.Init(false, key.KeyParameter);
        verifier.BlockUpdate(data, 0, data.Length);

        byte[] signature;
        if (decoded.Algorithm is SshSignatureAlgorithms.EcdsaP256 or SshSignatureAlgorithms.EcdsaP384 or SshSignatureAlgorithms.EcdsaP521)
        {
            try
            {
                var reader = new SshReader(decoded.Data);
                var r = reader.MPInt();
                var s = reader.MPInt();
                reader.EnsureEnd("ECDSA signature");
                signature = new DerSequence(new DerInteger(r), new DerInteger(s)).GetEncoded();
            }
            catch (FormatException)
            {
                return false;
            }
        }
        else
        {
            signature = decoded.Data;
        }
        return verifier.VerifySignature(signature);
    }

    /// <summary>
    /// Signs <paramref name="data"/> with a software private key and returns the SSH signature blob.
    /// For tests and tools; the signer signs through its own key handles.
    /// </summary>
    public static byte[] Create(AsymmetricKeyParameter privateKey, string algorithm, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var signer = SignerUtilities.GetSigner(SshSignatureAlgorithms.SignerAlgorithmName(algorithm));
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return Encode(algorithm, signer.GenerateSignature(), EcdsaSignatureFormat.Der);
    }

    private static (BigInteger R, BigInteger S) FromDer(byte[] der)
    {
        try
        {
            if (Asn1Object.FromByteArray(der) is not Asn1Sequence { Count: 2 } seq)
                throw new ArgumentException("The ECDSA signature is not a two-integer DER sequence.");
            var r = DerInteger.GetInstance(seq[0]).Value;
            var s = DerInteger.GetInstance(seq[1]).Value;
            if (r.SignValue <= 0 || s.SignValue <= 0)
                throw new ArgumentException("The ECDSA signature has a zero component.");
            return (r, s);
        }
        catch (Exception e) when (e is not ArgumentException)
        {
            throw new ArgumentException("The ECDSA signature is not valid DER.", e);
        }
    }

    private static (BigInteger R, BigInteger S) FromRaw(byte[] raw, int fieldBytes)
    {
        if (raw.Length != 2 * fieldBytes)
            throw new ArgumentException($"A raw signature on this curve is {2 * fieldBytes} bytes.");
        var r = new BigInteger(1, raw, 0, fieldBytes);
        var s = new BigInteger(1, raw, fieldBytes, fieldBytes);
        if (r.SignValue <= 0 || s.SignValue <= 0)
            throw new ArgumentException("The ECDSA signature has a zero component.");
        return (r, s);
    }
}
