using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pkcs;

namespace ModularCA.Ssh;

/// <summary>A private key read from an OpenSSH key file, with its public half.</summary>
/// <param name="PrivateKey">The private key.</param>
/// <param name="PublicKey">The public key, derived from the private key and checked against the file's own copy.</param>
public sealed record SshPrivateKey(AsymmetricKeyParameter PrivateKey, SshPublicKey PublicKey)
{
    /// <summary>The private key as DER PKCS#8 <c>PrivateKeyInfo</c>, the form the keystore holds.</summary>
    public byte[] ToPkcs8() => PrivateKeyInfoFactory.CreatePrivateKeyInfo(PrivateKey).GetEncoded();
}

/// <summary>
/// Reads unencrypted <c>openssh-key-v1</c> private key files, as <c>ssh-keygen</c> writes them,
/// for Ed25519, ECDSA P-256/P-384/P-521 and RSA. BouncyCastle decodes the key; this checks the
/// framing and that the file's public key matches its private key.
/// </summary>
public static class SshPrivateKeyFile
{
    private const string Begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string End = "-----END OPENSSH PRIVATE KEY-----";
    private static readonly byte[] AuthMagic = Encoding.ASCII.GetBytes("openssh-key-v1\0");

    /// <summary>Reads a PEM-armoured <c>openssh-key-v1</c> file.</summary>
    /// <exception cref="FormatException">
    /// The text is not one unencrypted OpenSSH private key of a supported type, or its public and
    /// private halves differ.
    /// </exception>
    public static SshPrivateKey Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var trimmed = text.Trim();
        if (!trimmed.StartsWith(Begin, StringComparison.Ordinal) || !trimmed.EndsWith(End, StringComparison.Ordinal))
            throw new FormatException("Not an OpenSSH private key file.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(trimmed[Begin.Length..^End.Length]);
        }
        catch (FormatException)
        {
            throw new FormatException("The OpenSSH private key is not valid base64.");
        }
        return ReadBlob(blob);
    }

    /// <summary>Reads the decoded body of an <c>openssh-key-v1</c> file.</summary>
    /// <exception cref="FormatException">As for <see cref="Read"/>.</exception>
    public static SshPrivateKey ReadBlob(byte[] blob)
    {
        ArgumentNullException.ThrowIfNull(blob);
        if (blob.Length < AuthMagic.Length || !blob.AsSpan(0, AuthMagic.Length).SequenceEqual(AuthMagic))
            throw new FormatException("Not an openssh-key-v1 private key.");

        var reader = new SshReader(blob[AuthMagic.Length..]);
        var cipher = reader.Utf8String();
        var kdf = reader.Utf8String();
        reader.String();
        if (cipher != "none" || kdf != "none")
            throw new FormatException("The OpenSSH private key is encrypted.");
        if (reader.UInt32() != 1)
            throw new FormatException("The OpenSSH key file must hold exactly one key.");
        var filePublic = SshPublicKey.FromBlob(reader.String());

        AsymmetricKeyParameter privateKey;
        try
        {
            privateKey = OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(blob);
        }
        catch (Exception e) when (e is not FormatException)
        {
            throw new FormatException("The OpenSSH private key could not be decoded.", e);
        }

        var derived = SshPublicKey.FromKeyParameter(PublicOf(privateKey));
        if (!derived.Equals(filePublic))
            throw new FormatException("The key file's public key does not match its private key.");
        return new SshPrivateKey(privateKey, derived);
    }

    private static AsymmetricKeyParameter PublicOf(AsymmetricKeyParameter privateKey) => privateKey switch
    {
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters("EC", ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        _ => throw new FormatException($"Unsupported OpenSSH private key type {privateKey.GetType().Name}."),
    };
}
