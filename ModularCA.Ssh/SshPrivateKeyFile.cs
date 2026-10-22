using System.Security.Cryptography;
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
/// An OpenSSH private key file that is protected by a passphrase. It is a
/// <see cref="FormatException"/>, since the reader takes unencrypted keys only, and a type of
/// its own so that a caller can tell the operator to remove the passphrase.
/// </summary>
public sealed class SshPrivateKeyEncryptedException : FormatException
{
    /// <summary>Creates the exception with the reader's message.</summary>
    public SshPrivateKeyEncryptedException() : base("The OpenSSH private key is encrypted.")
    {
    }
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
    /// <exception cref="SshPrivateKeyEncryptedException">The key is protected by a passphrase.</exception>
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

    /// <summary>
    /// Reads a PEM-armoured <c>openssh-key-v1</c> file from its bytes, as <see cref="Read"/>
    /// reads its text, without the key passing through a string: the armour is decoded in
    /// buffers that are zeroed before this returns. The caller zeroes <paramref name="file"/>.
    /// </summary>
    /// <exception cref="SshPrivateKeyEncryptedException">The key is protected by a passphrase.</exception>
    /// <exception cref="FormatException">As for <see cref="Read"/>.</exception>
    public static SshPrivateKey ReadFile(ReadOnlySpan<byte> file)
    {
        var text = new char[file.Length];
        byte[]? blob = null;
        try
        {
            for (var i = 0; i < file.Length; i++)
            {
                if (file[i] > 0x7F)
                    throw new FormatException("Not an OpenSSH private key file.");
                text[i] = (char)file[i];
            }

            var trimmed = text.AsSpan().Trim();
            if (!trimmed.StartsWith(Begin, StringComparison.Ordinal) || !trimmed.EndsWith(End, StringComparison.Ordinal)
                || trimmed.Length < Begin.Length + End.Length)
                throw new FormatException("Not an OpenSSH private key file.");

            var body = trimmed[Begin.Length..^End.Length];
            blob = new byte[body.Length];
            if (!Convert.TryFromBase64Chars(body, blob, out var written))
                throw new FormatException("The OpenSSH private key is not valid base64.");
            return ReadBlob(blob.AsSpan(0, written).ToArray(), zeroWhenRead: true);
        }
        finally
        {
            Array.Clear(text);
            if (blob != null)
                CryptographicOperations.ZeroMemory(blob);
        }
    }

    /// <summary>Reads the decoded body of an <c>openssh-key-v1</c> file.</summary>
    /// <exception cref="SshPrivateKeyEncryptedException">The key is protected by a passphrase.</exception>
    /// <exception cref="FormatException">As for <see cref="Read"/>.</exception>
    public static SshPrivateKey ReadBlob(byte[] blob) => ReadBlob(blob, zeroWhenRead: false);

    /// <summary>
    /// <see cref="ReadBlob(byte[])"/>; with <paramref name="zeroWhenRead"/> the blob is zeroed
    /// once the key has been read from it, or could not be.
    /// </summary>
    private static SshPrivateKey ReadBlob(byte[] blob, bool zeroWhenRead)
    {
        ArgumentNullException.ThrowIfNull(blob);
        byte[]? framed = null;
        try
        {
            if (blob.Length < AuthMagic.Length || !blob.AsSpan(0, AuthMagic.Length).SequenceEqual(AuthMagic))
                throw new FormatException("Not an openssh-key-v1 private key.");

            framed = blob[AuthMagic.Length..];
            var reader = new SshReader(framed);
            var cipher = reader.Utf8String();
            var kdf = reader.Utf8String();
            reader.String();
            if (cipher != "none" || kdf != "none")
                throw new SshPrivateKeyEncryptedException();
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
        finally
        {
            if (framed != null)
                CryptographicOperations.ZeroMemory(framed);
            if (zeroWhenRead)
                CryptographicOperations.ZeroMemory(blob);
        }
    }

    private static AsymmetricKeyParameter PublicOf(AsymmetricKeyParameter privateKey) => privateKey switch
    {
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters("EC", ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        _ => throw new FormatException($"Unsupported OpenSSH private key type {privateKey.GetType().Name}."),
    };
}
