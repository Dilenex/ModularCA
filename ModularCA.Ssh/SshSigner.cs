using Org.BouncyCastle.Crypto;

namespace ModularCA.Ssh;

/// <summary>
/// An SSH CA key that can sign, wherever its private half is held: in memory, in a keystore, on a
/// token, or behind a remote signer. <see cref="SshCertificateIssuer"/> signs through this and
/// never sees a private key.
/// </summary>
public interface ISshSigner
{
    /// <summary>The CA public key, written into each certificate as its signature key.</summary>
    SshPublicKey PublicKey { get; }

    /// <summary>
    /// Signs <paramref name="data"/> and returns the SSH signature blob,
    /// <c>string algorithm, string signature</c>. An implementation that holds a raw signer output
    /// makes the blob with <see cref="SshSignature.Encode"/>.
    /// </summary>
    /// <param name="algorithm">The SSH signature algorithm to sign with, one of <see cref="SshSignatureAlgorithms"/>.</param>
    /// <param name="data">The bytes to sign.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
}

/// <summary>An <see cref="ISshSigner"/> over a private key held in memory.</summary>
public sealed class SshKeySigner : ISshSigner
{
    private readonly AsymmetricKeyParameter _privateKey;

    /// <summary>Signs with <paramref name="privateKey"/>, whose public half is <paramref name="publicKey"/>.</summary>
    /// <exception cref="ArgumentException">The key is not private, or its type cannot sign certificates.</exception>
    public SshKeySigner(AsymmetricKeyParameter privateKey, SshPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(publicKey);
        if (!privateKey.IsPrivate)
            throw new ArgumentException("A private key is needed to sign.", nameof(privateKey));
        if (!SshKeyTypes.Certifiable.Contains(publicKey.KeyType))
            throw new ArgumentException($"A {publicKey.KeyType} key cannot sign certificates.", nameof(publicKey));
        _privateKey = privateKey;
        PublicKey = publicKey;
    }

    /// <summary>Signs with a key read from an OpenSSH private key file.</summary>
    public SshKeySigner(SshPrivateKey key) : this((key ?? throw new ArgumentNullException(nameof(key))).PrivateKey, key.PublicKey)
    {
    }

    /// <inheritdoc />
    public SshPublicKey PublicKey { get; }

    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!SshSignatureAlgorithms.IsCompatible(algorithm, PublicKey.KeyType))
            throw new ArgumentException($"A {PublicKey.KeyType} key does not make {algorithm} signatures.", nameof(algorithm));
        return ValueTask.FromResult(SshSignature.Create(_privateKey, algorithm, data.ToArray()));
    }
}
