using ModularCA.Keystore.Adapters;
using ModularCA.Ssh;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// An SSH CA key of the SSH keystore as <see cref="SshCertificateIssuer"/> signs with it: the
/// public half the key was bound to its row under, and a signature made through the key's handle.
/// The key never leaves the handle. Software keys only: a key on a PKCS#11 token returns ECDSA
/// signatures in another shape and is not served until SSH keys on tokens are built.
/// </summary>
/// <remarks>
/// It signs with one algorithm, the one the key's type signs certificates with
/// (<see cref="SshSignatureAlgorithms.ForKeyType"/>: <c>rsa-sha2-512</c> for RSA), and refuses
/// to be asked for any other, so an RSA key makes no SHA-256 signature here whatever the caller
/// of this class asks. Whatever goes wrong while signing is reported as
/// <see cref="SshSigningFailedException"/>, so the signer records it as a decision.
/// </remarks>
internal sealed class SshHandleSigner : ISshSigner
{
    private readonly SoftwarePrivateKeyHandle _handle;

    /// <summary>Signs with <paramref name="handle"/>, whose public half is <paramref name="publicKey"/>.</summary>
    public SshHandleSigner(SshPublicKey publicKey, SoftwarePrivateKeyHandle handle)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        _handle = handle ?? throw new ArgumentNullException(nameof(handle));
    }

    /// <inheritdoc />
    public SshPublicKey PublicKey { get; }

    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (algorithm != SshSignatureAlgorithms.ForKeyType(PublicKey.KeyType))
                throw new SshSigningFailedException($"A {PublicKey.KeyType} SSH CA key signs certificates with {SshSignatureAlgorithms.ForKeyType(PublicKey.KeyType)}, not {algorithm}.");
            var signature = _handle.Sign(data.ToArray(), SshSignatureAlgorithms.SignerAlgorithmName(algorithm));
            return ValueTask.FromResult(SshSignature.Encode(algorithm, signature, EcdsaSignatureFormat.Der));
        }
        catch (Exception ex) when (ex is not SshSigningFailedException)
        {
            throw new SshSigningFailedException($"The SSH CA key could not sign the certificate: {ex.Message}");
        }
    }
}
