using System.Security.Cryptography;
using ModularCA.Shared.Signing;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// A signer that does the one thing the settings store asks of one: wrap and unwrap a
/// <see cref="SecretKind.SettingSecret"/> bound to its setting, under
/// <see cref="SigningPurpose.Configuration"/>. The blobs are real version 2 envelopes under a key
/// made up for the test, so a blob read from the wrong place fails here as it does in the real
/// signer, whose own behaviour is in <c>SigningServiceContractTests</c>.
/// </summary>
internal sealed class SettingsTestSigner : ISigningService
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _keyId = RandomNumberGenerator.GetBytes(WrappedSecretEnvelope.KeyIdLength);

    /// <summary>When set, every call is refused as if the signer could not be reached.</summary>
    public bool Unreachable { get; set; }

    public int Wraps { get; private set; }
    public int Unwraps { get; private set; }

    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default)
    {
        Judge(kind, context);
        Wraps++;
        var salt = RandomNumberGenerator.GetBytes(WrappedSecretEnvelope.SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(WrappedSecretEnvelope.NonceLength);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[WrappedSecretEnvelope.TagLength];
        using var gcm = new AesGcm(_key, WrappedSecretEnvelope.TagLength);
        gcm.Encrypt(nonce, secret, ciphertext, tag, WrappedSecretEnvelope.AssociatedData(kind, _keyId, binding));
        return Task.FromResult(WrappedSecretEnvelope.Build(kind, _keyId, binding, salt, nonce, ciphertext, tag));
    }

    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default)
    {
        if (!WrappedSecretEnvelope.TryRead(wrapped, out var header))
            throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported, "The bytes offered are not a wrapped secret.");
        Judge(header.Kind, context);
        Unwraps++;
        if (header.Binding != binding)
            throw new SigningRefusedException(SigningRefusalReason.IntegrityFailure, "The secret was wrapped for another place than the one it was read from.");
        try
        {
            var secret = new byte[header.Ciphertext.Length];
            using var gcm = new AesGcm(_key, WrappedSecretEnvelope.TagLength);
            gcm.Decrypt(header.Nonce, header.Ciphertext, header.Tag, secret, header.AssociatedData);
            return Task.FromResult(secret);
        }
        catch (CryptographicException)
        {
            throw new SigningRefusedException(SigningRefusalReason.IntegrityFailure, "The wrapped secret does not authenticate.");
        }
    }

    private void Judge(SecretKind kind, SigningContext context)
    {
        if (Unreachable)
            throw new SigningRefusedException(SigningRefusalReason.SignerUnavailable, "The signer cannot be reached.");
        if (kind != SecretKind.SettingSecret || context.Purpose != SigningPurpose.Configuration)
            throw new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted, $"A {context.Purpose} context does not handle a {kind}.");
    }

    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}
