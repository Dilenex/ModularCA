namespace ModularCA.Shared.Signing;

/// <summary>
/// The shape of a blob <see cref="ISigningService.WrapSecretAsync"/> returns, and the reader
/// <see cref="ISigningService.UnwrapSecretAsync"/> uses to find out what it is holding before it
/// decrypts anything.
/// </summary>
/// <remarks>
/// <para>
/// The layout, all fixed width but the ciphertext:
/// <code>
/// "MCAW" (4) | version (1) | kind (1) | key id (32) | salt (32) | nonce (12) | ciphertext+tag
/// </code>
/// and the associated data an AEAD is given is the first <see cref="HeaderLength"/> bytes:
/// magic, version, kind and key id. That is what makes the kind part of the ciphertext's identity
/// rather than a label beside it: a blob wrapped as one kind does not authenticate as another,
/// whatever a caller claims and whatever the policy would have allowed.
/// </para>
/// <para>
/// The <b>key id</b> is SHA-256 over the DER-encoded <c>SubjectPublicKeyInfo</c> of the key the
/// wrapping key was derived from — the same SPKI digest the keystore pins and the registry
/// matches on. It is what makes rotation possible: a blob is unwrapped by the key it names, not
/// by whichever key is current, so a new key can be designated without re-wrapping anything.
/// </para>
/// </remarks>
public static class WrappedSecretEnvelope
{
    /// <summary>The four bytes every wrapped secret starts with.</summary>
    public static readonly byte[] Magic = "MCAW"u8.ToArray();

    /// <summary>The only envelope version there is.</summary>
    public const byte Version1 = 1;

    /// <summary>The bytes an AEAD takes as associated data: magic, version, kind and key id.</summary>
    public const int HeaderLength = 4 + 1 + 1 + 32;

    /// <summary>The length of the key id, a SHA-256 digest.</summary>
    public const int KeyIdLength = 32;

    /// <summary>The length of the per-blob HKDF salt.</summary>
    public const int SaltLength = 32;

    /// <summary>The length of the AES-GCM nonce.</summary>
    public const int NonceLength = 12;

    /// <summary>The length of the AES-GCM authentication tag.</summary>
    public const int TagLength = 16;

    /// <summary>Everything before the ciphertext: the associated data, the salt and the nonce.</summary>
    public const int PrefixLength = HeaderLength + SaltLength + NonceLength;

    /// <summary>
    /// Lays out a blob from its parts. The caller has already derived the key from
    /// <paramref name="salt"/> and encrypted under <paramref name="nonce"/> with
    /// <see cref="AssociatedData(SecretKind, ReadOnlySpan{byte})"/> as the associated data.
    /// </summary>
    public static byte[] Build(SecretKind kind, ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        if (keyId.Length != KeyIdLength) throw new ArgumentException($"A key id is {KeyIdLength} bytes.", nameof(keyId));
        if (salt.Length != SaltLength) throw new ArgumentException($"A salt is {SaltLength} bytes.", nameof(salt));
        if (nonce.Length != NonceLength) throw new ArgumentException($"A nonce is {NonceLength} bytes.", nameof(nonce));
        if (tag.Length != TagLength) throw new ArgumentException($"A tag is {TagLength} bytes.", nameof(tag));

        var blob = new byte[PrefixLength + ciphertext.Length + TagLength];
        var span = blob.AsSpan();
        Magic.CopyTo(span);
        span[4] = Version1;
        span[5] = checked((byte)kind);
        keyId.CopyTo(span[6..]);
        salt.CopyTo(span[HeaderLength..]);
        nonce.CopyTo(span[(HeaderLength + SaltLength)..]);
        ciphertext.CopyTo(span[PrefixLength..]);
        tag.CopyTo(span[(PrefixLength + ciphertext.Length)..]);
        return blob;
    }

    /// <summary>
    /// Reads the header of a blob without decrypting it: what kind of secret it holds, which key
    /// wrapped it, and where the salt, nonce, ciphertext and tag are. False for anything that is
    /// not a well-formed envelope of a version and kind this build knows, in which case nothing
    /// is set and the caller refuses rather than guessing.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> blob, out WrappedSecretHeader header)
    {
        header = default;
        if (blob.Length < PrefixLength + TagLength) return false;
        if (!blob[..4].SequenceEqual(Magic)) return false;
        if (blob[4] != Version1) return false;
        if (!Enum.IsDefined(typeof(SecretKind), (int)blob[5])) return false;

        var ciphertextLength = blob.Length - PrefixLength - TagLength;
        header = new WrappedSecretHeader(
            (SecretKind)blob[5],
            blob[6..HeaderLength].ToArray(),
            blob[HeaderLength..(HeaderLength + SaltLength)].ToArray(),
            blob[(HeaderLength + SaltLength)..PrefixLength].ToArray(),
            blob.Slice(PrefixLength, ciphertextLength).ToArray(),
            blob[(PrefixLength + ciphertextLength)..].ToArray(),
            blob[..HeaderLength].ToArray());
        return true;
    }

    /// <summary>
    /// The associated data for a blob that has not been laid out yet: what
    /// <see cref="TryRead"/> would return as <see cref="WrappedSecretHeader.AssociatedData"/>.
    /// </summary>
    public static byte[] AssociatedData(SecretKind kind, ReadOnlySpan<byte> keyId)
    {
        if (keyId.Length != KeyIdLength) throw new ArgumentException($"A key id is {KeyIdLength} bytes.", nameof(keyId));
        var aad = new byte[HeaderLength];
        Magic.CopyTo(aad.AsSpan());
        aad[4] = Version1;
        aad[5] = checked((byte)kind);
        keyId.CopyTo(aad.AsSpan(6));
        return aad;
    }

    /// <summary>
    /// The HKDF <c>info</c> a wrapping key is derived under: the label, the kind and the key id,
    /// so two kinds wrapped under the same keystore key never share a derived key.
    /// </summary>
    public static byte[] DerivationInfo(SecretKind kind, ReadOnlySpan<byte> keyId)
    {
        var label = "ModularCA.SecretWrap.v1"u8;
        var info = new byte[label.Length + 1 + keyId.Length];
        label.CopyTo(info);
        info[label.Length] = checked((byte)kind);
        keyId.CopyTo(info.AsSpan(label.Length + 1));
        return info;
    }

    /// <summary>Renders a key id for an audit row or a log line: lower-case hex.</summary>
    public static string KeyIdText(ReadOnlySpan<byte> keyId) => Convert.ToHexStringLower(keyId);
}

/// <summary>
/// What a wrapped blob says about itself before anything is decrypted.
/// </summary>
/// <param name="Kind">What kind of secret the blob holds.</param>
/// <param name="KeyId">SHA-256 of the SPKI of the key the wrapping key was derived from.</param>
/// <param name="Salt">The per-blob HKDF salt.</param>
/// <param name="Nonce">The AES-GCM nonce.</param>
/// <param name="Ciphertext">The encrypted secret, without its tag.</param>
/// <param name="Tag">The AES-GCM authentication tag.</param>
/// <param name="AssociatedData">The header bytes the AEAD authenticates but does not encrypt.</param>
public readonly record struct WrappedSecretHeader(
    SecretKind Kind,
    byte[] KeyId,
    byte[] Salt,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    byte[] AssociatedData);
