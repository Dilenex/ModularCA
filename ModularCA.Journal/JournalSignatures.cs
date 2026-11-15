using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace ModularCA.Journal;

/// <summary>
/// A key the journal signs with: the checkpoint key, or the system key when a checkpoint key is
/// made or changed. The journal library never sees a private key; the signer supplies this.
/// </summary>
public interface IJournalSigningKey
{
    /// <summary>The public key, as a DER SubjectPublicKeyInfo.</summary>
    byte[] PublicKey { get; }

    /// <summary>The signature algorithm's name, as <see cref="JournalSignatures.IsKnownAlgorithm"/> accepts it.</summary>
    string Algorithm { get; }

    /// <summary>Signs <paramref name="message"/> and returns the signature as the algorithm encodes it.</summary>
    byte[] Sign(byte[] message);
}

/// <summary>
/// The messages the journal's signatures cover, and their verification. Each message begins
/// with a domain prefix that ends in a zero byte, so a signature made for one purpose is never
/// a signature for another, nor for a keystore file, which the system key also signs. After the
/// prefix every message carries the instance identifier as a big-endian u16 length and its
/// UTF-8 bytes.
/// </summary>
public static class JournalSignatures
{
    /// <summary>The prefix of a checkpoint's message.</summary>
    public const string CheckpointDomain = "ModularCA.Journal.Checkpoint.v1\0";

    /// <summary>The prefix of the message a system key signs over a checkpoint key.</summary>
    public const string CheckpointKeyDomain = "ModularCA.Journal.CheckpointKey.v1\0";

    /// <summary>The prefix of the message an old checkpoint key signs over the key that replaces it.</summary>
    public const string CheckpointKeyChangedDomain = "ModularCA.Journal.CheckpointKeyChanged.v1\0";

    /// <summary>The prefix of the message an old system key signs over the system key that replaces it.</summary>
    public const string SystemKeyChangedDomain = "ModularCA.Journal.SystemKeyChanged.v1\0";

    /// <summary>
    /// A checkpoint's message: the prefix, the instance identifier, the checkpoint record's own
    /// <c>seq</c> (u64, big-endian) and its <c>prev</c> (32 bytes), which is the hash of the
    /// record before it and so covers the whole chain to that point.
    /// </summary>
    public static byte[] CheckpointMessage(string instanceId, ulong seq, ReadOnlySpan<byte> prev)
    {
        var head = Head(CheckpointDomain, instanceId);
        var message = new byte[head.Length + 8 + prev.Length];
        head.CopyTo(message, 0);
        BinaryPrimitives.WriteUInt64BigEndian(message.AsSpan(head.Length), seq);
        prev.CopyTo(message.AsSpan(head.Length + 8));
        return message;
    }

    /// <summary>The message a system key signs over a checkpoint key: the prefix, the instance identifier and the key (SubjectPublicKeyInfo).</summary>
    public static byte[] CheckpointKeyMessage(string instanceId, ReadOnlySpan<byte> checkpointPublicKey)
        => Concat(Head(CheckpointKeyDomain, instanceId), checkpointPublicKey);

    /// <summary>The message an old checkpoint key signs over the new one: the prefix, the instance identifier and the new key (SubjectPublicKeyInfo).</summary>
    public static byte[] CheckpointKeyChangedMessage(string instanceId, ReadOnlySpan<byte> newCheckpointPublicKey)
        => Concat(Head(CheckpointKeyChangedDomain, instanceId), newCheckpointPublicKey);

    /// <summary>The message an old system key signs over the new one: the prefix, the instance identifier and SHA-256 of the new system key's SubjectPublicKeyInfo.</summary>
    public static byte[] SystemKeyChangedMessage(string instanceId, ReadOnlySpan<byte> newSystemKeyHash)
        => Concat(Head(SystemKeyChangedDomain, instanceId), newSystemKeyHash);

    private static byte[] Head(string domain, string instanceId)
    {
        var id = Encoding.UTF8.GetBytes(instanceId ?? string.Empty);
        if (id.Length > ushort.MaxValue)
            throw new ArgumentException("The instance identifier is too long.", nameof(instanceId));
        var prefix = Encoding.ASCII.GetBytes(domain);
        var head = new byte[prefix.Length + 2 + id.Length];
        prefix.CopyTo(head, 0);
        BinaryPrimitives.WriteUInt16BigEndian(head.AsSpan(prefix.Length), (ushort)id.Length);
        id.CopyTo(head, prefix.Length + 2);
        return head;
    }

    private static byte[] Concat(byte[] head, ReadOnlySpan<byte> tail)
    {
        var message = new byte[head.Length + tail.Length];
        head.CopyTo(message, 0);
        tail.CopyTo(message.AsSpan(head.Length));
        return message;
    }

    /// <summary>SHA-256 of a public key's DER SubjectPublicKeyInfo, which is how the journal names a key.</summary>
    public static byte[] KeyHash(ReadOnlySpan<byte> subjectPublicKeyInfo) => SHA256.HashData(subjectPublicKeyInfo);

    /// <summary>
    /// Whether <paramref name="algorithm"/> is a signature algorithm the journal names: a
    /// SHA-2 digest with RSA (PKCS #1 v1.5 or PSS with MGF1) or ECDSA, Ed25519, Ed448, an ML-DSA
    /// parameter set or an SLH-DSA parameter set. Names are compared without case.
    /// </summary>
    public static bool IsKnownAlgorithm(string? algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
            return false;
        var name = algorithm.ToUpperInvariant();
        return name is "SHA256WITHRSA" or "SHA384WITHRSA" or "SHA512WITHRSA"
                   or "SHA256WITHRSAANDMGF1" or "SHA384WITHRSAANDMGF1" or "SHA512WITHRSAANDMGF1"
                   or "SHA256WITHECDSA" or "SHA384WITHECDSA" or "SHA512WITHECDSA"
                   or "ED25519" or "ED448"
                   or "ML-DSA-44" or "ML-DSA-65" or "ML-DSA-87"
               || name.StartsWith("SLH-DSA-", StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="message"/> under the public
    /// key <paramref name="subjectPublicKeyInfo"/> with <paramref name="algorithm"/>. False for
    /// a signature that does not verify, an algorithm the journal does not name, a key that
    /// does not parse, or an algorithm that is not the key's.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> subjectPublicKeyInfo, string? algorithm, byte[] message, byte[] signature)
    {
        if (!IsKnownAlgorithm(algorithm))
            return false;
        try
        {
            var key = PublicKeyFactory.CreateKey(subjectPublicKeyInfo.ToArray());
            ISigner verifier = SignerUtilities.GetSigner(algorithm);
            verifier.Init(false, key);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A key or signature that does not parse, or an algorithm that is not the key's.
            return false;
        }
    }

    /// <summary>
    /// Verifies a key block's system signature under <paramref name="systemPublicKey"/>, which
    /// must be the key the block names by hash.
    /// </summary>
    public static bool VerifyKeyBlock(KeyBlock block, string instanceId, ReadOnlySpan<byte> systemPublicKey)
        => KeyHash(systemPublicKey).AsSpan().SequenceEqual(block.SystemKey)
           && Verify(systemPublicKey, block.Algorithm, CheckpointKeyMessage(instanceId, block.Key), block.SystemSignature);

    /// <summary>Makes a key block: the system key signs the checkpoint public key for this instance.</summary>
    public static KeyBlock MakeKeyBlock(string instanceId, byte[] checkpointPublicKey, IJournalSigningKey systemKey)
    {
        ArgumentNullException.ThrowIfNull(checkpointPublicKey);
        ArgumentNullException.ThrowIfNull(systemKey);
        return new KeyBlock(checkpointPublicKey, KeyHash(systemKey.PublicKey),
            systemKey.Sign(CheckpointKeyMessage(instanceId, checkpointPublicKey)), systemKey.Algorithm);
    }
}
