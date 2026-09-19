using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;

namespace ModularCA.Shared.Signing;

/// <summary>
/// The signature algorithm a signing request names, as the algorithm string the key handles and
/// BouncyCastle already accept: <c>SHA256withRSA</c>, <c>SHA384withECDSA</c>, <c>Ed25519</c>,
/// <c>ML-DSA-65</c> and so on. Wrapping the string keeps the contract typed without inventing a
/// second vocabulary for something every layer below already agrees on.
/// </summary>
/// <param name="Name">The normalized algorithm name, hyphen-free for the classical hash prefixes.</param>
public readonly record struct SignatureAlgorithm(string Name)
{
    /// <summary>
    /// Wraps an algorithm name, normalizing the classical hash prefix so <c>SHA-256withRSA</c>
    /// and <c>SHA256withRSA</c> name the same algorithm.
    /// </summary>
    public static SignatureAlgorithm FromName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A signature algorithm name is required.", nameof(name));
        return new SignatureAlgorithm(CertificateUtil.NormalizeSigAlgName(name));
    }

    /// <summary>
    /// The algorithm a key of this type signs with, by the same curve-to-hash pairing every
    /// signing path in the node already uses. The public key is the signer's own, not its
    /// issuer's: how a CA was signed says nothing about how it signs.
    /// </summary>
    public static SignatureAlgorithm ForPublicKey(AsymmetricKeyParameter publicKey)
        => FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(publicKey));

    /// <inheritdoc />
    public override string ToString() => Name;
}
