using Net.Pkcs11Interop.HighLevelAPI;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// What the signer asks of a PKCS#11 token to bind a CA's key to its certificate and sign with
/// it: the private key objects under a label, whether one is held the way an HSM key must be,
/// the public key that goes with it, and a signature. <see cref="Pkcs11SessionManager"/> is the
/// implementation; the interface is the seam <see cref="Pkcs11KeyBinder"/> and
/// <see cref="Pkcs11PrivateKeyHandle"/> are tested through without a token.
/// </summary>
public interface IPkcs11Token
{
    /// <summary>
    /// Every private key object whose <c>CKA_LABEL</c> is <paramref name="label"/>, whatever its
    /// other attributes, so the caller can tell a missing key from an ambiguous one.
    /// </summary>
    /// <param name="label">The label to match.</param>
    IReadOnlyList<IObjectHandle> FindPrivateKeysByLabel(string label);

    /// <summary>
    /// Whether <paramref name="privateKey"/> is a token-resident, private, sensitive and
    /// non-extractable key, as a key the signer adopts must be.
    /// </summary>
    /// <param name="privateKey">The private key object.</param>
    /// <param name="lookupDescription">How the key was found, for the warning a refusal logs.</param>
    bool IsHsmContained(IObjectHandle privateKey, string lookupDescription);

    /// <summary>
    /// The public key that goes with <paramref name="privateKey"/>, as the token reports it.
    /// Throws <see cref="InvalidOperationException"/> when it cannot be read or the public key
    /// object that pairs with the private key is missing or ambiguous.
    /// </summary>
    /// <param name="privateKey">The private key object.</param>
    /// <param name="label">The label the private key was found under, for pairing a public key object when the private key has no <c>CKA_ID</c>.</param>
    Pkcs11PublicKeyMaterial ReadPublicKey(IObjectHandle privateKey, string label);

    /// <summary>
    /// Signs <paramref name="data"/> on the token with <paramref name="key"/> and returns what
    /// <c>C_Sign</c> returns, in the mechanism's own shape (raw <c>r || s</c> for ECDSA).
    /// </summary>
    /// <param name="key">The private key object.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="mechanism">The signing mechanism, with the parameters it needs.</param>
    byte[] Sign(IObjectHandle key, byte[] data, Pkcs11SignMechanism mechanism);
}
