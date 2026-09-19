using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The registry the signer resolves keys from: <see cref="IKeystoreCertificates"/> plus the
/// private key handles the node unlocked or the signer committed since. This is the only
/// interface through which a handle is reached, and it is internal to the keystore project's
/// consumers: the signer, its persistence and the startup unlock.
/// </summary>
public interface ISignerKeyRegistry : ModularCA.Shared.Interfaces.IKeystoreCertificates
{
    /// <summary>
    /// The private key handle for <paramref name="cert"/>, matched by public key, or null when
    /// the registry holds no key for it.
    /// </summary>
    IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert);

    /// <summary>
    /// Registers a certificate with its private key handle at runtime, so a key the signer has
    /// just committed resolves without a restart. A certificate already held (same public key,
    /// or same serial and subject) is not added twice; it joins the trusted authorities either way.
    /// </summary>
    void RegisterSigner(X509Certificate certificate, IPrivateKeyHandle handle);
}
