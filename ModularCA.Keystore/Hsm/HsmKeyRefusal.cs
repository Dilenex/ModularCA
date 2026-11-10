using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// A CA whose PKCS#11 key the signer refused when it loaded its HSM signers: the key under the
/// CA's label was ambiguous, not held the way an HSM key must be, or not the certificate's key
/// (<see cref="Pkcs11KeyBinder"/>). The signer holds no key for the certificate, and a request
/// to sign with it is refused with <see cref="Reason"/> and audited.
/// </summary>
/// <param name="Certificate">The CA certificate the key was to be bound to.</param>
/// <param name="Label">The CA's key label (<c>HsmKeyLabel</c>).</param>
/// <param name="CaName">The CA's name, for the startup log.</param>
/// <param name="Reason">Why the key was refused.</param>
public sealed record HsmKeyRefusal(X509Certificate Certificate, string Label, string CaName, string Reason);
