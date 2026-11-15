using ModularCA.Shared.Models;
using Org.BouncyCastle.X509;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// The certificates the node loaded from its keystores: the trusted CA certificates and the
/// CAs it can sign for. Private keys are not reachable through this interface; they are the
/// signer's, behind <see cref="ModularCA.Shared.Signing.ISigningService"/>.
/// </summary>
public interface IKeystoreCertificates
{
    /// <summary>
    /// Returns all trusted CA certificates (public certs, no private keys).
    /// </summary>
    List<X509Certificate> GetTrustedAuthorities();

    /// <summary>
    /// Returns the CAs the signer holds a private key for, as their public certificates.
    /// </summary>
    List<CertificateAuthorityIdentity> GetSigners();

    /// <summary>
    /// Registers an external CA certificate as a trusted authority at runtime, for
    /// cross-certification. The certificate joins the trusted list without a private key;
    /// one already present by serial is not added twice.
    /// </summary>
    void RegisterTrustedCert(X509Certificate cert);

    /// <summary>
    /// Makes a CA's renewed certificate, over a key the signer already holds, the certificate
    /// that CA is known by from now on: it joins the trusted list, and <see cref="GetSigners"/>
    /// names it before the certificate it renews, so a caller that takes the first signer that
    /// matches a key or a name gets the current one. The earlier certificate stays in both
    /// lists. No key is given or moved: the registry pairs certificates with keys by public
    /// key, and a certificate whose key it does not hold only joins the trusted list.
    /// </summary>
    void RegisterRenewedCaCertificate(X509Certificate cert) => RegisterTrustedCert(cert);
}
