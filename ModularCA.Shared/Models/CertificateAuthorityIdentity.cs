using Org.BouncyCastle.X509;

namespace ModularCA.Shared.Models
{
    /// <summary>
    /// A certificate authority the node can sign for: its public certificate. The private key
    /// is the signer's and is never part of the identity; a caller that needs a signature holds
    /// a <see cref="ModularCA.Shared.Signing.KeyRef"/> and asks the signer.
    /// </summary>
    /// <param name="PublicCertificate">The CA certificate.</param>
    public record CertificateAuthorityIdentity(X509Certificate PublicCertificate);
}
