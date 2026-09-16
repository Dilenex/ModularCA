using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// What a Windows renewal request proves about the certificate it renews.
/// </summary>
/// <remarks>
/// The enrollment engine renews with a CMC request whose PKCS#10 has an empty subject and carries
/// the existing certificate in attribute <see cref="CmcRequests.RenewalCertificateOid"/>, and whose
/// wrapper is signed twice: by the new key (proof of possession, checked as for any request) and
/// by the existing certificate's key, identified by issuer and serial. The second signature is
/// what makes it a renewal rather than a stranger asking for someone else's subject.
/// </remarks>
/// <param name="OldCertificateDer">The certificate named in the renewal attribute.</param>
/// <param name="SignedByOldCertificate">Whether a wrapper signature verified with that certificate's key.</param>
public sealed record MsaeRenewal(byte[] OldCertificateDer, bool SignedByOldCertificate)
{
    private X509Certificate? _certificate;

    /// <summary>The certificate being renewed, parsed.</summary>
    public X509Certificate Certificate => _certificate ??= new X509CertificateParser().ReadCertificate(OldCertificateDer);
}
