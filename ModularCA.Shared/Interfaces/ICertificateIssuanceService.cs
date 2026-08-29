using ModularCA.Shared.Models;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace ModularCA.Shared.Interfaces
{
    /// <summary>
    /// High-level service for issuing and reissuing certificates from approved CSRs.
    /// </summary>
    public interface ICertificateIssuanceService
    {
        /// <summary>
        /// Issues a certificate from an approved CSR and returns the PEM-encoded certificate
        /// along with any warnings (e.g. validity clamped to issuing CA expiry).
        /// The stored PEM includes the leaf certificate and all intermediate CA certificates (excludes root).
        /// </summary>
        Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter, CancellationToken cancellationToken = default);

        /// <summary>
        /// Issues a certificate using a pre-resolved CA cert and key handle. Used for infrastructure
        /// certs (TSA, OCSP) where the CA is not yet registered in the keystore registry.
        /// </summary>
        Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCert, IPrivateKeyHandle caKeyHandle, CancellationToken cancellationToken = default);

        /// <summary>
        /// Issues a CA certificate — one whose profile carries <c>IsCaProfile</c>, producing
        /// <c>cA=TRUE</c> basic constraints and a key that can sign further certificates.
        /// </summary>
        /// <remarks>
        /// This is the only entry point that permits a CA-flagged profile. Every other issuance
        /// method rejects one, because the cert profile id is caller-supplied on the public
        /// enrollment, integration, and protocol paths and was validated only for existence: a
        /// holder of an integration API key could name a CA profile's GUID and receive a
        /// <c>cA=TRUE</c> certificate signed by the production CA, auto-approved. The profile GUID
        /// is not a secret — the profile list endpoint returns every profile unfiltered.
        ///
        /// Intended for <c>CaCreationService</c>, which is the legitimate CA-creation path and
        /// applies its own authorization and ceremony controls before calling this.
        /// </remarks>
        Task<IssuanceResult> IssueCaCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCert, IPrivateKeyHandle caKeyHandle, CancellationToken cancellationToken = default);

        /// <summary>
        /// Reissues a certificate by certificate ID, serial number, or CSR ID. Optional
        /// <paramref name="newSubjectDn"/> and <paramref name="newSans"/> override the original CSR's
        /// subject and SANs respectively; both still flow through profile validation before signing.
        /// </summary>
        Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId, DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null);
    }
}
