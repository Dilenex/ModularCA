using ModularCA.Shared.Enums;
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
        /// <param name="csrId">The approved CSR to issue against.</param>
        /// <param name="notBefore">Optional explicit start; defaults to now, backdated for clock skew.</param>
        /// <param name="notAfter">Optional explicit expiry; defaults to the cert profile's maximum.</param>
        /// <param name="ceilingEnforcement">
        /// Whether this call site lets the tenant's <c>ValidityCeilingBehavior</c> refuse an
        /// over-reaching request. Leave at the default on any path whose caller cannot see or
        /// change the tenant ceiling — which is every enrollment protocol and every scheduled
        /// renewal. See <see cref="ValidityCeilingEnforcement"/>.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default);

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
        /// <param name="certId">Reissue by certificate id.</param>
        /// <param name="certSN">Reissue by serial number.</param>
        /// <param name="csrId">Reissue by CSR id.</param>
        /// <param name="notBefore">Optional explicit start.</param>
        /// <param name="notAfter">Optional explicit expiry.</param>
        /// <param name="newSubjectDn">Optional replacement subject DN.</param>
        /// <param name="newSans">Optional replacement SAN list.</param>
        /// <param name="ceilingEnforcement">
        /// Whether this call site lets the tenant's <c>ValidityCeilingBehavior</c> refuse an
        /// over-reaching request; see <see cref="ValidityCeilingEnforcement"/>. The default never
        /// refuses.
        /// </param>
        Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId, DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten);
    }
}
