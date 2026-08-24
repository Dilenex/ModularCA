using ModularCA.Shared.Models.Csr;
using Org.BouncyCastle.Crypto;

namespace ModularCA.Shared.Interfaces
{
    /// <summary>
    /// Manages certificate signing requests including generation, upload, and retrieval.
    /// </summary>
    public interface ICsrService
    {
        /// <summary>
        /// Generates a CSR for an infrastructure certificate (TSA signer, OCSP responder).
        /// Does not encrypt the private key onto the CSR entity — the caller writes it to the
        /// keystore. Sets Status="Approved" and IsInfrastructureCert=true.
        /// </summary>
        /// <returns>The CSR entity ID and the generated key pair (caller owns the private key).</returns>
        Task<(Guid csrId, AsymmetricCipherKeyPair keyPair)> GenerateInfrastructureCsrAsync(
            string subjectDn, string keyAlgorithm, int keySizeOrCurve,
            Guid certProfileId, Guid signingProfileId,
            List<string>? sans = null);

        /// <summary>
        /// Generates a new CSR with a fresh key pair and stores it, returning the PEM-encoded CSR.
        /// </summary>
        Task<List<string>> GenerateCsrAsync(CreateCsrRequest request, Guid userId);

        /// <summary>
        /// Returns all pending (unapproved) certificate signing requests.
        /// When <paramref name="accessibleCaIds"/> is provided, results are filtered to only
        /// include CSRs whose signing profile's issuer certificate belongs to one of the
        /// accessible CAs (CLM-022 tenant scoping fix).
        /// </summary>
        Task<List<CertRequestDto>> GetPendingRequests(List<Guid>? accessibleCaIds = null);

        /// <summary>
        /// Uploads an externally generated PEM-encoded CSR and associates it with profiles.
        /// </summary>
        Task<string> UploadCsrAsync(string pem, Guid certProfileId, Guid signingProfileId, Guid userId);

        /// <summary>
        /// Uploads an externally generated PEM-encoded CSR with optional subject and SAN
        /// overrides, and an optional requested validity window that issuance falls back to
        /// when the issuer does not specify one.
        /// </summary>
        Task<string> UploadCsrAsync(string pem, Guid certProfileId, Guid signingProfileId, Guid userId,
            Dictionary<string, string>? subjectOverrides, List<SanOverride>? sanOverrides,
            DateTime? requestedNotBefore = null, DateTime? requestedNotAfter = null);
    }

}
