using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Models.Csr;

namespace ModularCA.Shared.Models.Issuance
{
    /// <summary>
    /// Request body for requesting a certificate with a server-generated key pair. The server
    /// generates the key pair, builds a PKCS#10 CSR and submits it as a pending request; the
    /// private key is returned in the response, once, and is not stored by the CA.
    /// </summary>
    public class IssueWithKeyRequest
    {
        /// <summary>
        /// Subject DN fields keyed by field name (e.g., CN, O, OU, L, ST, C).
        /// </summary>
        [Required]
        public Dictionary<string, string> Subject { get; set; } = new();

        /// <summary>
        /// Subject Alternative Names to include in the certificate.
        /// </summary>
        public List<SanOverride> Sans { get; set; } = new();

        /// <summary>
        /// Key algorithm: RSA, ECDSA, or Ed25519.
        /// </summary>
        [Required, MaxLength(50)]
        public string KeyAlgorithm { get; set; } = "RSA";

        /// <summary>
        /// Key size or curve name. RSA: "2048"/"3072"/"4096"/"7680"/"8192". ECDSA: "P-256"/"P-384"/"P-521". Ignored for Ed25519.
        /// </summary>
        [Required, MaxLength(50)]
        public string KeySize { get; set; } = "2048";

        /// <summary>
        /// Certificate profile ID that defines constraints for the issued certificate.
        /// </summary>
        public Guid CertProfileId { get; set; }

        /// <summary>
        /// Signing profile ID that identifies the CA and signing parameters.
        /// </summary>
        public Guid SigningProfileId { get; set; }

        /// <summary>
        /// Optional certificate validity start date. Defaults to now if not specified.
        /// </summary>
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Optional certificate validity end date. Defaults to the profile maximum if not specified.
        /// </summary>
        public DateTime? NotAfter { get; set; }
    }
}
