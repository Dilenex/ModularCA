using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models.Csr
{
    /// <summary>
    /// Request body for generating a new CSR with server-side key generation.
    /// </summary>
    public class CreateCsrRequest
    {
        [Required, MaxLength(500)]
        public string SubjectName { get; set; } = default!;  // e.g., "CN=example.com,O=ModularCA"

        public List<String>? SubjectAlternativeNames { get; set; } // optional SANs

        [Required, MaxLength(50)]
        public string KeyAlgorithm { get; set; } = "RSA"; // RSA, ECDSA, Ed25519, Ed448, ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-*

        [Required, MaxLength(50)]
        public string SignatureAlgorithm { get; set; } = "SHA256withRSA"; // For EdDSA/PQC, use the algorithm name directly (e.g., "ML-DSA-87")

        [Required, MaxLength(50)]
        public string KeySize { get; set; } = "2048"; // RSA: 2048/3072/4096/7680/8192, ECDSA: P-256/P-384/P-521, EdDSA/PQC: ignored

        public Guid SigningProfileId { get; set; }

        public Guid CertificateProfileId { get; set; }

        /// <summary>The request profile the request is made under. The console routes require it.</summary>
        public Guid? RequestProfileId { get; set; }

        public Guid RequestorUserId { get; set; }
    }
}
