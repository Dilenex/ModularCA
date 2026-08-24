using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models.Csr
{
    /// <summary>
    /// Request body for uploading an externally-generated PEM-encoded CSR with optional
    /// subject and SAN overrides that replace the CSR's original values during issuance.
    /// </summary>
    public class UploadCsrRequest
    {
        [Required, MaxLength(65536)]
        public string Pem { get; set; } = string.Empty;

        public Guid CertificateProfileId { get; set; }
        public Guid SigningProfileId { get; set; }

        public Guid RequestorUserId { get; set; }

        /// <summary>
        /// Optional subject DN field overrides (keyed by field name: CN, O, OU, etc.).
        /// When provided, these values replace the CSR's original subject fields at issuance time.
        /// </summary>
        public Dictionary<string, string>? SubjectOverrides { get; set; }

        /// <summary>
        /// Optional SAN overrides. When provided, these replace the CSR's original SANs at issuance time.
        /// </summary>
        public List<SanOverride>? SanOverrides { get; set; }

        /// <summary>
        /// Optional requested validity window, stored on the request and used at issuance
        /// unless the issuer overrides it. Null leaves the choice to the certificate profile.
        /// </summary>
        public DateTime? NotBefore { get; set; }

        /// <inheritdoc cref="NotBefore"/>
        public DateTime? NotAfter { get; set; }
    }

    /// <summary>
    /// A single SAN override entry specifying the type and value.
    /// </summary>
    public class SanOverride
    {
        /// <summary>SAN type: DNS, IP, Email, URI.</summary>
        [Required, MaxLength(50)]
        public string Type { get; set; } = string.Empty;

        /// <summary>SAN value.</summary>
        [Required, MaxLength(500)]
        public string Value { get; set; } = string.Empty;
    }
}
