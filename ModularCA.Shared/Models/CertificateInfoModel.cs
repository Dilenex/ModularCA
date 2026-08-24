using System.Text.Json.Serialization;

namespace ModularCA.Shared.Models
{
    public class CertificateInfoModel
    {
        public Guid CertificateId { get; set; } // <- Required for GET /cert/{id}
        public string Pem { get; set; } = string.Empty; // <- Required to return the PEM

        public string SubjectDN { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string? Thumbprints { get; set; } = string.Empty;

        public List<string> SubjectAlternativeNames { get; set; } = new();
        public List<string> KeyUsages { get; set; } = new();
        public List<string> ExtendedKeyUsages { get; set; } = new();

        public bool IsCA { get; set; }

        public string KeyAlgorithm { get; set; } = string.Empty;
        public string KeySize { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;

        // Wrapped key material. Carried on this model only so the store can persist it on the
        // way IN; the read paths never populate it. JsonIgnore makes that structural rather than
        // incidental — this model is returned directly by API endpoints, and a future mapper
        // that filled these in would otherwise ship wrapped private keys to every browser that
        // lists certificates.
        [JsonIgnore]
        public byte[]? Iv { get; set; }
        [JsonIgnore]
        public byte[]? EncryptedAesKey { get; set; }
        [JsonIgnore]
        public byte[]? EncryptedPrivateKey { get; set; }

        /// <summary>
        /// Whether an exportable private key is stored for this certificate.
        /// </summary>
        /// <remarks>
        /// The user portal gated its "Export PFX" button on <c>encryptedPrivateKey</c> being
        /// present in the response — but the read mappings never populate that field (correctly:
        /// key material must not be sent to a browser), so the button rendered for nobody and
        /// PFX export was unreachable through the UI. This boolean is the safe answer to the
        /// question the UI was actually asking.
        /// </remarks>
        public bool HasPrivateKey { get; set; }

        /// <summary>Serial number of the certificate whose public key was used to encrypt EncryptedPrivateKey.</summary>
        public string? EncryptionCertSerialNumber { get; set; }

        public bool Revoked { get; set; }
        public string RevocationReason { get; set; } = string.Empty;

        public DateTime? RevocationDate { get; set; }
        public Guid SigningProfileId { get; set; }
        public Guid CertProfileId { get; set; }

        /// <summary>
        /// FK to the issuing CA's <see cref="CertificateId"/>.
        /// Populated by the issuance path so <c>CertificateStore.SaveCertificateAsync</c>
        /// can persist it directly instead of relying on the CRL service's
        /// DN-based fallback resolution.
        /// </summary>
        public Guid? IssuerCertificateId { get; set; }

    }
}