namespace ModularCA.Core.Services
{
    /// <summary>
    /// Evaluates system-wide certificate policy rules at issuance time.
    /// Unlike per-request profile validation, these policies apply globally
    /// to all certificate issuance regardless of the profile used.
    /// </summary>
    public interface ICertPolicyService
    {
        /// <summary>
        /// Evaluates all configured certificate policy rules against the given issuance context.
        /// Returns a list of violations. Error-level violations block issuance; Warning-level
        /// violations are logged but allowed.
        /// </summary>
        /// <param name="context">The certificate issuance context containing key, algorithm, validity, and SAN information.</param>
        /// <returns>A list of policy violations, possibly empty if all rules pass.</returns>
        List<PolicyViolation> Evaluate(CertificateIssuanceContext context);
    }

    /// <summary>
    /// Represents a single policy rule violation detected during certificate issuance evaluation.
    /// </summary>
    public class PolicyViolation
    {
        /// <summary>The name of the policy rule that was violated (e.g., "MinRsaKeySize", "ForbiddenAlgorithm").</summary>
        public string Rule { get; set; } = string.Empty;

        /// <summary>
        /// The severity of the violation. "Error" blocks issuance; "Warning" allows issuance but logs the violation.
        /// </summary>
        public string Severity { get; set; } = "Error";

        /// <summary>A human-readable description of the violation.</summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Contains the certificate parameters to be evaluated against system-wide policy rules.
    /// Populated from the CSR and issuance request before the certificate is built.
    /// </summary>
    public class CertificateIssuanceContext
    {
        /// <summary>The key algorithm (e.g., "RSA", "ECDSA", "Ed25519").</summary>
        public string KeyAlgorithm { get; set; } = string.Empty;

        /// <summary>The key size in bits (for RSA) or curve name (for ECDSA).</summary>
        public string KeySize { get; set; } = string.Empty;

        /// <summary>The signature algorithm (e.g., "SHA256WithRSA", "SHA384WithECDSA").</summary>
        public string SignatureAlgorithm { get; set; } = string.Empty;

        /// <summary>The certificate validity start date.</summary>
        public DateTime NotBefore { get; set; }

        /// <summary>The certificate validity end date.</summary>
        public DateTime NotAfter { get; set; }

        /// <summary>The Subject Distinguished Name of the certificate.</summary>
        public string SubjectDn { get; set; } = string.Empty;

        /// <summary>The list of Subject Alternative Names (e.g., "DNS:example.com", "IP:10.0.0.1").</summary>
        public List<string> SubjectAlternativeNames { get; set; } = new();

        /// <summary>The certificate profile name or ID, if available.</summary>
        public string CertProfileName { get; set; } = string.Empty;

        /// <summary>
        /// When true, this is an infrastructure certificate (TSA, OCSP, Web TLS). These are
        /// exempt from several issuance-time limits, including the tenant validity ceiling —
        /// their validity is governed by their cert profile and clamped to the issuing CA.
        /// </summary>
        public bool IsInfrastructureCert { get; set; } = false;
    }
}
