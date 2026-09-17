using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin
{
    /// <summary>
    /// Admin endpoints for evaluating system-wide certificate policy rules
    /// without performing actual certificate issuance.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/policy")]
    [Authorize]
    [NodeRole(ProcessRole.Control)]
    public class AdminPolicyController : ControllerBase
    {
        private readonly ICertPolicyService _certPolicy;

        /// <summary>
        /// Initializes a new instance of <see cref="AdminPolicyController"/>.
        /// </summary>
        /// <param name="certPolicy">The certificate policy evaluation service.</param>
        public AdminPolicyController(ICertPolicyService certPolicy)
        {
            _certPolicy = certPolicy;
        }

        /// <summary>
        /// Evaluates certificate parameters against all configured system-wide policy rules
        /// and returns the list of violations without issuing a certificate. Useful for
        /// pre-flight validation before submitting an issuance request.
        /// </summary>
        /// <param name="request">The certificate parameters to evaluate.</param>
        /// <returns>A response containing any policy violations found.</returns>
        [HttpPost("check")]
        [Authorize]
        [RequireCaCapability(Capabilities.CertRevoke, CaTarget.AnyCa)]
        public IActionResult CheckPolicy([FromBody] PolicyCheckRequest request)
        {
            var context = new CertificateIssuanceContext
            {
                KeyAlgorithm = request.KeyAlgorithm ?? string.Empty,
                KeySize = request.KeySize ?? string.Empty,
                SignatureAlgorithm = request.SignatureAlgorithm ?? string.Empty,
                NotBefore = request.NotBefore ?? DateTime.UtcNow,
                NotAfter = request.NotAfter ?? DateTime.UtcNow.AddDays(365),
                SubjectDn = request.SubjectDn ?? string.Empty,
                SubjectAlternativeNames = request.SubjectAlternativeNames ?? new List<string>(),
                CertProfileName = request.CertProfileName ?? string.Empty
            };

            var violations = _certPolicy.Evaluate(context);

            var response = new PolicyCheckResponse
            {
                Passed = !violations.Any(v => string.Equals(v.Severity, "Error", StringComparison.OrdinalIgnoreCase)),
                Violations = violations
            };

            return Ok(response);
        }
    }

    /// <summary>
    /// Request model for the policy check endpoint. Contains the certificate parameters
    /// to evaluate against system-wide policy rules.
    /// </summary>
    public class PolicyCheckRequest
    {
        /// <summary>The key algorithm (e.g., "RSA", "ECDSA", "Ed25519").</summary>
        public string? KeyAlgorithm { get; set; }

        /// <summary>The key size in bits (for RSA) or curve name (for ECDSA).</summary>
        public string? KeySize { get; set; }

        /// <summary>The signature algorithm (e.g., "SHA256WithRSA", "SHA384WithECDSA").</summary>
        public string? SignatureAlgorithm { get; set; }

        /// <summary>The certificate validity start date. Defaults to now if not provided.</summary>
        public DateTime? NotBefore { get; set; }

        /// <summary>The certificate validity end date. Defaults to one year from now if not provided.</summary>
        public DateTime? NotAfter { get; set; }

        /// <summary>The Subject Distinguished Name of the certificate.</summary>
        public string? SubjectDn { get; set; }

        /// <summary>The list of Subject Alternative Names (e.g., "DNS:example.com", "IP:10.0.0.1").</summary>
        public List<string>? SubjectAlternativeNames { get; set; }

        /// <summary>The certificate profile name or ID, if applicable.</summary>
        public string? CertProfileName { get; set; }
    }

    /// <summary>
    /// Response model for the policy check endpoint. Indicates whether all policy rules
    /// passed and provides details of any violations.
    /// </summary>
    public class PolicyCheckResponse
    {
        /// <summary>True if no Error-level violations were found; false if issuance would be blocked.</summary>
        public bool Passed { get; set; }

        /// <summary>The list of policy violations (both errors and warnings).</summary>
        public List<PolicyViolation> Violations { get; set; } = new();
    }
}
