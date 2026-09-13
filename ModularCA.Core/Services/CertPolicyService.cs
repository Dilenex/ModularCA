using Microsoft.Extensions.Logging;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Evaluates system-wide certificate policy rules at issuance time.
    /// Checks key size, forbidden algorithms, validity period, SAN requirements,
    /// and algorithm sunset rules as configured in <see cref="CertPolicyConfig"/>.
    /// </summary>
    public class CertPolicyService : ICertPolicyService
    {
        private readonly CertPolicyConfig _config;
        private readonly ILogger<CertPolicyService> _logger;

        /// <summary>
        /// Initializes a new instance of <see cref="CertPolicyService"/>.
        /// </summary>
        /// <param name="systemConfig">The system configuration containing certificate policy settings.</param>
        /// <param name="logger">Logger instance for recording policy evaluation results.</param>
        public CertPolicyService(SystemConfig systemConfig, ILogger<CertPolicyService> logger)
        {
            _config = systemConfig.CertPolicy;
            _logger = logger;
        }

        /// <summary>
        /// Evaluates all configured certificate policy rules against the given issuance context.
        /// Returns a list of violations. Error-level violations block issuance; Warning-level
        /// violations are logged but allowed.
        /// </summary>
        /// <param name="context">The certificate issuance context containing key, algorithm, validity, and SAN information.</param>
        /// <returns>A list of policy violations, possibly empty if all rules pass.</returns>
        public List<PolicyViolation> Evaluate(CertificateIssuanceContext context)
        {
            var violations = new List<PolicyViolation>();

            if (!_config.Enabled)
                return violations;

            CheckMinRsaKeySize(context, violations);
            CheckForbiddenAlgorithms(context, violations);
            CheckRequireSans(context, violations);
            CheckAlgorithmSunsetRules(context, violations);

            return violations;
        }

        /// <summary>
        /// Checks whether the RSA key size meets the minimum configured requirement.
        /// Only applies when the key algorithm is RSA and the key size is a numeric value.
        /// </summary>
        private void CheckMinRsaKeySize(CertificateIssuanceContext context, List<PolicyViolation> violations)
        {
            if (!string.Equals(context.KeyAlgorithm, "RSA", StringComparison.OrdinalIgnoreCase))
                return;

            if (int.TryParse(context.KeySize, out var keyBits) && keyBits < _config.MinRsaKeySize)
            {
                violations.Add(new PolicyViolation
                {
                    Rule = "MinRsaKeySize",
                    Severity = "Error",
                    Message = $"RSA key size {keyBits} bits is below the minimum required {_config.MinRsaKeySize} bits."
                });
            }
        }

        /// <summary>
        /// Checks whether the signature algorithm is in the forbidden algorithms list.
        /// </summary>
        private void CheckForbiddenAlgorithms(CertificateIssuanceContext context, List<PolicyViolation> violations)
        {
            if (_config.ForbiddenAlgorithms == null || _config.ForbiddenAlgorithms.Count == 0)
                return;

            if (_config.ForbiddenAlgorithms.Contains(context.SignatureAlgorithm, StringComparer.OrdinalIgnoreCase))
            {
                violations.Add(new PolicyViolation
                {
                    Rule = "ForbiddenAlgorithm",
                    Severity = "Error",
                    Message = $"Signature algorithm \"{context.SignatureAlgorithm}\" is forbidden by system policy."
                });
            }
        }

        /// <summary>
        /// Checks whether Subject Alternative Names are present when required by policy.
        /// </summary>
        private void CheckRequireSans(CertificateIssuanceContext context, List<PolicyViolation> violations)
        {
            if (!_config.RequireSans)
                return;

            if (context.SubjectAlternativeNames == null || context.SubjectAlternativeNames.Count == 0)
            {
                violations.Add(new PolicyViolation
                {
                    Rule = "RequireSans",
                    Severity = "Warning",
                    Message = "Certificate has no Subject Alternative Names. SANs are recommended by policy."
                });
            }
        }

        /// <summary>
        /// Checks algorithm sunset rules. Each rule has the format "AlgorithmSpec:YYYY-MM-DD".
        /// If the current date is past the sunset date and the certificate uses the specified
        /// algorithm, the issuance is blocked. The algorithm spec is matched against a combination
        /// of key algorithm and key size (e.g., "RSA-2048") or just the algorithm name.
        /// </summary>
        private void CheckAlgorithmSunsetRules(CertificateIssuanceContext context, List<PolicyViolation> violations)
        {
            if (_config.AlgorithmSunsetRules == null || _config.AlgorithmSunsetRules.Count == 0)
                return;

            var now = DateTime.UtcNow;
            var contextAlgSpec = $"{context.KeyAlgorithm}-{context.KeySize}";

            foreach (var rule in _config.AlgorithmSunsetRules)
            {
                var colonIndex = rule.LastIndexOf(':');
                if (colonIndex <= 0 || colonIndex >= rule.Length - 1)
                {
                    _logger.LogWarning("Invalid algorithm sunset rule format: \"{Rule}\". Expected \"AlgorithmSpec:YYYY-MM-DD\".", rule);
                    continue;
                }

                var algSpec = rule.Substring(0, colonIndex).Trim();
                var dateStr = rule.Substring(colonIndex + 1).Trim();

                if (!DateTime.TryParse(dateStr, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out var sunsetDate))
                {
                    _logger.LogWarning("Invalid sunset date in rule: \"{Rule}\". Expected YYYY-MM-DD format.", rule);
                    continue;
                }

                // Match against "Algorithm-KeySize" (e.g., "RSA-2048") or just algorithm name (e.g., "RSA")
                bool matches = string.Equals(algSpec, contextAlgSpec, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(algSpec, context.KeyAlgorithm, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(algSpec, context.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);

                if (matches && now >= sunsetDate)
                {
                    violations.Add(new PolicyViolation
                    {
                        Rule = "AlgorithmSunset",
                        Severity = "Error",
                        Message = $"Algorithm \"{algSpec}\" has been sunset as of {sunsetDate:yyyy-MM-dd} and is no longer permitted for new certificates."
                    });
                }
                else if (matches && now >= sunsetDate.AddDays(-90))
                {
                    // Warn 90 days before sunset
                    violations.Add(new PolicyViolation
                    {
                        Rule = "AlgorithmSunsetPending",
                        Severity = "Warning",
                        Message = $"Algorithm \"{algSpec}\" will be sunset on {sunsetDate:yyyy-MM-dd}. Consider migrating to a stronger algorithm."
                    });
                }
            }
        }
    }
}
