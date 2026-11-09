using System.Text.RegularExpressions;
using FluentValidation;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Validation.Issuance
{
    /// <summary>
    /// Validator for <see cref="SubmitCertificateRequest"/>. Caps CSR PEM
    /// length at 16 KB (well above any realistic CSR) and enforces a strict, non-backtracking
    /// regex against the whole PEM body. Downstream BouncyCastle parsing is kept for the
    /// byte-level verification.
    /// </summary>
    public partial class SubmitCertificateRequestValidator : AbstractValidator<SubmitCertificateRequest>
    {
        /// <summary>Maximum CSR PEM length accepted by the validator, in characters.</summary>
        public const int MaxCsrPemLength = 16 * 1024;

        // RegexOptions.NonBacktracking (available in .NET 7+) guarantees linear-time matching
        // and immunity to RegexDoS. The pattern anchors on the BEGIN/END markers and allows
        // only base64 characters plus whitespace between them.
        [GeneratedRegex(
            @"^-----BEGIN CERTIFICATE REQUEST-----[\s]+[A-Za-z0-9+/=\s]+-----END CERTIFICATE REQUEST-----\s*$",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
        private static partial Regex CsrPemRegex();

        /// <summary>Builds the rules: a CSR PEM matching the PKCS#10 PEM pattern within <see cref="MaxCsrPemLength"/>, and a signing profile.</summary>
        public SubmitCertificateRequestValidator()
        {
            RuleFor(x => x.CsrPem)
                .NotEmpty().WithMessage("CSR (PEM) must be provided.")
                .MaximumLength(MaxCsrPemLength)
                    .WithMessage($"CSR PEM exceeds maximum length of {MaxCsrPemLength} characters.")
                .Must(pem => pem != null && pem.Contains("-----END CERTIFICATE REQUEST-----"))
                    .WithMessage("CSR PEM is missing the END CERTIFICATE REQUEST marker.")
                .Must(pem => pem != null && CsrPemRegex().IsMatch(pem.Trim()))
                    .WithMessage("CSR must be a valid PEM-encoded PKCS#10 request.");

            RuleFor(x => x.SigningProfileId)
                .NotEmpty().WithMessage("Signing profile is required.");
        }
    }
}
