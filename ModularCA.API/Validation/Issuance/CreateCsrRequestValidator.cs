using FluentValidation;
using ModularCA.Shared.Models.Csr;

namespace ModularCA.API.Validation.Issuance
{
    /// <summary>
    /// Validator for <see cref="CreateCsrRequest"/>: certificate profile, signing profile and subject
    /// name are required; the key is RSA or ECDSA of a size <see cref="ValidKeySize"/> accepts; and the
    /// signature algorithm suits the key (<see cref="ValidSignatureAlgorithm"/>).
    /// </summary>
    public class CreateCsrRequestValidator : AbstractValidator<CreateCsrRequest>
    {
        /// <summary>Builds the rules.</summary>
        public CreateCsrRequestValidator()
        {
            RuleFor(x => x.CertificateProfileId)
                .NotEmpty().WithMessage("CSR (PEM) must be provided.");

            RuleFor(x => x.SigningProfileId)
                .NotEmpty().WithMessage("Signing profile is required.");

            RuleFor(x => x.SubjectName)
                .NotEmpty().WithMessage("Subject name is required.");

            RuleFor(x => x.KeyAlgorithm)
                .Must(alg => alg == "RSA" || alg == "ECDSA")
                .WithMessage("Key algorithm must be either 'RSA' or 'ECDSA'.");

            RuleFor(x => x.KeySize)
                .Must((request, keySize) => ValidKeySize(keySize, request.KeyAlgorithm))
                .WithMessage(request => $"Key size {request.KeySize} is not valid for algorithm {request.KeyAlgorithm}.");

            RuleFor(x => x.SignatureAlgorithm)
                .Must((request, signatureAlgorithm) => ValidSignatureAlgorithm(request.KeyAlgorithm, signatureAlgorithm))
                .WithMessage(string.Format("Signature algorithm {0} is not valid for key algorithm {1}.", "{PropertyValue}", "{KeyAlgorithm}"));
        }

        /// <summary>
        /// Whether <paramref name="keySize"/> is allowed for <paramref name="keyAlgorithm"/>: 2048, 3072,
        /// 4096, 7680 or 8192 for <c>RSA</c>; <c>P-256</c>, <c>P-384</c> or <c>P-521</c> for <c>ECDSA</c>.
        /// Any other algorithm is refused.
        /// </summary>
        /// <param name="keySize">RSA modulus length in bits, or ECDSA curve name.</param>
        /// <param name="keyAlgorithm"><c>RSA</c> or <c>ECDSA</c>, case-sensitive.</param>
        public static bool ValidKeySize(string keySize, string keyAlgorithm)
        {
            if (keyAlgorithm == "RSA")
            {
                return keySize is "2048" or "3072" or "4096" or "7680" or "8192";
            }
            else if (keyAlgorithm == "ECDSA")
            {
                return keySize == "P-256" || keySize == "P-384" || keySize == "P-521";
            }
            return false;
        }

        /// <summary>
        /// Validates that the signature algorithm is compatible with the key algorithm.
        /// Accepts both PKCS#1 v1.5 and RSA-PSS variants for RSA keys.
        /// </summary>
        public static bool ValidSignatureAlgorithm(string keyAlgorithm, string signatureAlgorithm)
        {
            if (keyAlgorithm == "RSA")
            {
                return signatureAlgorithm is "SHA256withRSA" or "SHA384withRSA" or "SHA512withRSA"
                    or "SHA256withRSAandMGF1" or "SHA384withRSAandMGF1" or "SHA512withRSAandMGF1";
            }
            else if (keyAlgorithm == "ECDSA")
            {
                return signatureAlgorithm == "SHA256withECDSA" || signatureAlgorithm == "SHA384withECDSA" || signatureAlgorithm == "SHA512withECDSA";
            }
            return false;
        }


    }
}