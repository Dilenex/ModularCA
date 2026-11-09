using FluentValidation;
using ModularCA.Shared.Models.Acme;

namespace ModularCA.API.Validation.Acme;

/// <summary>
/// Validator for <see cref="FinalizeAcmeOrderRequest"/>: the CSR must be present and consist only of
/// base64url characters (<c>A–Z a–z 0–9 - _</c>, no padding).
/// </summary>
public class FinalizeAcmeOrderValidator : AbstractValidator<FinalizeAcmeOrderRequest>
{
    /// <summary>Builds the rules.</summary>
    public FinalizeAcmeOrderValidator()
    {
        RuleFor(x => x.Csr)
            .NotEmpty().WithMessage("CSR is required.")
            .Must(BeValidBase64Url).WithMessage("CSR must be a valid base64url-encoded value.");
    }

    private static bool BeValidBase64Url(string csr)
    {
        if (string.IsNullOrWhiteSpace(csr))
            return false;

        // Base64url uses only [A-Za-z0-9_-] with no padding
        return csr.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
    }
}
