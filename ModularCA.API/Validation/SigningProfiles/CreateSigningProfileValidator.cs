using FluentValidation;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.API.Validation.SigningProfiles
{
    /// <summary>
    /// Validator for <see cref="CreateSigningProfileRequest"/>: a name of at most 100 characters, a
    /// description of at most 255, an issuer (CA certificate) id, and a default flag.
    /// </summary>
    public class CreateSigningProfileValidator : AbstractValidator<CreateSigningProfileRequest>
    {
        /// <summary>Builds the rules.</summary>
        public CreateSigningProfileValidator()
        {
            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Name is required.")
                .MaximumLength(100);

            RuleFor(x => x.Description)
                .MaximumLength(255);

            RuleFor(x => x.IssuerId)
                .NotEmpty().WithMessage("IssuerId (CA certificate) is required.");

            RuleFor(x => x.IsDefault)
                .NotNull();
        }
    }
}
