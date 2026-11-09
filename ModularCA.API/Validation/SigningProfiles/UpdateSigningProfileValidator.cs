using FluentValidation;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.API.Validation.SigningProfiles
{
    /// <summary>Validator for <see cref="UpdateSigningProfileRequest"/>: the same rules as <see cref="CreateSigningProfileValidator"/>.</summary>
    public class UpdateSigningProfileValidator : AbstractValidator<UpdateSigningProfileRequest>
    {
        /// <summary>Builds the rules by including <see cref="CreateSigningProfileValidator"/>.</summary>
        public UpdateSigningProfileValidator()
        {
            Include(new CreateSigningProfileValidator());
        }
    }
}