using FluentValidation;
using ModularCA.Database;
using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.API.Validation.CertProfiles
{
    /// <summary>
    /// Applies the create-time rules to an update. Takes the database context because
    /// <see cref="CreateCertProfileValidator"/> now resolves usages against the OID catalog rather
    /// than a hardcoded list, and an update must be held to the same standard as a create.
    /// </summary>
    public class UpdateCertProfileValidator : AbstractValidator<UpdateCertProfileRequest>
    {
        /// <param name="db">Database context, passed through to the included create validator.</param>
        public UpdateCertProfileValidator(ModularCADbContext db)
        {
            Include(new CreateCertProfileValidator(db));
        }
    }
}
