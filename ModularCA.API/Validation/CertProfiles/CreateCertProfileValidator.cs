using FluentValidation;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Validation.CertProfiles
{
    /// <summary>
    /// Validates a certificate profile's usages against the <c>OIDOptions</c> catalog — the same
    /// table issuance resolves them against.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both lists used to be hardcoded here as friendly-name string literals: eight key usages and
    /// seven extended key usages. Anything else was rejected at profile creation whatever the
    /// catalog held, which made the catalog decorative for this path and put a fixed ceiling on
    /// what the CA could ever be configured to issue — no Kerberos KDC authentication
    /// (<c>1.3.6.1.5.2.3.5</c>), so no domain controller certificates and therefore no smart-card
    /// logon; none of the PIV usages; no EFS, no document signing.
    /// </para>
    /// <para>
    /// The decision itself lives in <see cref="CertProfileUsageValidation"/> so it can be tested
    /// without standing up the API, and so it resolves through <see cref="UsageCatalogResolver"/>
    /// exactly as <c>IssuanceValidationService</c> does. This class is the adapter: it reads the
    /// catalog and reports the outcome in FluentValidation's terms.
    /// </para>
    /// </remarks>
    public class CreateCertProfileValidator : AbstractValidator<CreateCertProfileRequest>
    {
        private readonly Lazy<List<(string? Oid, string? FriendlyName)>> _standardCatalog;
        private readonly Lazy<List<(string? Oid, string? FriendlyName)>> _extendedCatalog;

        /// <summary>
        /// Constructs the validator. The catalog is read lazily and at most once per instance, so
        /// a request rejected by an earlier rule costs no query.
        /// </summary>
        /// <param name="db">Database context used to read the OID catalog.</param>
        public CreateCertProfileValidator(ModularCADbContext db)
        {
            _standardCatalog = new Lazy<List<(string?, string?)>>(() => ReadCatalog(db, "Standard"));
            _extendedCatalog = new Lazy<List<(string?, string?)>>(() => ReadCatalog(db, "Extended"));

            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Name is required.")
                .MaximumLength(100);

            RuleFor(x => x.Description)
                .MaximumLength(255);

            RuleFor(x => x.KeyUsages)
                .NotEmpty()
                .Must(input => CertProfileUsageValidation
                    .CheckKeyUsages(input, _standardCatalog.Value).IsValid)
                .WithMessage(x => CertProfileUsageValidation.DescribeFailure(
                    "KeyUsages",
                    CertProfileUsageValidation.CheckKeyUsages(x.KeyUsages, _standardCatalog.Value)));

            RuleFor(x => x.ExtendedKeyUsages)
                .Must(input => CertProfileUsageValidation
                    .CheckExtendedKeyUsages(input, _extendedCatalog.Value).IsValid)
                .When(x => !string.IsNullOrEmpty(x.ExtendedKeyUsages))
                .WithMessage(x => CertProfileUsageValidation.DescribeFailure(
                    "ExtendedKeyUsages",
                    CertProfileUsageValidation.CheckExtendedKeyUsages(x.ExtendedKeyUsages, _extendedCatalog.Value)));

            RuleFor(x => x.ValidityPeriodMax)
                .NotEmpty()
                .Matches(@"^P(\d+Y)?(\d+M)?(\d+D)?$")
                .WithMessage("ValidityPeriodMax must be an ISO 8601 duration like P1Y, P6M, or P90D.");
        }

        private static List<(string? Oid, string? FriendlyName)> ReadCatalog(
            ModularCADbContext db, string keyUsageKind) =>
            db.OIDOptions
                .AsNoTracking()
                .Where(o => o.KeyUsage == keyUsageKind)
                .Select(o => new { o.OID, o.FriendlyName })
                .AsEnumerable()
                .Select(o => ((string?)o.OID, (string?)o.FriendlyName))
                .ToList();
    }
}
