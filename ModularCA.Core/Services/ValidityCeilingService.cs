using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Resolves the effective validity ceiling for a profile pairing by walking
/// signing profile → issuing CA → tenant, then handing the three numbers to
/// <see cref="CertificateValidityUtil.ResolveCeiling"/>.
/// </summary>
/// <remarks>
/// <para>
/// The lookups live here and the decision lives in the util, deliberately. The decision is the
/// part worth testing — three layers, a tie-break and a defaulted profile period — and it is
/// testable as a pure function only if nothing in it needs a database. What is left here is a
/// chain of foreign keys that a test would only be restating.
/// </para>
/// <para>
/// It reads the same tables issuance reads, through the same profile resolver, so a profile that
/// inherits from another is pre-flighted against its <em>merged</em> maximum rather than its own.
/// Reimplementing that merge here would be a second source of truth that drifts silently, and the
/// drift would only ever be discovered as a clamp the operator was promised would not happen.
/// </para>
/// </remarks>
public class ValidityCeilingService : IValidityCeilingService
{
    private readonly ModularCADbContext _db;
    private readonly IProfileResolutionService _profileResolver;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of <see cref="ValidityCeilingService"/>.
    /// </summary>
    /// <param name="db">Database context for the profile → CA → tenant walk.</param>
    /// <param name="profileResolver">Resolves the effective (merged/inherited) certificate profile.</param>
    /// <param name="timeProvider">
    /// Clock; optional and defaulted to <see cref="TimeProvider.System"/> the way the scheduler
    /// jobs take theirs, so nothing has to be registered in DI for this to resolve.
    /// </param>
    public ValidityCeilingService(
        ModularCADbContext db,
        IProfileResolutionService profileResolver,
        TimeProvider? timeProvider = null)
    {
        _db = db;
        _profileResolver = profileResolver;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<ValidityCeilingPreflight?> ResolveAsync(
        Guid signingProfileId,
        Guid certProfileId,
        DateTime? notBefore = null,
        CancellationToken cancellationToken = default)
    {
        var signingProfile = await _db.SigningProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == signingProfileId, cancellationToken);
        if (signingProfile == null)
            return null;

        var certProfileExists = await _db.CertProfiles
            .AsNoTracking()
            .AnyAsync(p => p.Id == certProfileId, cancellationToken);
        if (!certProfileExists)
            return null;

        // Through the resolver, not the entity: an inheriting profile's effective maximum is the
        // merged one, and that is the number issuance will enforce.
        var effectiveCertProfile = await _profileResolver.ResolveCertProfileAsync(certProfileId);

        // The same default every issuance path applies. A profile with no ValidityPeriodMax is not
        // unlimited — it is one year — and a pre-flight that showed "unlimited" here would be
        // telling the operator the opposite of what they will get.
        var certProfileMax = Iso8601ParserUtil.ParseIso8601(effectiveCertProfile.ValidityPeriodMax ?? "P1Y");

        // Signing profile → issuer certificate → CA → tenant. Each link is optional in the schema,
        // and a system-wide signing profile genuinely has no CA, so every step degrades to "that
        // layer cannot bind" rather than to an error.
        DateTime? issuingCaNotAfter = null;
        string? issuingCaName = null;
        string? tenantName = null;
        var tenantMaxValidityDays = 0;
        var tenantBehavior = Shared.Enums.ValidityCeilingBehavior.Shorten;

        if (signingProfile.IssuerId.HasValue)
        {
            var issuerCert = await _db.Certificates
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId.Value, cancellationToken);
            if (issuerCert != null)
            {
                // AsUtc for the same reason issuance applies it: EF returns MySQL datetime columns
                // as DateTimeKind.Unspecified, and comparing one of those against a UTC instant is
                // off by the host's UTC offset.
                issuingCaNotAfter = CertificateValidityUtil.AsUtc(issuerCert.NotAfter);

                var ca = await _db.CertificateAuthorities
                    .AsNoTracking()
                    .FirstOrDefaultAsync(a => a.CertificateId == issuerCert.CertificateId, cancellationToken);
                if (ca != null)
                {
                    issuingCaName = ca.Label ?? ca.Name;
                    var tenant = await _db.Tenants
                        .AsNoTracking()
                        .FirstOrDefaultAsync(t => t.Id == ca.TenantId, cancellationToken);
                    if (tenant != null)
                    {
                        tenantName = tenant.Name;
                        tenantMaxValidityDays = tenant.MaxValidityDays;
                        tenantBehavior = tenant.ValidityCeilingBehavior;
                    }
                }
            }
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var start = CertificateValidityUtil.AsUtc(notBefore) ?? CertificateValidityUtil.DefaultNotBefore();

        // A CA certificate is exempt from the tenant ceiling — shortening a ten-year intermediate
        // to two years takes everything beneath it down with it — so the pre-flight must not
        // report a tenant cap that issuance will not apply. Passing 0 is how "unlimited" is spelled
        // everywhere else in this feature.
        var tenantCeilingApplies = !effectiveCertProfile.IsCaProfile;

        var resolution = CertificateValidityUtil.ResolveCeiling(
            start,
            now,
            certProfileMax,
            tenantCeilingApplies ? tenantMaxValidityDays : 0,
            issuingCaNotAfter);

        return new ValidityCeilingPreflight(
            resolution,
            signingProfile.Name,
            effectiveCertProfile.Name,
            effectiveCertProfile.ValidityPeriodMax,
            issuingCaName,
            issuingCaNotAfter,
            tenantName,
            tenantMaxValidityDays,
            tenantBehavior,
            tenantCeilingApplies);
    }
}
