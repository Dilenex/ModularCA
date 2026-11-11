using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Authorization;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// What one caller could submit a self-service certificate request against, for the lists the
/// request form fills its pickers from. Each answer is the submission's own rule asked ahead of
/// time, so a list offers what <c>POST /api/v1/user/requests</c> (and <c>upload</c>,
/// <c>request-with-key</c>) would accept and nothing it would refuse:
/// <list type="bullet">
///   <item><description>a signing profile: <c>cert.request</c> on its CA, the check
///     <c>[RequireCaCapability(cert.request, SigningProfile)]</c> makes
///     (<see cref="BodyTargetAuthorization.AllowedSigningProfileIdsAsync"/>), with its CA inside
///     the caller's fence as <c>request-with-key</c> and <c>key-options</c> require;</description></item>
///   <item><description>a request profile: usable with at least one such signing profile
///     (<see cref="RequestProfileEnforcement.BindingAdmits"/>);</description></item>
///   <item><description>a certificate profile a request profile names: in the scope of the CA of
///     at least one such signing profile (<see cref="CertProfileScope.Admits(Guid?, Guid?, Guid, Guid?)"/>).</description></item>
/// </list>
/// Holding <c>profile.view</c> or <c>profile.use</c> plays no part: submission does not ask for them.
/// </summary>
public sealed class SubmittableProfiles
{
    /// <summary>A signing profile the caller may submit against.</summary>
    /// <param name="Id">The signing profile.</param>
    /// <param name="CaId">The live CA it issues from, as submission reads it; null when it has no issuer.</param>
    /// <param name="CaSpaceId">That CA's space; null for an instance CA or when there is no CA.</param>
    /// <param name="CaName">That CA's name, for the request form's CA picker; null when there is no CA.</param>
    public sealed record SigningProfile(Guid Id, Guid? CaId, Guid? CaSpaceId, string? CaName = null);

    private SubmittableProfiles(IReadOnlyList<SigningProfile> signingProfiles) => SigningProfiles = signingProfiles;

    /// <summary>The signing profiles the caller may submit a request against.</summary>
    public IReadOnlyList<SigningProfile> SigningProfiles { get; }

    /// <summary>
    /// Resolves what <paramref name="userId"/> may submit against. A signing profile whose CA is
    /// deleted is left out: nothing can be issued from it. Each one carries its CA's id, space
    /// and name, which the lists hand to the request form so it can filter by the chosen CA.
    /// </summary>
    /// <param name="auth">The capability resolver.</param>
    /// <param name="db">The application database.</param>
    /// <param name="fence">The caller's fence narrowed to <c>cert.request</c>.</param>
    /// <param name="userId">The caller.</param>
    public static async Task<SubmittableProfiles> ForAsync(
        ICaGroupAuthorizationService auth, ModularCADbContext db, SpaceFence fence, Guid userId)
    {
        var allowed = await BodyTargetAuthorization.AllowedSigningProfileIdsAsync(auth, db, userId, Capabilities.CertRequest);
        if (allowed.Count == 0)
            return new([]);

        var profiles = await db.SigningProfiles.AsNoTracking()
            .Where(p => allowed.Contains(p.Id))
            .Select(p => new { p.Id, p.IssuerId })
            .ToListAsync();
        var issuers = profiles.Where(p => p.IssuerId != null).Select(p => p.IssuerId!.Value).Distinct().ToList();
        var liveCas = (await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.CertificateId != null && issuers.Contains(ca.CertificateId.Value))
                .Select(ca => new { ca.Id, ca.SpaceId, ca.Name, CertificateId = ca.CertificateId!.Value })
                .ToListAsync())
            .GroupBy(ca => ca.CertificateId)
            .ToDictionary(g => g.Key, g => g.First());

        var submittable = new List<SigningProfile>();
        foreach (var profile in profiles)
        {
            if (profile.IssuerId is not Guid issuer)
                submittable.Add(new SigningProfile(profile.Id, null, null));
            else if (liveCas.TryGetValue(issuer, out var ca) && fence.Allows(ca.SpaceId))
                submittable.Add(new SigningProfile(profile.Id, ca.Id, ca.SpaceId, ca.Name));
        }
        return new(submittable);
    }

    /// <summary>
    /// Whether a request profile bound to <paramref name="requestProfileCaId"/> (null when
    /// unbound) can be used in a submission by this caller: with at least one signing profile
    /// they may submit against.
    /// </summary>
    /// <param name="requestProfileCaId">The CA the request profile is bound to, or null.</param>
    public bool AdmitsRequestProfile(Guid? requestProfileCaId)
        => SigningProfiles.Any(s => RequestProfileEnforcement.BindingAdmits(requestProfileCaId, s.CaId));

    /// <summary>
    /// Whether a leaf certificate profile can be used in a submission by this caller under a
    /// request profile bound to <paramref name="requestProfileCaId"/>: some signing profile they
    /// may submit against goes with that request profile and issues from a CA whose scope admits
    /// the certificate profile. A signing profile with no CA puts no scope on it, as submission
    /// puts none.
    /// </summary>
    /// <param name="requestProfileCaId">The CA the request profile is bound to, or null.</param>
    /// <param name="certProfileSpaceId">The certificate profile's space, or null.</param>
    /// <param name="certProfileCaId">The CA the certificate profile is bound to, or null.</param>
    public bool AdmitsCertProfile(Guid? requestProfileCaId, Guid? certProfileSpaceId, Guid? certProfileCaId)
        => SigningProfiles.Any(s => RequestProfileEnforcement.BindingAdmits(requestProfileCaId, s.CaId)
            && (s.CaId is not Guid caId || CertProfileScope.Admits(certProfileSpaceId, certProfileCaId, caId, s.CaSpaceId)));
}
