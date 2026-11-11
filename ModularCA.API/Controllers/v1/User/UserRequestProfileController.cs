using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.API.Startup;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User endpoints for listing request profiles the authenticated user is allowed to use when submitting CSRs.
/// The list holds the profiles the caller could submit a request under (<see cref="SubmittableProfiles"/>).
/// </summary>
[ApiController]
[Route("api/v1/user/request-profiles")]
[Authorize(Policy = "CaUser")]
[NodeRole(ProcessRole.Control)]
public class UserRequestProfileController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IProfileResolutionService profileResolution,
    ICaGroupAuthorizationService authService
) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;

    /// <summary>
    /// Returns the request profiles the caller could submit a certificate request under: those a
    /// signing profile they may submit against goes with (<see cref="SubmittableProfiles"/>). That
    /// is every unbound profile and the profiles of the CAs the caller holds <c>cert.request</c>
    /// on that have a signing profile; group membership without <c>cert.request</c> lists nothing,
    /// and the rule is the same for a system administrator. Each row names, in
    /// <c>CertProfiles</c>, the leaf certificate profiles it designates that such a signing
    /// profile's CA admits; a designated profile of another CA or space is left out, since a
    /// submission naming it is refused. A row may name none: the form says so.
    /// <para>
    /// A row's <c>CertificateAuthorityId</c> is the CA it is bound to, null when unbound, and each
    /// entry of <c>CertProfiles</c> carries the certificate profile's own scope
    /// (<c>SpaceId</c>, <c>CertificateAuthorityId</c>). With the CA fields of
    /// <c>GET /api/v1/user/signing-profiles</c> that is what the request form needs to offer, for
    /// one chosen CA, exactly what a submission against it takes: the rows
    /// <see cref="RequestProfileEnforcement.BindingAdmits"/> admits for that CA, and of each row's
    /// certificate profiles those <see cref="ModularCA.Core.Authorization.CertProfileScope.Admits(Guid?, Guid?, Guid, Guid?)"/>
    /// admits for it.
    /// </para>
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAccessibleRequestProfiles()
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var userId = _currentUser.User.Id;

        // What the caller could submit against decides the list: a request profile is offered
        // when a signing profile they hold cert.request for goes with it, which is the rule the
        // submission applies. Membership of a CA's group is not that rule (an auditor is a member).
        var fence = SpaceFence.From(HttpContext, ModularCA.Shared.Authorization.Capabilities.CertRequest);
        var submittable = await SubmittableProfiles.ForAsync(authService, _db, fence, userId);

        var profiles = (await _db.RequestProfiles.ToListAsync())
            .Where(p => submittable.AdmitsRequestProfile(p.CertificateAuthorityId))
            .ToList();

        // A user never edits a profile, so what they see are the effective rules after
        // inheritance, which are the rules issuance applies. The form validates against these.
        var effective = new Dictionary<Guid, Core.Models.EffectiveRequestProfile>();
        foreach (var p in profiles)
        {
            try { effective[p.Id] = await profileResolution.ResolveRequestProfileAsync(p.Id); }
            catch (InvalidOperationException) { /* an unresolvable parent: fall back to the row's own rules below */ }
        }

        // The certificate profiles each request profile designates, default first, by name: a
        // user has no certificate profile listing, and the request form lets them choose among these.
        var designated = profiles.ToDictionary(p => p.Id, p => RequestProfileCertProfiles.DesignatedIds(
            effective.TryGetValue(p.Id, out var d) ? d.DefaultCertProfileId : p.DefaultCertProfileId,
            effective.TryGetValue(p.Id, out var a) ? a.AllowedCertProfileIds : p.AllowedCertProfileIds));
        var designatedIds = designated.Values.SelectMany(ids => ids).Distinct().ToList();
        var certProfiles = await _db.CertProfiles.AsNoTracking()
            .Where(c => designatedIds.Contains(c.Id) && !c.IsCaProfile)
            .Select(c => new { c.Id, c.Name, c.SpaceId, c.CertificateAuthorityId })
            .ToDictionaryAsync(c => c.Id);

        return Ok(profiles.Select(p => new
        {
            p.Id,
            p.Name,
            p.Description,
            CertProfiles = designated[p.Id]
                .Where(id => certProfiles.TryGetValue(id, out var c)
                    && submittable.AdmitsCertProfile(p.CertificateAuthorityId, c.SpaceId, c.CertificateAuthorityId))
                .Select(id => new { Id = id, certProfiles[id].Name, certProfiles[id].SpaceId, certProfiles[id].CertificateAuthorityId }),
            SubjectDnRules = effective.TryGetValue(p.Id, out var e) ? e.SubjectDnRules : p.SubjectDnRules,
            SanRules = effective.TryGetValue(p.Id, out var e2) ? e2.SanRules : p.SanRules,
            EffectiveSubjectDnRules = effective.TryGetValue(p.Id, out var e3) ? e3.SubjectDnRules : p.SubjectDnRules,
            EffectiveSanRules = effective.TryGetValue(p.Id, out var e4) ? e4.SanRules : p.SanRules,
            AllowedCertProfileIds = effective.TryGetValue(p.Id, out var e5) ? e5.AllowedCertProfileIds : p.AllowedCertProfileIds,
            RequireApproval = effective.TryGetValue(p.Id, out var e6) ? e6.RequireApproval : p.RequireApproval,
            DefaultCertProfileId = effective.TryGetValue(p.Id, out var e7) ? e7.DefaultCertProfileId : p.DefaultCertProfileId,
            p.CertificateAuthorityId,
            p.RequiredApprovalCount,
            p.InheritsFromId,
            p.InheritanceEnabled,
        }));
    }
}
