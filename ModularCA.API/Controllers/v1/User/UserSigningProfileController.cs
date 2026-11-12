using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User endpoints for listing signing profiles available for certificate requests.
/// Returns basic signing profile information needed to submit CSR upload requests.
/// The list holds the profiles the caller could submit a request against
/// (<see cref="SubmittableProfiles"/>), neither more nor fewer.
/// </summary>
[ApiController]
[Route("api/v1/user/signing-profiles")]
[Authorize(Policy = "CaUser")]
[NodeRole(ProcessRole.Control)]
public class UserSigningProfileController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    ICaGroupAuthorizationService authService
) : ControllerBase
{
    private readonly ICaGroupAuthorizationService _authService = authService;

    /// <summary>
    /// Returns the signing profiles the caller could submit a certificate request against: those
    /// of the CAs they hold <c>cert.request</c> on, inside their
    /// <see cref="ModularCA.Auth.Authorization.SpaceFence"/>. This is the check the submission
    /// endpoints make (<see cref="SubmittableProfiles"/>), so a requester sees the profiles of
    /// their CA and no other CA's. A <c>profile.*</c> capability neither adds a row nor is needed
    /// for one. A profile with no issuer is listed only for a caller who holds
    /// <c>cert.request</c> at system scope, and one whose issuer is no live CA for nobody: a
    /// submission naming either is refused for everyone else.
    /// <para>
    /// Each row names the CA the profile issues from, as submission reads it: <c>CaId</c>,
    /// <c>CaName</c> and <c>CaSpaceId</c> (the CA's space, null for an instance CA). All three
    /// are null for a profile with no issuer. The request form builds its CA picker from them
    /// and offers the signing profiles of the chosen CA.
    /// </para>
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetSigningProfiles()
    {
        await currentUser.EnsureLoadedAsync();
        if (!currentUser.IsAuthenticated || currentUser.User == null)
            return Unauthorized();

        var fence = ModularCA.Auth.Authorization.SpaceFence.From(HttpContext, ModularCA.Shared.Authorization.Capabilities.CertRequest);
        var submittable = await SubmittableProfiles.ForAsync(_authService, db, fence, currentUser.User.Id);
        var issuing = submittable.SigningProfiles.ToDictionary(s => s.Id);
        var ids = issuing.Keys.ToList();
        var profiles = await db.SigningProfiles
            .AsNoTracking()
            .Where(sp => ids.Contains(sp.Id))
            .Select(sp => new
            {
                sp.Id,
                sp.Name,
                sp.Description,
                sp.IsDefault,
                sp.CreatedAt,
            })
            .ToListAsync();

        return Ok(profiles.Select(sp => new
        {
            sp.Id,
            sp.Name,
            sp.Description,
            sp.IsDefault,
            sp.CreatedAt,
            issuing[sp.Id].CaId,
            issuing[sp.Id].CaName,
            issuing[sp.Id].CaSpaceId,
        }));
    }
}
