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
/// Profiles are filtered by the caller's profile.* capability grants.
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
    /// Returns signing profiles the caller has profile.* grants for. System admins
    /// see all profiles; other users see only those with an explicit capability grant.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetSigningProfiles()
    {
        await currentUser.EnsureLoadedAsync();
        if (!currentUser.IsAuthenticated || currentUser.User == null)
            return Unauthorized();

        var profiles = await db.SigningProfiles
            .AsNoTracking()
            .Select(sp => new
            {
                sp.Id,
                sp.Name,
                sp.Description,
                sp.IsDefault,
                sp.CreatedAt,
            })
            .ToListAsync();

        // Filter by profile.* capability grants unless caller is a system admin
        if (HttpContext.Items["IsSystemAdmin"] is not true)
        {
            var (grantedIds, hasWildcard) = await _authService.GetGrantedResourceIdsAsync(
                currentUser.User.Id, "profile.", "SigningProfile");
            if (!hasWildcard)
                profiles = profiles.Where(p => grantedIds.Contains(p.Id)).ToList();
        }

        return Ok(profiles);
    }
}
