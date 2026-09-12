using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User endpoints for listing request profiles the authenticated user is allowed to use when submitting CSRs.
/// </summary>
[ApiController]
[Route("api/v1/user/request-profiles")]
[Authorize(Policy = "CaUser")]
public class UserRequestProfileController(
    ModularCADbContext db,
    ICurrentUserService currentUser
) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;

    /// <summary>
    /// Returns request profiles accessible to the authenticated user based on their group memberships.
    /// System admins see all profiles; other users see profiles scoped to their accessible CAs plus system-wide profiles.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAccessibleRequestProfiles()
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var userId = _currentUser.User.Id;

        // Get CA IDs the user has access to
        var userCaIds = await _db.CaGroupMembers
            .Where(gm => gm.UserId == userId && gm.Group.CertificateAuthorityId != null)
            .Select(gm => gm.Group.CertificateAuthorityId!.Value)
            .Distinct()
            .ToListAsync();

        // Audit-finding #49 consolidation: use the canonical super-admin idiom populated by
        // TenantResolutionMiddleware (which checks all four SystemManage grant sources:
        // direct group grant, role via group, direct user grant, role via user) instead of
        // the previous open-coded query that only covered source #1 and could silently
        // deny access to role-based system admins.
        var isSystemAdmin = HttpContext.Items["IsSystemAdmin"] is true;

        var profiles = await _db.RequestProfiles.ToListAsync();
        if (!isSystemAdmin)
            profiles = profiles
                .Where(p => p.CertificateAuthorityId == null || userCaIds.Contains(p.CertificateAuthorityId.Value))
                .ToList();

        return Ok(profiles.Select(p => new
        {
            p.Id,
            p.Name,
            p.Description,
            p.SubjectDnRules,
            p.SanRules,
            p.AllowedCertProfileIds,
            p.RequireApproval,
            p.DefaultCertProfileId,
            p.CertificateAuthorityId,
            p.RequiredApprovalCount,
            p.InheritsFromId,
            p.InheritanceEnabled,
        }));
    }
}
