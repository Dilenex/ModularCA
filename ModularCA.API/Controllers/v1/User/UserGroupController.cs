using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User endpoints for viewing the authenticated user's group memberships and associated CAs.
/// </summary>
[ApiController]
[Route("api/v1/user/groups")]
[Authorize(Policy = "CaUser")]
[NodeRole(ProcessRole.Control)]
public class UserGroupController(
    ModularCADbContext db,
    ICurrentUserService currentUser
) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICurrentUserService _currentUser = currentUser;

    /// <summary>
    /// Returns group memberships for the authenticated user with pagination, including group details and associated CA info.
    /// </summary>
    /// <param name="page">Page number (1-based). Defaults to 1.</param>
    /// <param name="pageSize">Number of items per page. Defaults to 25, clamped to 1-100.</param>
    /// <returns>A paginated result containing group memberships and total count metadata.</returns>
    [HttpGet]
    public async Task<IActionResult> GetMyGroups(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        // Clamp pagination parameters
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 1;
        if (pageSize > 100) pageSize = 100;

        var userId = _currentUser.User.Id;

        var query = _db.CaGroupMembers
            .Where(gm => gm.UserId == userId)
            .Include(gm => gm.Group)
            .ThenInclude(g => g.CertificateAuthority)
            .Select(gm => new
            {
                gm.Group.Id,
                gm.Group.Name,
                gm.Group.DisplayName,
                gm.Group.TemplateName,
                gm.Group.IsSystemGroup,
                CaId = gm.Group.CertificateAuthorityId,
                CaName = gm.Group.CertificateAuthority != null ? gm.Group.CertificateAuthority.Name : null,
                CaLabel = gm.Group.CertificateAuthority != null ? gm.Group.CertificateAuthority.Label : null,
            });

        var total = await query.CountAsync();

        var pagedItems = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return Ok(new
        {
            total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling((double)total / pageSize),
            items = pagedItems
        });
    }
}
