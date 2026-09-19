using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Public endpoint for protocol clients to discover available certificate templates.
/// Returns only enabled templates with name and description — no profile details are exposed.
/// </summary>
[ApiController]
[Route("api/v1/public/templates")]
[AllowAnonymous]
[NodeRole(ProcessRole.Enrollment)]
public class PublicTemplateController(ModularCADbContext db) : ControllerBase
{
    /// <summary>
    /// Lists enabled certificate templates with name and description only, with pagination.
    /// No authentication required — suitable for protocol client auto-discovery.
    /// </summary>
    /// <param name="page">Page number (1-based). Defaults to 1.</param>
    /// <param name="pageSize">Number of items per page. Defaults to 25, clamped to 1-100.</param>
    /// <returns>A paginated result containing enabled templates and total count metadata.</returns>
    [HttpGet]
    public async Task<IActionResult> ListTemplates(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25)
    {
        // Clamp pagination parameters
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 1;
        if (pageSize > 100) pageSize = 100;

        var query = db.CertificateTemplates
            .AsNoTracking()
            .Where(t => t.IsEnabled)
            .OrderBy(t => t.Name)
            .Select(t => new
            {
                t.Name,
                t.Description
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
