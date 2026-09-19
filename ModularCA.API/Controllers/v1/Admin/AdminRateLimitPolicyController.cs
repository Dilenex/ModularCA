using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing per-protocol rate-limit policy. Rows are keyed by
/// protocol name (EST, SCEP, CMP, ACME, OCSP, TSA, CRL, CA, Integration, HEALTH, ...).
/// Missing rows cause the middleware to fall back to its built-in defaults.
/// </summary>
[ApiController]
[Route("api/v1/admin/rate-limit-policy")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminRateLimitPolicyController(
    ModularCADbContext db,
    IProtocolRateLimitService policyService,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>Returns every per-protocol rate-limit row.</summary>
    [HttpGet]
    public async Task<IActionResult> List()
    {
        var rows = await db.ProtocolRateLimits
            .AsNoTracking()
            .OrderBy(r => r.Protocol)
            .ToListAsync();
        return Ok(rows);
    }

    /// <summary>
    /// Bulk upsert — each entry in the body is created or updated by protocol name.
    /// Protocols not present in the body are left alone (use DELETE for removal).
    /// </summary>
    [HttpPut]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> Update([FromBody] Dictionary<string, RateLimitUpdateRequest> request)
    {
        if (request == null || request.Count == 0)
            return BadRequest(new { error = "Body must contain at least one protocol entry." });

        foreach (var (protocol, values) in request)
        {
            if (string.IsNullOrWhiteSpace(protocol))
                return BadRequest(new { error = "Protocol name must not be empty." });
            if (values.MaxRequests is int mr && mr < 1)
                return BadRequest(new { error = $"MaxRequests for '{protocol}' must be >= 1." });
            if (values.WindowMinutes is int wm && wm < 1)
                return BadRequest(new { error = $"WindowMinutes for '{protocol}' must be >= 1." });

            var existing = await db.ProtocolRateLimits
                .FirstOrDefaultAsync(r => r.Protocol == protocol);
            if (existing == null)
            {
                existing = new ProtocolRateLimitEntity { Protocol = protocol };
                db.ProtocolRateLimits.Add(existing);
            }

            if (values.MaxRequests is int mrv) existing.MaxRequests = mrv;
            if (values.WindowMinutes is int wmv) existing.WindowMinutes = wmv;
            existing.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
        policyService.InvalidateCache();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(
            AuditActionType.RateLimitPolicyUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "ProtocolRateLimit", null,
            new { Protocols = request.Keys.ToArray() },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Rate-limit policy updated", protocols = request.Keys.ToArray() });
    }

    /// <summary>
    /// Removes the custom limit for a protocol, reverting to the middleware's built-in default.
    /// </summary>
    [HttpDelete("{protocol}")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> Delete(string protocol)
    {
        var row = await db.ProtocolRateLimits
            .FirstOrDefaultAsync(r => r.Protocol == protocol);
        if (row == null)
            return NotFound(new { error = $"No custom limit configured for '{protocol}'." });

        db.ProtocolRateLimits.Remove(row);
        await db.SaveChangesAsync();
        policyService.InvalidateCache();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(
            AuditActionType.RateLimitPolicyUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "ProtocolRateLimit", row.Id.ToString(),
            new { Removed = protocol },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Custom limit for '{protocol}' removed — middleware default applies." });
    }
}

/// <summary>Partial-update DTO for a single protocol's rate limits.</summary>
public class RateLimitUpdateRequest
{
    public int? MaxRequests { get; set; }
    public int? WindowMinutes { get; set; }
}
