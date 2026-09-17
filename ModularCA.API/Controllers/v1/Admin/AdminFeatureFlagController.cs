using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing feature flags that control optional system behaviors.
/// </summary>
[ApiController]
[Route("api/v1/admin/features")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminFeatureFlagController(
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser,
    IFeatureFlagService featureFlagService) : ControllerBase
{
    /// <summary>
    /// Returns all feature flags with their current state and metadata.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var flags = await db.FeatureFlags
            .AsNoTracking()
            .OrderBy(f => f.Name)
            .Select(f => new { f.Name, f.Enabled, f.Value, f.Description, f.RequiresRestart })
            .ToListAsync();
        return Ok(flags);
    }

    /// <summary>
    /// Returns a single feature flag by name.
    /// </summary>
    [HttpGet("{name}")]
    public async Task<IActionResult> GetByName(string name)
    {
        var flag = await db.FeatureFlags.AsNoTracking().FirstOrDefaultAsync(f => f.Name == name);
        if (flag == null)
            return NotFound(new { error = $"Feature flag '{name}' not found" });
        return Ok(new { flag.Name, flag.Enabled, flag.Value, flag.Description, flag.RequiresRestart });
    }

    /// <summary>
    /// Updates a feature flag's enabled state and optional value, then invalidates the in-memory cache.
    /// Step-up MFA is required because flipping a flag can disable Syslog, EventLog, or metrics
    /// emission — silently turning off security gates without code review.
    /// </summary>
    [HttpPut("{name}")]
    [RequireStepUp(StepUpOps.UpdateFeatureFlag, "name")]
    public async Task<IActionResult> Update(string name, [FromBody] FeatureFlagUpdateRequest request)
    {
        var flag = await db.FeatureFlags.FirstOrDefaultAsync(f => f.Name == name);
        if (flag == null)
            return NotFound(new { error = $"Feature flag '{name}' not found" });

        var oldEnabled = flag.Enabled;
        flag.Enabled = request.Enabled;
        if (request.Value != null)
            flag.Value = request.Value;
        await db.SaveChangesAsync();

        // Invalidate the in-memory cache so the middleware and other consumers pick up the change immediately.
        featureFlagService.InvalidateCache();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.FeatureFlagUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "FeatureFlag", name, new { name, flag.Enabled, OldEnabled = oldEnabled, flag.Value },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { flag.Name, flag.Enabled, flag.Value, flag.RequiresRestart });
    }
}

public class FeatureFlagUpdateRequest
{
    public bool Enabled { get; set; }
    public string? Value { get; set; }
}
