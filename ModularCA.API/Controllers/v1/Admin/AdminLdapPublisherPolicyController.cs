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
/// Admin endpoints for the global LDAP publisher job policy — the master
/// enable-flag plus two job-level tunables. Per-CA per-directory publisher
/// configs live under <c>/api/v1/admin/authorities/{caId}/ldap-publishers</c>.
/// </summary>
[ApiController]
[Route("api/v1/admin/ldap-publisher/policy")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminLdapPublisherPolicyController(
    ModularCADbContext db,
    ILdapPublisherPolicyService policyService,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>Returns the current LDAP publisher policy row.</summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.LdapPublisherPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No LDAP publisher policy configured." });
        return Ok(policy);
    }

    /// <summary>
    /// Applies a partial update to the policy. Null fields are left untouched.
    /// </summary>
    [HttpPut]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> Update([FromBody] LdapPublisherPolicyUpdateRequest request)
    {
        var policy = await db.LdapPublisherPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new LdapPublisherPolicyEntity();
            db.LdapPublisherPolicies.Add(policy);
        }

        if (request.Enabled.HasValue)
            policy.Enabled = request.Enabled.Value;
        if (request.SinceFallbackHours is int sfh && sfh >= 1)
            policy.SinceFallbackHours = sfh;
        if (request.ConnectionTimeoutSeconds is int cts && cts >= 5)
            policy.ConnectionTimeoutSeconds = cts;

        policy.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        policyService.InvalidateCache();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(
            AuditActionType.LdapPublisherPolicyUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapPublisherPolicy", policy.Id.ToString(),
            request,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(policy);
    }
}

/// <summary>Partial-update DTO. Null fields are left untouched.</summary>
public class LdapPublisherPolicyUpdateRequest
{
    public bool? Enabled { get; set; }
    public int? SinceFallbackHours { get; set; }
    public int? ConnectionTimeoutSeconds { get; set; }
}
