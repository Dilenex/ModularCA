using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for viewing and managing certificate quota limits per CA.
/// Quotas are configured on the CA's admin group and enforce a maximum number of
/// active certificates that can be issued through that CA.
/// </summary>
[ApiController]
[Route("api/v1/admin/quotas")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminQuotaController(
    ModularCADbContext db,
    IQuotaService quotaService,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Returns quota usage summaries for all enabled CAs, including issued counts,
    /// remaining capacity, and warning/exceeded status.
    /// The caller sees the CAs inside their <see cref="SpaceFence"/>; an instance-wide caller sees all.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAllQuotas()
    {
        var summary = await quotaService.GetUsageSummaryAsync();
        var fence = SpaceFence.From(HttpContext, Capabilities.CaManage);
        if (!fence.InstanceWide)
        {
            var accessibleCaIds = await db.CertificateAuthorities
                .Where(fence.Predicate<Shared.Entities.CertificateAuthorityEntity>(ca => ca.SpaceId))
                .Select(ca => ca.Id)
                .ToListAsync();
            var accessibleCaIdSet = new HashSet<Guid>(accessibleCaIds);
            summary.CaQuotas = summary.CaQuotas.Where(q => accessibleCaIdSet.Contains(q.CaId)).ToList();
            summary.TotalIssuedCertificates = summary.CaQuotas.Sum(q => q.IssuedCount);
            summary.ExceededCount = summary.CaQuotas.Count(q => q.IsExceeded);
            summary.WarningCount = summary.CaQuotas.Count(q => !q.IsExceeded && q.MaxCertificates > 0 && q.UsagePercent >= 80);
        }
        return Ok(summary);
    }

    /// <summary>
    /// Returns all spaces with their certificate authorities and each CA's certificate-issuance
    /// quota nested underneath, for the combined Spaces &amp; Quotas view, with per-CA issued and
    /// pending usage. Space quotas were removed in 0.4.0; quotas are per CA, on its admin group.
    /// Gated to SystemAdmin (space configuration is admin-only).
    /// <c>instance</c> carries the instance's own CA policy and its CAs (those with no space: the system signing CA, SSH CAs).
    /// </summary>
    [HttpGet("by-space")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> GetQuotasBySpace()
    {
        // Per-CA quota usage (issued/pending computed live), keyed by CaId. Only enabled CAs appear
        // in the summary, so disabled CAs nest with a null quota below.
        var summary = await quotaService.GetUsageSummaryAsync();
        var quotaByCa = summary.CaQuotas.ToDictionary(q => q.CaId);

        var spaces = await db.Spaces
            .AsNoTracking()
            .OrderBy(t => t.Name)
            .ToListAsync();
        var spaceIds = spaces.Select(t => t.Id).ToList();

        // CAs per space and the instance's (exclude soft-deleted), grouped for nesting.
        var cas = await db.CertificateAuthorities
            .AsNoTracking()
            .Where(ca => (ca.SpaceId == null || spaceIds.Contains(ca.SpaceId.Value)) && !ca.IsDeleted)
            .Select(ca => new { ca.Id, ca.SpaceId, ca.Name, ca.Label, ca.Type, ca.IsEnabled, ca.IsSshCa })
            .ToListAsync();
        var casBySpace = cas.Where(c => c.SpaceId != null).GroupBy(c => c.SpaceId!.Value).ToDictionary(g => g.Key, g => g.ToList());
        var instanceCas = cas.Where(c => c.SpaceId == null).ToList();

        // Distinct user counts per space (via group memberships) — same source as the space list.
        var userCounts = await db.CaGroupMembers
            .Where(gm => gm.Group.SpaceId != null && spaceIds.Contains(gm.Group.SpaceId.Value))
            .GroupBy(gm => gm.Group.SpaceId!.Value)
            .Select(g => new { SpaceId = g.Key, Count = g.Select(gm => gm.UserId).Distinct().Count() })
            .ToDictionaryAsync(x => x.SpaceId, x => x.Count);
        var instanceUserCount = await db.CaGroupMembers
            .Where(gm => gm.Group.SpaceId == null)
            .Select(gm => gm.UserId).Distinct().CountAsync();

        object CaDto(Guid id, string name, string label, string? type, bool isEnabled, bool isSshCa)
        {
            var q = quotaByCa.GetValueOrDefault(id);
            return new
            {
                Id = id,
                Name = name,
                Label = label,
                Type = type,
                IsEnabled = isEnabled,
                IsSshCa = isSshCa,
                Quota = q == null ? null : new
                {
                    groupId = q.GroupId,
                    maxCertificates = q.MaxCertificates,
                    maxPendingRequests = q.MaxPendingRequests,
                    issuedCount = q.IssuedCount,
                    pendingCount = q.PendingCount,
                    remainingCount = q.RemainingCount,
                    usagePercent = q.UsagePercent,
                    isExceeded = q.IsExceeded
                }
            };
        }

        var instancePolicy = await new EffectivePolicyResolver(db).ResolveAsync(null);
        var instance = new
        {
            instancePolicy.RequireKeyCeremony,
            instancePolicy.CeremonyRequiredApprovals,
            instancePolicy.MaxValidityDays,
            instancePolicy.ValidityCeilingBehavior,
            CaCount = instanceCas.Count,
            UserCount = instanceUserCount,
            IssuedCertificates = instanceCas.Sum(ca => quotaByCa.GetValueOrDefault(ca.Id)?.IssuedCount ?? 0),
            CertificateAuthorities = instanceCas.Select(ca => CaDto(ca.Id, ca.Name, ca.Label, ca.Type, ca.IsEnabled, ca.IsSshCa)).ToList(),
        };

        var spaceDtos = spaces.Select(t =>
        {
            var spaceCas = casBySpace.GetValueOrDefault(t.Id, new());
            var caDtos = spaceCas.Select(ca => CaDto(ca.Id, ca.Name, ca.Label, ca.Type, ca.IsEnabled, ca.IsSshCa)).ToList();

            // Active certificates across the space's CAs.
            var spaceIssued = spaceCas.Sum(ca => quotaByCa.GetValueOrDefault(ca.Id)?.IssuedCount ?? 0);

            return new
            {
                t.Id,
                t.Name,
                t.Slug,
                t.Description,
                t.IsEnabled,
                t.CreatedAt,
                t.MaxValidityDays,
                t.ValidityCeilingBehavior,
                t.RequireKeyCeremony,
                t.CeremonyRequiredApprovals,
                CaCount = spaceCas.Count,
                UserCount = userCounts.GetValueOrDefault(t.Id, 0),
                IssuedCertificates = spaceIssued,
                CertificateAuthorities = caDtos
            };
        }).ToList();

        return Ok(new
        {
            spaces = spaceDtos,
            instance,
            totals = new
            {
                totalSpaces = spaceDtos.Count,
                totalCAs = summary.CaQuotas.Count,
                casAtLimit = summary.ExceededCount,
                casNearLimit = summary.WarningCount
            },
        });
    }

    /// <summary>
    /// Returns detailed quota status for a single CA identified by its ID.
    /// </summary>
    /// <param name="caId">The certificate authority ID.</param>
    [HttpGet("{caId:guid}")]
    public async Task<IActionResult> GetQuota(Guid caId)
    {
        try
        {
            var status = await quotaService.CheckQuotaAsync(caId);
            return Ok(status);
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Updates certificate quota limits on a CA group. Only admin-level groups can
    /// have quotas configured. Use 0 to indicate unlimited.
    /// </summary>
    /// <param name="groupId">The CA group ID to update.</param>
    /// <param name="request">The new quota limits.</param>
    [HttpPut("{groupId:guid}")]
    public async Task<IActionResult> UpdateQuota(Guid groupId, [FromBody] UpdateQuotaRequest request)
    {
        var group = await db.CaGroups.Include(g => g.Grants).FirstOrDefaultAsync(g => g.Id == groupId);
        if (group == null)
            return NotFound(new { error = "Group not found." });

        if (group.TemplateName != "Administrator" && !group.Grants.Any(gr => gr.Capability == Capabilities.CaManage))
            return BadRequest(new { error = "Quotas can only be configured on admin-level groups." });

        if (request.MaxCertificates < 0)
            return BadRequest(new { error = "MaxCertificates must be 0 (unlimited) or a positive integer." });

        if (request.MaxPendingRequests < 0)
            return BadRequest(new { error = "MaxPendingRequests must be 0 (unlimited) or a positive integer." });

        var oldMaxCerts = group.MaxCertificates;
        var oldMaxPending = group.MaxPendingRequests;

        group.MaxCertificates = request.MaxCertificates;
        group.MaxPendingRequests = request.MaxPendingRequests;
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(
            AuditActionType.QuotaUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "CaGroup",
            groupId.ToString(),
            new
            {
                GroupName = group.Name,
                OldMaxCertificates = oldMaxCerts,
                NewMaxCertificates = request.MaxCertificates,
                OldMaxPendingRequests = oldMaxPending,
                NewMaxPendingRequests = request.MaxPendingRequests
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            group.Id,
            group.Name,
            group.MaxCertificates,
            group.MaxPendingRequests
        });
    }
}

/// <summary>
/// Request body for updating certificate quota limits on a CA group.
/// </summary>
public class UpdateQuotaRequest
{
    /// <summary>Maximum certificates that can be issued. 0 = unlimited.</summary>
    public int MaxCertificates { get; set; }

    /// <summary>Maximum pending CSRs allowed. 0 = unlimited.</summary>
    public int MaxPendingRequests { get; set; }
}
