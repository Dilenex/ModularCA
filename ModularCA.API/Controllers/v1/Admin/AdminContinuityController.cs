using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// The standing notice that this instance runs from an earlier or copied state
/// (<c>docs/architecture/rollback-continuity.md</c>, section 2): what a start found, and the
/// acknowledgement that ends it. Reading needs the system auditor's rights, as
/// <c>/health/ready</c> does; acknowledging needs a system administrator and step-up.
/// </summary>
[ApiController]
[Route("api/v1/admin/continuity")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminContinuityController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit) : ControllerBase
{
    /// <summary>
    /// The notice: whether any continuity event is unacknowledged, those events with the text to
    /// show for each, and the incarnation the database holds (its source and short tag; never
    /// the value).
    /// </summary>
    [HttpGet("notice")]
    [Authorize(Policy = "SystemAuditor")]
    public async Task<IActionResult> GetNotice()
    {
        var events = await InstanceContinuity.UnacknowledgedAsync(db, HttpContext.RequestAborted);
        var incarnation = await db.InstanceIncarnation.AsNoTracking().FirstOrDefaultAsync(HttpContext.RequestAborted);
        return Ok(new
        {
            applies = events.Count > 0,
            events = events.Select(Describe),
            incarnation = incarnation == null ? null : new
            {
                source = incarnation.Source,
                tag = IncarnationReading.TagOf(incarnation.ValueHash),
                recordedAt = incarnation.RecordedAt,
                recordedBy = incarnation.RecordedBy,
            },
        });
    }

    /// <summary>The continuity events, acknowledged or not, newest first; at most <paramref name="limit"/> (100 by default, 500 at most).</summary>
    [HttpGet("events")]
    [Authorize(Policy = "SystemAuditor")]
    public async Task<IActionResult> GetEvents([FromQuery] int limit = 100)
    {
        var rows = await db.InstanceContinuityEvents.AsNoTracking()
            .OrderByDescending(e => e.DetectedAt)
            .Take(Math.Clamp(limit, 1, 500))
            .ToListAsync(HttpContext.RequestAborted);
        return Ok(rows.Select(Describe));
    }

    /// <summary>
    /// Acknowledges one continuity event, which takes it out of the notice in the console and in
    /// <c>/health/ready</c>. Needs step-up for that event. Acknowledging says the administrator
    /// has read it; it changes nothing else. 404 for an event that does not exist; an event
    /// already acknowledged is returned unchanged.
    /// </summary>
    [HttpPost("events/{id:guid}/acknowledge")]
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Manage)]
    [Authorize(Policy = "SystemAdmin")]
    [RequireStepUp(StepUpOps.AcknowledgeContinuityEvent, "id")]
    public async Task<IActionResult> Acknowledge(Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        var before = await db.InstanceContinuityEvents.AsNoTracking()
            .Where(e => e.Id == id).Select(e => new { e.AcknowledgedAt }).FirstOrDefaultAsync(HttpContext.RequestAborted);
        if (before == null)
            return NotFound(new { error = "Continuity event not found." });

        var acknowledged = await InstanceContinuity.AcknowledgeAsync(db, id, currentUser.User.Id, currentUser.User.Username, HttpContext.RequestAborted);
        if (acknowledged == null)
            return NotFound(new { error = "Continuity event not found." });
        if (before.AcknowledgedAt == null)
        {
            await audit.LogAsync(AuditActionType.InstanceContinuityAcknowledged, currentUser.User.Id, currentUser.User.Username,
                "InstanceContinuityEvent", id.ToString(),
                new { acknowledged.Kind, acknowledged.DetectedAt, acknowledged.OldTag, acknowledged.NewTag, acknowledged.EdgeOfMemoryUtc },
                HttpContext.Connection.RemoteIpAddress?.ToString());
        }
        return Ok(Describe(acknowledged));
    }

    private static object Describe(InstanceContinuityEventEntity e) => new
    {
        id = e.Id,
        kind = e.Kind,
        detectedAt = e.DetectedAt,
        oldTag = e.OldTag,
        newTag = e.NewTag,
        edgeOfMemoryUtc = e.EdgeOfMemoryUtc,
        auditNewestUtc = e.AuditNewestUtc,
        crlNumberFloor = e.CrlNumberFloor,
        crlCountersRaised = e.CrlCountersRaised,
        message = InstanceContinuity.MessageFor(e),
        acknowledgedAt = e.AcknowledgedAt,
        acknowledgedBy = e.AcknowledgedByUsername,
    };
}
