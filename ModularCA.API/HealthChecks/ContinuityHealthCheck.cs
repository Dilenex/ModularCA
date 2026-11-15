using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.API.Startup;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Puts the standing continuity notice in <c>/health/ready</c>
/// (<c>docs/architecture/rollback-continuity.md</c>, section 2): under <c>continuity</c>, the
/// events nobody has acknowledged, each with what the console shows for it, so an orchestrator
/// can read that the instance runs from an earlier or copied state and wait for an administrator.
/// <para>
/// The entry is always healthy. An instance that came back after a rollback serves; reporting it
/// not ready would take it out of rotation and turn a recoverable gap into an outage, which is
/// what the design rejects. A reader that must act on the notice reads
/// <c>checks.continuity.status</c>, which is <c>notice</c> while one stands.
/// </para>
/// <para>
/// Two things are reported and kept apart. <c>incarnationCheck</c>, with
/// <c>incarnationCheckedAt</c>, is the comparison this process made at its own start.
/// <c>events</c> are the events still waiting to be acknowledged, whichever start recorded them:
/// each carries <c>detectedAt</c>, when it was recorded, and <c>recordedAtThisStart</c>, true
/// when this process recorded it at this start and false when an earlier start, or another
/// process, did. <c>eventsFromThisStart</c> and <c>eventsFromEarlierStarts</c> count the two. So
/// <c>incarnationCheck: "Same"</c> beside an event with <c>recordedAtThisStart: false</c> reads as
/// it is: nothing new at this start, and an earlier notice nobody has acknowledged yet.
/// </para>
/// </summary>
public sealed class ContinuityHealthCheck(ModularCADbContext db, ContinuityStartState state) : IHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        object report;
        try
        {
            var events = await InstanceContinuity.UnacknowledgedAsync(db, cancellationToken);
            report = new
            {
                status = events.Count > 0 ? "notice" : state.Fault != null ? "check_failed" : "ok",
                unacknowledged = events.Count,
                // The comparison this process made at its own start, and when. It says nothing of
                // the events below that an earlier start recorded: "Same" here beside an open
                // event means this start found nothing new, and the earlier notice still stands.
                incarnationCheck = state.Case?.ToString(),
                incarnationCheckedAt = state.ComparedAt,
                eventsFromThisStart = events.Count(e => state.RecordedAtThisStart(e.Id)),
                eventsFromEarlierStarts = events.Count(e => !state.RecordedAtThisStart(e.Id)),
                checkFault = state.Fault,
                publishedCrlsCompared = state.PublishedCrlsCompared,
                journalReplayed = false,
                events = events.Select(e => new
                {
                    id = e.Id,
                    kind = e.Kind,
                    detectedAt = e.DetectedAt,
                    recordedAtThisStart = state.RecordedAtThisStart(e.Id),
                    oldTag = e.OldTag,
                    newTag = e.NewTag,
                    edgeOfMemoryUtc = e.EdgeOfMemoryUtc,
                    auditNewestUtc = e.AuditNewestUtc,
                    crlNumberFloor = e.CrlNumberFloor,
                    crlCountersRaised = e.CrlCountersRaised,
                    message = InstanceContinuity.MessageFor(e),
                }).ToList(),
            };
        }
        catch (Exception ex)
        {
            // Setup mode, or a database the main check already reports: nothing to say here.
            Serilog.Log.Debug(ex, "Health check: the continuity events could not be read");
            report = new { status = "unknown" };
        }
        return HealthCheckResult.Healthy("Continuity notice", new Dictionary<string, object> { ["continuity"] = report });
    }
}
