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
                incarnationCheck = state.Case?.ToString(),
                checkFault = state.Fault,
                publishedCrlsCompared = state.PublishedCrlsCompared,
                journalReplayed = false,
                events = events.Select(e => new
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
