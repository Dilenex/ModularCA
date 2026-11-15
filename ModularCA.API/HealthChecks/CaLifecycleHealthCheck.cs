using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Utils;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// The notices about each CA's key and certificate in <c>/health/ready</c>, under
/// <c>checks.caLifecycle</c>: the same list the CA's page shows as <c>keyAdvisories</c>
/// (<see cref="CaKeyPolicy.Advisories"/> and <see cref="CaCryptoperiod.Advisories"/>), for every
/// enabled X.509 CA that has any. <c>status</c> is <c>ok</c> with none, <c>notice</c> when there
/// is something to plan for, and <c>attention</c> when one is a warning or critical (a CA
/// certificate in its expiry warning, or expired). The dashboard lists those under "Needs
/// attention".
/// <para>
/// The entry is always healthy. A CA certificate that nears its end is something an
/// administrator acts on, in months; a node that answered not ready for it would be taken out
/// of service while it still serves everything it served the day before.
/// </para>
/// </summary>
public sealed class CaLifecycleHealthCheck(IServiceProvider services) : IHealthCheck
{
    /// <summary>The status when no CA carries a notice.</summary>
    public const string Ok = "ok";

    /// <summary>The status when a CA carries a notice and none is a warning or critical.</summary>
    public const string Notice = "notice";

    /// <summary>The status when a CA carries a warning or a critical notice.</summary>
    public const string Attention = "attention";

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        object report;
        try
        {
            // Resolved here, not in the constructor: a process without the database (setup mode)
            // must get an answer from this check, not an exception from building it.
            var db = services.GetRequiredService<ModularCADbContext>();
            var lifecycle = services.GetRequiredService<CaLifecycleService>();
            var now = DateTime.UtcNow;
            var cas = await db.CertificateAuthorities.AsNoTracking()
                .Include(ca => ca.Certificate)
                .Where(ca => !ca.IsSshCa && ca.IsEnabled && ca.CertificateId != null)
                .ToListAsync(cancellationToken);
            var periods = await lifecycle.DescribeAsync(cas, now, cancellationToken);

            var listed = cas
                .Select(ca => new
                {
                    Ca = ca,
                    Advisories = CaKeyPolicy.Advisories(ca.Certificate)
                        .Concat(periods.TryGetValue(ca.Id, out var period) ? period.Advisories : []).ToList(),
                })
                .Where(x => x.Advisories.Count > 0)
                .OrderBy(x => x.Ca.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var pressing = listed.Count(x => x.Advisories.Any(a => a.Severity != CaKeyAdvisory.Notice));
            report = new
            {
                status = pressing > 0 ? Attention : listed.Count > 0 ? Notice : Ok,
                message = pressing > 0
                    ? $"{pressing} CA(s) need attention: a CA certificate is in its expiry warning or has expired. Each CA's page says what to do."
                    : listed.Count > 0
                        ? $"{listed.Count} CA(s) carry a notice about their key or certificate. Nothing has stopped; each CA's page says what to plan for."
                        : null,
                casWithNotices = listed.Count,
                casNeedingAttention = pressing,
                cas = listed.Select(x => new
                {
                    caId = x.Ca.Id,
                    caName = x.Ca.Name,
                    caLabel = x.Ca.Label,
                    certificateNotAfter = x.Ca.Certificate?.NotAfter,
                    // The CA's page in the console, as a path a link from elsewhere can use.
                    consolePath = $"/admin/authorities/manage/{x.Ca.Id:D}",
                    keyAdvisories = x.Advisories.Select(a => new { reason = a.Reason, severity = a.Severity, title = a.Title, message = a.Message }).ToList(),
                }).ToList(),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Setup mode, or a database the main check already reports.
            Serilog.Log.Debug(ex, "Health check: the CA lifecycle notices could not be read");
            report = new { status = "unknown", message = "The CA lifecycle notices could not be read." };
        }
        return HealthCheckResult.Healthy(data: new Dictionary<string, object> { ["caLifecycle"] = report });
    }
}
