using ModularCA.API.Startup;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Services;

/// <summary>
/// The published-CRL check of a start (<c>docs/architecture/rollback-continuity.md</c>, section 3):
/// reads back the CRLs this instance published elsewhere and, when one carries a higher number
/// than the database knows, treats the start as one from an earlier state
/// (<see cref="InstanceContinuity.CheckPublishedCrlsAsync"/>). It is a hosted service registered
/// before the scheduler, and the host starts its services in order and waits for each, so it has
/// finished before the scheduler ticks and before this process generates or serves a CRL.
/// <para>
/// It never fails a start: a publisher that does not answer is skipped, and any fault is logged.
/// </para>
/// </summary>
public sealed class PublishedCrlCheckService(IServiceScopeFactory scopes, ContinuityStartState state, ILogger<PublishedCrlCheckService> logger) : IHostedService
{
    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var readers = scope.ServiceProvider.GetServices<IPublishedCrlReader>().ToList();
            var published = new List<PublishedCrl>();
            foreach (var reader in readers)
                published.AddRange(await reader.ReadAsync(cancellationToken));
            state.PublishedCompared(published.Count);
            if (published.Count == 0)
                return;

            var ahead = await InstanceContinuity.CheckPublishedCrlsAsync(
                scope.ServiceProvider.GetRequiredService<ModularCADbContext>(),
                scope.ServiceProvider.GetService<AuditDbContext>(),
                scope.ServiceProvider.GetRequiredService<IAuditService>(),
                published, DateTimeOffset.UtcNow, logger, cancellationToken);
            if (ahead.Count == 0)
                logger.LogInformation("Published-CRL check: {Count} CRL(s) read back; none is ahead of the database.", published.Count);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "The published-CRL check could not be completed. The start goes on without it.");
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
