using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Modes;

namespace ModularCA.Core.Services;

/// <summary>
/// Records the first certificate of every CA that has none in <c>CaCertificates</c>
/// (<see cref="CaCertificateHistory.EnsureInitialRowsAsync"/>): the CAs made before the table
/// existed and those made by bootstrap. It runs in the background after the node has started,
/// as the journal's revocation merge does, and like it waits out DR mode: an instance in DR
/// mode changes nothing by itself, so nothing is written until the mode is changed, and it
/// comes back every <see cref="Interval"/> to see whether it has been. In full, restricted and
/// maintenance mode it writes: the row is a fact the instance records about itself
/// (<see cref="ModeOperation.Fact"/>), not configuration a person changes. It stops once a pass
/// has written what there was to write. Until then a CA simply has no row, and everything that
/// reads the table takes the CA's one certificate from its own row, as before the table existed.
/// </summary>
public sealed class CaCertificateHistoryService(IServiceScopeFactory scopes, IInstanceModeGate modeGate,
    ILogger<CaCertificateHistoryService> logger) : BackgroundService
{
    /// <summary>How long it waits before it looks at the mode again, or tries again after a failure.</summary>
    public static TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(15);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (!await PassAsync(stoppingToken))
                    return;
                await Task.Delay(Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }

    /// <summary>
    /// One pass. Returns whether another is needed: true while the instance is in DR mode, where
    /// nothing is written, and after a pass that failed; false once the rows are recorded.
    /// </summary>
    public async Task<bool> PassAsync(CancellationToken cancellationToken)
    {
        if (!InstanceModeGate.Allows(modeGate.Current.Mode, ModeOperation.Fact))
            return true;
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            var added = await CaCertificateHistory.EnsureInitialRowsAsync(db, cancellationToken);
            if (added > 0)
                logger.LogInformation("Recorded the first certificate of {Count} CA(s) in the certificate history.", added);
            return false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogDebug(ex, "The CA certificate history could not be completed yet.");
            return true;
        }
    }
}
