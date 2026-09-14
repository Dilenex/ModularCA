using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Services;

/// <summary>
/// Retries the whitelist snapshot load in the background until it succeeds, and again whenever
/// it goes cold.
/// </summary>
/// <remarks>
/// <para>
/// Until this existed the snapshot was loaded at startup, at bootstrap, and when an administrator
/// edited a rule, and at no other time. A database that came up a few seconds after the service
/// (the ordinary systemd ordering on a single host) left the whitelist cold for the life of the
/// process, and cold meant pass-through for every non-admin path. The middleware now fails closed
/// in that state; this service is what ends the state.
/// </para>
/// <para>
/// Polls rather than subscribes because there is nothing to subscribe to: the failure is the
/// database being unreachable. The interval is short enough that an outage's tail costs seconds,
/// and a healthy instance pays one cheap property read per tick.
/// </para>
/// </remarks>
public sealed class WhitelistRewarmService(
    IWhitelistService whitelist,
    ILogger<WhitelistRewarmService> logger) : BackgroundService
{
    /// <summary>How often to check for a cold snapshot.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (whitelist.IsWarm)
                continue;

            try
            {
                await whitelist.ReloadAsync(stoppingToken);
                if (whitelist.IsWarm)
                    logger.LogInformation("IP whitelist snapshot re-warmed after being cold.");
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                // ReloadAsync catches its own failures; this is a belt for anything it does not.
                logger.LogWarning(ex, "IP whitelist re-warm attempt failed; will retry.");
            }
        }
    }
}
