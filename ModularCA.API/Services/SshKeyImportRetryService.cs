using ModularCA.Core.Services;
using ModularCA.Shared.Signing;

namespace ModularCA.API.Services;

/// <summary>
/// Runs the import of SSH CA keys into the signer again, in the background of the control role,
/// for as long as a key is left: the pass at start imports nothing while the signer is locked
/// or out of reach, and a signer that is unlocked later must not need a restart of the node.
/// </summary>
/// <remarks>
/// It polls, as <see cref="WhitelistRewarmService"/> does and for the same reason: there is
/// nothing to subscribe to. A remote signer says it is unlocked only when asked, and nothing
/// announces a file an operator has put in place. Every <see cref="Interval"/> it reads
/// <see cref="SshKeyImportState"/>, which costs nothing, and asks the signer for its state only
/// while keys wait on the signer. Keys left for a reason an operator has to act on are looked
/// at again every <see cref="SettledInterval"/>. It ends once nothing is left: a key file can
/// only appear again through a restore, after which the node restarts.
/// </remarks>
public sealed class SshKeyImportRetryService : BackgroundService
{
    /// <summary>How often the state of the last pass is read, and the signer asked while keys wait on it.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);

    /// <summary>How often keys left for a reason other than the signer's state are looked at again.</summary>
    public static readonly TimeSpan SettledInterval = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopes;
    private readonly ISigningService _signer;
    private readonly SshKeyImportState _state;
    private readonly ILogger<SshKeyImportRetryService> _logger;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _settledInterval;

    /// <summary>Creates the retry with the intervals the service runs at.</summary>
    public SshKeyImportRetryService(IServiceScopeFactory scopes, ISigningService signer, SshKeyImportState state, ILogger<SshKeyImportRetryService> logger)
        : this(scopes, signer, state, logger, Interval, SettledInterval)
    {
    }

    /// <summary>Creates the retry with intervals of the caller's choosing, for tests.</summary>
    public SshKeyImportRetryService(IServiceScopeFactory scopes, ISigningService signer, SshKeyImportState state,
        ILogger<SshKeyImportRetryService> logger, TimeSpan interval, TimeSpan settledInterval)
    {
        _scopes = scopes;
        _signer = signer;
        _state = state;
        _logger = logger;
        _interval = interval;
        _settledInterval = settledInterval;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                switch (_state.Next(DateTime.UtcNow, _settledInterval))
                {
                    case SshKeyImportNext.Nothing:
                        return;
                    case SshKeyImportNext.Wait:
                        continue;
                    case SshKeyImportNext.RunWhenSignerUnlocked when !(await _signer.HealthAsync(stoppingToken)).Unlocked:
                        continue;
                }

                using var scope = _scopes.CreateScope();
                var report = await scope.ServiceProvider.GetRequiredService<SshKeyFileImport>().RunAsync(stoppingToken);
                if (report.Imported.Count > 0)
                    _logger.LogInformation("SSH key import: {Imported} key(s) imported into the signer in the background; {Awaiting} still await import.",
                        report.Imported.Count, report.Awaiting.Count);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("SSH key import: a background pass failed ({Error}: {Message}); it is tried again.", ex.GetType().Name, ex.Message);
            }
        }
    }
}
