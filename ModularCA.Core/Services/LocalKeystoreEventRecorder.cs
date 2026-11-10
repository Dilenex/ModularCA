using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Keystore.Services;

namespace ModularCA.Core.Services;

/// <summary>
/// Gets the keystore events of a node that holds the signer in process into the audit trail
/// when they happen. The keystore service records an event (a key appended, a keystore created,
/// a signature, pin or unlock that failed) from static code with no audit service at hand, as a
/// line in <c>logs/bootstrap-audit-*.jsonl</c>; until now such a line became an audit row only
/// when the node next started and replayed the file. This listens for
/// <see cref="KeystoreService.AuditEventWritten"/> and, a moment after a line is written, has
/// <see cref="BootstrapAuditReplayService.RecordNewLinesAsync"/> record what the trail lacks.
/// </summary>
/// <remarks>
/// <para>
/// Nothing is recorded twice. A row carries the id the file replay gives the same line, so the
/// drain at the next start finds the file's lines already in the trail, writes none and renames
/// the file; this never renames or removes a file itself.
/// </para>
/// <para>
/// A pass runs when the recorder starts, for anything written before it listened, and then only
/// when an event is written. A pass that could not record everything (the audit database is
/// away) is tried again every <see cref="RetryInterval"/> until it can; the lines wait in the
/// file meanwhile, and the next start replays them if the node stops first.
/// </para>
/// </remarks>
public sealed class LocalKeystoreEventRecorder
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<LocalKeystoreEventRecorder> _logger;
    private readonly string? _logsDirectory;
    private readonly SemaphoreSlim _signal = new(0);
    private string? _lastFailure;

    /// <summary>
    /// Creates the recorder. Each pass runs in a scope of its own, where it resolves
    /// <see cref="BootstrapAuditReplayService"/>.
    /// </summary>
    /// <param name="scopes">Opens the scope of a pass.</param>
    /// <param name="logger">Receives what was recorded and what could not be.</param>
    /// <param name="logsDirectory">
    /// The directory read; null for the one the keystore service writes to in this process
    /// (<see cref="KeystoreService.AuditLogDirectory"/>, or <c>logs/</c> under the application directory).
    /// </param>
    public LocalKeystoreEventRecorder(IServiceScopeFactory scopes, ILogger<LocalKeystoreEventRecorder> logger, string? logsDirectory = null)
    {
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _logsDirectory = logsDirectory;
    }

    /// <summary>How long after an event is written the pass runs, so the events of one operation are taken together.</summary>
    public TimeSpan Settle { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>How often a pass that could not record everything is tried again.</summary>
    public TimeSpan RetryInterval { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Listens and records until <paramref name="stoppingToken"/> is cancelled. Returns when it
    /// is; never throws for a pass that fails.
    /// </summary>
    public async Task RunAsync(CancellationToken stoppingToken)
    {
        KeystoreService.AuditEventWritten += Signal;
        try
        {
            var complete = await RunOnceAsync(stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                if (complete)
                    await _signal.WaitAsync(stoppingToken);
                else
                    await _signal.WaitAsync(RetryInterval, stoppingToken);
                await Task.Delay(Settle, stoppingToken);
                while (_signal.Wait(0))
                {
                    // One pass takes every event signalled so far.
                }
                complete = await RunOnceAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            KeystoreService.AuditEventWritten -= Signal;
        }
    }

    /// <summary>
    /// The handler of <see cref="KeystoreService.AuditEventWritten"/>: wakes the loop and
    /// returns. It runs on the thread of the keystore operation and does nothing else there.
    /// </summary>
    private void Signal()
    {
        try
        {
            _signal.Release();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or SemaphoreFullException)
        {
        }
    }

    /// <summary>
    /// One pass; true when every line is in the trail. What it recorded is logged; a failure is
    /// logged once and again only when it changes, so an audit database that stays away does not
    /// fill the log.
    /// </summary>
    private async Task<bool> RunOnceAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var replay = scope.ServiceProvider.GetRequiredService<BootstrapAuditReplayService>();
            var directory = _logsDirectory ?? KeystoreService.AuditLogDirectory ?? Path.Combine(AppContext.BaseDirectory, "logs");
            var result = await replay.RecordNewLinesAsync(directory, stoppingToken);
            if (result.Recorded > 0)
                _logger.LogInformation("Recorded {Count} keystore event(s) of this node in the audit trail", result.Recorded);

            if (result.Failure == null)
            {
                if (_lastFailure != null)
                    _logger.LogInformation("This node's keystore events are being recorded again");
                _lastFailure = null;
                return true;
            }
            if (!string.Equals(result.Failure, _lastFailure, StringComparison.Ordinal))
            {
                _lastFailure = result.Failure;
                _logger.LogWarning(
                    "This node's keystore events could not all be recorded, and wait in {Directory}; it is tried again every {Interval}: {Failure}",
                    directory, RetryInterval, result.Failure);
            }
            return false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Recording this node's keystore events failed; it is tried again in {Interval}", RetryInterval);
            return false;
        }
    }
}
