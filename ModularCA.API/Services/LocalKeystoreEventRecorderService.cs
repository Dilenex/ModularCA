using ModularCA.Core.Services;

namespace ModularCA.API.Services;

/// <summary>
/// Runs <see cref="LocalKeystoreEventRecorder"/> for as long as the node runs: on a node that
/// holds the signer in process, a keystore event becomes an audit row when it is written, not at
/// the next start. Registered on the control role only, which is where the audit trail is
/// written from, and only with an audit database. A node whose signer is remote runs
/// <see cref="SignerKeystoreEventDeliveryService"/> instead.
/// </summary>
public sealed class LocalKeystoreEventRecorderService : BackgroundService
{
    private readonly LocalKeystoreEventRecorder _recorder;

    /// <summary>Creates the service over the recorder.</summary>
    public LocalKeystoreEventRecorderService(LocalKeystoreEventRecorder recorder)
    {
        _recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _recorder.RunAsync(stoppingToken);
}
