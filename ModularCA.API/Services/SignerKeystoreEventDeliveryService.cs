using ModularCA.Core.Services;

namespace ModularCA.API.Services;

/// <summary>
/// Runs <see cref="SignerKeystoreEventDelivery"/> for a node whose signer is remote: shortly
/// after the node starts, and then every <see cref="Interval"/>, it reads the signer's journal
/// of keystore events and writes what is new into the audit trail. Registered on the control
/// role only, which is where the audit trail is written from. A signer that is away, or an audit
/// database that refuses, is tried again at the next interval; the events wait on the signer.
/// </summary>
public sealed class SignerKeystoreEventDeliveryService : BackgroundService
{
    /// <summary>How long after the node starts the first pass runs.</summary>
    public static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(5);

    /// <summary>How often the journal is read.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<SignerKeystoreEventDeliveryService> _logger;
    private string? _lastFailure;

    /// <summary>Creates the service; each pass runs in a scope of its own.</summary>
    public SignerKeystoreEventDeliveryService(IServiceScopeFactory scopes, ILogger<SignerKeystoreEventDeliveryService> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(FirstDelay, stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                await RunOnceAsync(stoppingToken);
                await Task.Delay(Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>
    /// One pass. What it recorded is logged; a failure is logged once and again only when it
    /// changes, so a signer that stays away does not fill the log.
    /// </summary>
    private async Task RunOnceAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var delivery = scope.ServiceProvider.GetRequiredService<SignerKeystoreEventDelivery>();
            var result = await delivery.DeliverAsync(stoppingToken);
            if (result.Recorded > 0)
                _logger.LogInformation("Recorded {Count} keystore event(s) from the signer in the audit trail", result.Recorded);

            if (result.Failure == null)
            {
                if (_lastFailure != null)
                    _logger.LogInformation("The signer's keystore events are being recorded again");
                _lastFailure = null;
            }
            else if (!string.Equals(result.Failure, _lastFailure, StringComparison.Ordinal))
            {
                _lastFailure = result.Failure;
                if (result.SignerUnreachable)
                    _logger.LogInformation("The signer's keystore events could not be read, and wait on the signer: {Failure}", result.Failure);
                else
                    _logger.LogWarning("The signer's keystore events could not all be recorded, and wait on the signer: {Failure}", result.Failure);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Recording the signer's keystore events failed; it is tried again in {Interval}", Interval);
        }
    }
}
