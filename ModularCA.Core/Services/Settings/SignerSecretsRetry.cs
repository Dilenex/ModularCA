using Microsoft.Extensions.Logging;
using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services.Settings;

/// <summary>
/// Whether this process still waits to read the secrets its signer wraps: true from a start at
/// which the remote signer did not answer until <see cref="SignerSecretsRetry"/> has read them.
/// The node's health reports it, so a process that started without its secrets says it is not
/// ready instead of looking whole.
/// </summary>
public sealed class SignerSecretsState
{
    private volatile bool _pending;
    private volatile string? _detail;
    private DateTime? _since;
    private readonly HashSet<string> _madeUp = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>Whether the secrets have not been read yet because the signer did not answer.</summary>
    public bool Pending => _pending;

    /// <summary>Since when, in UTC; null when nothing is pending.</summary>
    public DateTime? Since
    {
        get { lock (_gate) return _since; }
    }

    /// <summary>What is waiting, for the health report and the log. Holds no secret.</summary>
    public string? Detail => _detail;

    /// <summary>
    /// The secrets, by key, whose value this process made up for itself while it waits (the
    /// temporary JWT secret): never stored, replaced by the stored value once it is read.
    /// </summary>
    public IReadOnlySet<string> MadeUp
    {
        get { lock (_gate) return new HashSet<string>(_madeUp, StringComparer.Ordinal); }
    }

    /// <summary>Records that the secrets wait for the signer, and why.</summary>
    public void MarkPending(string detail)
    {
        lock (_gate)
        {
            _since ??= DateTime.UtcNow;
            _detail = detail;
            _pending = true;
        }
    }

    /// <summary>Records that this process runs on a value it made up for the secret <paramref name="key"/>.</summary>
    public void MarkMadeUp(string key)
    {
        lock (_gate)
            _madeUp.Add(key);
    }

    /// <summary>Records that the secrets have been read: nothing is pending, and no value is made up any longer.</summary>
    public void MarkDone()
    {
        lock (_gate)
        {
            _pending = false;
            _detail = null;
            _since = null;
            _madeUp.Clear();
        }
    }
}

/// <summary>
/// The background half of the settings step for a node whose remote signer did not answer when
/// the node started, which is what happens when a container manager starts the two together and
/// the node wins. Until the signer answers, the secrets the node keeps wrapped behind it stay
/// where the start left them: unmoved in <c>config.yaml</c> on a first start, unread (and the JWT
/// secret a temporary one) on a later one. This asks the signer's health with backoff and, once
/// it answers, runs the secrets step again (<see cref="SettingsRuntime.CompleteSecretsAsync"/>
/// through the delegate it is given) without a restart, then clears <see cref="SignerSecretsState"/>.
/// </summary>
/// <param name="signer">The node's signer, whose health says whether it answers.</param>
/// <param name="state">What the node's health reports; cleared once the secrets are read.</param>
/// <param name="complete">Runs the secrets step once and returns what it did. Called only once the signer answers.</param>
/// <param name="logger">Where progress goes.</param>
/// <param name="firstDelay">The first wait; it doubles after each attempt that finds the signer down.</param>
/// <param name="maxDelay">The longest wait between attempts.</param>
public sealed class SignerSecretsRetry(
    ISigningService signer,
    SignerSecretsState state,
    Func<CancellationToken, Task<SettingsSecretsReport>> complete,
    ILogger logger,
    TimeSpan firstDelay,
    TimeSpan maxDelay)
{
    /// <summary>The first wait of the service as it runs.</summary>
    public static readonly TimeSpan DefaultFirstDelay = TimeSpan.FromSeconds(2);

    /// <summary>The longest wait between attempts of the service as it runs.</summary>
    public static readonly TimeSpan DefaultMaxDelay = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Waits, asks, and completes, until the secrets step has run or <paramref name="stoppingToken"/>
    /// is cancelled. An attempt that fails for any other reason (the database, say) is logged and
    /// tried again on the same backoff. Returns the report of the step that ran; null when stopped first.
    /// </summary>
    public async Task<SettingsSecretsReport?> RunAsync(CancellationToken stoppingToken)
    {
        var delay = firstDelay;
        for (var attempt = 1; !stoppingToken.IsCancellationRequested; attempt++)
        {
            try
            {
                await Task.Delay(Jitter(delay), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return null;
            }

            try
            {
                var health = await signer.HealthAsync(stoppingToken);
                if (health.Backend == SignerHealth.UnreachableBackend)
                {
                    if (attempt == 1 || delay < maxDelay && delay * 2 >= maxDelay)
                        logger.LogWarning("Settings: the signer still does not answer; the secrets it wraps are read when it does. Asking again every {Seconds} s at most.",
                            maxDelay.TotalSeconds);
                    delay = Next(delay);
                    continue;
                }

                var report = await complete(stoppingToken);
                state.MarkDone();
                Describe(report);
                return report;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return null;
            }
            catch (Exception ex)
            {
                logger.LogWarning("Settings: reading the secrets once the signer answered failed ({Kind}: {Message}); trying again.", ex.GetType().Name, ex.Message);
                delay = Next(delay);
            }
        }
        return null;
    }

    /// <summary>The next wait: twice the last, at most <c>maxDelay</c>.</summary>
    private TimeSpan Next(TimeSpan delay) => TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, maxDelay.Ticks));

    /// <summary><paramref name="delay"/> plus or minus 20%.</summary>
    private static TimeSpan Jitter(TimeSpan delay) =>
        TimeSpan.FromMilliseconds(delay.TotalMilliseconds * (0.8 + Random.Shared.NextDouble() * 0.4));

    /// <summary>Logs what the step did, as the start would have. No secret is in any line.</summary>
    private void Describe(SettingsSecretsReport report)
    {
        logger.LogInformation("Settings: the signer answers; the secrets it wraps have been read and are in force from now on.");
        if (report.SecretsMoved.Count > 0)
            logger.LogWarning("Settings: {Count} secret(s) moved from config.yaml to the database, wrapped by the signer: {Keys}. Earlier copies of config.yaml, and backup archives made before now, still hold them in the clear.",
                report.SecretsMoved.Count, string.Join(", ", report.SecretsMoved));
        foreach (var problem in report.SecretProblems)
            logger.LogWarning("Settings: {Problem}", problem);
        if (report.FileBackup != null)
            logger.LogWarning("Settings: config.yaml rewritten without the moved secrets; the file as it was, less those secrets, is {Backup}", report.FileBackup);
        if (report.FileProblem != null)
            logger.LogWarning("Settings: config.yaml could not be rewritten without the secrets that are now in the database ({Problem}). They are ignored where they stand.", report.FileProblem);
    }
}
