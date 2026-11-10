using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Services;

/// <summary>
/// Runs <see cref="SignerSecretsRetry"/> for a node whose remote signer did not answer at start:
/// asks the signer's health with backoff (2 s, doubling to 60 s) and, once it answers, reads the
/// wrapped secrets onto the running configuration, and moves those still in <c>config.yaml</c>
/// on the control role, without a restart. Registered only for such a start; it ends once the
/// secrets are read. Until then <see cref="SignerSecretsState"/> is pending and the node's health
/// (<see cref="ModularCA.API.HealthChecks.SignerSecretsHealthCheck"/>) reports not ready.
/// </summary>
public sealed class SignerSecretsRetryService : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ISigningService _signer;
    private readonly SignerSecretsState _state;
    private readonly SystemConfig _config;
    private readonly SettingsPersistence _persistence;
    private readonly EnvVarConfigOverlay _environment;
    private readonly bool _mayMove;
    private readonly ILogger<SignerSecretsRetryService> _logger;

    /// <summary>Creates the retry over the node's signer, its running configuration and where it saves settings.</summary>
    /// <param name="scopes">For a settings store per attempt, over the node's database and signer.</param>
    /// <param name="signer">The node's remote signer.</param>
    /// <param name="state">What the node's health reports.</param>
    /// <param name="config">The running configuration the secrets are read onto.</param>
    /// <param name="persistence">Where the node saves its settings; takes the snapshot the step reads.</param>
    /// <param name="environment">The environment overlay, whose secrets are left alone.</param>
    /// <param name="mayMove">Whether this process moves secrets out of its file: the control role.</param>
    /// <param name="logger">Where progress goes.</param>
    public SignerSecretsRetryService(IServiceScopeFactory scopes, ISigningService signer, SignerSecretsState state, SystemConfig config,
        SettingsPersistence persistence, EnvVarConfigOverlay environment, bool mayMove, ILogger<SignerSecretsRetryService> logger)
    {
        _scopes = scopes;
        _signer = signer;
        _state = state;
        _config = config;
        _persistence = persistence;
        _environment = environment;
        _mayMove = mayMove;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var madeUp = _state.MadeUp;
        var jwtBefore = _config.JWT.Secret;
        var retry = new SignerSecretsRetry(_signer, _state, async ct =>
        {
            using var scope = _scopes.CreateScope();
            var store = scope.ServiceProvider.GetRequiredService<ISettingsStore>();
            return await SettingsRuntime.CompleteSecretsAsync(store, _config, _persistence, _environment.EnvSourcedPaths, _mayMove, madeUp, ct);
        }, _logger, SignerSecretsRetry.DefaultFirstDelay, SignerSecretsRetry.DefaultMaxDelay);

        var report = await retry.RunAsync(stoppingToken);
        if (report != null && madeUp.Contains(SettingsPersistence.JwtSecretKey) && !ReferenceEquals(jwtBefore, _config.JWT.Secret))
            _logger.LogInformation("Settings: sessions are now signed and checked with the stored JWT secret. Those signed with the temporary one have ended; "
                + "a refresh or a new sign-in gets a session under the stored one.");
    }
}
