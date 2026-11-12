using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Core.Services.Settings;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Reports whether the secrets the signer wraps have been read. A node whose remote signer did
/// not answer at start runs without them (the JWT secret a temporary one, the directory and mail
/// passwords and the webhook endpoints unread, or still unmoved in <c>config.yaml</c>) until the
/// signer answers and <see cref="ModularCA.API.Services.SignerSecretsRetryService"/> reads them.
/// Until then the entry is unhealthy, so <c>/health/live</c> and <c>/health/ready</c> answer 503
/// and a load balancer or container manager treats the node as not ready rather than whole.
/// </summary>
public sealed class SignerSecretsHealthCheck(SignerSecretsState state) : IHealthCheck
{
    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!state.Pending)
            return Task.FromResult(HealthCheckResult.Healthy("The secrets the signer wraps have been read",
                new Dictionary<string, object> { ["signerSecrets"] = new { pending = false } }));

        var data = new Dictionary<string, object>
        {
            ["signerSecrets"] = new { pending = true, since = state.Since, detail = state.Detail },
        };
        return Task.FromResult(HealthCheckResult.Unhealthy(state.Detail ?? "The secrets the signer wraps have not been read yet", data: data));
    }
}
