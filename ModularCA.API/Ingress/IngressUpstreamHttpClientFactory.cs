using Yarp.ReverseProxy.Forwarder;

namespace ModularCA.API.Ingress;

/// <summary>
/// YARP's client factory with the upstream trust decision applied per cluster: the handler
/// for a cluster validates the node's certificate as <see cref="UpstreamTrustPolicy"/> says
/// for that cluster's pin and loopback fact. A cluster whose metadata changed (a new pin,
/// say) gets a new client rather than the old handler with the old callback.
/// </summary>
public sealed class IngressUpstreamHttpClientFactory : ForwarderHttpClientFactory
{
    private readonly UpstreamTrustPolicy _policy;

    /// <summary>Creates the factory over the trust policy.</summary>
    public IngressUpstreamHttpClientFactory(UpstreamTrustPolicy policy, ILogger<ForwarderHttpClientFactory> logger)
        : base(logger)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    /// <inheritdoc />
    protected override bool CanReuseOldClient(ForwarderHttpClientContext context)
        => base.CanReuseOldClient(context) && SameMetadata(context.OldMetadata, context.NewMetadata);

    /// <inheritdoc />
    protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        base.ConfigureHandler(context, handler);
        var callback = _policy.CallbackFor(context.NewMetadata);
        if (callback != null)
            handler.SslOptions.RemoteCertificateValidationCallback = callback;
    }

    private static bool SameMetadata(IReadOnlyDictionary<string, string>? a, IReadOnlyDictionary<string, string>? b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a == null || b == null) return a is null or { Count: 0 } && b is null or { Count: 0 };
        if (a.Count != b.Count) return false;
        foreach (var (key, value) in a)
        {
            if (!b.TryGetValue(key, out var other) || !string.Equals(value, other, StringComparison.Ordinal))
                return false;
        }
        return true;
    }
}
