using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using ModularCA.Core.Services.ProxyProtocol;

namespace ModularCA.API.ProxyProtocol;

/// <summary>
/// Wires the PROXY protocol into a host: the connection middleware on the listeners an operator
/// marked (<c>Https.ProxyProtocol</c>, <c>Http.ProxyProtocol</c>), and the forwarded-headers step
/// kept off the connections that came through it. Public and static so a test can host the same
/// wiring on its own Kestrel listeners.
/// </summary>
public static class ProxyProtocolHosting
{
    /// <summary>
    /// Makes the listener take the PROXY protocol. Call it before <c>UseHttps</c> on the same
    /// listener, so the header is read ahead of TLS and the handshake, client certificates and
    /// ALPN work as before on the bytes that follow.
    /// </summary>
    /// <param name="listenOptions">The listener.</param>
    /// <param name="trustedProxies">The networks allowed to send the header (<c>Http.ProxyProtocolTrustedCidrs</c>); never empty.</param>
    /// <param name="listenerName">The listener's name for the log.</param>
    /// <param name="headerTimeout">The deadline for the header; <see cref="ProxyProtocolConnectionMiddleware.DefaultHeaderTimeout"/> when null.</param>
    public static ListenOptions UseProxyProtocol(
        this ListenOptions listenOptions,
        IReadOnlyList<IPNetwork> trustedProxies,
        string listenerName,
        TimeSpan? headerTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(listenOptions);
        ArgumentNullException.ThrowIfNull(trustedProxies);
        if (trustedProxies.Count == 0)
            throw new ArgumentException("A listener that takes the PROXY protocol needs at least one trusted proxy network.", nameof(trustedProxies));

        var networks = trustedProxies.ToArray();
        var timeout = headerTimeout ?? ProxyProtocolConnectionMiddleware.DefaultHeaderTimeout;
        listenOptions.Use(next =>
        {
            var loggerFactory = listenOptions.ApplicationServices.GetService<ILoggerFactory>();
            var logger = (ILogger?)loggerFactory?.CreateLogger<ProxyProtocolConnectionMiddleware>()
                ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
            return new ProxyProtocolConnectionMiddleware(next, networks, timeout, logger, listenerName).OnConnectionAsync;
        });
        return listenOptions;
    }

    /// <summary>
    /// Adds the forwarded-headers step for every request except those on a connection whose
    /// address came from a PROXY header. There the address is the one the trusted proxy wrote
    /// from the TCP connection, and an <c>X-Forwarded-For</c> the client wrote inside its own
    /// TLS must not replace it, not even when that address happens to be loopback or inside
    /// <c>Http.TrustedProxyCidrs</c> (loopback is always a known proxy to this step). Requests
    /// on other listeners get the step exactly as before.
    /// </summary>
    /// <param name="app">The pipeline.</param>
    /// <param name="options">The forwarded-headers options, as configured for the other listeners.</param>
    public static IApplicationBuilder UseForwardedHeadersUnlessProxyProtocol(this IApplicationBuilder app, ForwardedHeadersOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);
        return app.UseWhen(
            context => !ArrivedThroughProxyProtocol(context),
            branch => branch.UseForwardedHeaders(options));
    }

    /// <summary>Whether the request's connection came through a listener's PROXY header.</summary>
    /// <param name="context">The request.</param>
    public static bool ArrivedThroughProxyProtocol(HttpContext context)
        => context.Features.Get<ProxyProtocolFeature>() is not null;
}
