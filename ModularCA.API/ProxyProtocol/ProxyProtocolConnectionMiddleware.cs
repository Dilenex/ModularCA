using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using ModularCA.Core.Services.ProxyProtocol;

namespace ModularCA.API.ProxyProtocol;

/// <summary>
/// Kestrel connection middleware for a listener that takes the PROXY protocol. It runs before
/// TLS (it is added to the listener ahead of <c>UseHttps</c>), so the header is read from the
/// raw TCP stream and everything after it, the TLS ClientHello or the plain HTTP request,
/// reaches the next middleware byte for byte.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>A TCP peer outside the trusted proxy networks is closed before a byte is read: only the
/// proxy may speak on this listener.</item>
/// <item>From a trusted peer the header is required. A connection that sends anything else, a
/// malformed header, or nothing within the deadline, is closed; its bytes are never handed on
/// as TLS or HTTP. If the header were optional, a client reaching the node directly could send
/// one and choose its own address.</item>
/// <item>A header naming a client sets the connection's remote endpoint (and so
/// <c>HttpContext.Connection.RemoteIpAddress</c> and <c>RemotePort</c>) to that client. A header
/// naming none (v2 LOCAL or UNSPEC, v1 UNKNOWN: the proxy's health checks) keeps the proxy as
/// the peer. The local endpoint is never changed: the listener-port checks downstream depend on
/// it.</item>
/// <item>Either way <see cref="ProxyProtocolFeature"/> is set on the connection, which is how the
/// request pipeline knows not to let <c>X-Forwarded-For</c> replace the address.</item>
/// </list>
/// </remarks>
public sealed class ProxyProtocolConnectionMiddleware
{
    /// <summary>How long a trusted peer has to deliver the whole header after connecting.</summary>
    public static readonly TimeSpan DefaultHeaderTimeout = TimeSpan.FromSeconds(5);

    private readonly ConnectionDelegate _next;
    private readonly IReadOnlyList<IPNetwork> _trustedProxies;
    private readonly TimeSpan _headerTimeout;
    private readonly ILogger _logger;
    private readonly string _listenerName;

    /// <summary>Creates the middleware for one listener.</summary>
    /// <param name="next">The rest of the listener's connection pipeline: TLS, then HTTP.</param>
    /// <param name="trustedProxies">The networks a peer must be in to send the header; never empty.</param>
    /// <param name="headerTimeout">The deadline for the whole header, from the start of the connection.</param>
    /// <param name="logger">Where refusals are logged.</param>
    /// <param name="listenerName">The listener's name for the log, e.g. <c>HTTPS :8443</c>.</param>
    public ProxyProtocolConnectionMiddleware(
        ConnectionDelegate next,
        IReadOnlyList<IPNetwork> trustedProxies,
        TimeSpan headerTimeout,
        ILogger logger,
        string listenerName)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(trustedProxies);
        if (trustedProxies.Count == 0)
            throw new ArgumentException("A listener that takes the PROXY protocol needs at least one trusted proxy network.", nameof(trustedProxies));
        if (headerTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(headerTimeout), "The PROXY header deadline must be positive.");
        _next = next;
        _trustedProxies = trustedProxies;
        _headerTimeout = headerTimeout;
        _logger = logger;
        _listenerName = listenerName;
    }

    /// <summary>
    /// Whether <paramref name="address"/> is in one of <paramref name="networks"/>, with an
    /// IPv4-mapped IPv6 address (how a dual-stack listener reports an IPv4 peer) compared as IPv4.
    /// </summary>
    /// <param name="address">The peer address.</param>
    /// <param name="networks">The trusted networks.</param>
    public static bool IsTrusted(IPAddress address, IReadOnlyList<IPNetwork> networks)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        foreach (var network in networks)
        {
            if (network.Contains(address))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Handles one connection: closes it unless it comes from a trusted proxy and starts with a
    /// valid PROXY header, otherwise applies the header's client address and hands the
    /// connection on with the header consumed and every later byte untouched.
    /// </summary>
    /// <param name="context">The connection.</param>
    public async Task OnConnectionAsync(ConnectionContext context)
    {
        if (context.RemoteEndPoint is not IPEndPoint peer || !IsTrusted(peer.Address, _trustedProxies))
        {
            _logger.LogWarning("[PROXY] {Listener}: connection from {Peer} closed: the listener takes the PROXY protocol and that peer is not in Http.ProxyProtocolTrustedCidrs.",
                _listenerName, context.RemoteEndPoint?.ToString() ?? "an unknown peer");
            context.Abort(new ConnectionAbortedException("The peer is not a trusted PROXY protocol sender."));
            return;
        }

        var header = await ReadHeaderAsync(context, peer);
        if (header is not { } accepted)
            return;

        if (accepted.Source is { } client)
            SetRemoteEndPoint(context, client);
        context.Features.Set(new ProxyProtocolFeature(peer, accepted.Source, accepted.Version));

        await _next(context);
    }

    /// <summary>
    /// Reads until the header is whole, refused, or late. Returns the accepted header with the
    /// pipe advanced past it, or null after closing the connection.
    /// </summary>
    private async Task<ProxyHeaderResult?> ReadHeaderAsync(ConnectionContext context, IPEndPoint peer)
    {
        var input = context.Transport.Input;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.ConnectionClosed);
        deadline.CancelAfter(_headerTimeout);

        while (true)
        {
            System.IO.Pipelines.ReadResult read;
            try
            {
                read = await input.ReadAsync(deadline.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("[PROXY] {Listener}: connection from {Peer} closed: no complete PROXY header within {Seconds}s.",
                    _listenerName, peer, _headerTimeout.TotalSeconds);
                context.Abort(new ConnectionAbortedException("No PROXY header before the deadline."));
                return null;
            }

            var buffer = read.Buffer;
            var result = ProxyProtocolParser.Parse(buffer);
            switch (result.Status)
            {
                case ProxyHeaderStatus.Complete:
                    // Consume exactly the header. The rest of this read (the ClientHello, when it
                    // came in the same segment) stays in the pipe, unexamined, so the next reader
                    // gets it at once.
                    var end = buffer.GetPosition(result.HeaderLength);
                    input.AdvanceTo(end, end);
                    return result;

                case ProxyHeaderStatus.Invalid:
                    input.AdvanceTo(buffer.Start, buffer.End);
                    _logger.LogWarning("[PROXY] {Listener}: connection from {Peer} closed: {Reason}.", _listenerName, peer, result.Error);
                    context.Abort(new ConnectionAbortedException("Invalid PROXY header."));
                    return null;

                default:
                    input.AdvanceTo(buffer.Start, buffer.End);
                    if (read.IsCompleted || read.IsCanceled)
                    {
                        // A proxy's plain TCP health check connects and closes without a byte.
                        if (buffer.IsEmpty)
                            _logger.LogDebug("[PROXY] {Listener}: connection from {Peer} closed by the peer before any byte.", _listenerName, peer);
                        else
                            _logger.LogWarning("[PROXY] {Listener}: connection from {Peer} closed: it ended inside the PROXY header.", _listenerName, peer);
                        context.Abort(new ConnectionAbortedException("The connection ended inside the PROXY header."));
                        return null;
                    }
                    break;
            }
        }
    }

    /// <summary>
    /// Makes <paramref name="client"/> the connection's remote endpoint everywhere it is read:
    /// the connection context (from which Kestrel builds each request's
    /// <see cref="IHttpConnectionFeature"/>), and any endpoint or HTTP connection feature
    /// already on the connection.
    /// </summary>
    private static void SetRemoteEndPoint(ConnectionContext context, IPEndPoint client)
    {
        context.RemoteEndPoint = client;
        if (context.Features.Get<IConnectionEndPointFeature>() is { } endPoints && !ReferenceEquals(endPoints, context))
            endPoints.RemoteEndPoint = client;
        if (context.Features.Get<IHttpConnectionFeature>() is { } connection)
        {
            connection.RemoteIpAddress = client.Address;
            connection.RemotePort = client.Port;
        }
    }
}
