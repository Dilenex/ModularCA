using Microsoft.AspNetCore.Connections.Features;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Middleware;

/// <summary>
/// Answers <c>421 Misdirected Request</c> when a request names a hostname whose TLS handshake is
/// gated (the mTLS auth subdomain, the EST subdomain) but arrives on a connection whose handshake
/// was made for another name. A browser reuses an HTTP/2 connection for every name the server
/// certificate covers and that resolves to the same address, so a request for the mTLS subdomain
/// otherwise rides the main hostname's connection, where no client certificate was asked for: the
/// picker never shows and the sign-in fails with no certificate. A 421 makes the client retry on a
/// new connection (RFC 9110 section 15.5.20), whose handshake is the gated one.
/// </summary>
/// <remarks>
/// Only a connection that sent SNI for a different name is refused. A request with no TLS handshake
/// on this node (TLS ended at a proxy) or with no SNI passes as before.
/// </remarks>
public class MisdirectedRequestMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IReadOnlyList<string> _gatedHosts;

    /// <summary>
    /// Initializes a new <see cref="MisdirectedRequestMiddleware"/>.
    /// </summary>
    /// <param name="next">The next delegate in the pipeline.</param>
    /// <param name="gatedHosts">The hostnames the handshake treats apart, as resolved at start.</param>
    public MisdirectedRequestMiddleware(RequestDelegate next, IReadOnlyList<string> gatedHosts)
    {
        _next = next;
        _gatedHosts = gatedHosts;
    }

    /// <summary>
    /// Answers 421 for a request that reached a gated hostname over another hostname's connection;
    /// otherwise invokes the next delegate.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var tls = context.Features.Get<ITlsHandshakeFeature>();
        if (tls != null && IsMisdirected(tls.HostName, context.Request.Host.Host, _gatedHosts))
        {
            context.Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("This hostname needs its own connection. Retry the request on a new connection.");
            return;
        }
        await _next(context);
    }

    /// <summary>
    /// Whether a request for <paramref name="requestHost"/> on a connection whose ClientHello named
    /// <paramref name="serverName"/> must be sent again on a new connection: the request names a
    /// gated hostname and the connection named a different one.
    /// </summary>
    /// <param name="serverName">The SNI of the connection's handshake, or null when none was sent.</param>
    /// <param name="requestHost">The request's host, without the port.</param>
    /// <param name="gatedHosts">The gated hostnames.</param>
    public static bool IsMisdirected(string? serverName, string? requestHost, IReadOnlyList<string> gatedHosts)
    {
        if (string.IsNullOrEmpty(serverName) || string.IsNullOrEmpty(requestHost))
            return false;
        if (string.Equals(serverName, requestHost, StringComparison.OrdinalIgnoreCase))
            return false;
        foreach (var gated in gatedHosts)
        {
            if (SubdomainUtil.MatchesSni(requestHost, gated))
                return true;
        }
        return false;
    }
}
