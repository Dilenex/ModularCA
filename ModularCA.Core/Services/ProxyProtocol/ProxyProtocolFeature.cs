using System.Net;

namespace ModularCA.Core.Services.ProxyProtocol;

/// <summary>
/// Set on a connection that arrived on a listener taking the PROXY protocol, once its header
/// was read and accepted. Its presence is what tells the request pipeline that the client
/// address came from a trusted proxy's header, so <c>X-Forwarded-For</c> must not replace it.
/// Visible on every request of the connection through <c>HttpContext.Features</c>.
/// </summary>
/// <param name="Proxy">The TCP peer that sent the header: the proxy.</param>
/// <param name="Client">
/// The client the header named, or null when it named none (v2 <c>LOCAL</c> or UNSPEC, v1
/// <c>UNKNOWN</c>) and the connection kept the proxy as its peer.
/// </param>
/// <param name="Version">The PROXY protocol version the header used, 1 or 2.</param>
public sealed record ProxyProtocolFeature(IPEndPoint Proxy, IPEndPoint? Client, int Version);
