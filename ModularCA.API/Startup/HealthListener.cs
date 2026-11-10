using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace ModularCA.API.Startup;

/// <summary>
/// The loopback-only health listener (<c>Health.LoopbackPort</c>): plain HTTP on
/// <c>127.0.0.1</c>, never with the PROXY protocol, serving <c>/health</c>,
/// <c>/health/live</c> and <c>/health/ready</c> and nothing else. It exists for this host's own
/// health command (<c>--check-ready</c>, the pod's probes), which connects from loopback and so
/// is closed by a main listener that takes the PROXY protocol from a proxy elsewhere. Public and
/// static so a test can host the same wiring on its own Kestrel.
/// </summary>
/// <remarks>
/// <para>
/// IPv4 loopback only. The health command connects to <c>127.0.0.1</c>, and binding <c>::1</c>
/// as well would add nothing for it while failing the start on a host or container with IPv6
/// turned off.
/// </para>
/// <para>
/// The port is gated by <see cref="UseHealthPortGate"/>, the first step of the pipeline: a
/// request on it for any other path, or with a method other than GET or HEAD, is answered 404
/// before any other middleware runs. The health paths then go through the pipeline like a
/// loopback health request on a main listener: the IP allow-list (the System rule, which lets
/// loopback in by default), the scheme redirect, the setup redirect and the request audit all
/// let <c>/health</c> through as they do there, and <c>/health/ready</c> still needs its
/// SystemAuditor token. The ingress branch never routes a request from this port.
/// </para>
/// </remarks>
public static class HealthListener
{
    /// <summary>The only paths the port serves.</summary>
    public static readonly IReadOnlyList<string> Paths = ["/health", "/health/live", "/health/ready"];

    /// <summary>
    /// Opens the listener: plain HTTP/1.1 on <c>127.0.0.1</c>:<paramref name="port"/>, with no
    /// connection middleware, so never the PROXY protocol whatever the main listeners take.
    /// </summary>
    /// <param name="options">Kestrel's options.</param>
    /// <param name="port"><c>Health.LoopbackPort</c>, already validated; above 0.</param>
    public static void Listen(KestrelServerOptions options, int port)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        options.Listen(IPAddress.Loopback, port, listen => listen.Protocols = HttpProtocols.Http1);
    }

    /// <summary>Whether <paramref name="path"/> is one of <see cref="Paths"/>, exactly, in any case.</summary>
    /// <param name="path">The request path.</param>
    public static bool IsHealthPath(PathString path)
        => Paths.Any(p => path.Equals(new PathString(p), StringComparison.OrdinalIgnoreCase));

    /// <summary>Whether the request arrived on the health port; never when <paramref name="port"/> is 0.</summary>
    /// <param name="context">The request.</param>
    /// <param name="port"><c>Health.LoopbackPort</c>.</param>
    public static bool ArrivedOnHealthPort(HttpContext context, int port)
        => port > 0 && context.Connection.LocalPort == port;

    /// <summary>
    /// Adds the gate as the next step of <paramref name="app"/>, which must be its first: a
    /// request on the health port that is not a GET or HEAD of one of <see cref="Paths"/> is
    /// answered 404 and goes no further. Requests on other ports pass untouched.
    /// </summary>
    /// <param name="app">The pipeline.</param>
    /// <param name="port"><c>Health.LoopbackPort</c>, above 0.</param>
    public static IApplicationBuilder UseHealthPortGate(this IApplicationBuilder app, int port)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        return app.Use(async (context, next) =>
        {
            if (ArrivedOnHealthPort(context, port)
                && !((HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)) && IsHealthPath(context.Request.Path)))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            await next(context);
        });
    }
}
