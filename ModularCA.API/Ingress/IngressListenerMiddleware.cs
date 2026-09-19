using System.Text.Json;
using Yarp.ReverseProxy.Model;

namespace ModularCA.API.Ingress;

/// <summary>
/// The step of the proxy pipeline that chooses the destination by the listener the request
/// arrived on: a request from the plain-HTTP listener goes to the route's plain-HTTP
/// upstream when it has one (the node's own CRL and OCSP listener, no redirect), every
/// other request to the HTTPS upstream. When the chosen destination is withheld because its
/// health probes fail, the request is answered 503 with a body that names the host, rather
/// than sent to a node known to be down or to the wrong listener of one that is up.
/// </summary>
public sealed class IngressListenerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly int _plainHttpPort;

    /// <summary>Creates the step; <paramref name="plainHttpPort"/> is <c>Http.Port</c>, 0 when the plain listener is off.</summary>
    public IngressListenerMiddleware(RequestDelegate next, int plainHttpPort)
    {
        _next = next;
        _plainHttpPort = plainHttpPort;
    }

    /// <summary>Whether the request arrived on the plain-HTTP listener.</summary>
    public static bool ArrivedOnPlainHttp(HttpContext context, int plainHttpPort)
        => plainHttpPort > 0 && !context.Request.IsHttps && context.Connection.LocalPort == plainHttpPort;

    /// <summary>
    /// The destination id a request should use, given the listener it arrived on and which
    /// destinations the cluster defines.
    /// </summary>
    public static string ChooseDestination(bool arrivedOnPlainHttp, bool clusterHasPlainDestination)
        => arrivedOnPlainHttp && clusterHasPlainDestination ? IngressProxyConfigProvider.PlainDestination : IngressProxyConfigProvider.HttpsDestination;

    /// <inheritdoc cref="IngressListenerMiddleware"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var proxy = context.GetReverseProxyFeature();
        var hasPlain = proxy.AllDestinations.Any(d => d.DestinationId == IngressProxyConfigProvider.PlainDestination);
        var wanted = ChooseDestination(ArrivedOnPlainHttp(context, _plainHttpPort), hasPlain);
        var chosen = proxy.AvailableDestinations.Where(d => d.DestinationId == wanted).ToList();
        proxy.AvailableDestinations = chosen;

        if (chosen.Count == 0)
        {
            var host = proxy.Cluster.Config.Metadata != null && proxy.Cluster.Config.Metadata.TryGetValue(IngressProxyConfigProvider.HostMetadata, out var h)
                ? h
                : context.Request.Host.Host;
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "10";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                error = $"The node serving '{host}' is not answering its health checks; the ingress is not forwarding to it. Try again shortly.",
                host,
                upstream = wanted,
            }));
            return;
        }

        await _next(context);
    }
}
