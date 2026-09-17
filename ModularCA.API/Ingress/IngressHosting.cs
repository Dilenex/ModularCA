using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace ModularCA.API.Ingress;

/// <summary>
/// Wires the ingress role into a host: YARP over <see cref="IngressProxyConfigProvider"/>
/// with the upstream trust policy, and the branch of the request pipeline that proxies a
/// request whose host has an upstream and lets every other request fall through to the
/// local roles. The branch sits right after the forwarded-headers step and before every
/// local middleware, so a proxied request meets no local redirect, security header, rate
/// limit or authentication: the node it reaches applies its own. Public and static so a
/// test can host the same wiring in front of a stub node.
/// </summary>
public static class IngressHosting
{
    /// <summary>
    /// Registers the route table, the provider, the trust policy and YARP. The table is the
    /// one the hostname service reloads after a change.
    /// </summary>
    /// <param name="services">The host's services.</param>
    /// <param name="config">The ingress section, already validated.</param>
    /// <param name="table">The route table the provider watches.</param>
    /// <param name="trust">The upstream trust policy.</param>
    public static IServiceCollection AddIngress(this IServiceCollection services, IngressConfig config, IngressRouteTableService table, UpstreamTrustPolicy trust)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(trust);
        services.AddSingleton(table);
        services.AddSingleton(trust);
        services.AddReverseProxy();
        services.AddSingleton<IProxyConfigProvider>(sp => new IngressProxyConfigProvider(table, config));
        services.AddSingleton<IForwarderHttpClientFactory>(sp =>
            new IngressUpstreamHttpClientFactory(trust, sp.GetRequiredService<ILogger<ForwarderHttpClientFactory>>()));
        return services;
    }

    /// <summary>
    /// Adds the proxy branch: a request whose host the table routes is proxied here and
    /// goes no further; any other request continues down the local pipeline.
    /// </summary>
    /// <param name="app">The host's pipeline, positioned after the forwarded-headers step.</param>
    /// <param name="table">The route table.</param>
    /// <param name="plainHttpPort"><c>Http.Port</c>, so the branch can tell a plain-HTTP arrival from an HTTPS one; 0 when off.</param>
    public static IApplicationBuilder UseIngress(this IApplicationBuilder app, IngressRouteTableService table, int plainHttpPort)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(table);
        return app.MapWhen(
            context => table.HasUpstream(context.Request.Host.Host),
            branch =>
            {
                branch.UseRouting();
                branch.UseEndpoints(endpoints => endpoints.MapReverseProxy(proxy =>
                {
                    proxy.UseMiddleware<IngressListenerMiddleware>(plainHttpPort);
                    proxy.UseLoadBalancing();
                    proxy.UsePassiveHealthChecks();
                }));
            });
    }
}
