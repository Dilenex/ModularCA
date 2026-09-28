using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// What the provider hands to YARP: one route and one cluster per host that has an upstream,
/// the route matching that host alone, the cluster holding the HTTPS destination and the
/// plain-HTTP one when named, probed actively, with the pin and the loopback fact in its
/// metadata. A host with no upstream is not in the table and so has no route.
/// </summary>
public sealed class IngressProxyConfigProviderTests
{
    private static (IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters) Build(IReadOnlyList<IngressRoute> routes, IngressConfig? config = null)
    {
        var result = IngressApi.Call(IngressApi.Provider, "Build", routes, config ?? new IngressConfig())!;
        var tuple = (System.Runtime.CompilerServices.ITuple)result;
        return ((IReadOnlyList<RouteConfig>)tuple[0]!, (IReadOnlyList<ClusterConfig>)tuple[1]!);
    }

    private static IReadOnlyList<IngressRoute> Table(params IngressRouteConfig[] configured)
        => IngressRouteTable.Build(configured);

    [Fact]
    public void One_route_and_one_cluster_per_host_with_an_upstream_and_none_for_a_host_without()
    {
        var table = Table(
            new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443" },
            new IngressRouteConfig { Host = "ca.b.test", Upstream = "http://10.0.0.2:8080" });

        var (routes, clusters) = Build(table);

        Assert.Equal(2, routes.Count);
        Assert.Equal(2, clusters.Count);
        Assert.Equal(new[] { "ingress:ca.a.test", "ingress:ca.b.test" }, routes.Select(r => r.RouteId));
        Assert.Equal(routes.Select(r => r.ClusterId), clusters.Select(c => c.ClusterId));
        Assert.DoesNotContain(routes, r => r.RouteId.Contains("local.test"));
        foreach (var route in routes)
        {
            var host = Assert.Single(route.Match.Hosts!);
            Assert.Equal(route.RouteId, "ingress:" + host);
            Assert.Null(route.Match.Path);
        }
    }

    [Fact]
    public void The_cluster_holds_the_https_destination_and_the_plain_one_only_when_named()
    {
        var table = Table(
            new IngressRouteConfig { Host = "both.test", Upstream = "https://127.0.0.1:8443", PlainHttpUpstream = "http://127.0.0.1:8080" },
            new IngressRouteConfig { Host = "one.test", Upstream = "https://127.0.0.1:8445" });

        var (_, clusters) = Build(table);

        var both = clusters.Single(c => c.ClusterId == "ingress:both.test");
        Assert.Equal(new[] { "https", "plain" }, both.Destinations!.Keys.OrderBy(k => k == "plain"));
        Assert.Equal("https://127.0.0.1:8443/", both.Destinations!["https"].Address);
        Assert.Equal("http://127.0.0.1:8080/", both.Destinations!["plain"].Address);

        var one = clusters.Single(c => c.ClusterId == "ingress:one.test");
        var only = Assert.Single(one.Destinations!);
        Assert.Equal("https", only.Key);
    }

    [Fact]
    public void Every_cluster_is_probed_actively_and_withholds_unhealthy_destinations()
    {
        var config = new IngressConfig { HealthCheckIntervalSeconds = 3, HealthCheckTimeoutSeconds = 2, HealthCheckPath = "/health/live" };
        var (_, clusters) = Build(Table(new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443" }), config);

        var cluster = Assert.Single(clusters);
        Assert.True(cluster.HealthCheck!.Active!.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(3), cluster.HealthCheck.Active.Interval);
        Assert.Equal(TimeSpan.FromSeconds(2), cluster.HealthCheck.Active.Timeout);
        Assert.Equal("/health/live", cluster.HealthCheck.Active.Path);
        Assert.Equal("ConsecutiveFailures", cluster.HealthCheck.Active.Policy);
        Assert.Equal("HealthyAndUnknown", cluster.HealthCheck.AvailableDestinationsPolicy);
        Assert.False(cluster.HttpClient!.DangerousAcceptAnyServerCertificate);
    }

    [Fact]
    public void The_metadata_carries_the_host_the_pin_and_the_loopback_fact()
    {
        var pin = new string('b', 64);
        var table = Table(
            new IngressRouteConfig { Host = "pinned.test", Upstream = "https://10.0.0.5:8443", PinnedSpki = pin },
            new IngressRouteConfig { Host = "loop.test", Upstream = "https://127.0.0.1:8443" });

        var (_, clusters) = Build(table);

        var pinned = clusters.Single(c => c.ClusterId == "ingress:pinned.test").Metadata!;
        Assert.Equal("pinned.test", pinned[IngressApi.ProviderConstant("HostMetadata")]);
        Assert.Equal(pin, pinned[IngressApi.ProviderConstant("PinMetadata")]);
        Assert.Equal("false", pinned[IngressApi.ProviderConstant("LoopbackMetadata")]);
        Assert.Equal(3, pinned.Count);

        var loop = clusters.Single(c => c.ClusterId == "ingress:loop.test").Metadata!;
        Assert.False(loop.ContainsKey(IngressApi.ProviderConstant("PinMetadata")));
        Assert.Equal("true", loop[IngressApi.ProviderConstant("LoopbackMetadata")]);
        Assert.Equal(2, loop.Count);
    }

    [Fact]
    public void An_empty_table_is_an_empty_configuration()
    {
        var (routes, clusters) = Build(Array.Empty<IngressRoute>());
        Assert.Empty(routes);
        Assert.Empty(clusters);
    }

    [Fact]
    public void The_provider_serves_the_configured_routes_under_a_token_that_can_carry_a_callback_and_never_fires()
    {
        var config = new IngressConfig { Routes = { new IngressRouteConfig { Host = "new.test", Upstream = "https://127.0.0.1:8443" } } };
        var service = new IngressRouteTableService(config);
        var provider = (IProxyConfigProvider)Activator.CreateInstance(IngressApi.Provider, service, config)!;

        var first = provider.GetConfig();
        Assert.Equal("ingress:new.test", Assert.Single(first.Routes).RouteId);
        Assert.Equal("ingress:new.test", Assert.Single(first.Clusters).ClusterId);
        Assert.True(first.ChangeToken.ActiveChangeCallbacks);
        Assert.False(first.ChangeToken.HasChanged);
        Assert.Same(first, provider.GetConfig());
        (provider as IDisposable)?.Dispose();
    }
}
