using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// The route table's rules: a configured value that does not parse is dropped and reported, a
/// host listed twice keeps its first entry, and hosts are keyed without regard to case or a
/// trailing dot.
/// </summary>
public sealed class IngressRouteTableTests
{
    private static IngressRouteConfig Route(string host, string upstream, string? plain = null, string? pin = null)
        => new() { Host = host, Upstream = upstream, PlainHttpUpstream = plain, PinnedSpki = pin };

    [Fact]
    public void A_configured_route_is_a_route()
    {
        var route = Assert.Single(IngressRouteTable.Build(new[] { Route("ca.a.test", "https://10.0.0.1:8443") }));
        Assert.Equal("ca.a.test", route.Host);
        Assert.Equal(new Uri("https://10.0.0.1:8443"), route.Upstream);
        Assert.Null(route.PlainHttpUpstream);
        Assert.Null(route.PinnedSpki);
    }

    [Fact]
    public void A_route_whose_upstream_or_host_does_not_parse_is_dropped_and_reported()
    {
        var problems = new List<string>();
        var routes = IngressRouteTable.Build(
            new[] { Route("odd.test", "10.0.0.4:8443"), Route("odder.test", "ftp://x"), Route("https://bad/", "https://10.0.0.1:8443") },
            problems.Add);

        Assert.Empty(routes);
        Assert.Equal(3, problems.Count);
    }

    [Fact]
    public void A_host_listed_twice_keeps_its_first_entry()
    {
        var problems = new List<string>();
        var route = Assert.Single(IngressRouteTable.Build(
            new[] { Route("CA.A.Test.", "https://127.0.0.1:8443"), Route("ca.a.test", "https://10.0.0.2:8443") },
            problems.Add));

        Assert.Equal("ca.a.test", route.Host);
        Assert.Equal(new Uri("https://127.0.0.1:8443"), route.Upstream);
        Assert.Contains(problems, p => p.Contains("more than once"));
    }

    [Fact]
    public void The_plain_http_upstream_and_the_pin_are_carried_in_canonical_form()
    {
        var pin = "sha256:" + new string('A', 64);
        var route = Assert.Single(IngressRouteTable.Build(new[] { Route("ca.a.test", "https://127.0.0.1:8443", "http://127.0.0.1:8080", pin) }));

        Assert.Equal(new Uri("http://127.0.0.1:8080"), route.PlainHttpUpstream);
        Assert.Equal(new string('a', 64), route.PinnedSpki);
        Assert.True(route.AnyHttps);
    }

    [Fact]
    public void A_configured_route_with_a_bad_pin_is_dropped_rather_than_routed_unpinned()
    {
        var problems = new List<string>();
        var routes = IngressRouteTable.Build(new[] { Route("ca.a.test", "https://10.0.0.1:8443", pin: "not-a-pin") }, problems.Add);

        Assert.Empty(routes);
        Assert.Contains(problems, p => p.Contains("PinnedSpki"));
    }

    [Fact]
    public void The_result_is_ordered_by_host()
    {
        var routes = IngressRouteTable.Build(new[] { Route("z.test", "https://127.0.0.1:1"), Route("a.test", "https://127.0.0.1:2"), Route("m.test", "https://127.0.0.1:3") });
        Assert.Equal(new[] { "a.test", "m.test", "z.test" }, routes.Select(r => r.Host));
    }
}

/// <summary>
/// The table service: built from the configured routes when it is created, and a lookup is a
/// case-insensitive read that ignores a trailing dot.
/// </summary>
public sealed class IngressRouteTableServiceTests
{
    [Fact]
    public void The_configured_routes_are_served_from_the_start()
    {
        var config = new IngressConfig { Routes = { new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443" } } };
        var service = new IngressRouteTableService(config);

        Assert.Equal("ca.a.test", Assert.Single(service.Routes).Host);
        Assert.True(service.HasUpstream("ca.a.test"));
        Assert.True(service.HasUpstream("CA.A.TEST."));
        Assert.Equal(new Uri("https://127.0.0.1:8443"), service.Find("ca.a.test")!.Upstream);
        Assert.False(service.HasUpstream("public.test"));
        Assert.False(service.HasUpstream(null));
        Assert.False(service.HasUpstream(""));
    }

    [Fact]
    public void No_configured_route_means_nothing_is_routed()
    {
        var service = new IngressRouteTableService(new IngressConfig());
        Assert.Empty(service.Routes);
        Assert.False(service.HasUpstream("anything.test"));
    }

    [Fact]
    public void A_dropped_route_is_reported_once()
    {
        var problems = new List<string>();
        var config = new IngressConfig { Routes = { new IngressRouteConfig { Host = "ca.a.test", Upstream = "nope" } } };
        var service = new IngressRouteTableService(config, problems.Add);

        Assert.Empty(service.Routes);
        Assert.Single(problems);
    }
}
