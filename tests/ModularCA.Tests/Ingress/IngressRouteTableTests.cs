using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// The route table's rules: configuration wins over the database for the same host, a row
/// with no upstream is not a route (the name is served locally), a value that does not parse
/// is dropped and reported, and hosts are keyed without regard to case or a trailing dot.
/// </summary>
public sealed class IngressRouteTableTests
{
    private static IngressRouteConfig Route(string host, string upstream, string? plain = null, string? pin = null)
        => new() { Host = host, Upstream = upstream, PlainHttpUpstream = plain, PinnedSpki = pin };

    [Fact]
    public void Configuration_wins_over_the_database_for_the_same_host()
    {
        var routes = IngressRouteTable.Merge(
            new[] { Route("ca.a.test", "https://10.0.0.1:8443") },
            new[] { new TenantHostnameUpstream("ca.a.test", "https://10.0.0.2:8443") });

        var route = Assert.Single(routes);
        Assert.Equal("ca.a.test", route.Host);
        Assert.Equal(new Uri("https://10.0.0.1:8443"), route.Upstream);
        Assert.Equal(IngressRouteSource.Configuration, route.Source);
    }

    [Fact]
    public void A_database_row_with_an_upstream_is_a_route_when_configuration_does_not_name_the_host()
    {
        var routes = IngressRouteTable.Merge(
            Array.Empty<IngressRouteConfig>(),
            new[] { new TenantHostnameUpstream("ca.b.test", "http://10.0.0.3:8080") });

        var route = Assert.Single(routes);
        Assert.Equal("ca.b.test", route.Host);
        Assert.Equal(new Uri("http://10.0.0.3:8080"), route.Upstream);
        Assert.Null(route.PlainHttpUpstream);
        Assert.Equal(IngressRouteSource.Database, route.Source);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_row_with_no_upstream_means_the_name_is_served_locally(string? upstream)
    {
        var routes = IngressRouteTable.Merge(
            Array.Empty<IngressRouteConfig>(),
            new[] { new TenantHostnameUpstream("local.test", upstream) });

        Assert.Empty(routes);
    }

    [Fact]
    public void A_row_whose_upstream_does_not_parse_is_dropped_and_reported()
    {
        var problems = new List<string>();
        var routes = IngressRouteTable.Merge(
            Array.Empty<IngressRouteConfig>(),
            new[] { new TenantHostnameUpstream("odd.test", "10.0.0.4:8443"), new TenantHostnameUpstream("odder.test", "ftp://x") },
            problems.Add);

        Assert.Empty(routes);
        Assert.Equal(2, problems.Count);
        Assert.All(problems, p => Assert.Contains("served locally", p));
    }

    [Fact]
    public void Hosts_are_keyed_case_insensitively_without_a_trailing_dot()
    {
        var routes = IngressRouteTable.Merge(
            new[] { Route("CA.A.Test.", "https://127.0.0.1:8443") },
            new[] { new TenantHostnameUpstream("ca.a.test", "https://10.0.0.2:8443") });

        var route = Assert.Single(routes);
        Assert.Equal("ca.a.test", route.Host);
        Assert.Equal(IngressRouteSource.Configuration, route.Source);
    }

    [Fact]
    public void The_plain_http_upstream_and_the_pin_are_carried_in_canonical_form()
    {
        var pin = "sha256:" + new string('A', 64);
        var routes = IngressRouteTable.Merge(
            new[] { Route("ca.a.test", "https://127.0.0.1:8443", "http://127.0.0.1:8080", pin) },
            Array.Empty<TenantHostnameUpstream>());

        var route = Assert.Single(routes);
        Assert.Equal(new Uri("http://127.0.0.1:8080"), route.PlainHttpUpstream);
        Assert.Equal(new string('a', 64), route.PinnedSpki);
        Assert.True(route.AnyHttps);
    }

    [Fact]
    public void A_configured_route_with_a_bad_pin_is_dropped_rather_than_routed_unpinned()
    {
        var problems = new List<string>();
        var routes = IngressRouteTable.Merge(
            new[] { Route("ca.a.test", "https://10.0.0.1:8443", pin: "not-a-pin") },
            Array.Empty<TenantHostnameUpstream>(),
            problems.Add);

        Assert.Empty(routes);
        Assert.Contains(problems, p => p.Contains("PinnedSpki"));
    }

    [Fact]
    public void The_result_is_ordered_by_host_and_merges_both_sources()
    {
        var routes = IngressRouteTable.Merge(
            new[] { Route("z.test", "https://127.0.0.1:1"), Route("a.test", "https://127.0.0.1:2") },
            new[] { new TenantHostnameUpstream("m.test", "https://127.0.0.1:3"), new TenantHostnameUpstream("local.test", null) });

        Assert.Equal(new[] { "a.test", "m.test", "z.test" }, routes.Select(r => r.Host));
    }
}

/// <summary>
/// The table service: a lookup is a snapshot read, a failed database read keeps the last rows
/// and the configured routes, and Changed fires only when the set differs.
/// </summary>
public sealed class IngressRouteTableServiceTests
{
    [Fact]
    public void Nothing_is_routed_before_the_first_build_and_configuration_routes_after_it()
    {
        var config = new IngressConfig { Routes = { new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443" } } };
        var service = new IngressRouteTableService(config, () => Array.Empty<TenantHostnameUpstream>(), TimeSpan.FromMinutes(5));

        Assert.False(service.Loaded);
        Assert.Equal(1, service.LoadNow());
        Assert.True(service.Loaded);
        Assert.True(service.HasUpstream("ca.a.test"));
        Assert.True(service.HasUpstream("CA.A.TEST."));
        Assert.False(service.HasUpstream("public.test"));
        Assert.False(service.HasUpstream(null));
    }

    [Fact]
    public void A_failed_database_read_keeps_the_previous_rows_and_says_so()
    {
        var problems = new List<string>();
        var fail = false;
        var rows = new List<TenantHostnameUpstream> { new("ca.b.test", "https://10.0.0.2:8443") };
        var service = new IngressRouteTableService(
            new IngressConfig(),
            () => fail ? throw new InvalidOperationException("db down") : rows,
            TimeSpan.FromMinutes(5),
            problems.Add);

        Assert.Equal(1, service.LoadNow());
        Assert.True(service.DatabaseReachable);

        fail = true;
        Assert.Equal(1, service.LoadNow());
        Assert.False(service.DatabaseReachable);
        Assert.True(service.HasUpstream("ca.b.test"));
        Assert.Contains(problems, p => p.Contains("db down"));
    }

    [Fact]
    public void Changed_fires_on_the_first_build_and_when_the_set_differs_and_not_otherwise()
    {
        var rows = new List<TenantHostnameUpstream>();
        var service = new IngressRouteTableService(new IngressConfig(), () => rows.ToList(), TimeSpan.FromMinutes(5));
        var changes = 0;
        service.Changed += () => changes++;

        service.LoadNow();
        Assert.Equal(1, changes);
        service.LoadNow();
        Assert.Equal(1, changes);

        rows.Add(new TenantHostnameUpstream("ca.c.test", "https://10.0.0.3:8443"));
        service.Reload();
        Assert.Equal(2, changes);
        Assert.True(service.HasUpstream("ca.c.test"));

        rows.Clear();
        service.Reload();
        Assert.Equal(3, changes);
        Assert.False(service.HasUpstream("ca.c.test"));
    }

    [Fact]
    public async Task A_stale_table_is_rebuilt_in_the_background_by_a_lookup()
    {
        var rows = new List<TenantHostnameUpstream>();
        var service = new IngressRouteTableService(new IngressConfig(), () => rows.ToList(), TimeSpan.FromSeconds(1));
        service.LoadNow();
        rows.Add(new TenantHostnameUpstream("late.test", "https://10.0.0.9:8443"));

        Assert.False(service.HasUpstream("late.test"));
        await Task.Delay(TimeSpan.FromSeconds(1.2));
        service.Find("anything"); // triggers the refresh
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!service.HasUpstream("late.test") && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.True(service.HasUpstream("late.test"));
    }
}
