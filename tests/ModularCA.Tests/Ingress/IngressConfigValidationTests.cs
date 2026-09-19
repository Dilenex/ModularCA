using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// The ingress section's startup validation: the dangerous flag is refused for any https
/// upstream that is not loopback, and accepted for loopback; hosts are bare and unique;
/// upstreams are absolute http or https; a pin is 32 hex bytes.
/// </summary>
public sealed class IngressConfigValidationTests
{
    private static IngressConfig With(params IngressRouteConfig[] routes)
    {
        var config = new IngressConfig();
        config.Routes.AddRange(routes);
        return config;
    }

    [Theory]
    [InlineData("https://10.0.0.5:8443")]
    [InlineData("https://node-a.internal:8443")]
    public void The_dangerous_flag_is_refused_for_a_non_loopback_https_upstream(string upstream)
    {
        var config = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = upstream });
        config.DangerousAcceptAnyUpstreamCertificate = true;

        var problems = config.Validate();

        var problem = Assert.Single(problems);
        Assert.Contains("DangerousAcceptAnyUpstreamCertificate", problem);
        Assert.Contains("not loopback", problem);
    }

    [Fact]
    public void The_dangerous_flag_is_refused_for_a_non_loopback_https_plain_upstream_too()
    {
        var config = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443", PlainHttpUpstream = "https://10.0.0.5:8080" });
        config.DangerousAcceptAnyUpstreamCertificate = true;

        var problem = Assert.Single(config.Validate());
        Assert.Contains("PlainHttpUpstream", problem);
    }

    [Theory]
    [InlineData("https://127.0.0.1:8443")]
    [InlineData("https://localhost:8443")]
    [InlineData("https://[::1]:8443")]
    public void The_dangerous_flag_is_accepted_for_a_loopback_https_upstream(string upstream)
    {
        var config = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = upstream, PlainHttpUpstream = "http://127.0.0.1:8080" });
        config.DangerousAcceptAnyUpstreamCertificate = true;

        Assert.Empty(config.Validate());
    }

    [Fact]
    public void A_plain_http_upstream_off_loopback_is_fine_under_the_flag_since_there_is_nothing_to_verify()
    {
        var config = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = "http://10.0.0.5:8080" });
        config.DangerousAcceptAnyUpstreamCertificate = true;

        Assert.Empty(config.Validate());
    }

    [Fact]
    public void Without_the_flag_a_non_loopback_https_upstream_is_fine()
    {
        var config = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://10.0.0.5:8443" });
        Assert.Empty(config.Validate());
    }

    [Fact]
    public void An_empty_section_is_valid()
        => Assert.Empty(new IngressConfig().Validate());

    [Theory]
    [InlineData("https://ca.a.test")]
    [InlineData("ca.a.test:443")]
    [InlineData("ca.a.test/path")]
    [InlineData("*.a.test")]
    [InlineData("")]
    public void A_host_that_is_not_a_bare_name_is_refused(string host)
    {
        var problem = Assert.Single(With(new IngressRouteConfig { Host = host, Upstream = "https://127.0.0.1:8443" }).Validate());
        Assert.Contains("Host", problem);
    }

    [Fact]
    public void A_host_listed_twice_is_refused()
    {
        var problems = With(
            new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://127.0.0.1:8443" },
            new IngressRouteConfig { Host = "CA.A.TEST", Upstream = "https://127.0.0.1:8444" }).Validate();
        var problem = Assert.Single(problems);
        Assert.Contains("more than once", problem);
    }

    [Theory]
    [InlineData("")]
    [InlineData("127.0.0.1:8443")]
    [InlineData("ftp://127.0.0.1")]
    public void An_upstream_that_is_not_absolute_http_or_https_is_refused(string upstream)
    {
        var problem = Assert.Single(With(new IngressRouteConfig { Host = "ca.a.test", Upstream = upstream }).Validate());
        Assert.Contains("Upstream", problem);
    }

    [Fact]
    public void A_pin_that_is_not_a_sha256_pin_is_refused_and_a_good_one_normalises()
    {
        var bad = With(new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://10.0.0.5:8443", PinnedSpki = "abc" }).Validate();
        Assert.Contains(bad, p => p.Contains("PinnedSpki"));

        var good = new string('F', 64);
        Assert.Empty(With(new IngressRouteConfig { Host = "ca.a.test", Upstream = "https://10.0.0.5:8443", PinnedSpki = "SHA256:" + good }).Validate());
        Assert.Equal(new string('f', 64), IngressRouteConfig.NormalizePin("SHA256:" + good));
    }

    [Fact]
    public void Intervals_below_one_second_and_a_relative_health_path_are_refused()
    {
        var config = new IngressConfig { HealthCheckIntervalSeconds = 0, HealthCheckTimeoutSeconds = 0, RouteRefreshSeconds = 0, HealthCheckPath = "health" };
        var problems = config.Validate();
        Assert.Equal(4, problems.Count);
    }

    [Fact]
    public void A_missing_upstream_ca_file_is_refused_when_the_base_directory_is_known()
    {
        var config = new IngressConfig { UpstreamCaCertificatePath = "config/no-such-ca.pem" };
        Assert.Empty(config.Validate());
        var problem = Assert.Single(config.Validate(Path.GetTempPath()));
        Assert.Contains("UpstreamCaCertificatePath", problem);
    }
}
