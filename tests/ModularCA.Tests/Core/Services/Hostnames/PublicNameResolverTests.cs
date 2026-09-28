using ModularCA.Core.Services.Hostnames;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Core.Services.Hostnames;

/// <summary>
/// URLs that point back at this service name the host the client used only when that host is
/// the instance's public domain; anything else is the public domain.
/// </summary>
public class PublicNameResolverTests
{
    private static (PublicNameResolver Resolver, SystemConfig Config) Build()
    {
        var config = new SystemConfig { Https = { PublicDomain = "ca4.example.test", PublicPort = 443 } };
        return (new PublicNameResolver(config), config);
    }

    [Fact]
    public void Only_the_public_domain_is_known()
    {
        var (resolver, _) = Build();
        Assert.Equal("ca4.example.test", resolver.Resolve("CA4.Example.Test."));
        Assert.Null(resolver.Resolve("ca.customer-a.example"));
        Assert.Null(resolver.Resolve("evil.example"));
        Assert.Null(resolver.Resolve(null));
        Assert.Null(resolver.Resolve(""));
    }

    [Fact]
    public void Nothing_is_known_without_a_public_domain()
    {
        var resolver = new PublicNameResolver(new SystemConfig());
        Assert.Null(resolver.Resolve("ca4.example.test"));
    }

    [Fact]
    public void A_request_host_is_advertised_only_when_known_and_the_public_port_rule_applies()
    {
        var (resolver, config) = Build();
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForRequest("ca4.example.test"));
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForRequest("attacker.example"));
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForRequest(null));

        config.Https.PublicPort = 8443;
        Assert.Equal("https://ca4.example.test:8443", resolver.BaseUrlForRequest("ca4.example.test"));
        Assert.Equal("https://ca4.example.test:8443", resolver.BaseUrlForRequest("nope.example"));
    }

    [Theory]
    [InlineData("HTTP/ca.customer-a.example", "ca.customer-a.example")]
    [InlineData("HTTP/CA.Customer-A.Example.", "ca.customer-a.example")]
    [InlineData("HTTP/ca.customer-a.example@LAB.MSAE.TEST", "ca.customer-a.example")]
    [InlineData("HTTP/ca.customer-a.example:8443", "ca.customer-a.example")]
    [InlineData("ca.customer-a.example", "ca.customer-a.example")]
    [InlineData("HTTP/", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void The_host_is_read_out_of_a_service_principal(string? spn, string? expected)
        => Assert.Equal(expected, PublicNameResolver.HostFromServicePrincipal(spn));

    [Fact]
    public void A_service_principal_yields_the_public_domain_whatever_host_it_names()
    {
        var (resolver, _) = Build();
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForServicePrincipal("HTTP/ca4.example.test"));
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForServicePrincipal("HTTP/ca.customer-a.example"));
        Assert.Equal("https://ca4.example.test", resolver.BaseUrlForServicePrincipal(null));
    }
}
