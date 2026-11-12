using Microsoft.AspNetCore.Http;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// A plain-HTTP request is sent to HTTPS on the public domain whatever host it named, so the
/// Host header cannot steer the redirect; without a public domain, to the request host on the
/// public HTTPS port (PublicPort, else the listener port).
/// </summary>
public class HttpsRedirectTargetTests
{
    private static string Target(string host, string? publicDomain = "ca4.example.test", int? publicPort = 443)
    {
        var config = new SystemConfig { Https = { PublicDomain = publicDomain ?? "", PublicPort = publicPort, Port = 8443 } };
        return HttpsRedirectTarget.Build(host, "/msae/staging/cep?x=1", config);
    }

    [Theory]
    [InlineData("ca4.example.test")]
    [InlineData("ca.lab.example.test")]
    [InlineData("evil.example.test")]
    public void Every_host_redirects_to_the_public_domain(string host)
        => Assert.Equal("https://ca4.example.test/msae/staging/cep?x=1", Target(host));

    [Fact]
    public void The_public_port_is_kept_when_it_is_not_443()
        => Assert.Equal("https://ca4.example.test:9443/msae/staging/cep?x=1", Target("evil.example.test", publicPort: 9443));

    [Fact]
    public void Without_a_public_domain_the_request_host_and_public_port_are_used()
        => Assert.Equal("https://anything.example.test:9443/msae/staging/cep?x=1", Target("anything.example.test", publicDomain: null, publicPort: 9443));

    [Fact]
    public void Without_a_public_domain_or_public_port_the_request_host_and_listener_port_are_used()
        => Assert.Equal("https://anything.example.test:8443/msae/staging/cep?x=1", Target("anything.example.test", publicDomain: null, publicPort: null));

    /// <summary>
    /// The redirect and the public base URL (AIA/CDP bases, the ACME directory, portal links) used
    /// to compute the port differently: the redirect read <c>PublicPort ?? 443</c> with a public
    /// domain and the listener port without one, the base URL <c>PublicPort ?? Port</c>. With a
    /// listener on 8443 and no public port, the redirect sent clients to 443, where nothing
    /// listened; behind a proxy publishing 443 for a listener on 8443 with no public domain, it
    /// sent them to 8443, which the proxy does not publish. Both now take the port from
    /// <see cref="HttpsConfig.GetPublicHttpsPort"/>.
    /// </summary>
    [Theory]
    [InlineData(443, null, "")]          // default listener on 443
    [InlineData(8443, null, ":8443")]    // non-default listener, nothing in front
    [InlineData(8443, 443, "")]          // proxy publishes 443 for a listener on 8443
    [InlineData(8443, 9443, ":9443")]    // proxy publishes another non-default port
    [InlineData(443, 8443, ":8443")]     // an explicit public port wins over a 443 listener
    [InlineData(0, null, "")]            // an unusable listener port degrades to 443
    public void The_redirect_and_the_public_base_url_agree_on_the_port(int listener, int? publicPort, string suffix)
    {
        var withDomain = new SystemConfig { Https = { PublicDomain = "ca.example.test", PublicPort = publicPort, Port = listener } };
        var withoutDomain = new SystemConfig { Https = { PublicDomain = "", PublicPort = publicPort, Port = listener } };

        Assert.Equal($"https://ca.example.test{suffix}", withDomain.Https.GetPublicHttpsBaseUrl());
        Assert.Equal($"https://ca.example.test{suffix}/admin", HttpsRedirectTarget.Build("evil.example.test", "/admin", withDomain));
        Assert.Equal($"https://setup.example.test{suffix}/admin", HttpsRedirectTarget.Build("setup.example.test", "/admin", withoutDomain));
        Assert.Equal($"https://setup.example.test{suffix}", withoutDomain.Https.GetHttpsBaseUrlFor("setup.example.test"));
    }

    [Theory]
    [InlineData("ca4.example.test")]
    [InlineData("ca.lab.example.test")]
    public async Task The_middleware_built_from_the_config_alone_redirects_plain_http_to_the_public_domain(string host)
    {
        var config = new SystemConfig { Https = { PublicDomain = "ca4.example.test", PublicPort = 443, Port = 8443 }, Http = { Port = 8080 } };
        var type = ModularCA.Tests.Roles.ApiAssembly.TypeNamed("ModularCA.API.Middleware.HttpSchemeEnforcementMiddleware");
        var reached = false;
        RequestDelegate next = _ => { reached = true; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(type, next, config)!;

        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString(host);
        context.Request.Path = "/admin";
        context.Connection.LocalPort = 8080;
        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;

        Assert.False(reached);
        Assert.Equal(308, context.Response.StatusCode);
        Assert.Equal("https://ca4.example.test/admin", context.Response.Headers.Location.ToString());
    }
}
