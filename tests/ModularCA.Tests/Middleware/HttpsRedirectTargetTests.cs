using Microsoft.AspNetCore.Http;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// A plain-HTTP request is sent to HTTPS on the public domain whatever host it named, so the
/// Host header cannot steer the redirect; without a public domain, to the request host on the
/// HTTPS listener port.
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
    public void Without_a_public_domain_the_request_host_and_listener_port_are_used()
        => Assert.Equal("https://anything.example.test:8443/msae/staging/cep?x=1", Target("anything.example.test", publicDomain: null));

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
