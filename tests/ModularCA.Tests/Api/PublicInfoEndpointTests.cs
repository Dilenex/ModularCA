using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The base URL the public portal shows for ACME. ACME is served over HTTPS only, and with no
/// public domain configured the info endpoint answered a plain-HTTP request with an
/// <c>http://</c> base, so the portal's ACME page showed a directory URL no client can use.
/// </summary>
public sealed class PublicInfoEndpointTests
{
    private static string BaseUrl(SystemConfig config, string scheme, string host)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Public.PublicInfoController");
        var controller = (ControllerBase)Activator.CreateInstance(type, config,
            InstanceCeremonyEndpointTests.Fake<IFeatureFlagService>.Create())!;
        var http = new DefaultHttpContext();
        http.Request.Scheme = scheme;
        http.Request.Host = new HostString(host);
        controller.ControllerContext = new ControllerContext { HttpContext = http };

        var result = Assert.IsType<OkObjectResult>(type.GetMethod("GetInfo")!.Invoke(controller, []));
        return JsonDocument.Parse(JsonSerializer.Serialize(result.Value)).RootElement
            .GetProperty("publicHttpsBaseUrl").GetString()!;
    }

    [Fact]
    public void Over_plain_http_without_a_public_domain_the_base_is_where_the_redirect_goes()
    {
        var config = new SystemConfig();
        config.Https.Port = 8443;

        Assert.Equal("https://ca.lab.test:8443", BaseUrl(config, "http", "ca.lab.test:8080"));

        config.Https.Port = 443;
        Assert.Equal("https://ca.lab.test", BaseUrl(config, "http", "ca.lab.test"));
    }

    [Fact]
    public void Over_https_without_a_public_domain_the_base_is_the_requested_origin()
        => Assert.Equal("https://ca.lab.test:9443", BaseUrl(new SystemConfig(), "https", "ca.lab.test:9443"));

    [Fact]
    public void With_a_public_domain_the_base_is_the_public_https_url_over_either_scheme()
    {
        var config = new SystemConfig();
        config.Https.PublicDomain = "pki.example.test";
        config.Https.PublicPort = 443;

        Assert.Equal("https://pki.example.test", BaseUrl(config, "http", "10.0.0.1:8080"));
        Assert.Equal("https://pki.example.test", BaseUrl(config, "https", "10.0.0.1:8443"));
    }
}
