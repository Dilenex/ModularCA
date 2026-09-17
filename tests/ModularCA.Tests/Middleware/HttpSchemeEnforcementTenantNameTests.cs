using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// A plain-HTTP request on a tenant's own name is sent to HTTPS on that name; any other host is
/// still sent to the public domain, so the Host header cannot steer the redirect.
/// </summary>
public class HttpSchemeEnforcementTenantNameTests
{
    private static X509Certificate2 SelfSigned(string cn)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }

    private static string Target(string host, bool withTenantName, string? publicDomain = "ca4.example.test")
    {
        var config = new SystemConfig { Https = { PublicDomain = publicDomain ?? "", PublicPort = 443, Port = 8443 } };
        var cache = new TenantHostnameCertificateCache(
            () => withTenantName ? new Dictionary<string, X509Certificate2> { ["ca.lab.example.test"] = SelfSigned("ca.lab.example.test") } : new(),
            TimeSpan.FromMinutes(5));
        cache.LoadNow();
        return HttpsRedirectTarget.Build(host, "/msae/staging/cep?x=1", config, cache);
    }

    [Fact]
    public void A_tenant_name_redirects_to_https_on_itself()
        => Assert.Equal("https://ca.lab.example.test/msae/staging/cep?x=1", Target("ca.lab.example.test", withTenantName: true));

    [Fact]
    public void An_unknown_host_still_redirects_to_the_public_domain()
    {
        Assert.Equal("https://ca4.example.test/msae/staging/cep?x=1", Target("evil.example.test", withTenantName: true));
        Assert.Equal("https://ca4.example.test/msae/staging/cep?x=1", Target("ca.lab.example.test", withTenantName: false));
        Assert.Equal("https://CA.LAB.EXAMPLE.TEST/msae/staging/cep?x=1".ToLowerInvariant().Replace("?x=1", "?x=1"), Target("ca.lab.example.test", withTenantName: true).ToLowerInvariant());
    }

    [Fact]
    public void Without_a_public_domain_the_request_host_and_listener_port_are_used()
        => Assert.Equal("https://anything.example.test:8443/msae/staging/cep?x=1", Target("anything.example.test", withTenantName: false, publicDomain: null));
}
