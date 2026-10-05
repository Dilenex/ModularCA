using ModularCA.Bootstrap;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Covers the AIA/CDP/OCSP base URL baked into every certificate at bootstrap.
/// <para>
/// The CLI and the setup wizard derived this separately and each got it wrong, so both installs
/// produced certificates whose revocation endpoint nothing answered. A CDP is fixed at signing
/// and cannot be corrected afterwards, so each case below is a certificate that would have had
/// to be reissued.
/// </para>
/// </summary>
public class BootstrapServiceUrlBuilderTests
{
    /// <summary>
    /// The CLI's original expression was <c>"http://localhost:" + HttpsApi.Port</c> — plaintext
    /// HTTP aimed at the TLS port, while the HTTP listener sat on 8080.
    /// </summary>
    [Fact]
    public void The_http_port_is_used_not_the_tls_port()
    {
        var url = BootstrapServiceUrlBuilder.Build(publicDomain: null, dnsSans: null, httpPort: 8080);

        Assert.Equal("http://localhost:8080", url);
        Assert.DoesNotContain("8443", url);
    }

    /// <summary>
    /// Both paths dropped the port on the DNS-SAN branch, producing a URL that resolves to port
    /// 80 while the listener is on 8080.
    /// </summary>
    [Fact]
    public void A_dns_san_host_keeps_the_http_port()
    {
        var url = BootstrapServiceUrlBuilder.Build(
            publicDomain: null,
            dnsSans: new[] { "DNS:localhost", "DNS:ca.example.test", "IP:127.0.0.1" },
            httpPort: 8080);

        Assert.Equal("http://ca.example.test:8080", url);
    }

    /// <summary>
    /// The wizard offers "set to 0 to disable" and Kestrel honours it, but the URL was still
    /// built as <c>http://{domain}:{port}</c> — yielding a literal <c>:0</c>. Publishing nothing
    /// is correct here: a certificate with no CDP is honest about having no reachable endpoint,
    /// while one with an unreachable CDP fails revocation checking at every relying party.
    /// </summary>
    [Fact]
    public void Disabling_plain_http_publishes_no_url_at_all()
    {
        Assert.Null(BootstrapServiceUrlBuilder.Build("ca.example.test", null, httpPort: 0));
        Assert.Null(BootstrapServiceUrlBuilder.Build("ca.example.test", null, httpPort: -1));
    }

    /// <summary>Port 80 is the scheme default and is the one port correctly omitted.</summary>
    [Fact]
    public void Port_80_is_omitted()
    {
        Assert.Equal("http://ca.example.test",
            BootstrapServiceUrlBuilder.Build("ca.example.test", null, httpPort: 80));
    }

    /// <summary>An operator-supplied public domain wins over the certificate's SANs.</summary>
    [Fact]
    public void The_public_domain_takes_precedence_over_the_sans()
    {
        var url = BootstrapServiceUrlBuilder.Build(
            publicDomain: "pki.example.test",
            dnsSans: new[] { "DNS:internal.example.test" },
            httpPort: 8080);

        Assert.Equal("http://pki.example.test:8080", url);
    }

    /// <summary>
    /// localhost is never a usable distribution point for anyone but the CA host, so it is only
    /// the last resort — a routable DNS SAN is preferred whatever order the SANs arrive in.
    /// </summary>
    [Fact]
    public void Localhost_sans_are_skipped_in_favour_of_a_routable_name()
    {
        var url = BootstrapServiceUrlBuilder.Build(
            publicDomain: null,
            dnsSans: new[] { "DNS:localhost", "DNS:LOCALHOST", "DNS:ca.example.test" },
            httpPort: 8080);

        Assert.Equal("http://ca.example.test:8080", url);
    }

    /// <summary>
    /// With nothing routable to name, localhost is the honest answer — but the port must still be
    /// the HTTP one.
    /// </summary>
    [Fact]
    public void Only_localhost_sans_fall_back_to_localhost_on_the_http_port()
    {
        var url = BootstrapServiceUrlBuilder.Build(
            publicDomain: null,
            dnsSans: new[] { "DNS:localhost", "IP:127.0.0.1" },
            httpPort: 8080);

        Assert.Equal("http://localhost:8080", url);
    }

    /// <summary>
    /// The scheme is always plain HTTP: fetching a CRL over HTTPS makes revocation checking
    /// depend on a certificate whose own revocation status is what the client is establishing.
    /// </summary>
    [Theory]
    [InlineData(80)]
    [InlineData(8080)]
    [InlineData(443)]
    public void The_scheme_is_always_http(int port)
    {
        var url = BootstrapServiceUrlBuilder.Build("ca.example.test", null, port);

        Assert.NotNull(url);
        Assert.StartsWith("http://", url);
    }

    /// <summary>
    /// The unattended bootstrap wrote an empty Https.PublicDomain, and the node exits at startup
    /// without one. The name it now writes is never empty.
    /// </summary>
    [Theory]
    [InlineData("ca.example.test", new[] { "DNS:other.example.test" }, "ca.example.test")]
    [InlineData(" ca.example.test ", null, "ca.example.test")]
    [InlineData(null, new[] { "DNS:localhost", "DNS:ca.example.test", "IP:10.0.0.5" }, "ca.example.test")]
    [InlineData("", new[] { "DNS:localhost", "IP:127.0.0.1" }, "localhost")]
    [InlineData(null, null, "localhost")]
    public void The_public_name_is_the_stated_one_then_the_first_routable_san_then_localhost(
        string? stated, string[]? sans, string expected)
        => Assert.Equal(expected, BootstrapServiceUrlBuilder.ResolvePublicDomain(stated, sans));

    [Theory]
    [InlineData("https://ca.example.test")]
    [InlineData("ca.example.test/admin")]
    [InlineData("ca.example.test:8443")]
    [InlineData("not a host")]
    public void A_public_name_the_node_would_refuse_is_refused_at_bootstrap(string stated)
        => Assert.Throws<ModularCA.Shared.Errors.InvalidRequestException>(
            () => BootstrapServiceUrlBuilder.EnsurePublicDomainUsable(stated));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ca.example.test")]
    [InlineData("10.0.0.5")]
    [InlineData("fd00::5")]
    public void A_bare_name_or_address_or_none_is_accepted(string? stated)
        => BootstrapServiceUrlBuilder.EnsurePublicDomainUsable(stated);

    /// <summary>A certificate that does not cover the public name fails every client that verifies it.</summary>
    [Theory]
    [InlineData("ca.example.test", new[] { "DNS:localhost" }, new[] { "DNS:ca.example.test", "DNS:localhost" })]
    [InlineData("CA.example.test", new[] { "DNS:ca.example.test" }, new[] { "DNS:ca.example.test" })]
    [InlineData("10.0.0.5", new[] { "DNS:localhost" }, new[] { "IP:10.0.0.5", "DNS:localhost" })]
    [InlineData("10.0.0.5", new[] { "IP:10.0.0.5" }, new[] { "IP:10.0.0.5" })]
    [InlineData("localhost", new[] { "IP:127.0.0.1" }, new[] { "IP:127.0.0.1" })]
    [InlineData("ca.example.test", null, new[] { "DNS:ca.example.test" })]
    public void The_certificate_covers_the_public_name(string publicName, string[]? sans, string[] expected)
        => Assert.Equal(expected, BootstrapServiceUrlBuilder.SansCovering(publicName, sans));

    /// <summary>The unattended path resolves the name once and uses it for all three.</summary>
    [Fact]
    public void The_unattended_bootstrap_writes_the_public_name_it_builds_the_urls_from()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var text = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.Bootstrap", "BootstrapModularCA.cs"));

        Assert.Contains("ResolvePublicDomain(\n            bootstrapConfig.HttpsApi.PublicDomain, bootstrapConfig.HttpsApi.SANs)", text.Replace("\r\n", "\n"));
        Assert.Contains("publicDomain: publicDomain,\n            dnsSans:", text.Replace("\r\n", "\n"));
        Assert.Contains("SansCovering(publicDomain, httpsApi.SANs)", text);
        var write = text.IndexOf("BootstrapDatabaseSetup.WriteConfigFile(", StringComparison.Ordinal);
        Assert.Contains("publicDomain: publicDomain,", text[write..text.IndexOf(");", write, StringComparison.Ordinal)]);
    }

    [Theory]
    [InlineData("HttpsApi:\n  PublicDomain: \"ca.example.test\"\n", "ca.example.test")]
    [InlineData("HttpsApi:\n  CN: \"x\"\n", null)]
    [InlineData("", null)]
    public void Bootstrap_yaml_may_state_the_public_name(string section, string? expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, "CA:\n  Subject:\n    CN: \"Test Root\"\n" + section);
        try
        {
            Assert.Equal(expected, ModularCA.Shared.Utils.YamlBootstrapLoader.Load(path).HttpsApi.PublicDomain);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
