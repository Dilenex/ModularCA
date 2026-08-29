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
}
