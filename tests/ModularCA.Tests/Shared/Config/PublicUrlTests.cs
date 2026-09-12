using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Config;

/// <summary>
/// Covers the public base URLs that get frozen into every issued certificate.
/// </summary>
/// <remarks>
/// <para>
/// CDP, AIA and OCSP extensions carry absolute URLs, and they are written at issuance. A wrong
/// port there is not a setting someone corrects later — it is baked into every certificate
/// already issued, and fixing it means reissuing the hierarchy. That makes these two methods
/// some of the least forgiving code in the product, and they had no tests.
/// </para>
/// <para>
/// The contract is <c>PublicPort ?? Port</c>, with the scheme's default port omitted. The setup
/// wizard broke it by always sending a concrete PublicPort — hardcoded to 8443/8080 and never
/// following the listener — so an operator who moved the listeners to 443/80 still got :8443 and
/// :8080 in their certificates. The fallback below is what the wizard now relies on by sending
/// null, so it is worth pinning.
/// </para>
/// </remarks>
public class PublicUrlTests
{
    private static HttpsConfig Https(int port, int? publicPort = null, string domain = "ca.example.test")
        => new() { Port = port, PublicPort = publicPort, PublicDomain = domain };

    // ---- HTTPS ------------------------------------------------------------------------------

    [Fact]
    public void The_public_port_falls_back_to_the_listener_port()
    {
        // The whole fix depends on this: the wizard sends null and expects the listener port.
        Assert.Equal("https://ca.example.test:8443", Https(8443).GetPublicHttpsBaseUrl());
    }

    [Fact]
    public void A_listener_on_443_produces_a_url_with_no_port()
    {
        // The reported symptom, from the other side: move the listener to 443, send no public
        // port, and the URL must lose the port entirely rather than keep 8443.
        Assert.Equal("https://ca.example.test", Https(443).GetPublicHttpsBaseUrl());
    }

    [Fact]
    public void An_explicit_public_port_wins_over_the_listener()
    {
        // The legitimate reverse-proxy case: Kestrel on 8443, proxy terminating on 443.
        Assert.Equal("https://ca.example.test", Https(8443, publicPort: 443).GetPublicHttpsBaseUrl());
        Assert.Equal("https://ca.example.test:9443", Https(8443, publicPort: 9443).GetPublicHttpsBaseUrl());
    }

    [Fact]
    public void A_stale_public_port_overrides_a_corrected_listener()
    {
        // Exactly the bug, pinned as behaviour rather than as a defect: an explicit 8443 beats a
        // listener moved to 443. The server is right to honour it — only the caller knows whether
        // a proxy exists — which is why the fix belonged in the wizard, and why the review step
        // now shows the operator this URL before anything is issued.
        Assert.Equal("https://ca.example.test:8443", Https(443, publicPort: 8443).GetPublicHttpsBaseUrl());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_nonsensical_port_degrades_to_the_scheme_default(int port)
        => Assert.Equal("https://ca.example.test", Https(port).GetPublicHttpsBaseUrl());

    // ---- HTTP (CDP / AIA / OCSP) -------------------------------------------------------------

    [Fact]
    public void Http_falls_back_to_the_bind_port_and_omits_80()
    {
        var cfg = Https(8443);

        Assert.Equal("http://ca.example.test:8080", cfg.GetPublicHttpBaseUrl(8080));
        Assert.Equal("http://ca.example.test", cfg.GetPublicHttpBaseUrl(80));
    }

    [Fact]
    public void An_explicit_http_public_port_wins()
    {
        var cfg = Https(8443);

        Assert.Equal("http://ca.example.test", cfg.GetPublicHttpBaseUrl(8080, httpPublicPort: 80));
        Assert.Equal("http://ca.example.test:8080", cfg.GetPublicHttpBaseUrl(80, httpPublicPort: 8080));
    }

    [Fact]
    public void Revocation_urls_use_http_not_https()
    {
        // CDP and AIA are fetched over plain HTTP on purpose — RFC 5280 §4.2.1.13, and to avoid
        // the chicken-and-egg of needing a valid chain to fetch the thing that validates it. A
        // change to https here would break revocation checking for clients that refuse to follow.
        Assert.StartsWith("http://", Https(8443).GetPublicHttpBaseUrl(8080), StringComparison.Ordinal);
    }

    [Fact]
    public void Both_schemes_agree_on_the_configured_domain()
    {
        var cfg = Https(443, domain: "pki.internal.example");

        Assert.Equal("https://pki.internal.example", cfg.GetPublicHttpsBaseUrl());
        Assert.Equal("http://pki.internal.example", cfg.GetPublicHttpBaseUrl(80));
    }
}
