using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins how a configured subdomain becomes the hostname the TLS layer gates on.
/// </summary>
/// <remarks>
/// This logic decides which SNI name gets a CertificateRequest, and separately which URL the UI
/// tells people to visit. It used to exist as four inline copies that had already drifted on
/// whitespace handling. When those two answers disagree, the product hands out a hostname the
/// handshake does not gate, and the resulting failure looks like an authentication problem.
/// </remarks>
public class SubdomainUtilTests
{
    [Fact]
    public void A_short_prefix_is_completed_from_the_public_domain()
    {
        Assert.Equal("est.ca.example.com", SubdomainUtil.ResolveFqdn("est", "ca.example.com"));
    }

    [Fact]
    public void A_value_that_already_contains_a_dot_is_taken_as_a_complete_fqdn()
    {
        // Deployments whose enrollment hostname does not sit under the portal's domain rely on
        // this — completing it would produce est.example.net.ca.example.com.
        Assert.Equal("est.example.net", SubdomainUtil.ResolveFqdn("est.example.net", "ca.example.com"));
    }

    [Fact]
    public void Whitespace_is_trimmed_from_both_parts()
    {
        // A trailing space in a YAML value is invisible in an editor and would otherwise produce a
        // hostname that matches no ClientHello ever sent.
        Assert.Equal("est.ca.example.com", SubdomainUtil.ResolveFqdn("  est  ", "  ca.example.com  "));
    }

    [Fact]
    public void A_short_prefix_with_no_public_domain_stays_a_single_label()
    {
        // Meaningful on an internal network where the host is reached as a bare name.
        Assert.Equal("est", SubdomainUtil.ResolveFqdn("est", ""));
        Assert.Equal("est", SubdomainUtil.ResolveFqdn("est", null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_unset_subdomain_resolves_to_null(string? configured)
    {
        // Null is what turns the gate off. Returning an empty string instead would make the SNI
        // comparison below match a client that sent no server name.
        Assert.Null(SubdomainUtil.ResolveFqdn(configured, "ca.example.com"));
    }

    [Fact]
    public void Sni_matching_ignores_case()
    {
        // RFC 4343. A case-sensitive compare withholds the CertificateRequest from a client that
        // capitalised the hostname, and the client then reports an authentication failure for what
        // is really a string comparison.
        Assert.True(SubdomainUtil.MatchesSni("EST.ca.example.com", "est.ca.example.com"));
        Assert.True(SubdomainUtil.MatchesSni("est.ca.example.com", "EST.CA.EXAMPLE.COM"));
    }

    [Fact]
    public void Sni_matching_requires_an_exact_hostname()
    {
        Assert.False(SubdomainUtil.MatchesSni("ca.example.com", "est.ca.example.com"));
        Assert.False(SubdomainUtil.MatchesSni("est.ca.example.com.evil.test", "est.ca.example.com"));
        Assert.False(SubdomainUtil.MatchesSni("notest.ca.example.com", "est.ca.example.com"));
    }

    [Fact]
    public void A_connection_with_no_sni_matches_nothing()
    {
        // Connecting by IP address sends no server name. Matching it against a gated hostname would
        // hand a client-certificate prompt to every such connection.
        Assert.False(SubdomainUtil.MatchesSni(null, "est.ca.example.com"));
        Assert.False(SubdomainUtil.MatchesSni("", "est.ca.example.com"));
    }

    [Fact]
    public void An_unconfigured_gate_matches_nothing()
    {
        // The off switch. If an empty setting matched, turning the subdomain off would gate every
        // connection instead of none.
        Assert.False(SubdomainUtil.MatchesSni("est.ca.example.com", null));
        Assert.False(SubdomainUtil.MatchesSni("est.ca.example.com", ""));
    }
}
