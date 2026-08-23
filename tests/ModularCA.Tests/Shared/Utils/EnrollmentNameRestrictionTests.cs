using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="EnrollmentNameRestriction"/>, which decides whether a CSR satisfies a public
/// enrollment token's name restrictions.
/// <para>
/// The endpoint enforcing these is anonymous: possession of the token is the entire
/// authorization. So the interesting cases are not the ones that match — they are the ones that
/// used to slip through. Each of the three below was a real bypass.
/// </para>
/// </summary>
public class EnrollmentNameRestrictionTests
{
    // ── The three original defects ─────────────────────────────────────────────

    [Fact]
    public void Empty_subject_no_longer_bypasses_a_subject_restriction()
    {
        // The old check was `restriction set && subject non-empty && !subject.Contains(...)`,
        // so an empty subject short-circuited to "permitted". A SAN-only TLS CSR has exactly
        // that shape, which made this the easiest bypass available.
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("", "example.com", out var why));
        Assert.Contains("no subject", why, StringComparison.OrdinalIgnoreCase);

        Assert.False(EnrollmentNameRestriction.SubjectSatisfies(null, "example.com", out _));
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("   ", "example.com", out _));
    }

    [Fact]
    public void Substring_lookalike_domain_is_rejected()
    {
        // `subject.Contains("example.com")` accepted this: the restriction appears verbatim
        // inside a hostname the operator has no control over.
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies(
            "CN=evil-example.com.attacker.net", "example.com", out _));

        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("CN=notexample.com", "example.com", out _));
    }

    [Fact]
    public void San_restriction_is_actually_enforced()
    {
        // SANRestriction was accepted, stored and echoed, but read by nothing — so this CSR
        // enrolled successfully under a token restricted to example.com.
        var sans = new[] { "DNS:attacker.net" };

        Assert.False(EnrollmentNameRestriction.SansSatisfy(sans, "example.com", out var why));
        Assert.Contains("attacker.net", why, StringComparison.OrdinalIgnoreCase);
    }

    // ── Subject matching ───────────────────────────────────────────────────────

    [Fact]
    public void Unset_restriction_permits_anything()
    {
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("CN=anything", null, out _));
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("", "   ", out _));
        Assert.True(EnrollmentNameRestriction.SansSatisfy(new[] { "DNS:anything" }, null, out _));
    }

    [Theory]
    [InlineData("CN=example.com", true)]
    [InlineData("CN=host.example.com", true)]
    [InlineData("CN=deep.host.example.com", true)]
    [InlineData("CN=*.example.com", true)]           // wildcard judged by the domain it covers
    [InlineData("CN=example.com.", true)]            // trailing root dot
    [InlineData("CN=EXAMPLE.COM", true)]             // DNS is case-insensitive
    [InlineData("CN=example.comx", false)]
    [InlineData("CN=badexample.com", false)]
    [InlineData("CN=example.org", false)]
    public void Dns_pattern_matches_on_label_boundaries(string subject, bool expected)
    {
        Assert.Equal(expected, EnrollmentNameRestriction.SubjectSatisfies(subject, "example.com", out _));
    }

    [Fact]
    public void Subject_with_no_common_name_fails_a_dns_pattern()
    {
        // Fail closed: there is nothing for a DNS pattern to test, so the restriction cannot be
        // shown to hold.
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("O=Acme,C=US", "example.com", out var why));
        Assert.Contains("Common Name", why, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Common_name_is_read_from_any_position_in_the_dn()
    {
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("O=Acme,CN=host.example.com,C=US", "example.com", out _));
    }

    // ── DN component patterns ──────────────────────────────────────────────────

    [Fact]
    public void Dn_component_matches_on_rdn_boundaries()
    {
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("CN=host,O=Acme,C=US", "O=Acme", out _));
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("CN=host, O = Acme", "O=Acme", out _));

        // A substring test would accept this. The operator asked for the organisation Acme, not
        // any organisation whose name starts with it.
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("CN=host,O=Acme Evil Corp", "O=Acme", out _));
    }

    [Fact]
    public void Any_one_pattern_in_a_list_is_enough()
    {
        Assert.True(EnrollmentNameRestriction.SubjectSatisfies("CN=a.example.org", "example.com, example.org", out _));
        Assert.False(EnrollmentNameRestriction.SubjectSatisfies("CN=a.example.net", "example.com, example.org", out _));
    }

    // ── SAN matching ───────────────────────────────────────────────────────────

    [Fact]
    public void Every_san_must_match_not_just_one()
    {
        // The dangerous shape: one legitimate name alongside one the token never authorised.
        var sans = new[] { "DNS:ok.example.com", "DNS:evil.attacker.net" };

        Assert.False(EnrollmentNameRestriction.SansSatisfy(sans, "example.com", out var why));
        Assert.Contains("evil.attacker.net", why);
    }

    [Fact]
    public void Non_dns_sans_cannot_satisfy_a_dns_restriction()
    {
        // Fail closed. Permitting these would let a token restricted to example.com issue for an
        // arbitrary IP or email identity, neither of which the restriction can speak about.
        Assert.False(EnrollmentNameRestriction.SansSatisfy(new[] { "IP:10.0.0.1" }, "example.com", out _));
        Assert.False(EnrollmentNameRestriction.SansSatisfy(new[] { "Email:root@attacker.net" }, "example.com", out _));
        Assert.False(EnrollmentNameRestriction.SansSatisfy(new[] { "Other:1.2.3.4" }, "example.com", out _));
    }

    [Fact]
    public void Dn_only_restriction_rejects_every_san()
    {
        // A DN component says nothing about a SAN, so there is no rule any SAN could satisfy.
        // Treating that as "no applicable rule, permit" would silently disable the control.
        Assert.False(EnrollmentNameRestriction.SansSatisfy(new[] { "DNS:anything.com" }, "O=Acme", out _));
    }

    [Fact]
    public void Empty_san_list_satisfies_any_restriction()
    {
        // A restriction bounds which names may appear; it does not require that any do. The
        // subject restriction covers the CN.
        Assert.True(EnrollmentNameRestriction.SansSatisfy([], "example.com", out _));
        Assert.True(EnrollmentNameRestriction.SansSatisfy(null, "example.com", out _));
    }

    [Fact]
    public void Sans_match_subdomains_and_wildcards_like_the_subject_does()
    {
        Assert.True(EnrollmentNameRestriction.SansSatisfy(
            new[] { "DNS:example.com", "DNS:a.example.com", "DNS:*.example.com" }, "example.com", out _));
    }

    [Fact]
    public void ParsePatterns_splits_on_commas_and_whitespace()
    {
        Assert.Equal(new[] { "a.com", "b.com", "c.com" },
            EnrollmentNameRestriction.ParsePatterns("a.com, b.com  c.com"));
        Assert.Empty(EnrollmentNameRestriction.ParsePatterns(null));
        Assert.Empty(EnrollmentNameRestriction.ParsePatterns("  "));
    }
}
