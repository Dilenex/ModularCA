using ModularCA.Core.Services.Est;
using ModularCA.Core.Services.Scep;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the SAN half of caller-identity binding on the two enrollment protocols that had only
/// the subject DN half.
/// <para>
/// Both protocols authenticate a caller and then decide what names that caller may be issued. Both
/// compared the CSR's Common Name and stopped there. A Common Name is not where a TLS
/// certificate's identity lives — every relying party reads the SAN extension — so "the CN matches
/// the caller" bounded nothing that mattered.
/// </para>
/// </summary>
public class ScepRenewalSanBindingTests
{
    // A SCEP renewal skips the challenge password precisely because the CMS signer certificate
    // stands in for it. That makes the signer's own names the entire authorization.
    private static readonly string[] SignerSans = ["DNS:printer1.devices.example.com", "IP:10.0.0.7"];

    [Fact]
    public void A_renewal_that_asks_for_exactly_what_it_holds_is_allowed()
    {
        Assert.Null(ScepService.FirstSanNotHeldBySigner(
            ["DNS:printer1.devices.example.com"], SignerSans));
    }

    [Fact]
    public void A_renewal_that_drops_a_name_is_allowed()
    {
        // Narrowing is always fine; the rule bounds what may be added.
        Assert.Null(ScepService.FirstSanNotHeldBySigner([], SignerSans));
    }

    [Fact]
    public void A_renewal_may_not_add_a_name_the_signer_does_not_hold()
    {
        // The escalation: a device certificate renewed into a certificate for the CA's own front
        // end. The subject DN check passes — the subject is unchanged — and the SANRestriction
        // that would have caught it only runs on initial enrollment.
        var unheld = ScepService.FirstSanNotHeldBySigner(
            ["DNS:printer1.devices.example.com", "DNS:ca.example.com"], SignerSans);
        Assert.Equal("DNS:ca.example.com", unheld);
    }

    [Fact]
    public void A_wildcard_is_not_covered_by_the_name_it_would_match()
    {
        // "*.devices.example.com" is a superset of the held name, not a member of it.
        Assert.NotNull(ScepService.FirstSanNotHeldBySigner(
            ["DNS:*.devices.example.com"], SignerSans));
    }

    [Fact]
    public void Prefix_spelling_differences_do_not_reject_a_healthy_renewal()
    {
        // The certificate parser writes "Email:", the CSR parser writes something else; comparing
        // whole entries would make one identical address look like two different ones and break
        // every renewal of an email certificate.
        Assert.Null(ScepService.FirstSanNotHeldBySigner(
            ["EMAIL:ops@example.com"], ["Email:ops@example.com"]));
    }

    [Fact]
    public void Case_differences_in_a_hostname_do_not_reject_a_healthy_renewal()
    {
        Assert.Null(ScepService.FirstSanNotHeldBySigner(
            ["DNS:Printer1.Devices.Example.COM"], SignerSans));
    }

    [Fact]
    public void An_ip_san_is_bound_the_same_way_as_a_hostname()
    {
        Assert.Null(ScepService.FirstSanNotHeldBySigner(["IP:10.0.0.7"], SignerSans));
        Assert.NotNull(ScepService.FirstSanNotHeldBySigner(["IP:10.0.0.8"], SignerSans));
    }

    [Fact]
    public void A_signer_with_no_sans_at_all_may_add_none()
    {
        // Fail closed: a signer that holds no alternative names cannot confer any.
        Assert.Equal("DNS:anything.example.com",
            ScepService.FirstSanNotHeldBySigner(["DNS:anything.example.com"], []));
    }

    [Fact]
    public void Blank_entries_are_ignored_rather_than_rejected()
    {
        Assert.Null(ScepService.FirstSanNotHeldBySigner(["", "   "], SignerSans));
    }
}

/// <summary>
/// The EST half: a caller authenticated by username, rather than by client certificate, was bound
/// only by its CN.
/// <para>
/// The mTLS branch of <c>SimpleEnrollAsync</c> requires every CSR SAN to be a name the client
/// certificate already carries. The HTTP-auth branch checked the CN and nothing else, so the two
/// routes into the same endpoint were not equally bound: an account with plain enrollment rights
/// could submit <c>CN=&lt;its own username&gt;</c> — satisfying the CN check exactly — with
/// <c>DNS:vpn.example.com</c> in the SAN extension and receive a server certificate for a host it
/// has no relationship to.
/// </para>
/// </summary>
public class EstBasicAuthSanBindingTests
{
    [Fact]
    public void A_san_equal_to_the_callers_username_is_bound()
    {
        Assert.True(EstService.SanIsBoundToCaller("printer1", "printer1", csrCn: "printer1"));
    }

    [Fact]
    public void A_san_repeating_the_csr_common_name_is_bound()
    {
        // The CN has already had to equal the username to reach this point, so a CSR that repeats
        // its own subject in the SAN extension asserts nothing new. This is the ordinary shape and
        // it has to keep working.
        Assert.True(EstService.SanIsBoundToCaller("printer1", "printer1", csrCn: "printer1"));
    }

    [Fact]
    public void An_unrelated_hostname_is_not_bound()
    {
        Assert.False(EstService.SanIsBoundToCaller("vpn.example.com", "printer1", csrCn: "printer1"));
    }

    [Fact]
    public void Case_is_not_a_way_around_the_binding_nor_a_way_to_fail_it()
    {
        Assert.True(EstService.SanIsBoundToCaller("Printer1", "printer1", csrCn: "printer1"));
    }

    [Fact]
    public void An_empty_common_name_does_not_bind_anything()
    {
        // A CSR with no CN passes the CN check vacuously — it is the cheapest way to have nothing
        // compared — so it must not then be treated as vouching for the SANs.
        Assert.False(EstService.SanIsBoundToCaller("vpn.example.com", "printer1", csrCn: null));
        Assert.False(EstService.SanIsBoundToCaller("vpn.example.com", "printer1", csrCn: ""));
    }

    [Fact]
    public void A_blank_san_value_is_not_bound()
    {
        Assert.False(EstService.SanIsBoundToCaller("   ", "printer1", csrCn: "printer1"));
    }
}
