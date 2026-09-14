using ModularCA.Core.Services.Cmp;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Pins the rule that a signature-protected CMP request may only name its signer.
/// </summary>
/// <remarks>
/// Before this rule, any holder of any unrevoked certificate from the CA could sign an <c>ir</c>
/// for any subject and any SAN the request profile tolerated. The protection verified, the
/// request counted as authenticated, and the CA issued.
/// </remarks>
public class CmpSignerNameBindingTests
{
    private static bool Dn(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void A_request_for_the_signers_own_subject_and_sans_is_bound()
    {
        Assert.Null(CmpSignerNameBinding.Check(
            "CN=printer7", ["DNS:printer7.example.test"],
            "CN=printer7", ["DNS:printer7.example.test", "IP:10.0.0.7"], Dn));
    }

    [Fact]
    public void A_request_for_someone_elses_subject_is_refused()
    {
        // The attack: a device holding CN=printer7 signs a request for CN=ca-admin.
        var error = CmpSignerNameBinding.Check("CN=ca-admin", [], "CN=printer7", [], Dn);
        Assert.NotNull(error);
        Assert.Contains("subject", error);
    }

    [Fact]
    public void A_san_the_signer_does_not_hold_is_refused_by_name()
    {
        var error = CmpSignerNameBinding.Check(
            "CN=printer7", ["DNS:ca.example.test"],
            "CN=printer7", ["DNS:printer7.example.test"], Dn);
        Assert.NotNull(error);
        Assert.Contains("DNS:ca.example.test", error);
    }

    [Fact]
    public void San_comparison_ignores_case_but_not_type()
    {
        Assert.Null(CmpSignerNameBinding.Check(
            "CN=printer7", ["dns:PRINTER7.example.test"], "CN=printer7", ["DNS:printer7.example.test"], Dn));
        // EST's mTLS branch strips SAN types before comparing; this one does not. An email: SAN
        // does not authorise a DNS: SAN for the same string.
        Assert.NotNull(CmpSignerNameBinding.Check(
            "CN=printer7", ["DNS:x"], "CN=printer7", ["EMAIL:x"], Dn));
    }

    [Fact]
    public void An_empty_template_subject_is_refused()
    {
        // Leaving the subject to the profile is not the same as naming the signer. The comparer
        // here accepts everything, so the only thing that can refuse is the empty-subject rule
        // itself; with the real comparer this test passed even without the rule.
        static bool AcceptAll(string a, string b) => true;
        Assert.NotNull(CmpSignerNameBinding.Check("", [], "CN=printer7", [], AcceptAll));
        Assert.NotNull(CmpSignerNameBinding.Check(null, [], "CN=printer7", [], AcceptAll));
        Assert.NotNull(CmpSignerNameBinding.Check("   ", [], "CN=printer7", [], AcceptAll));
    }

    [Fact]
    public void A_signer_with_no_subject_binds_nothing()
    {
        Assert.NotNull(CmpSignerNameBinding.Check("CN=printer7", [], "", [], Dn));
    }

    [Fact]
    public void Dn_equivalence_is_delegated_not_reimplemented()
    {
        // The supplied comparer decides subject equality, so RDN-order and whitespace tolerance
        // come from the same place CMP uses elsewhere.
        var calls = 0;
        bool Spy(string a, string b) { calls++; return true; }
        Assert.Null(CmpSignerNameBinding.Check("CN=a, O=b", [], "O=b, CN=a", [], Spy));
        Assert.Equal(1, calls);
    }
}
