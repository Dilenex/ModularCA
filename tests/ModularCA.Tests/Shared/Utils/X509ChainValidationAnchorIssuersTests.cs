using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// <see cref="X509ChainValidationUtil.ValidateAgainstAnchor(X509Certificate2, X509Certificate2, IReadOnlyCollection{X509Certificate2}?, bool, out string?)"/>
/// with an intermediate CA as the anchor and the anchor's own issuers supplied, which is what lets
/// a required revocation check run where the chain engine checks revocation only on a chain that
/// reaches a self-signed root.
/// <para>
/// Nothing here branches on the platform. The CRLs are served by a
/// <see cref="LocalCrlServer"/>, and the tests that expect a check to have run also look at what
/// the server was asked for, so "validates" cannot be satisfied by a check that never happened.
/// </para>
/// </summary>
public sealed class X509ChainValidationAnchorIssuersTests : IDisposable
{
    private readonly LocalCrlServer _crls = new();
    private readonly List<X509Certificate2> _owned = [];

    /// <summary>Disposes the certificates and the CRL server.</summary>
    public void Dispose()
    {
        foreach (var certificate in _owned)
            certificate.Dispose();
        _crls.Dispose();
    }

    /// <summary>A subject no other test, and no earlier run, has used: the engines cache by name.</summary>
    private static string Name(string cn) => $"CN={cn} {Guid.NewGuid():N}, O=ModularCA";

    private X509Certificate2 Own(X509Certificate2 certificate)
    {
        _owned.Add(certificate);
        return certificate;
    }

    private X509Certificate2 Root() => Own(TestCertificates.CreateCa(Name("Offline Root")));

    /// <summary>An intermediate under <paramref name="issuer"/>, naming <paramref name="crlUrl"/> when given.</summary>
    private X509Certificate2 Intermediate(X509Certificate2 issuer, string? crlUrl = null, int pathLength = 0, string cn = "Login Issuing CA")
        => Own(TestCertificates.IssueIntermediateWithCrl(issuer, Name(cn), crlUrl, pathLength));

    /// <summary>
    /// A leaf under <paramref name="ca"/> with a distribution point, and <paramref name="ca"/>'s
    /// CRL published there: empty, or listing the leaf when <paramref name="revoked"/>.
    /// </summary>
    private (X509Certificate2 Leaf, string CrlUrl) LeafWithPublishedCrl(X509Certificate2 ca, bool revoked = false)
    {
        var url = _crls.NewUrl();
        var leaf = Own(TestCertificates.IssueLeafWithCrl(ca, Name("alice"), url));
        _crls.Publish(url, revoked ? TestCertificates.BuildCrl(ca, leaf) : TestCertificates.BuildCrl(ca));
        return (leaf, url);
    }

    [Fact]
    public void With_the_root_supplied_a_leaf_whose_CRL_clears_it_validates_with_revocation_required()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor);

        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors);

        Assert.True(ok, $"expected the leaf to validate with its revocation checked, got: {errors}");
        Assert.Null(errors);
        Assert.True(_crls.RequestsFor(leafCrl) > 0, "the leaf's CRL was never fetched, so its revocation was not checked");
    }

    [Fact]
    public void With_the_root_supplied_a_revoked_leaf_does_not_validate()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var (leaf, _) = LeafWithPublishedCrl(anchor, revoked: true);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors));
        Assert.Contains("Revoked", errors);
    }

    [Fact]
    public void With_the_root_supplied_a_leaf_that_names_no_revocation_source_still_fails_closed()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var leaf = Own(TestCertificates.IssueLeaf(anchor, Name("alice")));

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors));
        Assert.Contains("RevocationStatusUnknown", errors);
    }

    [Fact]
    public void With_the_root_supplied_a_leaf_whose_CRL_cannot_be_fetched_still_fails_closed()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var unpublished = _crls.NewUrl();
        var leaf = Own(TestCertificates.IssueLeafWithCrl(anchor, Name("alice"), unpublished));

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors));
        Assert.Matches("RevocationStatusUnknown|OfflineRevocation", errors);
    }

    /// <summary>
    /// The anchor's own status: a CRL from its issuer that clears it is fetched and accepted.
    /// </summary>
    [Fact]
    public void The_anchor_is_checked_too_when_its_issuer_publishes_a_CRL()
    {
        var root = Root();
        var anchorCrl = _crls.NewUrl();
        var anchor = Intermediate(root, anchorCrl);
        _crls.Publish(anchorCrl, TestCertificates.BuildCrl(root));
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor);

        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors);

        Assert.True(ok, $"expected the leaf to validate, got: {errors}");
        Assert.True(_crls.RequestsFor(leafCrl) > 0, "the leaf's CRL was never fetched");
        Assert.True(_crls.RequestsFor(anchorCrl) > 0, "the anchor's CRL was never fetched");
    }

    /// <summary>
    /// A revocation of the anchor that the root has published is honoured, whatever the leaf's
    /// own CRL says.
    /// </summary>
    [Fact]
    public void A_leaf_under_an_anchor_its_root_has_revoked_does_not_validate()
    {
        var root = Root();
        var anchorCrl = _crls.NewUrl();
        var anchor = Intermediate(root, anchorCrl);
        _crls.Publish(anchorCrl, TestCertificates.BuildCrl(root, anchor));
        var (leaf, _) = LeafWithPublishedCrl(anchor);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors));
        Assert.Contains("Revoked", errors);
    }

    /// <summary>
    /// The anchor's own CRL being out of reach does not take down every sign-in under it, as long
    /// as the leaf's check ran and cleared the leaf.
    /// </summary>
    [Fact]
    public void An_anchor_whose_own_CRL_cannot_be_fetched_does_not_fail_a_leaf_that_was_checked()
    {
        var root = Root();
        var unpublished = _crls.NewUrl();
        var anchor = Intermediate(root, unpublished);
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor);

        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors);

        Assert.True(ok, $"expected the leaf to validate, got: {errors}");
        Assert.True(_crls.RequestsFor(leafCrl) > 0, "the leaf's CRL was never fetched");
    }

    [Fact]
    public void Issuers_through_a_second_intermediate_complete_the_chain_in_any_order()
    {
        var root = Root();
        var policy = Intermediate(root, pathLength: 1, cn: "Policy CA");
        var anchor = Intermediate(policy);
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor);

        Assert.True(
            X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root, policy], requireRevocationCheck: true, out var errors),
            $"expected the leaf to validate, got: {errors}");
        Assert.True(
            X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [policy, root], requireRevocationCheck: true, out errors),
            $"expected the leaf to validate, got: {errors}");
        Assert.True(_crls.RequestsFor(leafCrl) > 0, "the leaf's CRL was never fetched");
    }

    /// <summary>
    /// The property the issuers must not disturb: "issued by this CA" stays exact. The sibling CA
    /// is even handed over among the issuers, so a complete, valid chain from the leaf to the
    /// trusted root exists. It does not pass through the anchor, so it does not count, and the
    /// leaf is turned away before anything is fetched on its behalf.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_leaf_of_a_sibling_intermediate_does_not_validate_even_with_the_sibling_among_the_issuers(bool requireRevocationCheck)
    {
        var root = Root();
        var login = Intermediate(root);
        var other = Intermediate(root, cn: "Device Issuing CA");
        var (leaf, leafCrl) = LeafWithPublishedCrl(other);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, login, [root, other], requireRevocationCheck, out var errors));
        Assert.False(string.IsNullOrWhiteSpace(errors));
        Assert.Equal(0, _crls.RequestsFor(leafCrl));
    }

    [Fact]
    public void A_forged_issuer_naming_the_anchor_does_not_validate_with_the_root_supplied()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var forged = Own(TestCertificates.ForgedIssuer(anchor, Name("root-admin")));

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(forged, anchor, [root], requireRevocationCheck: true, out _));
        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(forged, anchor, [root], requireRevocationCheck: false, out _));
    }

    /// <summary>
    /// Supplying the intermediate as an "issuer" of the root does not make the root an anchor for
    /// the intermediate's leaves: a leaf validates only against its direct issuer.
    /// </summary>
    [Fact]
    public void A_leaf_does_not_validate_against_the_root_with_the_intermediate_passed_as_an_issuer()
    {
        var root = Root();
        var intermediate = Intermediate(root);
        var (leaf, _) = LeafWithPublishedCrl(intermediate);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, root, [intermediate], requireRevocationCheck: true, out _));
        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, root, [intermediate], requireRevocationCheck: false, out _));
    }

    [Fact]
    public void An_expired_leaf_does_not_validate_with_the_root_supplied()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var leaf = Own(TestCertificates.IssueExpiredLeaf(anchor, Name("expired")));

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errors));
        Assert.Contains("NotTimeValid", errors);
    }

    /// <summary>
    /// Without a revocation requirement the issuers are not used at all: the result is the one
    /// the anchor alone gives, and nothing is fetched.
    /// </summary>
    [Fact]
    public void Without_a_revocation_requirement_the_issuers_change_nothing_and_nothing_is_fetched()
    {
        var root = Root();
        var anchor = Intermediate(root);
        var unrelated = Root();
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor, revoked: true);

        Assert.True(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: false, out var errors), errors);
        Assert.True(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [unrelated], requireRevocationCheck: false, out errors), errors);
        Assert.Equal(0, _crls.RequestsFor(leafCrl));
    }

    /// <summary>
    /// Issuers that do not lead from the anchor to a self-signed root are the same as none, and
    /// with none a required check fails closed as undetermined even though the leaf's CRL is
    /// there to be read: the engine does not read it for a chain that stops at an intermediate
    /// (Windows says so itself; elsewhere the validator refuses because the engine says nothing).
    /// </summary>
    [Fact]
    public void Issuers_that_do_not_reach_a_root_through_the_anchor_leave_the_behaviour_without_issuers()
    {
        var root = Root();
        var policy = Intermediate(root, pathLength: 1, cn: "Policy CA");
        var anchor = Intermediate(policy);
        var unrelated = Root();
        var (leaf, leafCrl) = LeafWithPublishedCrl(anchor);

        var withoutIssuers = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, requireRevocationCheck: true, out var errorsWithout);
        var withUnrelatedRoot = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [unrelated], requireRevocationCheck: true, out var errorsUnrelated);
        var withTheRootButNotThePolicyCa = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [root], requireRevocationCheck: true, out var errorsGap);
        var withThePolicyCaButNoRoot = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [policy], requireRevocationCheck: true, out var errorsNoRoot);

        Assert.False(withoutIssuers);
        Assert.False(withUnrelatedRoot);
        Assert.False(withTheRootButNotThePolicyCa);
        Assert.False(withThePolicyCaButNoRoot);
        Assert.Contains("RevocationStatusUnknown", errorsWithout);
        Assert.Contains("RevocationStatusUnknown", errorsUnrelated);
        Assert.Contains("RevocationStatusUnknown", errorsGap);
        Assert.Contains("RevocationStatusUnknown", errorsNoRoot);

        // The same leaf does validate once the issuers given are the right ones.
        Assert.True(
            X509ChainValidationUtil.ValidateAgainstAnchor(leaf, anchor, [policy, root], requireRevocationCheck: true, out var errors),
            $"expected the leaf to validate with its real issuers supplied, got: {errors}");
        Assert.True(_crls.RequestsFor(leafCrl) > 0, "the leaf's CRL was never fetched");
    }
}
