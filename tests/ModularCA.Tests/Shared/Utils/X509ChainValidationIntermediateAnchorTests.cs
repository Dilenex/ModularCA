using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// <see cref="X509ChainValidationUtil.ValidateAgainstAnchor"/> with an intermediate CA as the
/// anchor, which is what the mTLS login path passes when a credential's signing CA is an issuing
/// CA under an offline root. The anchor is the only certificate the caller has; the root is not
/// supplied, so the chain has to stop at the intermediate.
/// </summary>
public class X509ChainValidationIntermediateAnchorTests
{
    [Fact]
    public void A_leaf_validates_against_its_intermediate_issuer_as_the_only_anchor()
    {
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var intermediate = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var leaf = TestCertificates.IssueLeaf(intermediate, "CN=alice");

        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, intermediate, requireRevocationCheck: false, out var errors);

        Assert.True(ok, $"expected the leaf to chain to its issuing intermediate, got: {errors}");
        Assert.Null(errors);
    }

    /// <summary>
    /// The certificates of a real instance name where their issuer's certificate can be fetched
    /// (CA Issuers). A chain engine that follows it fetches the root, builds leaf, intermediate,
    /// root, and ends on a root nobody said to trust: on a test host every certificate of an
    /// intermediate CA was then refused as not chaining to it, though the tests, whose
    /// certificates name no such address, passed. The validator is given the CA to trust and
    /// fetches nothing: the leaf validates, and the address is never asked for.
    /// </summary>
    [Fact]
    public void A_leaf_validates_under_an_intermediate_whose_certificate_says_where_to_fetch_its_root()
    {
        using var server = new LocalCrlServer();
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        var rootUrl = server.NewUrl();
        server.Publish(rootUrl, root.Export(X509ContentType.Cert));
        using var intermediate = TestCertificates.IssueIntermediateWithCaIssuers(root, "CN=Login Issuing CA, O=ModularCA", rootUrl);
        var intermediateUrl = server.NewUrl();
        server.Publish(intermediateUrl, intermediate.Export(X509ContentType.Cert));
        using var leaf = TestCertificates.IssueLeafWithCaIssuers(intermediate, "CN=alice", intermediateUrl);

        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(leaf, intermediate, requireRevocationCheck: false, out var errors);

        Assert.True(ok, $"expected the leaf to chain to its issuing intermediate, got: {errors}");
        Assert.Equal(0, server.RequestsFor(rootUrl));
        Assert.Equal(0, server.RequestsFor(intermediateUrl));
    }

    [Fact]
    public void A_leaf_of_a_sibling_intermediate_under_the_same_root_does_not_validate()
    {
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var login = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var other = TestCertificates.IssueIntermediate(root, "CN=Device Issuing CA, O=ModularCA");
        using var leaf = TestCertificates.IssueLeaf(other, "CN=alice");

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, login, requireRevocationCheck: false, out var errors));
        Assert.False(string.IsNullOrWhiteSpace(errors));
    }

    [Fact]
    public void A_leaf_does_not_validate_against_the_root_when_only_the_root_is_given()
    {
        // The intermediate is not supplied, so there is no path from the leaf to the root.
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var intermediate = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var leaf = TestCertificates.IssueLeaf(intermediate, "CN=alice");

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, root, requireRevocationCheck: false, out _));
    }

    [Fact]
    public void A_forged_issuer_naming_the_intermediate_does_not_validate()
    {
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var intermediate = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var forged = TestCertificates.ForgedIssuer(intermediate, "CN=root-admin");

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(forged, intermediate, requireRevocationCheck: false, out _));
    }

    /// <summary>
    /// With revocation required, a leaf whose status cannot be determined (it names no CRL or OCSP
    /// responder) still fails closed under an intermediate anchor. Only the anchor's own
    /// undetermined status is tolerated, as a self-signed anchor's is. No chain engine checks a
    /// leaf's revocation on a chain that stops at an intermediate: Windows reports the leaf's
    /// status as unknown without fetching anything, and the OpenSSL-backed engine reports nothing,
    /// where the refusal is the validator's own. The result and the status named are the same on
    /// every platform. A check that can pass needs the anchor's issuers: see
    /// <see cref="X509ChainValidationAnchorIssuersTests"/>.
    /// </summary>
    [Fact]
    public void Required_revocation_still_fails_closed_for_a_leaf_under_the_intermediate()
    {
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var intermediate = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var leaf = TestCertificates.IssueLeaf(intermediate, "CN=alice");

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, intermediate, requireRevocationCheck: true, out var errors));
        Assert.Contains("RevocationStatusUnknown", errors);
    }

    [Fact]
    public void An_expired_leaf_under_the_intermediate_does_not_validate()
    {
        using var root = TestCertificates.CreateCa("CN=Offline Root, O=ModularCA");
        using var intermediate = TestCertificates.IssueIntermediate(root, "CN=Login Issuing CA, O=ModularCA");
        using var leaf = TestCertificates.IssueExpiredLeaf(intermediate);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(leaf, intermediate, requireRevocationCheck: false, out var errors));
        Assert.Contains("NotTimeValid", errors);
    }
}
