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
    /// undetermined status is tolerated, as a self-signed anchor's is.
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
