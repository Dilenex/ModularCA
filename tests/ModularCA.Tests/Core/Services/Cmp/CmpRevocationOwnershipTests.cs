using ModularCA.Core.Services.Cmp;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Covers the guard that stops one CA revoking another CA's certificate over CMP.
/// <para>
/// The revocation handler looks the target certificate up by serial across ALL certificates —
/// <c>ResolveBySerialOrNullAsync</c> is not CA-scoped — so nothing about the lookup itself
/// constrains which CA may act on the result. Two checks follow it. The first reads the issuer
/// DN out of the request, which the caller controls and can simply omit. The second reads the
/// issuer stored on the certificate row, and is the only one that can be trusted.
/// </para>
/// <para>
/// That second check used to be wrapped in <c>if (!string.IsNullOrEmpty(certEntity.Issuer))</c>.
/// A row with a blank issuer skipped it and was revocable by any CMP-enabled CA in the
/// deployment. It is unconditional now, and fails closed.
/// </para>
/// </summary>
public class CmpRevocationOwnershipTests
{
    private const string ThisCa = "CN=Issuing CA,O=Acme,C=US";

    [Fact]
    public void A_ca_may_revoke_a_certificate_it_issued()
    {
        Assert.True(CmpService.IsRevocableByCa(ThisCa, ThisCa));
    }

    [Fact]
    public void A_ca_may_not_revoke_a_certificate_issued_by_a_different_ca()
    {
        Assert.False(CmpService.IsRevocableByCa("CN=Other CA,O=Acme,C=US", ThisCa));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_certificate_with_no_recorded_issuer_is_revocable_by_nobody(string? storedIssuer)
    {
        // The fail-open that was here: an unknown owner is not a matching owner. Skipping the
        // check for a blank issuer made such rows revocable by every CA on the deployment.
        Assert.False(CmpService.IsRevocableByCa(storedIssuer, ThisCa));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_ca_with_no_subject_may_revoke_nothing(string? caSubject)
    {
        // Defensive symmetry: an empty CA subject must not become a wildcard that matches an
        // equally empty stored issuer.
        Assert.False(CmpService.IsRevocableByCa(ThisCa, caSubject!));
    }

    [Fact]
    public void Two_blank_identities_do_not_match_each_other()
    {
        // The specific pairing the old code would have allowed: blank stored issuer skipped the
        // guard entirely, so it never even reached a comparison.
        Assert.False(CmpService.IsRevocableByCa("", ""));
    }

    [Fact]
    public void Ownership_uses_the_same_dn_normalisation_as_the_rest_of_the_path()
    {
        // Spacing and attribute case differences are the same certificate, and a prefix is not.
        Assert.True(CmpService.IsRevocableByCa("cn=Issuing CA, o=Acme, c=US", ThisCa));
        Assert.False(CmpService.IsRevocableByCa("CN=Issuing CA Backup,O=Acme,C=US", ThisCa));
    }
}
