using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the notBefore skew allowance and the issuer clamp that makes it safe.
/// <para>
/// Every issuance path used a bare <c>DateTime.UtcNow</c>, so a certificate was stamped valid
/// from exactly the instant the CA's clock said — invalid on any verifier running even slightly
/// behind. This was observed rather than theorised: a host whose clock had drifted an hour
/// produced a root CA stamped an hour in the future, and once the clock was corrected that CA
/// could not issue anything until real time caught up.
/// </para>
/// </summary>
public class CertificateValidityUtilTests
{
    [Fact]
    public void Default_notBefore_is_backdated_by_the_skew_allowance()
    {
        var before = DateTime.UtcNow;
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var after = DateTime.UtcNow;

        // DefaultNotBefore() samples UtcNow between `before` and `after`, so the result sits in
        // [before - allowance, after - allowance]. Asserting the window rather than a point
        // keeps this from being flaky under a slow test host.
        Assert.InRange(notBefore,
            before - CertificateValidityUtil.SkewAllowance,
            after - CertificateValidityUtil.SkewAllowance);
    }

    /// <summary>
    /// The allowance matches the margin already used when clamping against the issuing CA's
    /// notAfter, so both ends of the window tolerate the same skew.
    /// </summary>
    [Fact]
    public void Skew_allowance_matches_the_existing_upper_bound_margin()
        => Assert.Equal(TimeSpan.FromMinutes(5), CertificateValidityUtil.SkewAllowance);

    /// <summary>
    /// The pairing that matters. Backdating alone would break issuance from any CA whose own
    /// notBefore was not backdated — the leaf would start before its issuer and the old code
    /// threw. Clamping to the issuer is the correct earliest valid instant.
    /// </summary>
    [Fact]
    public void Leaf_starting_before_its_issuer_is_raised_to_the_issuer()
    {
        var issuer = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var leaf = issuer - TimeSpan.FromMinutes(5);   // backdated past the issuer's start

        var clamped = CertificateValidityUtil.ClampToIssuer(leaf, issuer, out var wasClamped);

        Assert.True(wasClamped);
        Assert.Equal(issuer, clamped);
    }

    /// <summary>A leaf that already starts after its issuer is left alone.</summary>
    [Fact]
    public void Leaf_starting_after_its_issuer_is_untouched()
    {
        var issuer = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var leaf = issuer + TimeSpan.FromHours(1);

        var clamped = CertificateValidityUtil.ClampToIssuer(leaf, issuer, out var wasClamped);

        Assert.False(wasClamped);
        Assert.Equal(leaf, clamped);
    }

    /// <summary>Exactly equal is valid — the boundary is inclusive.</summary>
    [Fact]
    public void Leaf_starting_exactly_at_its_issuer_is_not_clamped()
    {
        var issuer = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

        var clamped = CertificateValidityUtil.ClampToIssuer(issuer, issuer, out var wasClamped);

        Assert.False(wasClamped);
        Assert.Equal(issuer, clamped);
    }

    /// <summary>
    /// The scenario that motivated this: a CA stamped in the future by a skewed clock. Issuance
    /// must still produce a usable window rather than failing outright — the leaf simply cannot
    /// be valid before its issuer.
    /// </summary>
    [Fact]
    public void Issuer_stamped_in_the_future_still_yields_a_valid_start()
    {
        var futureIssuer = DateTime.UtcNow + TimeSpan.FromMinutes(40);

        var clamped = CertificateValidityUtil.ClampToIssuer(
            CertificateValidityUtil.DefaultNotBefore(), futureIssuer, out var wasClamped);

        Assert.True(wasClamped);
        Assert.Equal(futureIssuer, clamped);
    }
}
