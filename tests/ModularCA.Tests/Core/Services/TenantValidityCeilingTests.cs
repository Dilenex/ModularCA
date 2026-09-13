using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The tenant validity ceiling that replaced the global <c>CertPolicy.MaxValidityDays</c>.
/// <para>
/// The setting it replaced defaulted to 825 days — the CA/Browser Forum baseline for publicly
/// trusted TLS — and applied to every leaf in the installation regardless of tenant, profile or
/// purpose. A private CA issuing a five-year device identity was refused by a number that only
/// ever meant anything to public web PKI, and the only way to allow it was to relax the limit for
/// everyone at once. That infrastructure certificates already carried an explicit exemption from
/// it was the clearest sign the rule belonged somewhere narrower.
/// </para>
/// <para>
/// These cover <see cref="CertificateValidityUtil.ClampToValidityCeiling"/> directly rather than
/// restating its arithmetic, so a change to the real decision fails here.
/// </para>
/// </summary>
public class TenantValidityCeilingTests
{
    private static readonly DateTime NotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void A_request_within_the_ceiling_is_returned_untouched()
    {
        var requested = NotBefore.AddDays(365);

        var result = CertificateValidityUtil.ClampToValidityCeiling(requested, NotBefore, 730, out var clamped);

        Assert.False(clamped);
        Assert.Equal(requested, result);
    }

    [Fact]
    public void A_request_beyond_the_ceiling_is_shortened_to_it()
    {
        // Shortened, not refused: every enrollment protocol derives its expiry from the cert
        // profile with no knowledge of the tenant, so refusing would fail ACME, EST and CMP
        // enrollments over a condition the client cannot see or fix.
        var result = CertificateValidityUtil.ClampToValidityCeiling(NotBefore.AddDays(1096), NotBefore, 730, out var clamped);

        Assert.True(clamped);
        Assert.Equal(NotBefore.AddDays(730), result);
    }

    [Fact]
    public void A_request_landing_exactly_on_the_ceiling_is_not_treated_as_exceeding_it()
    {
        // An off-by-one here would shorten a certificate that asked for precisely what the tenant
        // permits, and raise a diagnostic saying so — undermining the advisory on every request
        // where it actually matters.
        var result = CertificateValidityUtil.ClampToValidityCeiling(NotBefore.AddDays(730), NotBefore, 730, out var clamped);

        Assert.False(clamped);
        Assert.Equal(NotBefore.AddDays(730), result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void A_ceiling_of_zero_or_less_means_unlimited(int maxValidityDays)
    {
        // 0 is unlimited, matching the tenant quota fields beside it — and it is the value every
        // existing tenant receives from the migration, so reading it as a ceiling of zero would
        // stop issuance installation-wide on upgrade. Negative cannot be set through the API and
        // is read the same way rather than as "expire immediately".
        var requested = NotBefore.AddDays(3650);

        var result = CertificateValidityUtil.ClampToValidityCeiling(requested, NotBefore, maxValidityDays, out var clamped);

        Assert.False(clamped);
        Assert.Equal(requested, result);
    }

    [Fact]
    public void The_ceiling_is_measured_from_notBefore_not_from_now()
    {
        // Backdating moves notBefore behind the current time by the skew allowance, and a
        // certificate must carry the validity its tenant permits rather than that minus the
        // backdate.
        var backdated = NotBefore - CertificateValidityUtil.SkewAllowance;

        var result = CertificateValidityUtil.ClampToValidityCeiling(backdated.AddDays(1000), backdated, 365, out var clamped);

        Assert.True(clamped);
        Assert.Equal(backdated.AddDays(365), result);
    }

    [Fact]
    public void A_long_ceiling_does_not_overflow()
    {
        // int.MaxValue days is not reachable through the UI, but DateTime.AddDays throws rather
        // than saturating, and an ArgumentOutOfRangeException surfacing from issuance would read
        // as the CA breaking rather than as a bad setting.
        var requested = NotBefore.AddDays(3650);

        var ex = Record.Exception(() =>
            CertificateValidityUtil.ClampToValidityCeiling(requested, NotBefore, 36500, out _));

        Assert.Null(ex);
    }

    [Fact]
    public void The_ceiling_only_ever_shortens()
    {
        // A ceiling is not a floor. A profile asking for less than the tenant permits gets what it
        // asked for; the tenant value must never extend a certificate's life.
        var shortRequest = NotBefore.AddDays(30);

        var result = CertificateValidityUtil.ClampToValidityCeiling(shortRequest, NotBefore, 3650, out var clamped);

        Assert.False(clamped);
        Assert.Equal(shortRequest, result);
        Assert.True(result <= shortRequest);
    }
}
