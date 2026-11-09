using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The certificate profile's maximum validity bounds the certificate's lifetime, measured from the
/// start it will carry: <see cref="IssuanceValidationService.NotBeyondMaximumDate"/> and
/// <see cref="IssuanceValidationService.MaximumNotAfter"/>.
/// <para>
/// Both used to measure from now. An explicitly requested notBefore is honoured as given (raised
/// only to the issuer's own start), so a start backdated by two years with an expiry inside
/// <c>now + max</c> passed the check, and a certificate whose profile allowed one year was issued
/// valid for three.
/// </para>
/// </summary>
public class MaximumValidityWindowTests
{
    private static readonly EffectiveCertProfile OneYear = new() { ValidityPeriodMax = "P365D" };

    private static IssuanceValidationService Service()
        => new(InMemoryDbContextFactory.Create(), NullLogger<IssuanceValidationService>.Instance);

    [Fact]
    public void A_backdated_notBefore_does_not_stretch_the_lifetime_past_the_maximum()
    {
        var now = DateTime.UtcNow;
        var notBefore = now.AddYears(-2);
        var notAfter = now.AddDays(180);

        // Inside now + 365 days, but the certificate would live about two and a half years.
        Assert.False(Service().NotBeyondMaximumDate(notBefore, notAfter, OneYear));
    }

    [Fact]
    public void A_backdated_notBefore_is_within_bounds_when_the_lifetime_is()
    {
        var notBefore = DateTime.UtcNow.AddDays(-100);

        Assert.True(Service().NotBeyondMaximumDate(notBefore, notBefore.AddDays(365), OneYear));
        Assert.False(Service().NotBeyondMaximumDate(notBefore, notBefore.AddDays(366), OneYear));
    }

    [Fact]
    public void A_future_notBefore_is_bounded_by_lifetime_not_by_now()
    {
        var notBefore = DateTime.UtcNow.AddDays(30);

        Assert.True(Service().NotBeyondMaximumDate(notBefore, notBefore.AddDays(360), OneYear));
        Assert.False(Service().NotBeyondMaximumDate(notBefore, notBefore.AddDays(366), OneYear));
    }

    [Fact]
    public void Without_a_requested_notBefore_the_maximum_is_measured_from_now()
    {
        var now = DateTime.UtcNow;

        Assert.True(Service().NotBeyondMaximumDate(null, now.AddDays(364), OneYear));
        Assert.False(Service().NotBeyondMaximumDate(null, now.AddDays(366), OneYear));
        Assert.True(Service().NotBeyondMaximumDate(null, null, OneYear));
    }

    [Fact]
    public void The_default_expiry_for_a_backdated_start_is_measured_from_that_start()
    {
        // The issuance pipeline's default notAfter. Measured from now, a backdated start with no
        // requested expiry also produced a certificate longer than the profile allows.
        var notBefore = new DateTime(2024, 3, 1, 0, 0, 0, DateTimeKind.Utc);

        Assert.Equal(notBefore.AddDays(365), Service().MaximumNotAfter(notBefore, OneYear));
    }

    [Fact]
    public void An_unspecified_kind_notBefore_is_read_as_utc()
    {
        // A requested window read back from the database arrives as DateTimeKind.Unspecified.
        var notBefore = new DateTime(2024, 3, 1, 0, 0, 0, DateTimeKind.Unspecified);

        var max = Service().MaximumNotAfter(notBefore, OneYear);

        Assert.Equal(DateTimeKind.Utc, max.Kind);
        Assert.Equal(new DateTime(2025, 3, 1, 0, 0, 0, DateTimeKind.Utc), max);
    }
}
