using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins that a client-supplied <c>notBefore</c> cannot start a certificate in the past.
/// </summary>
/// <remarks>
/// ACME's newOrder and CMP's OptionalValidity both let the client name a start date, and both
/// paths honoured it as given: a request for a certificate valid from 2021 produced one. The
/// maximum-date rule measures from now, so the end was capped but the start was not, and a
/// signature could be made to appear to predate a revocation. The floor is the same skew
/// allowance every other issuance path already uses for its default start.
/// </remarks>
public class RequestedNotBeforeTests
{
    [Fact]
    public void No_request_yields_the_default_start()
    {
        var before = CertificateValidityUtil.DefaultNotBefore();
        var result = CertificateValidityUtil.ClampRequestedNotBefore(null, out var wasRaised);
        var after = CertificateValidityUtil.DefaultNotBefore();

        Assert.False(wasRaised);
        Assert.InRange(result, before, after);
    }

    [Fact]
    public void A_start_in_the_past_is_raised_to_the_floor()
    {
        var requested = new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var floor = CertificateValidityUtil.DefaultNotBefore();

        var result = CertificateValidityUtil.ClampRequestedNotBefore(requested, out var wasRaised);

        Assert.True(wasRaised);
        Assert.True(result >= floor);
        Assert.Equal(DateTimeKind.Utc, result.Kind);
    }

    [Fact]
    public void A_start_within_the_skew_allowance_is_honoured()
    {
        // A client whose clock is a minute slow is not backdating anything.
        var requested = DateTime.UtcNow - TimeSpan.FromMinutes(1);

        var result = CertificateValidityUtil.ClampRequestedNotBefore(requested, out var wasRaised);

        Assert.False(wasRaised);
        Assert.Equal(requested, result);
    }

    [Fact]
    public void A_start_in_the_future_is_honoured()
    {
        // Pre-dating a certificate to become valid tomorrow is legitimate and unchanged.
        var requested = DateTime.UtcNow + TimeSpan.FromDays(1);

        var result = CertificateValidityUtil.ClampRequestedNotBefore(requested, out var wasRaised);

        Assert.False(wasRaised);
        Assert.Equal(requested, result);
    }

    [Fact]
    public void The_result_is_always_utc_whatever_kind_the_request_carried()
    {
        // ASN.1 times decode with Unspecified kind. The issuance pipeline compares against UTC
        // instants, so an un-normalised value would be compared, and then encoded, as whatever
        // the server's local zone happened to be. Checked on the honoured path, where the input
        // value is returned, so the normalisation itself is what is being observed.
        var requested = DateTime.SpecifyKind(DateTime.UtcNow.AddDays(1), DateTimeKind.Unspecified);

        var result = CertificateValidityUtil.ClampRequestedNotBefore(requested, out var wasRaised);

        Assert.False(wasRaised);
        Assert.Equal(DateTimeKind.Utc, result.Kind);
        Assert.Equal(requested.Ticks, result.Ticks);
    }
}
