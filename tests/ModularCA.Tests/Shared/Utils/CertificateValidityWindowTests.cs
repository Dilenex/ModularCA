using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// A validity window that has collapsed to nothing is refused before signing. Seen live: a
/// template whose profile chain resolved to zero seconds produced a certificate expired at birth.
/// </summary>
public class CertificateValidityWindowTests
{
    [Fact]
    public void A_window_that_leaves_under_a_minute_of_life_from_now_is_refused()
    {
        var now = new DateTime(2026, 9, 15, 20, 0, 0, DateTimeKind.Utc);
        var backdated = now.AddMinutes(-5);   // NotBefore as issuance backdates it

        // Zero-lifetime chain: NotAfter lands on "now". Five minutes from NotBefore, none from now.
        var ex = Assert.Throws<InvalidRequestException>(() => CertificateValidityUtil.EnsureUsableWindow(backdated, now, now));
        Assert.Contains("expired at issuance", ex.Message);
        Assert.Throws<InvalidRequestException>(() => CertificateValidityUtil.EnsureUsableWindow(backdated, now.AddSeconds(59), now));
        Assert.Throws<InvalidRequestException>(() => CertificateValidityUtil.EnsureUsableWindow(now, now, now));
        Assert.Throws<InvalidRequestException>(() => CertificateValidityUtil.EnsureUsableWindow(now, now.AddMinutes(-5), now));

        // A minute of life from now is enough; a future NotBefore counts from itself.
        CertificateValidityUtil.EnsureUsableWindow(backdated, now.AddSeconds(60), now);
        CertificateValidityUtil.EnsureUsableWindow(now.AddHours(1), now.AddHours(1).AddMinutes(1), now);
        Assert.Throws<InvalidRequestException>(() => CertificateValidityUtil.EnsureUsableWindow(now.AddHours(1), now.AddHours(1).AddSeconds(30), now));
    }
}
