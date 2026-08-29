using ModularCA.Core.Implementations;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the DateTime.Kind handling behind certificates issued with a future notBefore.
/// <para>
/// BouncyCastle's <c>SetNotBefore</c> / <c>SetNotAfter</c> call <see cref="DateTime.ToUniversalTime"/>
/// on the value they are handed. For <see cref="DateTimeKind.Unspecified"/> that assumes LOCAL time
/// and adds the host's UTC offset. Requested validity windows are persisted on the certificate
/// request and read back by EF, which returns MySQL <c>datetime</c> columns as Unspecified — so a
/// window that was correct when submitted became "the requested time plus the server's UTC offset"
/// at issuance. On the affected host that was six hours, and every relying party rejected the
/// certificate until then.
/// </para>
/// <para>
/// This was the second, server-side half of the problem. The first was the admin form seeding a
/// UTC clock reading into a local-time input (fixed in 7945125); the two compounded, which is why
/// the observed shift was twice the host offset.
/// </para>
/// </summary>
public class NotBeforeKindTests
{
    /// <summary>09:00 UTC, expressed three ways. All three name the same instant.</summary>
    private static readonly DateTime InstantUtc = new(2026, 8, 29, 9, 0, 0, DateTimeKind.Utc);

    private static CertificateRequestModel Request(DateTime notBefore) => new()
    {
        CommonName = "validity.test",
        Organization = "ModularCA",
        KeyAlgorithm = "ECDSA",
        KeySize = 256,
        NotBefore = notBefore,
        NotAfter = notBefore.AddYears(1),
        IsCA = false,
        KeyUsages = new List<string> { "digitalSignature" },
        ExtendedKeyUsages = new List<string>(),
    };

    private static DateTime IssuedNotBefore(DateTime notBefore)
    {
        var (der, _) = BouncyCastleCertificateAuthority.CreateSelfSignedCACertificate(Request(notBefore));
        return new X509CertificateParser().ReadCertificate(der).NotBefore;
    }

    /// <summary>
    /// The regression. An Unspecified value carrying a UTC instant must produce that instant, not
    /// that instant shifted by wherever the server happens to be.
    /// </summary>
    [Fact]
    public void An_unspecified_notBefore_is_not_shifted_by_the_host_timezone()
    {
        var unspecified = DateTime.SpecifyKind(InstantUtc, DateTimeKind.Unspecified);

        var issued = IssuedNotBefore(unspecified);

        Assert.Equal(InstantUtc, issued.ToUniversalTime());
    }

    /// <summary>
    /// All three kinds naming one instant must yield one certificate validity start. Written as a
    /// cross-check rather than three separate asserts: on a UTC host the buggy and fixed behaviour
    /// are identical, so a test that only pinned Unspecified would pass everywhere regardless.
    /// </summary>
    [Fact]
    public void Every_kind_naming_the_same_instant_yields_the_same_notBefore()
    {
        var fromUtc = IssuedNotBefore(InstantUtc);
        var fromLocal = IssuedNotBefore(InstantUtc.ToLocalTime());
        var fromUnspecified = IssuedNotBefore(DateTime.SpecifyKind(InstantUtc, DateTimeKind.Unspecified));

        Assert.Equal(fromUtc.ToUniversalTime(), fromLocal.ToUniversalTime());
        Assert.Equal(fromUtc.ToUniversalTime(), fromUnspecified.ToUniversalTime());
        Assert.Equal(InstantUtc, fromUtc.ToUniversalTime());
    }

    /// <summary>The certificate must be valid immediately, which is the operator-visible symptom.</summary>
    [Fact]
    public void A_certificate_requested_for_now_is_valid_now()
    {
        var now = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Unspecified);

        var issued = IssuedNotBefore(now).ToUniversalTime();

        Assert.True(issued <= DateTime.UtcNow.AddMinutes(1),
            $"notBefore {issued:u} is in the future; requested {now:u} (UTC offset here is " +
            $"{TimeZoneInfo.Local.GetUtcOffset(DateTime.Now)}).");
    }

    // ── The helper itself ────────────────────────────────────────────────────

    [Fact]
    public void AsUtc_treats_unspecified_as_already_utc()
    {
        var unspecified = DateTime.SpecifyKind(InstantUtc, DateTimeKind.Unspecified);

        var result = CertificateValidityUtil.AsUtc(unspecified);

        Assert.Equal(DateTimeKind.Utc, result.Kind);
        Assert.Equal(InstantUtc, result);
    }

    [Fact]
    public void AsUtc_converts_local_and_leaves_utc_alone()
    {
        Assert.Equal(InstantUtc, CertificateValidityUtil.AsUtc(InstantUtc.ToLocalTime()));
        Assert.Equal(InstantUtc, CertificateValidityUtil.AsUtc(InstantUtc));
        Assert.Null(CertificateValidityUtil.AsUtc((DateTime?)null));
    }
}
