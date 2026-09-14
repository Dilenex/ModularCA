using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the SAN coverage check used to warn that an SNI-gated hostname is missing from the server
/// certificate.
/// </summary>
/// <remarks>
/// The warning exists because a gated hostname that the certificate does not name fails as a
/// hostname mismatch <em>before</em> any client-certificate exchange happens. The operator then
/// debugs "mTLS login doesn't work" or "EST can't connect" at the authentication layer, where the
/// cause is not. A check that is wrong in the permissive direction stays silent in exactly the case
/// it was written for.
/// </remarks>
public class CertificateSanUtilTests
{
    private static X509Certificate2 CertWithDnsNames(params string[] dnsNames)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=web.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
            san.AddDnsName(name);
        req.CertificateExtensions.Add(san.Build());

        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    /// <summary>
    /// Builds a certificate whose SAN carries a UPN otherName alongside a DNS entry.
    /// </summary>
    /// <remarks>
    /// Hand-encoded because <c>SubjectAlternativeNameBuilder</c> cannot express otherName, and this
    /// product issues UPN SANs (<c>1.3.6.1.4.1.311.20.2.3</c>) routinely. The framework's own
    /// <c>EnumerateDnsNames</c> throws on entry types it does not model, which would turn a startup
    /// diagnostic into a startup crash.
    /// </remarks>
    private static X509Certificate2 CertWithUpnAndDnsSan(string upn, string dnsName)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // otherName [0] { type-id OID, value [0] EXPLICIT UTF8String }
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
            }

            // dNSName [2] IA5String
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, dnsName, new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=web.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension("2.5.29.17", writer.Encode(), false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public void An_exact_dns_san_covers_the_hostname()
    {
        using var cert = CertWithDnsNames("ca.example.com", "est.ca.example.com");
        Assert.True(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
    }

    [Fact]
    public void A_hostname_absent_from_the_sans_is_not_covered()
    {
        using var cert = CertWithDnsNames("ca.example.com");
        Assert.False(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
    }

    [Fact]
    public void Matching_is_case_insensitive_and_tolerates_a_trailing_dot()
    {
        using var cert = CertWithDnsNames("EST.ca.example.com");
        Assert.True(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
        Assert.True(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com."));
    }

    [Fact]
    public void A_wildcard_covers_one_label()
    {
        using var cert = CertWithDnsNames("*.ca.example.com");
        Assert.True(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
        Assert.True(CertificateSanUtil.CoversHostname(cert, "mtls.ca.example.com"));
    }

    [Fact]
    public void A_wildcard_does_not_cover_the_bare_domain_or_a_deeper_label()
    {
        // RFC 6125 section 6.4.3. Clients enforce both of these, so a check that accepted them
        // would suppress the warning for a certificate that is about to be rejected on the wire.
        using var cert = CertWithDnsNames("*.ca.example.com");
        Assert.False(CertificateSanUtil.CoversHostname(cert, "ca.example.com"));
        Assert.False(CertificateSanUtil.CoversHostname(cert, "a.est.ca.example.com"));
    }

    [Fact]
    public void A_common_name_alone_does_not_count_as_coverage()
    {
        // The subject here is CN=web.example.com with no matching SAN. RFC 2818 deprecated CN for
        // hostname verification and current clients refuse it, so treating it as coverage would
        // silence the warning in a case that still fails.
        using var cert = CertWithDnsNames("other.example.com");
        Assert.False(CertificateSanUtil.CoversHostname(cert, "web.example.com"));
    }

    [Fact]
    public void A_san_carrying_a_upn_otherName_is_read_without_throwing()
    {
        // This product issues UPN SANs. A diagnostic that crashed on its own certificates would
        // take the process down at startup rather than print a warning.
        using var cert = CertWithUpnAndDnsSan("device@local.private", "est.ca.example.com");

        Assert.True(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
        Assert.Equal(["est.ca.example.com"], CertificateSanUtil.GetDnsNames(cert));
    }

    [Fact]
    public void A_certificate_with_no_san_extension_covers_nothing()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=est.ca.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        Assert.False(CertificateSanUtil.CoversHostname(cert, "est.ca.example.com"));
        Assert.Empty(CertificateSanUtil.GetDnsNames(cert));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_missing_hostname_is_never_covered(string? hostname)
    {
        using var cert = CertWithDnsNames("est.ca.example.com");
        Assert.False(CertificateSanUtil.CoversHostname(cert, hostname));
    }

    [Fact]
    public void A_null_certificate_covers_nothing()
    {
        Assert.False(CertificateSanUtil.CoversHostname(null, "est.ca.example.com"));
    }
}
