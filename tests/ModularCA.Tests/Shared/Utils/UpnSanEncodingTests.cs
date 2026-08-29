using ModularCA.Core.Implementations;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the UPN <c>otherName</c> SAN that Windows uses to map a smart-card logon certificate to
/// an Active Directory account.
/// <para>
/// Nothing in the codebase supported <c>otherName</c> before this: the runtime builder threw on
/// any type outside DNS/IP/URI/EMAIL, the bootstrap builder silently turned an unknown prefix into
/// a DNS name, and all four SAN decode paths rendered an unrecognised tag as the literal
/// <c>"Other"</c> with <c>gn.Name.ToString()</c> — a DER dump, not a UPN. So a certificate could
/// not carry one, and one that arrived in a CSR could not survive parse → store → re-encode.
/// </para>
/// <para>
/// The explicit/implicit tag pairing is the part worth testing rather than eyeballing: the
/// <c>otherName</c> tag is IMPLICIT and the inner value tag is EXPLICIT, and getting that backwards
/// produces a structure Windows declines to map without saying why.
/// </para>
/// </summary>
public class UpnSanEncodingTests
{
    private const string Upn = "alice@example.test";

    // ── Encoding shape ───────────────────────────────────────────────────────

    /// <summary>
    /// The DER must be otherName with Microsoft's OID and an EXPLICIT-tagged UTF8String value.
    /// <para>
    /// Asserted after a real encode/decode round trip rather than on the in-memory object. On the
    /// object still held in memory, <c>GetBaseObject()</c> returns the UTF8String whether the tag
    /// was built EXPLICIT or IMPLICIT, so an in-memory assertion cannot tell the two apart — and
    /// the difference is exactly what makes Windows decline to map the certificate.
    /// </para>
    /// </summary>
    [Fact]
    public void The_encoded_general_name_matches_the_microsoft_othername_structure()
    {
        var encoded = UpnSanEncoding.BuildUpnGeneralName(Upn).GetEncoded();
        var gn = GeneralName.GetInstance(Asn1Object.FromByteArray(encoded));

        Assert.Equal(GeneralName.OtherName, gn.TagNo);

        var seq = Assert.IsAssignableFrom<Asn1Sequence>(gn.Name);
        Assert.Equal("1.3.6.1.4.1.311.20.2.3", Assert.IsType<DerObjectIdentifier>(seq[0]).Id);

        var tagged = Assert.IsAssignableFrom<Asn1TaggedObject>(seq[1]);
        Assert.Equal(0, tagged.TagNo);
        Assert.True(tagged.IsExplicit(), "OtherName's value tag must be EXPLICIT per RFC 5280 §4.2.1.6.");
        Assert.Equal(Upn, Assert.IsType<DerUtf8String>(tagged.GetBaseObject()).GetString());
    }

    /// <summary>Encode then decode, in memory.</summary>
    [Fact]
    public void A_upn_round_trips_through_the_general_name()
    {
        var gn = UpnSanEncoding.BuildUpnGeneralName(Upn);

        Assert.Equal(Upn, UpnSanEncoding.TryGetUpn(gn));
        Assert.Equal($"UPN:{Upn}", UpnSanEncoding.Describe(gn));
    }

    /// <summary>
    /// The decoder must not claim every otherName is a UPN — a different type-id belongs to some
    /// other application and reporting it as a principal name would be a false identity.
    /// </summary>
    [Fact]
    public void An_othername_with_a_different_oid_is_not_read_as_a_upn()
    {
        var other = new GeneralName(GeneralName.OtherName, new DerSequence(
            new DerObjectIdentifier("1.2.3.4.5"),
            new DerTaggedObject(true, 0, new DerUtf8String("not-a-upn"))));

        Assert.Null(UpnSanEncoding.TryGetUpn(other));
    }

    /// <summary>Ordinary SAN types keep their existing rendering.</summary>
    [Theory]
    [InlineData(GeneralName.DnsName, "host.example.test", "DNS:host.example.test")]
    [InlineData(GeneralName.Rfc822Name, "a@example.test", "Email:a@example.test")]
    [InlineData(GeneralName.UniformResourceIdentifier, "https://example.test/x", "URI:https://example.test/x")]
    public void Other_san_types_are_unchanged(int tag, string value, string expected)
    {
        Assert.Equal(expected, UpnSanEncoding.Describe(new GeneralName(tag, value)));
    }

    /// <summary>IP SANs are DER octets and must still render as an address, not a byte dump.</summary>
    [Fact]
    public void Ip_sans_still_render_as_addresses()
    {
        var gn = GeneralName.GetInstance(
            Asn1Object.FromByteArray(new GeneralName(GeneralName.IPAddress, "10.9.13.1").GetEncoded()));

        Assert.Equal("IP:10.9.13.1", UpnSanEncoding.Describe(gn));
    }

    // ── Round trip through a real signed certificate ─────────────────────────

    /// <summary>
    /// The one that matters: a UPN put into a certificate must come back out of the DER as a UPN.
    /// This is the parse → store → re-encode path that could not preserve one before.
    /// </summary>
    [Fact]
    public void A_upn_survives_a_round_trip_through_a_signed_certificate()
    {
        var (der, _) = BouncyCastleCertificateAuthority.CreateSelfSignedCACertificate(new CertificateRequestModel
        {
            CommonName = "smartcard.test",
            Organization = "ModularCA",
            KeyAlgorithm = "ECDSA",
            KeySize = 256,
            NotBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            IsCA = false,
            KeyUsages = new List<string> { "digitalSignature" },
            ExtendedKeyUsages = new List<string>(),
            SubjectAlternativeNames = new List<string> { $"UPN:{Upn}", "DNS:smartcard.test" },
        });

        var cert = new X509CertificateParser().ReadCertificate(der);

        // Straight off the DER, independently of our own helper.
        var sanSeq = Asn1Sequence.GetInstance(
            X509ExtensionUtilities.FromExtensionValue(cert.GetExtensionValue(X509Extensions.SubjectAlternativeName)));
        var names = sanSeq.Cast<Asn1Encodable>().Select(GeneralName.GetInstance).ToList();

        Assert.Contains(names, n => UpnSanEncoding.TryGetUpn(n) == Upn);

        // And through the path the application actually uses to display and re-store SANs.
        var parsed = CertificateUtil.ParseCertificate(cert);
        Assert.Contains($"UPN:{Upn}", parsed.SubjectAlternativeNames);
        Assert.Contains("DNS:smartcard.test", parsed.SubjectAlternativeNames);
    }

    /// <summary>
    /// The bootstrap builder used to map any unknown prefix to a DNS name, so "UPN:alice@..."
    /// became a DNS SAN containing that text — a wrong identity in a signed certificate. Unknown
    /// types are refused now.
    /// </summary>
    [Fact]
    public void An_unknown_san_prefix_is_refused_rather_than_becoming_a_dns_name()
    {
        var request = new CertificateRequestModel
        {
            CommonName = "typo.test",
            Organization = "ModularCA",
            KeyAlgorithm = "ECDSA",
            KeySize = 256,
            NotBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            IsCA = false,
            KeyUsages = new List<string> { "digitalSignature" },
            ExtendedKeyUsages = new List<string>(),
            SubjectAlternativeNames = new List<string> { "DSN:typo.test" },
        };

        var ex = Assert.Throws<InvalidOperationException>(
            () => BouncyCastleCertificateAuthority.CreateSelfSignedCACertificate(request));
        Assert.Contains("Unsupported SAN type", ex.Message);
    }

    // ── Validation ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("alice@example.test")]
    [InlineData("a@b")]
    [InlineData("first.last@sub.example.test")]
    public void Well_formed_upns_are_accepted(string upn)
        => DnComponentSanitizer.ValidateUpn(upn);

    /// <summary>
    /// A UPN is a claim to be a specific AD account, so a malformed one is rejected rather than
    /// sanitised. Note it is deliberately not validated as an email address: MailAddress accepts
    /// display-name forms, which would put "Alice" &lt;a@b&gt; into the certificate.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no-at-sign")]
    [InlineData("@example.test")]
    [InlineData("alice@")]
    [InlineData("alice@a@b")]
    [InlineData(" alice@example.test")]
    [InlineData("alice@example.test ")]
    [InlineData("alice@.example.test")]
    [InlineData("alice@example.test.")]
    [InlineData("alice@exam..ple.test")]
    [InlineData("alice @example.test")]
    [InlineData("\"Alice\" <alice@example.test>")]
    public void Malformed_upns_are_rejected(string upn)
        => Assert.Throws<InvalidOperationException>(() => DnComponentSanitizer.ValidateUpn(upn));
}
