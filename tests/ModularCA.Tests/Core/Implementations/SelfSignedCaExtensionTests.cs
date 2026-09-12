using ModularCA.Core.Implementations;
using ModularCA.Shared.Models;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Implementations;

/// <summary>
/// Covers the extensions a self-signed CA certificate is allowed to carry.
/// <para>
/// Bootstrap passed a six-entry EKU list and a KeyUsage set including <c>keyEncipherment</c> into
/// the root's own certificate request, and this builder emitted both. An EKU on a CA constrains
/// every certificate beneath it (RFC 5280 §4.2.1.12), so a <c>smartcardLogon</c> or
/// <c>kdcAuthentication</c> leaf under such a root fails EKU-nesting in Windows CryptoAPI with
/// <c>CERT_E_WRONG_USAGE</c>; CA/B BR §7.1.2.1.2 forbids <c>extKeyUsage</c> on a root outright.
/// <c>keyEncipherment</c> is invalid for <c>id-ecPublicKey</c> per RFC 5480 §3, and the shipped
/// default was ECDSA P-384.
/// </para>
/// <para>
/// Neither is correctable after issuance — the extensions are inside the signature — so this is
/// enforced at the layer that decides what gets signed, rather than only at the two call sites.
/// </para>
/// </summary>
public class SelfSignedCaExtensionTests
{
    /// <summary>A CA request with the usages a correct root carries.</summary>
    private static CertificateRequestModel CaRequest(
        List<string>? keyUsages = null,
        List<string>? extendedKeyUsages = null,
        bool isCa = true)
        => new()
        {
            CommonName = "Test Root CA",
            Organization = "ModularCA",
            KeyAlgorithm = "ECDSA",
            KeySize = 256,
            NotBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2036, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            IsCA = isCa,
            KeyUsages = keyUsages ?? new List<string> { "digitalSignature", "keyCertSign", "cRLSign" },
            ExtendedKeyUsages = extendedKeyUsages ?? new List<string>(),
        };

    private static X509Certificate Build(CertificateRequestModel request)
    {
        var (der, _) = BouncyCastleCertificateAuthority.CreateSelfSignedCACertificate(request);
        return new X509CertificateParser().ReadCertificate(der);
    }

    /// <summary>B-2: the root must come out with no EKU extension at all.</summary>
    [Fact]
    public void A_ca_certificate_carries_no_extended_key_usage_extension()
    {
        var cert = Build(CaRequest());

        Assert.Null(cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage));
    }

    /// <summary>
    /// B-2: and asking for one is refused rather than silently dropped, so a reintroduction is a
    /// failed bootstrap instead of a non-compliant root.
    /// </summary>
    [Fact]
    public void Requesting_an_eku_on_a_ca_certificate_is_refused()
    {
        var request = CaRequest(extendedKeyUsages: new List<string>
        {
            "1.3.6.1.5.5.7.3.1", // serverAuth
            "1.3.6.1.5.5.7.3.2", // clientAuth
        });

        var ex = Assert.Throws<ConfigurationValidationException>(() => Build(request));
        Assert.Contains("ExtendedKeyUsage", ex.Message);
    }

    /// <summary>B-3: keyEncipherment is invalid on a CA key and is refused.</summary>
    [Fact]
    public void Requesting_key_encipherment_on_a_ca_certificate_is_refused()
    {
        var request = CaRequest(keyUsages: new List<string>
        {
            "digitalSignature", "keyEncipherment", "keyCertSign", "cRLSign",
        });

        var ex = Assert.Throws<ConfigurationValidationException>(() => Build(request));
        Assert.Contains("keyEncipherment", ex.Message);
    }

    /// <summary>
    /// The usages a CA does need must still survive, and KeyUsage must stay critical. This is what
    /// stops the guard from degenerating into "reject everything".
    /// </summary>
    [Fact]
    public void The_signing_usages_a_ca_needs_are_still_emitted()
    {
        var cert = Build(CaRequest());

        var keyUsage = cert.GetKeyUsage();
        Assert.NotNull(keyUsage);
        Assert.True(keyUsage[0], "digitalSignature should be asserted");
        Assert.True(keyUsage[5], "keyCertSign should be asserted");
        Assert.True(keyUsage[6], "cRLSign should be asserted");
        Assert.False(keyUsage[2], "keyEncipherment must not be asserted");

        Assert.Contains(X509Extensions.KeyUsage.Id, cert.GetCriticalExtensionOids().Cast<string>());
    }

    /// <summary>
    /// The restriction is specific to CA certificates. A leaf may legitimately carry both an EKU
    /// and keyEncipherment, and this builder must not start rejecting those.
    /// </summary>
    [Fact]
    public void A_non_ca_certificate_may_still_carry_an_eku_and_key_encipherment()
    {
        var cert = Build(CaRequest(
            keyUsages: new List<string> { "digitalSignature", "keyEncipherment" },
            extendedKeyUsages: new List<string> { "1.3.6.1.5.5.7.3.1" },
            isCa: false));

        Assert.NotNull(cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage));
        Assert.True(cert.GetKeyUsage()[2], "keyEncipherment should be allowed on a leaf");
    }

    /// <summary>
    /// A CA request declaring no key usages at all still gets keyCertSign and cRLSign.
    /// <para>
    /// The encipherment guard used to sit inside <c>if (request.KeyUsages.Any())</c>, so an empty
    /// list skipped every check rather than failing any of them, and the root was signed with no
    /// KeyUsage extension whatsoever. Absence is not equivalent to the correct bits: a CA
    /// certificate without keyCertSign makes every chain beneath it fail path validation
    /// (RFC 5280 &#167;4.2.1.3).
    /// </para>
    /// </summary>
    [Fact]
    public void A_ca_request_with_no_declared_usages_still_gets_the_mandatory_bits()
    {
        var cert = Build(CaRequest(keyUsages: new List<string>()));

        var usage = cert.GetKeyUsage();
        Assert.NotNull(usage);
        Assert.True(usage[5], "keyCertSign must be set");
        Assert.True(usage[6], "cRLSign must be set");
    }

    /// <summary>A leaf declaring nothing must not gain a KeyUsage extension it never asked for.</summary>
    [Fact]
    public void A_leaf_request_with_no_declared_usages_gets_no_key_usage_extension()
    {
        var cert = Build(CaRequest(keyUsages: new List<string>(), isCa: false));

        Assert.Null(cert.GetKeyUsage());
    }
}
