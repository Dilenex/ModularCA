using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Regression cover for <see cref="KeyUsageFriendlyNames"/>.
/// <para>
/// This parser is the last step before the KeyUsage extension is written, and it used to accept
/// exactly one vocabulary — the spaced display form ("Digital Signature", "Key Certificate
/// Signing"). Three vocabularies actually reach it: that display form, the camelCase names stored in
/// the OIDOptions catalog ("digitalSignature", "keyCertSign"), and the admin UI's older labels
/// ("Key Cert Sign"). Feeding it a catalog name threw and aborted issuance outright — an ACME
/// finalize failed in production with "Unknown key usage friendly name: 'digitalSignature'".
/// </para>
/// <para>
/// Note that KeyCertSign and CrlSign differ between vocabularies by WORDS, not just case or
/// separators ("keycertsign" vs "keycertificatesigning"), so normalisation alone is insufficient and
/// they carry explicit aliases. Those two are the ones worth guarding.
/// </para>
/// </summary>
public class KeyUsageFriendlyNamesTests
{
    [Theory]
    // display form — the original vocabulary
    [InlineData("Digital Signature", KeyUsage.DigitalSignature)]
    [InlineData("Key Certificate Signing", KeyUsage.KeyCertSign)]
    [InlineData("CRL Signing", KeyUsage.CrlSign)]
    // OIDOptions catalog form — what SetupAllowedStandardOids now returns
    [InlineData("digitalSignature", KeyUsage.DigitalSignature)]
    [InlineData("keyCertSign", KeyUsage.KeyCertSign)]
    [InlineData("crlSign", KeyUsage.CrlSign)]
    [InlineData("keyEncipherment", KeyUsage.KeyEncipherment)]
    [InlineData("nonRepudiation", KeyUsage.NonRepudiation)]
    [InlineData("dataEncipherment", KeyUsage.DataEncipherment)]
    [InlineData("keyAgreement", KeyUsage.KeyAgreement)]
    [InlineData("encipherOnly", KeyUsage.EncipherOnly)]
    [InlineData("decipherOnly", KeyUsage.DecipherOnly)]
    // admin UI's older display labels
    [InlineData("Key Cert Sign", KeyUsage.KeyCertSign)]
    [InlineData("CRL Sign", KeyUsage.CrlSign)]
    [InlineData("Key Encipherment", KeyUsage.KeyEncipherment)]
    // separator / case tolerance
    [InlineData("  digital_signature  ", KeyUsage.DigitalSignature)]
    [InlineData("DIGITALSIGNATURE", KeyUsage.DigitalSignature)]
    public void Parse_accepts_every_vocabulary(string name, int expected)
        => Assert.Equal(expected, KeyUsageFriendlyNames.Parse(name));

    [Fact]
    public void ParseMany_ors_mixed_vocabularies_together()
    {
        // A profile can hold a mix once it has been edited by more than one client.
        var flags = KeyUsageFriendlyNames.ParseMany(
            new[] { "digitalSignature", "Key Encipherment", "CRL Sign" });

        Assert.Equal(
            KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign,
            flags);
    }

    [Fact]
    public void ParseMany_of_an_empty_list_is_zero()
        => Assert.Equal(0, KeyUsageFriendlyNames.ParseMany(Array.Empty<string>()));

    [Theory]
    [InlineData("Digital Signatur")]   // the typo case the fail-closed design exists for
    [InlineData("serverAuth")]         // an EXTENDED usage must not resolve as a standard one
    [InlineData("")]
    public void Parse_still_fails_closed_on_an_unknown_name(string name)
    {
        // Tolerance must not become permissiveness: an unrecognised usage still aborts issuance
        // rather than silently dropping a bit from the certificate.
        var ex = Assert.Throws<InvalidOperationException>(() => KeyUsageFriendlyNames.Parse(name));
        Assert.Contains("Unknown key usage friendly name", ex.Message);
    }
}
