using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the last hop of the key-usage pipeline: stored names to actual KeyUsage BITS.
/// <para>
/// This is the gap that let a broken root CA reach a running install. The bootstrap fix was
/// tested by asserting the catalog lookup returned the right NAMES, and it did — but the
/// certificate builder then fed those names to a different, fifth copy of the vocabulary that
/// understood only the spaced display form and scored every catalog camelCase name as zero. The
/// resulting root carried a CRITICAL KeyUsage extension with no bits set, which asserts the CA
/// key may do nothing. Every test passed.
/// </para>
/// <para>
/// So these assert bits, not names, and they start from the exact strings the seeder now stores.
/// </para>
/// </summary>
public class X509KeyUsageUtilTests
{
    /// <summary>
    /// The stored form is a JSON array. The old parser split on commas, so this input decomposed
    /// into tokens like <c>["Digital Signature"</c> that matched nothing — zero bits, silently.
    /// </summary>
    [Fact]
    public void Json_array_of_catalog_names_yields_the_right_bits()
    {
        var flags = X509KeyUsageUtil.ParseKeyUsages(
            "[\"digitalSignature\",\"keyCertSign\",\"crlSign\"]");

        Assert.Equal(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign, flags);
        Assert.NotEqual(0, flags);
    }

    /// <summary>The display vocabulary must keep working — profiles hold both.</summary>
    [Fact]
    public void Json_array_of_display_names_yields_the_right_bits()
    {
        var flags = X509KeyUsageUtil.ParseKeyUsages(
            "[\"Digital Signature\",\"Key Certificate Signing\",\"CRL Signing\"]");

        Assert.Equal(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign, flags);
    }

    /// <summary>Rows written before profiles moved to JSON are comma-separated.</summary>
    [Fact]
    public void Legacy_csv_still_parses()
    {
        var flags = X509KeyUsageUtil.ParseKeyUsages("Digital Signature, Key Encipherment");
        Assert.Equal(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment, flags);
    }

    /// <summary>
    /// The exact set the bootstrap seeder resolves for a root CA. If this ever returns 0 again,
    /// the root ships unusable.
    /// </summary>
    [Fact]
    public void Root_CA_usage_set_produces_signing_bits()
    {
        var flags = X509KeyUsageUtil.ParseKeyUsages(
            "[\"digitalSignature\",\"keyEncipherment\",\"keyCertSign\",\"crlSign\"]");

        Assert.NotEqual(0, flags);
        Assert.Equal(KeyUsage.KeyCertSign, flags & KeyUsage.KeyCertSign);  // must be able to sign certs
        Assert.Equal(KeyUsage.CrlSign, flags & KeyUsage.CrlSign);          // and CRLs
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[]")]
    public void Empty_input_yields_no_bits(string input)
        => Assert.Equal(0, X509KeyUsageUtil.ParseKeyUsages(input));

    /// <summary>
    /// Tolerance must not become permissiveness. Silently dropping an unknown usage is how a
    /// profile ends up requesting bits the certificate never carries.
    /// </summary>
    [Fact]
    public void Unknown_usage_throws_rather_than_dropping_a_bit()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => X509KeyUsageUtil.ParseKeyUsages("[\"digitalSignature\",\"telepathy\"]"));
        Assert.Contains("Unknown key usage friendly name", ex.Message);
    }
}
