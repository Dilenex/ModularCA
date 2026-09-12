using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Direct coverage of the rules three separate builders now depend on
/// (<c>BouncyCastleCertificateAuthority</c> for the bootstrap root, <c>CertificateBuilderService</c>
/// for intermediates, and <c>CaCreationService.CreateRootAsync</c> for a runtime root).
/// <para>
/// The builder-level tests exercise these through a real certificate, which is the right shape for
/// pinning that the rules are <em>wired in</em>, but it leaves the rules' own edges — a null list,
/// a lazily-evaluated sequence, a zero flag set — reachable only by inference. Those are covered
/// here so a change to the shared class cannot pass on the strength of three callers that all
/// happen to pass materialised, non-empty inputs.
/// </para>
/// </summary>
public class CaCertificateRulesTests
{
    private const int CaBits = KeyUsage.KeyCertSign | KeyUsage.CrlSign;

    // ---- EnsureKeyUsagesPermitted ----

    [Theory]
    [InlineData(KeyUsage.KeyEncipherment)]
    [InlineData(KeyUsage.DataEncipherment)]
    [InlineData(KeyUsage.KeyAgreement)]
    public void A_ca_may_not_assert_encipherment_or_agreement(int forbidden)
    {
        var ex = Assert.Throws<ConfigurationValidationException>(
            () => CaCertificateRules.EnsureKeyUsagesPermitted(true, CaBits | forbidden, new[] { "someUsage" }));

        Assert.Contains("must not assert keyEncipherment", ex.Message);
        Assert.Contains("someUsage", ex.Message);
        // The code is what a runbook or support ticket keys on, so it is pinned alongside the
        // prose rather than left to drift when the sentence gets reworded.
        Assert.Equal(ErrorCodes.CaKeyUsageForbidden, ex.Code);
        Assert.Equal(400, ex.Status);
    }

    [Fact]
    public void A_ca_asserting_only_signing_bits_is_permitted()
        => CaCertificateRules.EnsureKeyUsagesPermitted(true, CaBits | KeyUsage.DigitalSignature, new[] { "keyCertSign" });

    [Fact]
    public void A_leaf_may_assert_every_bit_a_ca_may_not()
        => CaCertificateRules.EnsureKeyUsagesPermitted(
            false,
            KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment | KeyUsage.KeyAgreement,
            new[] { "keyEncipherment" });

    [Fact]
    public void A_ca_with_no_bits_set_is_permitted()
        => CaCertificateRules.EnsureKeyUsagesPermitted(true, 0, Array.Empty<string>());

    // ---- EnsureNoExtendedKeyUsage ----

    [Fact]
    public void A_ca_may_not_carry_an_eku()
    {
        var ex = Assert.Throws<ConfigurationValidationException>(
            () => CaCertificateRules.EnsureNoExtendedKeyUsage(true, new[] { "1.3.6.1.5.5.7.3.1" }));

        Assert.Contains("must not carry an ExtendedKeyUsage", ex.Message);
        Assert.Contains("1.3.6.1.5.5.7.3.1", ex.Message);
        Assert.Equal(ErrorCodes.CaExtendedKeyUsageForbidden, ex.Code);
        Assert.Equal(400, ex.Status);
    }

    [Fact]
    public void A_ca_with_an_empty_eku_list_is_permitted()
        => CaCertificateRules.EnsureNoExtendedKeyUsage(true, Array.Empty<string>());

    [Fact]
    public void A_leaf_may_carry_ekus()
        => CaCertificateRules.EnsureNoExtendedKeyUsage(false, new[] { "1.3.6.1.5.5.7.3.1" });

    /// <summary>A non-CA is decided before the sequence is touched, so a null list is a no-op.</summary>
    [Fact]
    public void A_leaf_with_a_null_eku_list_does_not_throw()
        => CaCertificateRules.EnsureNoExtendedKeyUsage(false, null!);

    /// <summary>
    /// A lazy sequence must be enumerated exactly once — the count and the message are both read
    /// from it, and a single-pass source would otherwise come back empty for the message.
    /// </summary>
    [Fact]
    public void A_lazily_evaluated_eku_sequence_is_enumerated_once()
    {
        var enumerations = 0;
        IEnumerable<string> Lazy()
        {
            enumerations++;
            yield return "1.3.6.1.4.1.311.20.2.2";
        }

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => CaCertificateRules.EnsureNoExtendedKeyUsage(true, Lazy()));

        Assert.Equal(1, enumerations);
        Assert.Contains("1.3.6.1.4.1.311.20.2.2", ex.Message);
    }

    // ---- ApplyRequiredKeyUsages ----

    [Fact]
    public void A_ca_with_no_declared_usages_gains_both_mandatory_bits()
    {
        var flags = CaCertificateRules.ApplyRequiredKeyUsages(true, 0, out var added);

        Assert.Equal(CaBits, flags);
        Assert.Equal(CaBits, added);
    }

    [Fact]
    public void A_ca_keeps_the_usages_it_declared()
    {
        var flags = CaCertificateRules.ApplyRequiredKeyUsages(true, KeyUsage.DigitalSignature, out var added);

        Assert.Equal(KeyUsage.DigitalSignature | CaBits, flags);
        Assert.Equal(CaBits, added);
    }

    [Fact]
    public void A_ca_that_already_declared_the_mandatory_bits_gains_nothing()
    {
        var flags = CaCertificateRules.ApplyRequiredKeyUsages(true, CaBits, out var added);

        Assert.Equal(CaBits, flags);
        Assert.Equal(0, added);
    }

    [Fact]
    public void A_leaf_never_gains_the_ca_bits()
    {
        var flags = CaCertificateRules.ApplyRequiredKeyUsages(false, KeyUsage.DigitalSignature, out var added);

        Assert.Equal(KeyUsage.DigitalSignature, flags);
        Assert.Equal(0, added);
    }

    [Fact]
    public void A_leaf_with_no_usages_stays_at_zero()
    {
        var flags = CaCertificateRules.ApplyRequiredKeyUsages(false, 0, out var added);

        Assert.Equal(0, flags);
        Assert.Equal(0, added);
    }
}
