using ModularCA.Keystore.Hsm;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace ModularCA.Tests.Keystore.Hsm;

/// <summary>
/// An HSM key is bound to its CA certificate by public key, not by label alone. The label finds
/// the private key object; the public key the token reports for it must then be the
/// certificate's, and a label that more than one private key object carries binds nothing.
/// The comparison is a pure function over the attributes a token returns, so it is tested here
/// with software keys and a fake token; reading those attributes from a real token is not.
/// </summary>
public sealed class Pkcs11KeyBinderTests
{
    private const string Label = "ca-key";

    [Fact]
    public void An_rsa_key_whose_modulus_and_exponent_are_the_certificates_is_bound()
    {
        var keys = HsmTestKeys.Rsa();
        var cert = HsmTestKeys.SelfSigned(keys, "SHA256withRSA");
        var token = new FakePkcs11Token();
        var handle = token.Add(Label, HsmTestKeys.RsaMaterial(keys.Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Same(handle, binding.Key);
        Assert.Null(binding.Refusal);
    }

    [Fact]
    public void An_rsa_key_under_the_right_label_but_of_another_ca_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Rsa(), "SHA256withRSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.RsaMaterial(HsmTestKeys.Rsa().Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.False(binding.NotFound);
        Assert.Contains("modulus", binding.Refusal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_ec_key_whose_point_is_the_certificates_is_bound_whether_the_token_wraps_the_point_or_not(bool wrapped)
    {
        var keys = HsmTestKeys.Ec(HsmTestKeys.P256);
        var cert = HsmTestKeys.SelfSigned(keys, "SHA256withECDSA");
        var token = new FakePkcs11Token();
        var handle = token.Add(Label, HsmTestKeys.EcMaterial(keys.Public, HsmTestKeys.P256, wrapped));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Refusal);
        Assert.Same(handle, binding.Key);
    }

    [Fact]
    public void A_p521_point_wrapped_with_a_long_form_length_is_unwrapped_and_bound()
    {
        // 133 bytes of point need a two-byte DER length (0x81 0x85), which a check for a
        // one-byte length would not unwrap.
        var keys = HsmTestKeys.Ec(HsmTestKeys.P521);
        var cert = HsmTestKeys.SelfSigned(keys, "SHA512withECDSA");
        var token = new FakePkcs11Token();
        var handle = token.Add(Label, HsmTestKeys.EcMaterial(keys.Public, HsmTestKeys.P521, wrapped: true));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Refusal);
        Assert.Same(handle, binding.Key);
    }

    [Fact]
    public void An_ec_key_on_the_right_curve_but_of_another_ca_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Ec(HsmTestKeys.P384), "SHA384withECDSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.EcMaterial(HsmTestKeys.Ec(HsmTestKeys.P384).Public, HsmTestKeys.P384));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("point", binding.Refusal);
    }

    [Fact]
    public void An_ec_key_on_another_curve_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Ec(HsmTestKeys.P384), "SHA384withECDSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.EcMaterial(HsmTestKeys.Ec(HsmTestKeys.P256).Public, HsmTestKeys.P256));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("curve", binding.Refusal);
    }

    [Fact]
    public void A_token_key_of_another_type_from_the_certificates_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Ec(HsmTestKeys.P256), "SHA256withECDSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.RsaMaterial(HsmTestKeys.Rsa().Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("type", binding.Refusal);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void An_ed25519_key_whose_public_key_is_the_certificates_is_bound(bool curveByName, bool wrapped)
    {
        var keys = HsmTestKeys.Ed25519();
        var cert = HsmTestKeys.SelfSigned(keys, "Ed25519");
        var token = new FakePkcs11Token();
        var handle = token.Add(Label, HsmTestKeys.EdwardsMaterial(keys.Public, curveByName, wrapped));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Refusal);
        Assert.Same(handle, binding.Key);
    }

    [Fact]
    public void An_ed448_key_whose_public_key_is_the_certificates_is_bound()
    {
        var keys = HsmTestKeys.Ed448();
        var cert = HsmTestKeys.SelfSigned(keys, "Ed448");
        var token = new FakePkcs11Token();
        var handle = token.Add(Label, HsmTestKeys.EdwardsMaterial(keys.Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Refusal);
        Assert.Same(handle, binding.Key);
    }

    [Fact]
    public void An_ed25519_key_of_another_ca_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Ed25519(), "Ed25519");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.EdwardsMaterial(HsmTestKeys.Ed25519().Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.NotNull(binding.Refusal);
    }

    [Fact]
    public void An_ed448_key_named_as_ed25519_by_the_token_is_refused()
    {
        var keys = HsmTestKeys.Ed448();
        var cert = HsmTestKeys.SelfSigned(keys, "Ed448");
        var material = HsmTestKeys.EdwardsMaterial(keys.Public) with { EcParams = new DerPrintableString("edwards25519").GetEncoded() };
        var token = new FakePkcs11Token();
        token.Add(Label, material);

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("curve", binding.Refusal);
    }

    [Fact]
    public void A_label_two_private_key_objects_carry_binds_neither_even_when_one_matches()
    {
        var keys = HsmTestKeys.Rsa();
        var cert = HsmTestKeys.SelfSigned(keys, "SHA256withRSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.RsaMaterial(keys.Public));
        token.Add(Label, HsmTestKeys.RsaMaterial(HsmTestKeys.Rsa().Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("2 private key objects", binding.Refusal);
    }

    [Fact]
    public void A_duplicate_that_fails_containment_still_makes_the_label_ambiguous()
    {
        var keys = HsmTestKeys.Rsa();
        var cert = HsmTestKeys.SelfSigned(keys, "SHA256withRSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.RsaMaterial(keys.Public), contained: false);
        token.Add(Label, HsmTestKeys.RsaMaterial(keys.Public));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.NotNull(binding.Refusal);
    }

    [Fact]
    public void A_label_no_object_carries_is_not_found_rather_than_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Rsa(), "SHA256withRSA");

        var binding = Pkcs11KeyBinder.Bind(new FakePkcs11Token(), Label, cert);

        Assert.True(binding.NotFound);
    }

    [Fact]
    public void A_matching_key_that_is_extractable_or_session_scoped_is_refused()
    {
        var keys = HsmTestKeys.Rsa();
        var cert = HsmTestKeys.SelfSigned(keys, "SHA256withRSA");
        var token = new FakePkcs11Token();
        token.Add(Label, HsmTestKeys.RsaMaterial(keys.Public), contained: false);

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("containment", binding.Refusal);
    }

    [Fact]
    public void A_key_whose_public_key_cannot_be_read_is_refused()
    {
        var cert = HsmTestKeys.SelfSigned(HsmTestKeys.Ec(HsmTestKeys.P256), "SHA256withECDSA");
        var token = new FakePkcs11Token();
        token.Add(Label, null, readError: new InvalidOperationException("no public key object pairs with it"));

        var binding = Pkcs11KeyBinder.Bind(token, Label, cert);

        Assert.Null(binding.Key);
        Assert.Contains("no public key object pairs with it", binding.Refusal);
    }
}
