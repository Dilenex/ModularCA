using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The system key policy (<see cref="KeyAlgorithmPolicy"/>) is applied at issuance to the key the
/// certificate would certify. It was applied only where a request entered through the console and
/// to ACME account keys, so a protocol CSR with RSA-1024 or a key on a non-NIST curve was issued
/// whenever its profile listed no key sizes — as the leaf profile here lists none.
/// </summary>
public sealed class IssuanceKeyAlgorithmPolicyTests
{
    private static AsymmetricCipherKeyPair Rsa(int bits)
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        return gen.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair Secp256k1()
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256k1, new SecureRandom()));
        return gen.GenerateKeyPair();
    }

    [Fact]
    public async Task A_request_over_an_rsa_1024_key_is_refused_at_issuance()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var root = await w.CreateRootAsync("Key Policy Root", null, null);

        var ex = await Assert.ThrowsAsync<CertificatePolicyViolationException>(
            () => w.IssueLeafAsync(root, "CN=leaf", [], keys: Rsa(1024), csrSignatureAlgorithm: "SHA256WITHRSA"));

        Assert.Equal(ErrorCodes.PolicyViolation, ex.Code);
        Assert.Contains("RSA 1024", ex.Message);
    }

    /// <summary>
    /// A key on secp256k1 has a 256-bit order like P-256, so a check by bit length passes it; the
    /// request row even records P-256 here. The key itself decides.
    /// </summary>
    [Fact]
    public async Task A_request_over_a_non_nist_curve_is_refused_at_issuance_whatever_the_row_records()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var root = await w.CreateRootAsync("Curve Policy Root", null, null);

        var ex = await Assert.ThrowsAsync<CertificatePolicyViolationException>(
            () => w.IssueLeafAsync(root, "CN=leaf", [], keys: Secp256k1()));

        Assert.Contains("1.3.132.0.10", ex.Message);
    }

    [Fact]
    public async Task A_request_over_an_allowed_key_is_issued()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var root = await w.CreateRootAsync("Allowed Key Root", null, null);

        Assert.Contains("BEGIN CERTIFICATE", (await w.IssueLeafAsync(root, "CN=leaf", [])).Pem);
        Assert.Contains("BEGIN CERTIFICATE",
            (await w.IssueLeafAsync(root, "CN=leaf2", [], keys: Rsa(2048), csrSignatureAlgorithm: "SHA256WITHRSA")).Pem);
    }

    [Fact]
    public void The_policy_judges_a_public_key_by_its_own_parameters()
    {
        Assert.True(KeyAlgorithmPolicy.IsAllowedPublicKey(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-384").Public, out var p384));
        Assert.Equal("ECDSA P-384", p384);
        Assert.True(KeyAlgorithmPolicy.IsAllowedPublicKey(KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public, out _));
        Assert.False(KeyAlgorithmPolicy.IsAllowedPublicKey(Rsa(1024).Public, out var rsa));
        Assert.Equal("RSA 1024", rsa);
        Assert.False(KeyAlgorithmPolicy.IsAllowedPublicKey(Secp256k1().Public, out _));

        // Explicit parameters equal to P-256 are P-256.
        var named = (ECPublicKeyParameters)KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public;
        var p = named.Parameters;
        var explicitKey = new ECPublicKeyParameters(named.Q, new ECDomainParameters(p.Curve, p.G, p.N, p.H));
        Assert.Null(explicitKey.PublicKeyParamSet);
        Assert.True(KeyAlgorithmPolicy.IsAllowedPublicKey(explicitKey, out _));
    }
}
