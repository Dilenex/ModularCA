using ModularCA.Keystore.Hsm;
using Net.Pkcs11Interop.Common;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Operators.Utilities;
using Xunit;

namespace ModularCA.Tests.Keystore.Hsm;

/// <summary>
/// The PKCS#11 mechanism for a signing algorithm carries the parameters that algorithm needs,
/// and they are exactly what the AlgorithmIdentifier written into the certificate or CRL says:
/// for RSA-PSS the hash, MGF1 with the same hash and a salt as long as the hash; for Ed448 a
/// <c>CK_EDDSA_PARAMS</c> asking for pure EdDSA with no context. The AlgorithmIdentifier side is
/// read from <see cref="DefaultSignatureAlgorithmFinder"/>, the finder the signer's signature
/// factory writes it with.
/// </summary>
public sealed class Pkcs11SignMechanismTests
{
    private static readonly Dictionary<DerObjectIdentifier, (CKM Hash, CKG Mgf)> ByHashOid = new()
    {
        [NistObjectIdentifiers.IdSha256] = (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
        [NistObjectIdentifiers.IdSha384] = (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384),
        [NistObjectIdentifiers.IdSha512] = (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512),
    };

    [Theory]
    [InlineData("SHA256withRSAandMGF1", CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData("SHA384withRSAandMGF1", CKM.CKM_SHA384_RSA_PKCS_PSS)]
    [InlineData("SHA512withRSAandMGF1", CKM.CKM_SHA512_RSA_PKCS_PSS)]
    public void An_rsa_pss_mechanism_carries_the_parameters_the_algorithm_identifier_advertises(string algorithm, CKM expectedMechanism)
    {
        var advertised = RsassaPssParameters.GetInstance(DefaultSignatureAlgorithmFinder.Instance.Find(algorithm).Parameters);
        var hash = ByHashOid[advertised.HashAlgorithm.Algorithm];
        Assert.Equal(PkcsObjectIdentifiers.IdMgf1, advertised.MaskGenAlgorithm.Algorithm);
        var mgfHash = ByHashOid[Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier.GetInstance(advertised.MaskGenAlgorithm.Parameters).Algorithm];

        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism(algorithm);

        Assert.Equal(expectedMechanism, mechanism.Mechanism);
        Assert.NotNull(mechanism.Pss);
        Assert.Equal(hash.Hash, mechanism.Pss!.HashAlgorithm);
        Assert.Equal(mgfHash.Mgf, mechanism.Pss.Mgf);
        Assert.Equal(advertised.SaltLength.Value.LongValue, (long)mechanism.Pss.SaltLength);
        Assert.Null(mechanism.Eddsa);
    }

    [Fact]
    public void Ed448_asks_for_pure_eddsa_with_no_context()
    {
        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism("Ed448");

        Assert.Equal((CKM)0x00001057, mechanism.Mechanism);
        Assert.NotNull(mechanism.Eddsa);
        Assert.False(mechanism.Eddsa!.PreHash);
        Assert.Null(mechanism.Pss);
    }

    [Fact]
    public void Ed25519_carries_no_parameters_since_with_them_a_token_may_sign_ed25519ctx()
    {
        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism("Ed25519");

        Assert.Equal((CKM)0x00001057, mechanism.Mechanism);
        Assert.Null(mechanism.Eddsa);
        Assert.Null(mechanism.Pss);
    }

    [Theory]
    [InlineData("SHA256withRSA", CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData("SHA384withECDSA", CKM.CKM_ECDSA_SHA384)]
    public void Pkcs1_and_ecdsa_mechanisms_carry_no_parameters(string algorithm, CKM expected)
    {
        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism(algorithm);

        Assert.Equal(expected, mechanism.Mechanism);
        Assert.Null(mechanism.Pss);
        Assert.Null(mechanism.Eddsa);
    }

    [Theory]
    [InlineData(8, 0, 8, 24)] // 64-bit Unix: phFlag, 7 bytes padding, CK_ULONG, pointer
    [InlineData(4, 1, 8, 13)] // 64-bit Windows: packed, 4-byte CK_ULONG
    [InlineData(4, 1, 4, 9)]  // 32-bit Windows
    [InlineData(4, 0, 4, 12)] // 32-bit Unix
    public void The_eddsa_parameters_are_laid_out_as_the_platform_module_reads_them(int ulongSize, int packing, int pointerSize, int expectedSize)
    {
        var native = new Pkcs11EddsaParameters(PreHash: false).ToNative(ulongSize, packing, pointerSize);

        Assert.Equal(expectedSize, native.Length);
        Assert.All(native, b => Assert.Equal(0, b));
        Assert.Equal(1, new Pkcs11EddsaParameters(PreHash: true).ToNative(ulongSize, packing, pointerSize)[0]);
    }
}
