using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the RSA size allow-list in <see cref="KeyAlgorithmPolicy"/>. The policy is the
/// single source of truth that controllers, CSR validators, and the issuance pipeline
/// all consult — drift here breaks intent at every gate.
/// </summary>
public class KeyAlgorithmPolicyTests
{
    [Theory]
    [InlineData("2048")]
    [InlineData("3072")]
    [InlineData("4096")]
    [InlineData("7680")]
    [InlineData("8192")]
    public void IsAllowed_AcceptsSupportedRsaSizes(string size)
        => Assert.True(KeyAlgorithmPolicy.IsAllowed("RSA", size));

    [Theory]
    [InlineData("1024")] // below CABF BR floor
    [InlineData("1536")]
    [InlineData("6144")] 
    [InlineData("16384")]
    [InlineData("")]
    [InlineData("abc")]
    public void IsAllowed_RejectsUnsupportedRsaSizes(string size)
        => Assert.False(KeyAlgorithmPolicy.IsAllowed("RSA", size));

    [Theory]
    [InlineData("RSA", 2048)]
    [InlineData("RSA", 3072)]
    [InlineData("RSA", 4096)]
    [InlineData("RSA", 7680)]
    [InlineData("RSA", 8192)]
    public void IsAllowed_IntOverload_AcceptsSupportedRsa(string alg, int size)
        => Assert.True(KeyAlgorithmPolicy.IsAllowed(alg, size));

    [Theory]
    [InlineData(null, true)]
    [InlineData("PSS", true)]
    [InlineData("pss", true)]
    [InlineData("v15", false)]
    [InlineData("", false)]
    public void IsPss_ReadsTheConfiguredPadding(string? padding, bool expected)
        => Assert.Equal(expected, KeyAlgorithmPolicy.IsPss(padding));
}

/// <summary>Runs alone: the test below changes the padding every RSA signature in the process is made with.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class RsaPaddingCollection
{
    public const string Name = "RsaPadding";
}

/// <summary>
/// <c>CertPolicy.RsaSignaturePadding</c> is marked Live: the policy asks for it on every
/// signature instead of keeping what it was at start.
/// </summary>
[Collection(RsaPaddingCollection.Name)]
public class KeyAlgorithmPolicyRsaPaddingTests
{
    [Fact]
    public void The_rsa_signature_algorithm_follows_the_padding_as_it_is_saved()
    {
        var config = new SystemConfig();
        try
        {
            KeyAlgorithmPolicy.FollowRsaPadding(() => config.CertPolicy?.RsaSignaturePadding);
            Assert.True(KeyAlgorithmPolicy.UseRsaPss);
            Assert.Equal("SHA256withRSAandMGF1", KeyAlgorithmPolicy.ResolveSignatureAlgorithm("RSA", "2048"));

            config.CertPolicy.RsaSignaturePadding = "v15";
            Assert.False(KeyAlgorithmPolicy.UseRsaPss);
            Assert.Equal("SHA256withRSA", KeyAlgorithmPolicy.ResolveSignatureAlgorithm("RSA", "2048"));
            Assert.Equal("SHA256withECDSA", KeyAlgorithmPolicy.ResolveSignatureAlgorithm("ECDSA", "P-256"));

            config.CertPolicy = new CertPolicyConfig();
            Assert.Equal("SHA256withRSAandMGF1", KeyAlgorithmPolicy.ResolveSignatureAlgorithm("RSA", "2048"));
        }
        finally
        {
            KeyAlgorithmPolicy.FollowRsaPadding(() => null);
        }
    }
}
