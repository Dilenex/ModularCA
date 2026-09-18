using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// The rule that SCEP cannot run on a non-RSA authority, exercised on its own: the key algorithm
/// read from a real certificate, the advisory it produces, and the protocols and algorithms it
/// must leave alone.
/// </summary>
/// <remarks>
/// Proven live: a SCEP client wraps its certification request in a CMS envelope encrypted to the
/// CA certificate with RSA key transport, the only recipient type SCEP defines, and against an
/// ECDSA authority it cannot build the message at all. Nothing else in the configuration can
/// rescue that, which is why this is a refusal rather than a readiness step.
/// </remarks>
public sealed class ProtocolCompatibilityTests
{
    private static CertificateEntity RsaCa()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test RSA CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new CertificateEntity { Pem = cert.ExportCertificatePem() };
    }

    private static CertificateEntity EcdsaCa()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test EC CA", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new CertificateEntity { Pem = cert.ExportCertificatePem() };
    }

    [Fact]
    public void The_key_algorithm_comes_from_the_certificate()
    {
        Assert.Equal("RSA", ProtocolCompatibility.KeyAlgorithmOf(RsaCa()));
        Assert.Equal("ECDSA", ProtocolCompatibility.KeyAlgorithmOf(EcdsaCa()));
    }

    [Fact]
    public void A_missing_or_unparseable_certificate_says_nothing()
    {
        Assert.Null(ProtocolCompatibility.KeyAlgorithmOf(null));
        Assert.Null(ProtocolCompatibility.KeyAlgorithmOf(new CertificateEntity { Pem = "not a certificate" }));
        // And an unknown algorithm must not produce a refusal.
        Assert.Empty(ProtocolCompatibility.Advisories("SCEP", null));
        Assert.Null(ProtocolCompatibility.RefusalForEnabling("SCEP", ""));
    }

    [Fact]
    public void Scep_on_a_non_rsa_authority_is_advised_against_and_names_the_algorithm()
    {
        var advisories = ProtocolCompatibility.Advisories("SCEP", ProtocolCompatibility.KeyAlgorithmOf(EcdsaCa()));
        var advisory = Assert.Single(advisories);
        Assert.Equal(ProtocolCompatibility.ScepRequiresRsaKey, advisory.Reason);
        Assert.Contains("ECDSA", advisory.Message);
        Assert.Contains("RSA", advisory.Message);
        Assert.NotNull(ProtocolCompatibility.RefusalForEnabling("scep", "Ed25519"));
    }

    [Fact]
    public void Scep_on_an_rsa_authority_and_every_other_protocol_are_left_alone()
    {
        Assert.Empty(ProtocolCompatibility.Advisories("SCEP", ProtocolCompatibility.KeyAlgorithmOf(RsaCa())));
        Assert.Null(ProtocolCompatibility.RefusalForEnabling("SCEP", "RSA"));
        foreach (var protocol in new[] { "EST", "CMP", "ACME", "OCSP", "MSAE" })
            Assert.Empty(ProtocolCompatibility.Advisories(protocol, "ECDSA"));
    }

    [Fact]
    public void A_protocol_maps_to_the_feature_flag_that_gates_it()
    {
        Assert.Equal("SCEP.Enabled", ProtocolCompatibility.FeatureFlagName("SCEP"));
        Assert.Equal("ACME.Enabled", ProtocolCompatibility.FeatureFlagName("acme"));
        Assert.Equal("MSAE.Enabled", ProtocolCompatibility.FeatureFlagName(" msae "));
    }
}
