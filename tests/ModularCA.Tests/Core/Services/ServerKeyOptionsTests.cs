using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Which server-generated keys a signing profile and certificate profile accept together
/// (<see cref="ServerKeyOptionsResolver"/>), which is what the request form offers.
/// </summary>
public class ServerKeyOptionsTests
{
    private static readonly IssuanceValidationService Validation = new(null!, NullLogger<IssuanceValidationService>.Instance);

    private static SigningProfileEntity Signing(string allowedAlgorithms = "[]")
        => new() { Name = "signing", AllowedAlgorithms = allowedAlgorithms };

    private static CertProfileEntity Cert(string algorithms = "[]", string sizes = "[]", string signatures = "[]")
        => new()
        {
            Name = "cert",
            AllowedKeyAlgorithms = algorithms,
            AllowedKeySizes = sizes,
            AllowedSignatureAlgorithms = signatures,
        };

    private static EffectiveCertProfile Effective(CertProfileEntity cert, bool isCaProfile = false) => new()
    {
        Name = cert.Name,
        IsCaProfile = isCaProfile,
        AllowedKeyAlgorithms = cert.AllowedKeyAlgorithms,
        AllowedKeySizes = cert.AllowedKeySizes,
        AllowedSignatureAlgorithms = cert.AllowedSignatureAlgorithms,
    };

    private static ServerKeyOptions Resolve(SigningProfileEntity signing, CertProfileEntity cert, EffectiveCertProfile? effective = null)
        => ServerKeyOptionsResolver.Resolve(signing, cert, effective ?? Effective(cert), Validation);

    private static string[] Keys(ServerKeyOptions answer)
        => answer.Options.Select(o => o.KeySize == null ? o.Algorithm : $"{o.Algorithm} {o.KeySize}").ToArray();

    [Fact]
    public void Unrestricted_profiles_offer_every_key_the_CA_can_generate()
    {
        var answer = Resolve(Signing(), Cert());

        Assert.Equal(ServerKeyOptionsResolver.Catalog.Count, answer.Options.Count);
        Assert.Empty(answer.Refused);
        Assert.Equal("signing", answer.SigningProfileName);
        Assert.Equal("cert", answer.CertProfileName);
        Assert.All(answer.Options, o => Assert.False(string.IsNullOrEmpty(o.SignatureAlgorithm)));
    }

    [Fact]
    public void The_signing_profile_limits_the_algorithms()
    {
        var answer = Resolve(Signing("[\"ecdsa\",\"Ed25519\"]"), Cert());

        Assert.Equal(["ECDSA P-256", "ECDSA P-384", "ECDSA P-521", "Ed25519"], Keys(answer));
        Assert.Contains(answer.Refused, r => r.Algorithm == "RSA" && r.KeySize == "2048" && r.Reason.Contains("signing profile"));
    }

    [Fact]
    public void The_certificate_profile_limits_sizes_only_for_algorithms_that_have_one()
    {
        var answer = Resolve(Signing("[\"RSA\",\"ECDSA\",\"Ed448\"]"), Cert(sizes: "[\"4096\",\"P-384\"]"));

        Assert.Equal(["RSA 4096", "ECDSA P-384", "Ed448"], Keys(answer));
        Assert.Contains(answer.Refused, r => r.Algorithm == "RSA" && r.KeySize == "2048" && r.Reason.Contains("Key size"));
    }

    [Fact]
    public void A_key_whose_request_signature_is_not_allowed_is_refused()
    {
        var answer = Resolve(Signing("[\"RSA\",\"ECDSA\"]"), Cert(signatures: "[\"SHA256withECDSA\"]"));

        Assert.Equal(["ECDSA P-256"], Keys(answer));
        Assert.Contains(answer.Refused, r => r.Algorithm == "RSA" && r.Reason.Contains("Signature algorithm"));
        Assert.Contains(answer.Refused, r => r.Algorithm == "ECDSA" && r.KeySize == "P-384" && r.Reason.Contains("SHA384withECDSA"));
    }

    [Fact]
    public void The_inherited_limits_of_the_certificate_profile_apply_too()
    {
        var stored = Cert();
        var inherited = Effective(Cert(algorithms: "[\"ECDSA\"]", sizes: "[\"P-256\"]"));

        var answer = Resolve(Signing(), stored, inherited);

        Assert.Equal(["ECDSA P-256"], Keys(answer));
        Assert.Contains(answer.Refused, r => r.Algorithm == "RSA" && r.Reason.Contains("certificate profile"));
    }

    [Fact]
    public void A_CA_profile_offers_nothing()
    {
        var cert = Cert();

        var answer = Resolve(Signing(), cert, Effective(cert, isCaProfile: true));

        Assert.Empty(answer.Options);
        Assert.Equal(ServerKeyOptionsResolver.Catalog.Count, answer.Refused.Count);
    }

    public static TheoryData<string, string?> GeneratedKeys()
    {
        var data = new TheoryData<string, string?>();
        foreach (var (algorithm, keySize) in ServerKeyOptionsResolver.Catalog)
        {
            // One RSA size is enough: the size is read from the modulus, and the larger ones take long to generate.
            if (algorithm == "RSA" && keySize != "2048") continue;
            data.Add(algorithm, keySize);
        }
        return data;
    }

    /// <summary>
    /// The request handlers generate the key, sign a PKCS#10 with the resolved signature and
    /// hand the PEM to the upload path, which checks what it parses back. An offered key has to
    /// be the same key after that round trip.
    /// </summary>
    [Theory]
    [MemberData(nameof(GeneratedKeys))]
    public void An_offered_key_is_what_the_CA_reads_back_from_the_request_it_generates(string algorithm, string? keySize)
    {
        var option = Resolve(Signing(), Cert()).Options.Single(o => o.Algorithm == algorithm && o.KeySize == keySize);

        var keyPair = KeyGenerationUtil.GenerateKeyPair(algorithm, keySize ?? algorithm);
        var csr = new Pkcs10CertificationRequest(option.SignatureAlgorithm, new X509Name("CN=round-trip"), keyPair.Public, null, keyPair.Private);
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(csr);
        var parsed = CertificateUtil.ParseCsr(writer.ToString());

        Assert.Equal(algorithm, parsed.KeyAlgorithm, ignoreCase: true);
        Assert.Equal(keySize ?? string.Empty, parsed.KeySize);
        Assert.Equal(option.SignatureAlgorithm, parsed.SignatureAlgorithm, ignoreCase: true);
        Assert.True(CsrService.IsValidKeyParameters(parsed.KeyAlgorithm, parsed.KeySize, parsed.SignatureAlgorithm, Signing(), Cert()));
    }
}
