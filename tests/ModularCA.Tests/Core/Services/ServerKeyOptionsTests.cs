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

    /// <summary>
    /// The answer also says what the pair imposes besides the key, for the panel beside the
    /// pickers: the issuing CA and its name constraints from the signing profile, and the usages,
    /// validity and wildcard setting of the certificate profile after inheritance.
    /// </summary>
    [Fact]
    public async Task The_answer_carries_what_the_pair_imposes_on_the_certificate()
    {
        using var db = ModularCA.Tests.TestUtils.InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Name = "Staging CA R1", Label = "staging-ca-r1", CertificateId = Guid.NewGuid() };
        var signing = new SigningProfileEntity
        {
            Name = "Staging CA R1 Signing Profile",
            AllowedAlgorithms = "[]",
            IssuerId = ca.CertificateId,
            NameConstraintsPermitted = "[\"DNS:.corp.example\"]",
        };
        var parent = new CertProfileEntity
        {
            Name = "Server baseline",
            KeyUsages = "[\"digitalSignature\",\"keyEncipherment\"]",
            ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.1\",\"1.2.3.4\"]",
            AllowedKeySizes = "[]",
            AllowedSignatureAlgorithms = "[]",
            ValidityPeriodMin = "P1D",
            ValidityPeriodMax = "P397D",
        };
        db.AddRange(ca, signing, parent,
            new OIDOptionEntity { OID = "1.3.6.1.5.5.7.3.1", FriendlyName = "serverAuth", KeyUsage = "Extended" });
        await db.SaveChangesAsync();
        var service = new ServerKeyOptionsService(db,
            new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance), Validation);

        var answer = await service.ResolveAsync(signing.Id, parent.Id);

        var constraints = Assert.IsType<ProfilePairConstraints>(answer!.Constraints);
        Assert.Equal("Staging CA R1", constraints.IssuingCaName);
        Assert.Equal(["DNS:.corp.example"], constraints.NameConstraintsPermitted);
        Assert.Empty(constraints.NameConstraintsExcluded);
        Assert.Equal(["digitalSignature", "keyEncipherment"], constraints.KeyUsages);
        Assert.Equal([new NamedUsage("1.3.6.1.5.5.7.3.1", "serverAuth"), new NamedUsage("1.2.3.4", "1.2.3.4")], constraints.ExtendedKeyUsages);
        Assert.Equal("P1D", constraints.ValidityPeriodMin);
        Assert.Equal("P397D", constraints.ValidityPeriodMax);
        Assert.False(constraints.AllowWildcard);
        Assert.Equal(14, answer.Options.Count);

        // A signing profile that names no CA says so, and an unreadable list reads as empty.
        var loose = new SigningProfileEntity { Name = "Loose", AllowedAlgorithms = "[]", NameConstraintsExcluded = "not json" };
        db.Add(loose);
        await db.SaveChangesAsync();
        var unbound = (await service.ResolveAsync(loose.Id, parent.Id))!.Constraints!;
        Assert.Null(unbound.IssuingCaName);
        Assert.Equal(["not json"], unbound.NameConstraintsExcluded);
        Assert.Equal(["a", "b"], ProfileConstraintReader.ReadList("a, b"));
        Assert.Empty(ProfileConstraintReader.ReadList("[1,"));
        Assert.Empty(ProfileConstraintReader.ReadList(null));
    }
}
