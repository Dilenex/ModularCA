using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The timestamp service signs through the signer: the token it returns must validate under the
/// TSA certificate exactly as the key-based generator's did, and the signer's audit must show
/// the TSA key used for the TSA purpose of its own CA.
/// </summary>
public sealed class TimestampServiceTests
{
    [Fact]
    public async Task A_timestamp_token_signed_through_the_signer_validates_under_the_tsa_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName);
        using var db = world.OpenDb();
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer);

        var reqGen = new TimeStampRequestGenerator();
        reqGen.SetCertReq(true);
        var imprint = new byte[32];
        Random.Shared.NextBytes(imprint);
        var request = reqGen.Generate(TspAlgorithms.Sha256, imprint, BigInteger.ValueOf(4242));

        var encoded = await service.ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-rsa");

        var response = new TimeStampResponse(encoded);
        response.Validate(request);
        Assert.Equal(0, response.Status);
        var token = response.TimeStampToken;
        Assert.NotNull(token);
        token.Validate(world["tsa"].Certificate);
        Assert.Equal(imprint, token.TimeStampInfo.GetMessageImprintDigest());

        var row = Assert.Single(await ReadAuditAsync(world), r => r.Operation == "Sign");
        Assert.Equal("allowed", row.Outcome);
        Assert.Equal("Tsa", row.Purpose);
        Assert.Equal(world["tsa"].Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(world.CaRsaId, row.CaId);
    }

    [Fact]
    public async Task A_ca_without_a_tsa_certificate_is_rejected_without_touching_the_signer()
    {
        var world = SignerTestWorld.Create();
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName);
        using var db = world.OpenDb();
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer);

        var request = new TimeStampRequestGenerator().Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.One);

        var response = new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-ec"));

        Assert.NotEqual(0, response.Status);
        Assert.Null(response.TimeStampToken);
        Assert.Empty(await ReadAuditAsync(world));
    }

    /// <summary>
    /// The label-less TSA answers only as a CA marked default. Round one's deterministic default
    /// resolution let it fall back to whichever CA sorted first by name when none was marked, so
    /// a CA the operator never chose signed timestamp tokens; before that, it required a default.
    /// </summary>
    [Fact]
    public async Task The_label_less_tsa_answers_only_as_a_ca_marked_default()
    {
        var world = SignerTestWorld.Create();
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName);
        using var db = world.OpenDb();
        var rsa = db.CertificateAuthorities.Single(c => c.Id == world.CaRsaId);
        rsa.Name = "a-signer-test-rsa";
        db.SaveChanges();
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer);
        var request = new TimeStampRequestGenerator().Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.Two);

        var undesignated = new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded()));
        Assert.NotEqual(0, undesignated.Status);
        Assert.Null(undesignated.TimeStampToken);

        rsa.IsDefault = true;
        db.SaveChanges();
        var designated = new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded()));
        Assert.Equal(0, designated.Status);
        designated.TimeStampToken.Validate(world["tsa"].Certificate);
    }

    private static Task<IReadOnlyList<ModularCA.Shared.Entities.SignerAuditEntity>> ReadAuditAsync(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        IReadOnlyList<ModularCA.Shared.Entities.SignerAuditEntity> rows = db.SignerAudit.OrderBy(r => r.At).ToList();
        return Task.FromResult(rows);
    }
}
