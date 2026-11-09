using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Models.Config;
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
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer, new SystemConfig());

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
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer, new SystemConfig());

        var request = new TimeStampRequestGenerator().Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.One);

        var response = new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-ec"));

        Assert.NotEqual(0, response.Status);
        Assert.Null(response.TimeStampToken);
        Assert.Empty(await ReadAuditAsync(world));
    }

    /// <summary>
    /// A SHA-1 message imprint is refused with badAlg (RFC 3161 section 2.4.2) and nothing is
    /// signed: a token over a SHA-1 imprint attests to every document that collides with it.
    /// </summary>
    [Fact]
    public async Task A_sha1_message_imprint_is_refused_with_bad_alg()
    {
        var world = SignerTestWorld.Create();
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName);
        using var db = world.OpenDb();
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer, new SystemConfig());

        var request = new TimeStampRequestGenerator().Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(3));

        var response = new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-rsa"));

        Assert.Equal(2, response.Status); // rejection
        Assert.Null(response.TimeStampToken);
        Assert.Equal(Org.BouncyCastle.Asn1.Cmp.PkiFailureInfo.BadAlg, response.GetFailInfo().IntValue);
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
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, signer, new SystemConfig());
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

    /// <summary>A SHA-256 request for <paramref name="policy"/>, or with no reqPolicy when it is null.</summary>
    private static TimeStampRequest PolicyRequest(string? policy)
    {
        var reqGen = new TimeStampRequestGenerator();
        if (policy != null) reqGen.SetReqPolicy(new Org.BouncyCastle.Asn1.DerObjectIdentifier(policy));
        return reqGen.Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.ValueOf(77));
    }

    /// <summary>Answers <paramref name="request"/> as the RSA CA's TSA under <paramref name="config"/>.</summary>
    private static async Task<(TimeStampResponse Response, SignerTestWorld World)> AnswerAsync(TimeStampRequest request, SystemConfig config)
    {
        var world = SignerTestWorld.Create();
        using var db = world.OpenDb();
        var service = new TimestampService(db, NullLogger<TimestampService>.Instance, TestSigner.Over(world.Keystore, world.DatabaseName), config);
        return (new TimeStampResponse(await service.ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-rsa")), world);
    }

    [Fact]
    public async Task A_token_names_the_default_tsa_policy_under_the_dilenex_arc()
    {
        var request = PolicyRequest(null);
        var (response, world) = await AnswerAsync(request, new SystemConfig());

        response.Validate(request);
        Assert.Equal(0, response.Status);
        Assert.Equal("1.3.6.1.4.1.66874.1.5.1", TsaConfig.DefaultPolicyOid);
        Assert.Equal(TsaConfig.DefaultPolicyOid, response.TimeStampToken.TimeStampInfo.Policy);
        response.TimeStampToken.Validate(world["tsa"].Certificate);
    }

    [Fact]
    public async Task A_token_names_the_policy_the_operator_configured()
    {
        var config = new SystemConfig();
        config.Tsa.PolicyOid = "1.3.6.1.4.1.99999.7.1";

        var (response, _) = await AnswerAsync(PolicyRequest(null), config);

        Assert.Equal(0, response.Status);
        Assert.Equal("1.3.6.1.4.1.99999.7.1", response.TimeStampToken.TimeStampInfo.Policy);
    }

    /// <summary>RFC 3161 section 2.4.2: a reqPolicy the TSA does not support is refused with unacceptedPolicy, and nothing is signed.</summary>
    [Fact]
    public async Task A_request_for_a_policy_the_tsa_does_not_issue_under_is_refused_with_unaccepted_policy()
    {
        var (response, world) = await AnswerAsync(PolicyRequest("1.2.3.4.1"), new SystemConfig());

        Assert.Equal(2, response.Status); // rejection
        Assert.Null(response.TimeStampToken);
        Assert.Equal(Org.BouncyCastle.Asn1.Cmp.PkiFailureInfo.UnacceptedPolicy, response.GetFailInfo().IntValue);
        Assert.Empty(await ReadAuditAsync(world));
    }

    [Fact]
    public async Task A_request_for_the_tsa_policy_is_answered_under_it()
    {
        var config = new SystemConfig();
        config.Tsa.PolicyOid = "1.3.6.1.4.1.99999.7.1";
        var request = PolicyRequest("1.3.6.1.4.1.99999.7.1");

        var (response, _) = await AnswerAsync(request, config);

        response.Validate(request);
        Assert.Equal(0, response.Status);
        Assert.Equal("1.3.6.1.4.1.99999.7.1", response.TimeStampToken.TimeStampInfo.Policy);
    }

    [Fact]
    public async Task A_policy_setting_that_is_not_an_object_identifier_refuses_every_request_without_signing()
    {
        var config = new SystemConfig();
        config.Tsa.PolicyOid = "our policy";

        var (response, world) = await AnswerAsync(PolicyRequest(null), config);

        Assert.Equal(2, response.Status);
        Assert.Null(response.TimeStampToken);
        Assert.Empty(await ReadAuditAsync(world));
    }

    private static Task<IReadOnlyList<ModularCA.Shared.Entities.SignerAuditEntity>> ReadAuditAsync(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        IReadOnlyList<ModularCA.Shared.Entities.SignerAuditEntity> rows = db.SignerAudit.OrderBy(r => r.At).ToList();
        return Task.FromResult(rows);
    }
}
