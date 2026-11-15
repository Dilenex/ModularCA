using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// What the journal added to the signer's contract, over the wire: a node on the other side of
/// the mutually authenticated channel passes an issuance's origin with a signature, records a
/// fact, reads the journal's head and room, and is refused in the signer's own words.
/// </summary>
[Collection(RemoteSignerCollection.Name)]
public class SignerJournalWireTests
{
    private static X509Certificate IssueLeaf(ISigningService signer, SignerTestKey ca, long serial, IssuanceOrigin? origin)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetSubjectDN(new X509Name($"CN=wire-leaf-{serial}"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public);
        return generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            SigningContext.ForCa("wire-test", SigningPurpose.Certificate, ca.CaId!.Value, ca.SpaceId) with { Issuance = origin }));
    }

    [Fact]
    public async Task The_origin_of_an_issuance_a_fact_and_the_journals_head_cross_the_wire()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using var journal = new SignerJournal(() => sandbox.Options(files), new SignerJournalSettings(sandbox.Home, true, "0.0.0-test", new byte[32]), NullLogger.Instance);
        await using var host = await HostedSigner.StartAsync(TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal));
        using var node = host.Connect();
        var ca = world["ca-ec"];
        var caKey = Enumerable.Repeat((byte)9, 32).ToArray();
        var origin = new IssuanceOrigin(
            Spent: [new IssuanceSpent(TokenKind.CmpSharedSecret, "secret-row-3", 1)],
            Answers: new IssuanceAnswers(AnswersKind.EnrollmentTransaction, "aabbcc"),
            Replaces: new IssuanceReplaces([0x01, 0x02], caKey),
            Belongs: new IssuanceBelongs("profile", null, OwnerKind.User, "user-1", null),
            Protocol: "CMP", Requester: "user-1");

        // An issuance with everything the node knows, and one with nothing.
        var issued = IssueLeaf(node, ca, 0x51, origin);
        IssueLeaf(node, ca, 0x52, null);

        var records = sandbox.Records().Where(r => r.Record.Type == RecordType.Certificate).Select(r => CertificatePayload.Decode(r.Record.Payload)).ToList();
        Assert.Equal(issued.GetTbsCertificate(), records[0].Tbs);
        Assert.Equal(new SpentToken(TokenKind.CmpSharedSecret, "secret-row-3", 1), Assert.Single(records[0].Spent!));
        Assert.Equal(new Answers(AnswersKind.EnrollmentTransaction, "aabbcc"), records[0].Answers);
        Assert.Equal(new byte[] { 0x01, 0x02 }, records[0].Replaces!.Serial);
        Assert.Equal(caKey, records[0].Replaces!.CaKey);
        // A member the node did not know is absent on the far side too, not an empty string.
        Assert.Equal(new Belongs("profile", null, OwnerKind.User, "user-1", null), records[0].Belongs);
        Assert.Equal(new SigningContextInfo("Certificate", "CMP", "user-1"), records[0].Context);
        Assert.Null(records[1].Spent);
        Assert.Null(records[1].Answers);
        Assert.Null(records[1].Replaces);
        Assert.Null(records[1].Belongs);
        Assert.Equal(new SigningContextInfo("Certificate"), records[1].Context);

        // A fact.
        var fact = new DisabledPayload(DisabledKind.Ca, "ca-7", 99).Encode();
        var context = new SigningContext("node", SigningPurpose.JournalFact, null, null);
        var seq = await node.RecordFactAsync(RecordType.Disabled, fact, context);
        var recorded = sandbox.Records().Single(r => r.Record.Seq == seq).Record;
        Assert.True(recorded.NodeAsserted);
        Assert.Equal(fact, recorded.Payload);

        // Refusals arrive as the signer's own, with their reasons.
        var notAFact = await Assert.ThrowsAsync<SigningRefusedException>(() => node.RecordFactAsync(RecordType.Certificate, fact, context));
        Assert.Equal(SigningRefusalReason.FactNotAccepted, notAFact.Reason);
        var wrongPurpose = await Assert.ThrowsAsync<SigningRefusedException>(() => node.RecordFactAsync(RecordType.Disabled, fact, context with { Purpose = SigningPurpose.Crl }));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, wrongPurpose.Reason);

        // The head and the room.
        var info = (await node.JournalInfoAsync())!;
        var local = journal.Info();
        Assert.True(info.Available);
        Assert.Equal(local.Seq, info.Seq);
        Assert.Equal(local.Hash, info.Hash);
        Assert.Equal(local.SizeBytes, info.SizeBytes);
        Assert.NotNull(info.FreeBytes);
        Assert.NotNull(info.LastCheckpointAtUtc);
        Assert.Equal(DateTimeKind.Utc, info.LastCheckpointAtUtc!.Value.Kind);
        Assert.InRange((info.LastCheckpointAtUtc.Value - local.LastCheckpointAtUtc!.Value).Duration().TotalMilliseconds, 0, 1);

        // Fail closed reaches the node as a refusal it can name.
        files.FailFlush = _ => new IOException("There is not enough space on the disk.");
        var full = Assert.Throws<SigningRefusedException>(() => IssueLeaf(node, ca, 0x53, null));
        Assert.Equal(SigningRefusalReason.JournalUnavailable, full.Reason);
        var down = (await node.JournalInfoAsync())!;
        Assert.False(down.Available);
        Assert.Contains("not enough space", down.Fault!, StringComparison.Ordinal);
        files.FailFlush = null;
    }

    [Fact]
    public async Task A_refused_crl_its_serials_the_wait_and_the_space_levels_cross_the_wire()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        await using var journal = new SignerJournal(() => sandbox.Options(),
            new SignerJournalSettings(sandbox.Home, true, "0.0.0-test", new byte[32], LowSpaceBytes: 3L << 30, CriticalSpaceBytes: 0), NullLogger.Instance);
        await using var host = await HostedSigner.StartAsync(TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal));
        using var node = host.Connect();
        var ca = world["ca-ec"];

        void SignCrl(long number, params long[] serials)
        {
            var at = DateTime.UtcNow;
            var generator = new X509V2CrlGenerator();
            generator.SetIssuerDN(ca.Certificate.SubjectDN);
            generator.SetThisUpdate(at);
            generator.SetNextUpdate(at.AddHours(6));
            foreach (var serial in serials)
                generator.AddCrlEntry(BigInteger.ValueOf(serial), at.AddMinutes(-1), Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise);
            generator.AddExtension(X509Extensions.CrlNumber, false, new Org.BouncyCastle.Asn1.DerInteger(BigInteger.ValueOf(number)));
            generator.Generate(new SigningServiceSignatureFactory(node, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
                SigningContext.ForCa("wire-test", SigningPurpose.Crl, ca.CaId!.Value, ca.SpaceId)));
        }

        SignCrl(1, 0x71, 0x72, 0x73);
        var fine = (await node.JournalInfoAsync())!;
        Assert.Empty(fine.RefusedCrls!);
        Assert.Null(fine.AwaitingRestoreMarkerUntilUtc);
        // The signer's own levels, zero ("never") included, and what lies set aside beside the journal.
        Assert.Equal((3L << 30, 0L), (fine.LowSpaceBytes, fine.CriticalSpaceBytes));
        Assert.Equal((0, 0L), (fine.SetAsideJournals, fine.SetAsideBytes));
        Assert.Null(await node.JournalMissingRevocationsAsync(ca.CaId!.Value));

        var refused = Assert.Throws<SigningRefusedException>(() => SignCrl(2, 0x72));
        Assert.Equal(SigningRefusalReason.CrlNotContinuous, refused.Reason);

        var local = Assert.Single(journal.Info().RefusedCrls!);
        var standing = Assert.Single((await node.JournalInfoAsync())!.RefusedCrls!);
        Assert.Equal((local.CaId, local.CaKey, local.MissingSerials, local.JournaledCrlNumber), (standing.CaId, standing.CaKey, standing.MissingSerials, standing.JournaledCrlNumber));
        Assert.Equal(ca.CaId, standing.CaId);
        Assert.Equal(2, standing.MissingSerials);
        Assert.Equal(DateTimeKind.Utc, standing.RefusedAtUtc.Kind);
        Assert.InRange((standing.RefusedAtUtc - local.RefusedAtUtc).Duration().TotalMilliseconds, 0, 1);

        var missing = (await node.JournalMissingRevocationsAsync(ca.CaId.Value))!;
        Assert.Equal(ca.CaId.Value, missing.CaId);
        Assert.Equal(1, missing.JournaledCrlNumber);
        Assert.Equal(new[] { "71", "73" }, missing.Serials.Select(s => s.Serial));
        Assert.All(missing.Serials, s => { Assert.Equal(Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise, s.Reason); Assert.Equal(DateTimeKind.Utc, s.RevokedAtUtc.Kind); });
        Assert.Null(await node.JournalMissingRevocationsAsync(Guid.NewGuid()));

        // What the journal holds for the CA, for the merge: the journaled CRL's entries, a part at a time.
        var held = (await node.JournaledRevocationsAsync(ca.CaId.Value, 0, 2))!;
        Assert.True(held.Trusted);
        Assert.Null(held.NotTrustedReason);
        Assert.Equal((1L, 3), (held.CrlNumber, held.Total));
        Assert.True(held.CrlSeq > 0);
        Assert.Equal(new[] { "71", "72" }, held.Entries.Select(e => e.Serial));
        Assert.All(held.Entries, e =>
        {
            Assert.Equal(("crl", 1L, false, Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise), (e.Source, e.SourceNumber, e.Hold, e.Reason));
            Assert.Equal(held.CrlSeq, e.SourceSeq);
            Assert.Equal(DateTimeKind.Utc, e.RevokedAtUtc.Kind);
        });
        Assert.Equal(new[] { "73" }, (await node.JournaledRevocationsAsync(ca.CaId.Value, 2, 2))!.Entries.Select(e => e.Serial));
        Assert.Null(await node.JournaledRevocationsAsync(Guid.NewGuid(), 0, 10));
        Assert.True((await node.JournalInfoAsync())!.Verified);
    }

    [Fact]
    public async Task A_signer_that_keeps_no_journal_says_so_over_the_wire()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);
        using var node = host.Connect();

        Assert.Null(await node.JournalInfoAsync());
        Assert.Null(await node.JournalMissingRevocationsAsync(Guid.NewGuid()));
        Assert.Null(await node.JournaledRevocationsAsync(Guid.NewGuid(), 0, 10));
        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => node.RecordFactAsync(RecordType.Disabled,
            new DisabledPayload(DisabledKind.Ca, "ca-7", 99).Encode(), new SigningContext("node", SigningPurpose.JournalFact, null, null)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, refused.Reason);
    }
}
