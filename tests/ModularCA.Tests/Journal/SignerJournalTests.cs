using Xunit;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The signer with its journal: what it records of a certificate, a CRL and an SSH certificate,
/// that nothing is returned whose record could not be written, the two checks with the cases
/// they must let through, the facts the node asserts, and what survives a restart.
/// </summary>
public class SignerJournalTests
{
    /// <summary>A signer-test world, a journal directory of its own and a signer over both.</summary>
    private sealed class Bench : IAsyncDisposable
    {
        public SignerTestWorld World { get; } = SignerTestWorld.Create();
        public JournalSandbox Sandbox { get; } = new();
        public RecordingJournalFiles Files { get; } = new();
        public SignerJournal Journal { get; private set; }
        public ISigningService Signer { get; private set; }
        public bool Enforce { get; }

        public Bench(bool enforce = true)
        {
            Enforce = enforce;
            (Journal, Signer) = Open();
        }

        private (SignerJournal, ISigningService) Open()
        {
            var journal = new SignerJournal(() => Sandbox.Options(Files),
                new SignerJournalSettings(Sandbox.Home, Enforce, "0.0.0-test", new byte[32]), NullLogger.Instance);
            return (journal, TestSigner.Over(World.Keystore, World.DatabaseName, World.Persistence, journal));
        }

        /// <summary>Stops the signer's journal in order and starts a signer over the same directory, as a restart does.</summary>
        public async Task RestartAsync()
        {
            await Journal.DisposeAsync();
            (Journal, Signer) = Open();
        }

        public List<JournalRecord> Records(ushort type) => Sandbox.Records().Where(r => r.Record.Type == type).Select(r => r.Record).ToList();

        public async ValueTask DisposeAsync()
        {
            await Journal.DisposeAsync();
            Sandbox.Dispose();
        }
    }

    private static SigningContext Context(SignerTestKey ca, SigningPurpose purpose) => SigningContext.ForCa("journal-test", purpose, ca.CaId!.Value, ca.SpaceId);

    private static SignatureAlgorithm AlgorithmOf(SignerTestKey key) => SignatureAlgorithm.ForPublicKey(key.PublicKey);

    private static byte[] Spki(SignerTestKey key) => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.PublicKey).GetDerEncoded();

    /// <summary>Issues a leaf under <paramref name="ca"/> through the signer, as the certificate builder does.</summary>
    private static X509Certificate IssueLeaf(ISigningService signer, SignerTestKey ca, BigInteger serial, SigningContext? context = null,
        DateTime? notBefore = null, DateTime? notAfter = null)
    {
        var subject = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(serial);
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetSubjectDN(new X509Name($"CN=leaf-{serial}"));
        generator.SetNotBefore(notBefore ?? DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(notAfter ?? DateTime.UtcNow.AddDays(30));
        generator.SetPublicKey(subject.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        return generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, AlgorithmOf(ca), context ?? Context(ca, SigningPurpose.Certificate)));
    }

    /// <summary>Signs a CRL for <paramref name="ca"/> through the signer, as the CRL service does.</summary>
    private static X509Crl SignCrl(ISigningService signer, SignerTestKey ca, long number, (BigInteger Serial, int Reason)[] entries,
        long? deltaOfBase = null, DateTime? thisUpdate = null)
    {
        var at = thisUpdate ?? DateTime.UtcNow;
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetThisUpdate(at);
        generator.SetNextUpdate(at.AddHours(6));
        foreach (var (serial, reason) in entries)
            generator.AddCrlEntry(serial, at.AddMinutes(-1), reason);
        generator.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(number)));
        if (deltaOfBase is long baseNumber)
            generator.AddExtension(X509Extensions.DeltaCrlIndicator, true, new DerInteger(BigInteger.ValueOf(baseNumber)));
        return generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, AlgorithmOf(ca), Context(ca, SigningPurpose.Crl)));
    }

    private static BasicOcspResp SignOcsp(ISigningService signer, SignerTestKey responder, SignerTestKey ca, BigInteger serial, CertificateStatus? status)
    {
        var generator = new BasicOcspRespGenerator(new RespID(responder.Certificate.SubjectDN));
        generator.AddResponse(new CertificateID(CertificateID.DigestSha1, ca.Certificate, serial), status);
        return generator.Generate(new SigningServiceSignatureFactory(signer, responder.Ref, AlgorithmOf(responder),
            SigningContext.ForCa("journal-test", SigningPurpose.Ocsp, ca.CaId!.Value, ca.SpaceId)), null, DateTime.UtcNow);
    }

    /// <summary>The signer's refusal of an OCSP response; the response generator wraps what its signature factory throws.</summary>
    private static SigningRefusedException OcspRefused(Action sign)
    {
        var thrown = Assert.ThrowsAny<Exception>(sign);
        for (Exception? e = thrown; e != null; e = e.InnerException)
            if (e is SigningRefusedException refused)
                return refused;
        throw new Xunit.Sdk.XunitException($"Expected the signer's refusal, got {thrown.GetType().Name}: {thrown.Message}");
    }

    /// <summary>Rebuilds a certificate from a record's to-be-signed bytes and signature alone.</summary>
    private static byte[] Rebuild(CertificatePayload payload)
    {
        var tbs = TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(payload.Tbs));
        return new DerSequence(tbs, tbs.Signature, new DerBitString(payload.Signature)).GetDerEncoded();
    }

    [Fact]
    public async Task A_certificate_is_recorded_whole_and_rebuilds_byte_for_byte()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var origin = new IssuanceOrigin(
            Spent: [new IssuanceSpent(TokenKind.EnrollmentToken, "token-row-7", 2)],
            Answers: new IssuanceAnswers(AnswersKind.AcmeOrder, "order-42"),
            Replaces: new IssuanceReplaces([0x0a, 0x0b], new byte[32]),
            Belongs: new IssuanceBelongs("profile-1", "space-1", OwnerKind.User, "user-1", "template-1"),
            Protocol: "ACME", Requester: "user-1");

        var issued = IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(0x1234), Context(ca, SigningPurpose.Certificate) with { Issuance = origin });

        var record = Assert.Single(bench.Records(RecordType.Certificate));
        Assert.Equal(0, record.Flags);
        var payload = CertificatePayload.Decode(record.Payload);
        Assert.Equal(issued.GetEncoded(), Rebuild(payload));
        Assert.Equal(issued.GetTbsCertificate(), payload.Tbs);
        Assert.Equal(issued.GetSignature(), payload.Signature);
        Assert.Equal(new byte[] { 0x12, 0x34 }, payload.Serial);
        Assert.Equal(JournalFormat.ToMicros(issued.NotBefore.ToUniversalTime()), payload.NotBefore);
        Assert.Equal(JournalFormat.ToMicros(issued.NotAfter.ToUniversalTime()), payload.NotAfter);
        Assert.Equal(SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issued.GetPublicKey()).GetDerEncoded()), payload.SubjectKey);
        Assert.False(payload.IsCa);
        Assert.Equal(ca.CaId!.Value.ToString("D"), payload.Ca);
        Assert.Equal(SHA256.HashData(Spki(ca)), payload.CaKey);
        Assert.Equal(SHA256.HashData(ca.Certificate.GetEncoded()), payload.CaCert);
        Assert.Equal(new SigningContextInfo("Certificate", "ACME", "user-1"), payload.Context);
        Assert.Equal("0.0.0-test", payload.Version);
        Assert.Equal(new SpentToken(TokenKind.EnrollmentToken, "token-row-7", 2), Assert.Single(payload.Spent!));
        Assert.Equal(new Answers(AnswersKind.AcmeOrder, "order-42"), payload.Answers);
        Assert.Equal(new byte[] { 0x0a, 0x0b }, payload.Replaces!.Serial);
        Assert.Equal(new Belongs("profile-1", "space-1", OwnerKind.User, "user-1", "template-1"), payload.Belongs);
        Assert.Null(bench.Sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_certificate_with_nothing_known_about_it_carries_none_of_the_four_keys()
    {
        await using var bench = new Bench();

        IssueLeaf(bench.Signer, bench.World["ca-rsa"], BigInteger.ValueOf(77));

        var payload = CertificatePayload.Decode(Assert.Single(bench.Records(RecordType.Certificate)).Payload);
        Assert.Null(payload.Spent);
        Assert.Null(payload.Answers);
        Assert.Null(payload.Replaces);
        Assert.Null(payload.Belongs);
        var map = CborMap.Decode(Assert.Single(bench.Records(RecordType.Certificate)).Payload);
        Assert.DoesNotContain(JournalKeys.Spent, map.Keys);
        Assert.DoesNotContain(JournalKeys.Answers, map.Keys);
        Assert.DoesNotContain(JournalKeys.Replaces, map.Keys);
        Assert.DoesNotContain(JournalKeys.Belongs, map.Keys);
    }

    [Fact]
    public async Task What_is_not_a_certificate_or_a_crl_is_signed_and_not_recorded()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-rsa"];
        var before = bench.Sandbox.Records().Count;

        await bench.Signer.SignAsync(ca.Ref, AlgorithmOf(ca), TypedSigningData.ScepAttributes(), Context(ca, SigningPurpose.Scep));
        await bench.Signer.SignAsync(ca.Ref, AlgorithmOf(ca), TypedSigningData.CmpProtectedPart(AlgorithmOf(ca)), Context(ca, SigningPurpose.Cmp));
        SignOcsp(bench.Signer, ca, ca, BigInteger.ValueOf(5), CertificateStatus.Good);
        await Task.Delay(1300);

        // Only the checkpoint that an idle journal owes nobody: no record of these signatures.
        Assert.DoesNotContain(bench.Sandbox.Records().Skip(before), r => r.Record.Type != RecordType.Checkpoint);
    }

    [Fact]
    public async Task A_certificate_whose_record_cannot_be_flushed_is_not_returned()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(1));

        bench.Files.FailFlush = _ => new IOException("There is not enough space on the disk.");
        var refused = Assert.Throws<SigningRefusedException>(() => IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(2)));
        Assert.Equal(SigningRefusalReason.JournalUnavailable, refused.Reason);
        Assert.Contains("nothing is returned", refused.Message, StringComparison.Ordinal);
        // A CRL is refused the same way.
        var crl = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 1, []));
        Assert.Equal(SigningRefusalReason.JournalUnavailable, crl.Reason);

        // The refusal is in the signer's audit, as every decision is.
        using (var db = bench.World.OpenDb())
            Assert.Contains(db.SignerAudit, a => a.Outcome == SignerAuditEntity.RefusedOutcome && a.Reason!.Contains("journal", StringComparison.OrdinalIgnoreCase));

        // What does not go through the journal is still signed.
        await bench.Signer.SignAsync(ca.Ref, AlgorithmOf(ca), TypedSigningData.ScepAttributes(), Context(ca, SigningPurpose.Scep) with { Purpose = SigningPurpose.Scep });
        var info = await bench.Signer.JournalInfoAsync();
        Assert.False(info!.Available);

        // Space comes back: issuance does too, in a new segment.
        bench.Files.FailFlush = null;
        await Task.Delay(1100);
        IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(3));
        Assert.True((await bench.Signer.JournalInfoAsync())!.Available);
        Assert.Null(bench.Sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_signer_whose_journal_directory_cannot_be_made_issues_nothing_and_still_starts()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        // The home's name is taken by a file.
        File.WriteAllText(sandbox.Home, "not a directory");
        var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
        var ca = world["ca-ec"];

        var refused = Assert.Throws<SigningRefusedException>(() => IssueLeaf(signer, ca, BigInteger.ValueOf(1)));

        Assert.Equal(SigningRefusalReason.JournalUnavailable, refused.Reason);
        Assert.True((await signer.HealthAsync()).Unlocked);
        var info = await signer.JournalInfoAsync();
        Assert.False(info!.Available);
        Assert.NotNull(info.Fault);
        await signer.SignAsync(ca.Ref, AlgorithmOf(ca), TypedSigningData.ScepAttributes(), Context(ca, SigningPurpose.Scep));
    }

    [Fact]
    public async Task A_journal_of_another_instance_is_kept_set_aside_and_this_instance_begins_its_own()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        // The host ran another instance before an archive of this one was restored onto it.
        await using (var other = sandbox.Open())
            await other.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Space, "theirs", 1).Encode());
        var theirs = File.ReadAllBytes(Path.Combine(sandbox.Directory, sandbox.Names()[0]));
        var otherInstance = sandbox.InstanceId;
        sandbox.InstanceId = new string('c', 64);

        await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
        IssueLeaf(signer, world["ca-ec"], BigInteger.ValueOf(1));

        // Its journal is whole where it was moved to, byte for byte, and still verifies.
        var aside = Assert.Single(Directory.GetDirectories(sandbox.Home, "set-aside-instance-" + otherInstance[..16] + "-*"));
        Assert.Equal(theirs, File.ReadAllBytes(Assert.Single(Directory.GetFiles(aside))));
        Assert.Null(JournalVerifier.Verify(aside).Fault);
        // This instance's begins at sequence 1, with a Genesis of its own.
        var mine = sandbox.Verify();
        Assert.Null(mine.Fault);
        Assert.Equal(sandbox.InstanceId, mine.Head!.InstanceId);
        Assert.Equal(GenesisReason.FirstStart, GenesisPayload.Decode(sandbox.Records().Single(r => r.Record.Type == RecordType.Genesis).Record.Payload).Reason);
        Assert.Single(sandbox.Records(), r => r.Record.Type == RecordType.Certificate);
        Assert.True((await signer.JournalInfoAsync())!.Available);
    }

    private static Dictionary<string, long> Files(string directory)
        => Directory.Exists(directory)
            ? Directory.GetFiles(directory).ToDictionary(f => Path.GetFileName(f)!, f => new FileInfo(f).Length, StringComparer.Ordinal)
            : new Dictionary<string, long>(StringComparer.Ordinal);

    [Fact]
    public async Task A_signer_started_and_stopped_with_nothing_signed_leaves_the_journal_directory_as_it_was()
    {
        await using var bench = new Bench();
        IssueLeaf(bench.Signer, bench.World["ca-ec"], BigInteger.ValueOf(1));
        await bench.RestartAsync();
        var before = Files(bench.Sandbox.Directory);

        for (var i = 0; i < 4; i++)
        {
            // Each start can sign, says so, and has written nothing.
            var info = (await bench.Signer.JournalInfoAsync())!;
            Assert.True(info.Available);
            Assert.Null(info.Fault);
            Assert.Equal(before, Files(bench.Sandbox.Directory));
            await bench.RestartAsync();
        }

        Assert.Equal(before, Files(bench.Sandbox.Directory));
        Assert.DoesNotContain(bench.Files.Events, e => e.StartsWith("create ", StringComparison.Ordinal) && !e.Contains("00000000000000000001", StringComparison.Ordinal));
        // The next certificate begins the start's segment and is recorded.
        IssueLeaf(bench.Signer, bench.World["ca-ec"], BigInteger.ValueOf(2));
        Assert.Equal(before.Count + 1, Files(bench.Sandbox.Directory).Count);
        Assert.Equal(2, bench.Records(RecordType.Certificate).Count);
        Assert.Null(bench.Sandbox.Verify().Fault);
    }

    [Fact]
    public async Task In_an_empty_home_the_signer_makes_current_and_another_instances_journal_is_set_aside_inside_the_home()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        // The home is a freshly mounted, empty volume: it exists and holds nothing.
        var home = sandbox.Home;
        Directory.CreateDirectory(home);
        SignerJournal Open() => new(() => sandbox.Options(), new SignerJournalSettings(home, true, "t", new byte[32]), NullLogger.Instance);

        await using (var journal = Open())
        {
            // The signer made current/ in it, and the journal's first segment there.
            Assert.Equal(new[] { Path.Combine(home, "current") }, Directory.GetDirectories(home));
            Assert.Empty(Directory.GetFiles(home));
            Assert.Single(Directory.GetFiles(Path.Combine(home, "current")));
            IssueLeaf(TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal), world["ca-ec"], BigInteger.ValueOf(1));
            Assert.Equal((0, 0L), (journal.Info().SetAsideJournals, journal.Info().SetAsideBytes));
        }
        var theirs = sandbox.InstanceId;
        var theirFiles = Files(sandbox.Directory);
        var theirBytes = theirFiles.Values.Sum();

        // An archive of another instance is restored here: the journal in current/ is not this instance's.
        sandbox.InstanceId = new string('c', 64);
        await using (var journal = Open())
        {
            IssueLeaf(TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal), world["ca-ec"], BigInteger.ValueOf(2));
            var info = journal.Info();
            Assert.True(info.Available);
            // Counted in the home, with what it takes of the volume.
            Assert.Equal((1, theirBytes), (info.SetAsideJournals, info.SetAsideBytes));
        }

        // The home was not renamed: it holds current/ and the set-aside journal, and nothing lies beside it.
        Assert.Equal(new[] { home }, Directory.GetDirectories(sandbox.Root));
        var aside = Assert.Single(Directory.GetDirectories(home), d => Path.GetFileName(d) != "current");
        Assert.Matches(@"^set-aside-instance-a{16}-\d{8}-\d{6}-\d{3}$", Path.GetFileName(aside));
        Assert.StartsWith(JournalLayout.SetAsideInstancePrefix + JournalLayout.InstanceTag(theirs) + "-", Path.GetFileName(aside), StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(home));
        // Whole and unchanged.
        Assert.Equal(theirFiles, Files(aside));

        // The head command reads the set-aside directory as that instance's journal, and the home as this one's.
        var theirHead = JournalHead.Read(JournalLayout.ReadDirectory(aside), includeSealed: true);
        Assert.Equal(JournalHead.ExitOk, theirHead.ExitCode);
        using (var json = System.Text.Json.JsonDocument.Parse(theirHead.Json!))
        {
            Assert.Equal(theirs, json.RootElement.GetProperty("instanceId").GetString());
            Assert.Equal(theirFiles.Count, json.RootElement.GetProperty("sealed").GetArrayLength());
        }
        Assert.Null(JournalVerifier.Verify(aside).Fault);
        Assert.Equal(sandbox.Directory, JournalLayout.ReadDirectory(home));
        Assert.Equal(sandbox.InstanceId, JournalHead.Read(JournalLayout.ReadDirectory(home)).Verification!.Head!.InstanceId);
        Assert.Equal(sandbox.InstanceId, sandbox.Verify().Head!.InstanceId);

        // A journal a factory reset set aside is counted the same way; anything else in the home is not.
        var reset = Path.Combine(home, JournalLayout.SetAsideResetName(new DateTime(2026, 11, 13, 0, 0, 0, DateTimeKind.Utc)));
        Assert.Equal("set-aside-reset-20261113-000000-000", Path.GetFileName(reset));
        Directory.CreateDirectory(reset);
        File.WriteAllBytes(Path.Combine(reset, "00000000000000000001.mcaj"), new byte[1000]);
        Directory.CreateDirectory(Path.Combine(home, "other"));
        File.WriteAllBytes(Path.Combine(home, "other", "x"), new byte[77]);
        Assert.Equal((2, theirBytes + 1000), JournalLayout.SetAside(home));
    }

    [Fact]
    public async Task A_home_that_cannot_be_written_leaves_the_journal_unavailable_and_says_why()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        Directory.CreateDirectory(sandbox.Home);
        // A read-only home. Where the system has modes, the directory's own; elsewhere a file
        // lies where current/ would be made, which stops its creation the same way.
        if (OperatingSystem.IsWindows())
            File.WriteAllText(Path.Combine(sandbox.Home, "current"), "not a directory");
        else
            File.SetUnixFileMode(sandbox.Home, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
            var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);

            var refused = Assert.Throws<SigningRefusedException>(() => IssueLeaf(signer, world["ca-ec"], BigInteger.ValueOf(1)));

            Assert.Equal(SigningRefusalReason.JournalUnavailable, refused.Reason);
            var info = journal.Info();
            Assert.False(info.Available);
            Assert.Contains("could not be opened", info.Fault!, StringComparison.Ordinal);
            Assert.Contains(sandbox.Directory, info.Fault!, StringComparison.Ordinal);
            Assert.Equal(ModularCA.Core.Services.Journal.SignerJournalState.Unavailable,
                ModularCA.Core.Services.Journal.SignerJournalState.Assess(info, DateTime.UtcNow).Status);
        }
        finally
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(sandbox.Home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public async Task Another_instances_journal_that_cannot_be_renamed_is_left_as_it_is_and_the_signer_says_so()
    {
        // A directory holding an open file cannot be renamed on Windows; elsewhere such a rename succeeds.
        if (!OperatingSystem.IsWindows())
            return;
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        await using (var other = sandbox.Open())
            await other.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Space, "theirs", 1).Encode());
        var before = Files(sandbox.Directory);
        sandbox.InstanceId = new string('c', 64);

        using (new FileStream(Path.Combine(sandbox.Directory, sandbox.Names()[0]), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
            var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);

            var refused = Assert.Throws<SigningRefusedException>(() => IssueLeaf(signer, world["ca-ec"], BigInteger.ValueOf(1)));
            Assert.Equal(SigningRefusalReason.JournalUnavailable, refused.Reason);
            var info = journal.Info();
            Assert.False(info.Available);
            Assert.Contains("could not be set aside", info.Fault!, StringComparison.Ordinal);
            Assert.Contains("rename directories inside", info.Fault!, StringComparison.Ordinal);
        }
        // The other instance's journal is as it was, and nothing was begun in it.
        Assert.Equal(before, Files(sandbox.Directory));
        Assert.Equal(new[] { sandbox.Directory }, Directory.GetDirectories(sandbox.Home));
    }

    [Fact]
    public async Task A_refused_crl_stands_with_every_missing_serial_until_a_full_crl_is_signed()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var kept = (BigInteger.ValueOf(0xA1), CrlReason.KeyCompromise);
        var held = (BigInteger.ValueOf(0xC3), CrlReason.CertificateHold);
        // Seven revocations a database taken back would lose, with their reasons.
        var lost = Enumerable.Range(0, 7).Select(i => (BigInteger.ValueOf(0xB200 + i), i == 0 ? CrlReason.KeyCompromise : CrlReason.Superseded)).ToArray();
        var signedAt = DateTime.UtcNow;
        SignCrl(bench.Signer, ca, 5, [kept, held, .. lost], thisUpdate: signedAt);
        Assert.Empty((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);
        Assert.Null(await bench.Signer.JournalMissingRevocationsAsync(ca.CaId!.Value));

        var refused = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 6, [kept]));

        // The message stays short, counts them all, and says where the whole list is.
        Assert.Contains("leaves out 7 serial(s)", refused.Message, StringComparison.Ordinal);
        Assert.Contains(", ...", refused.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("b206", refused.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"GET /api/v1/admin/authorities/{ca.CaId.Value:D}/revoked-serials/missing-from-crl", refused.Message, StringComparison.Ordinal);

        // It stands in what the signer reports of its journal.
        var standing = Assert.Single((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);
        Assert.Equal(ca.CaId, standing.CaId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Spki(ca))), standing.CaKey);
        Assert.Equal(7, standing.MissingSerials);
        Assert.Equal(5, standing.JournaledCrlNumber);
        Assert.InRange((DateTime.UtcNow - standing.RefusedAtUtc).TotalSeconds, 0, 60);

        // Every serial, with the reason and the date the journaled CRL gives; the hold that was released is not among them.
        var missing = (await bench.Signer.JournalMissingRevocationsAsync(ca.CaId.Value))!;
        Assert.Equal(5, missing.JournaledCrlNumber);
        Assert.Equal(lost.Select(l => l.Item1.ToString(16).ToUpperInvariant()), missing.Serials.Select(s => s.Serial));
        Assert.Equal(CrlReason.KeyCompromise, missing.Serials[0].Reason);
        Assert.All(missing.Serials.Skip(1), s => Assert.Equal(CrlReason.Superseded, s.Reason));
        Assert.All(missing.Serials, s => Assert.InRange((s.RevokedAtUtc - signedAt.AddMinutes(-1)).Duration().TotalSeconds, 0, 2));
        Assert.Null(await bench.Signer.JournalMissingRevocationsAsync(bench.World["ca-rsa"].CaId!.Value));

        // Some are revoked again: the next refusal lists what is still missing.
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 6, [kept, .. lost.Take(4)]));
        Assert.Equal(3, Assert.Single((await bench.Signer.JournalInfoAsync())!.RefusedCrls!).MissingSerials);
        Assert.Equal(3, (await bench.Signer.JournalMissingRevocationsAsync(ca.CaId.Value))!.Serials.Count);
        // A delta CRL is signed meanwhile and does not end it.
        SignCrl(bench.Signer, ca, 6, [], deltaOfBase: 5);
        Assert.Single((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);

        // All of them are back: the CRL is signed and nothing stands.
        SignCrl(bench.Signer, ca, 7, [kept, .. lost]);
        Assert.Empty((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);
        Assert.Null(await bench.Signer.JournalMissingRevocationsAsync(ca.CaId.Value));
    }

    [Fact]
    public async Task With_the_checks_set_to_warn_a_crl_that_drops_a_serial_is_signed_and_no_refusal_stands()
    {
        await using var bench = new Bench(enforce: false);
        var ca = bench.World["ca-ec"];
        SignCrl(bench.Signer, ca, 1, [(BigInteger.ValueOf(0xA1), CrlReason.KeyCompromise)]);

        SignCrl(bench.Signer, ca, 2, []);

        Assert.Empty((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);
        Assert.Null(await bench.Signer.JournalMissingRevocationsAsync(ca.CaId!.Value));
    }

    [Fact]
    public async Task The_signer_reports_that_its_journal_waits_for_a_restore_marker_and_signs_meanwhile()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(1));
        Assert.Null((await bench.Signer.JournalInfoAsync())!.AwaitingRestoreMarkerUntilUtc);

        // Another system key, the old one not held, the same incarnation, and no restore marker yet.
        bench.Sandbox.SystemKey = new TestJournalKey();
        bench.Sandbox.CheckpointKey = new TestJournalKey();
        await bench.RestartAsync();

        var waiting = (await bench.Signer.JournalInfoAsync())!;
        Assert.True(waiting.Available);
        Assert.InRange((waiting.AwaitingRestoreMarkerUntilUtc!.Value - DateTime.UtcNow).TotalMinutes, 9.5, 10.1);
        // It signs and records during the wait.
        IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(2));
        Assert.Equal(2, bench.Records(RecordType.Certificate).Count);
        Assert.NotNull((await bench.Signer.JournalInfoAsync())!.AwaitingRestoreMarkerUntilUtc);

        // The node hands the marker over, and the wait is over.
        await bench.Signer.RecordFactAsync(RecordType.RestoreMarker,
            new RestoreMarkerPayload("modularca-backup-20261112-010000.enc", bench.Sandbox.InstanceId, 1_700_000_000_000_000, null).Encode(),
            new SigningContext("node", SigningPurpose.JournalFact, null, null));
        Assert.Null((await bench.Signer.JournalInfoAsync())!.AwaitingRestoreMarkerUntilUtc);
        await bench.Journal.DisposeAsync();
        var verification = bench.Sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(ExplanationKind.Restore, Assert.Single(verification.Unvouched).Explains.Kind);
    }

    [Fact]
    public async Task A_crl_carries_its_whole_list_when_the_set_changes_and_points_at_it_otherwise()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var one = (BigInteger.ValueOf(101), CrlReason.KeyCompromise);
        var two = (BigInteger.ValueOf(102), CrlReason.Superseded);

        // One time for all four: the entries carry it, and a revoked set is the same set only with the same dates.
        var at = DateTime.UtcNow;
        var first = SignCrl(bench.Signer, ca, 1, [one], thisUpdate: at);
        var second = SignCrl(bench.Signer, ca, 2, [one], thisUpdate: at);
        var third = SignCrl(bench.Signer, ca, 3, [two, one], thisUpdate: at);
        var fourth = SignCrl(bench.Signer, ca, 4, [one, two], thisUpdate: at);

        var records = bench.Records(RecordType.Crl);
        var payloads = records.Select(r => CrlPayload.Decode(r.Payload)).ToList();
        Assert.Equal(new ulong[] { 1, 2, 3, 4 }, payloads.Select(p => p.CrlNumber));
        // The first of a CA key carries the whole to-be-signed CRL.
        Assert.Equal(first.GetTbsCertList(), payloads[0].Tbs);
        Assert.Null(payloads[0].SameSetAs);
        Assert.Equal(first.GetSignature(), payloads[0].Signature);
        Assert.Equal(JournalFormat.ToMicros(first.ThisUpdate.ToUniversalTime()), payloads[0].ThisUpdate);
        Assert.Equal(JournalFormat.ToMicros(first.NextUpdate!.Value.ToUniversalTime()), payloads[0].NextUpdate);
        Assert.Equal(SHA256.HashData(Spki(ca)), payloads[0].CaKey);
        Assert.False(payloads[0].Delta);
        // The same revoked set: a pointer to the record that holds it, and the hash of this CRL's own bytes.
        Assert.Null(payloads[1].Tbs);
        Assert.Equal(records[0].Seq, payloads[1].SameSetAs);
        Assert.Equal(SHA256.HashData(second.GetTbsCertList()), payloads[1].TbsHash);
        Assert.Equal(second.GetSignature(), payloads[1].Signature);
        // A changed set: whole again.
        Assert.Equal(third.GetTbsCertList(), payloads[2].Tbs);
        // The same set in another order is the same set.
        Assert.Null(payloads[3].Tbs);
        Assert.Equal(records[2].Seq, payloads[3].SameSetAs);
        Assert.Equal(SHA256.HashData(fourth.GetTbsCertList()), payloads[3].TbsHash);
    }

    [Fact]
    public async Task The_first_crl_of_a_key_in_each_segment_carries_the_whole_list()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var entry = (BigInteger.ValueOf(101), CrlReason.KeyCompromise);
        // One time for all four, so the entry's revocation date, which is taken from it, is the same in each.
        var at = DateTime.UtcNow;
        SignCrl(bench.Signer, ca, 1, [entry], thisUpdate: at);
        SignCrl(bench.Signer, ca, 2, [entry], thisUpdate: at);

        await bench.RestartAsync();
        var afterRestart = SignCrl(bench.Signer, ca, 3, [entry], thisUpdate: at);
        SignCrl(bench.Signer, ca, 4, [entry], thisUpdate: at);

        var payloads = bench.Records(RecordType.Crl).Select(r => CrlPayload.Decode(r.Payload)).ToList();
        Assert.NotNull(payloads[0].Tbs);
        Assert.Null(payloads[1].Tbs);
        // A new segment: the set did not change, and the list is carried whole all the same.
        Assert.Equal(afterRestart.GetTbsCertList(), payloads[2].Tbs);
        Assert.Null(payloads[3].Tbs);
        Assert.Equal(bench.Records(RecordType.Crl)[2].Seq, payloads[3].SameSetAs);
        // A pointer and its record are in the same segment.
        var all = bench.Sandbox.Records();
        Assert.Equal(all.Single(r => r.Record.Seq == payloads[3].SameSetAs).Segment, all.Single(r => r.Record.Seq == bench.Records(RecordType.Crl)[3].Seq).Segment);
    }

    [Fact]
    public async Task A_crl_that_does_not_raise_the_number_is_refused_also_after_a_restart()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        SignCrl(bench.Signer, ca, 5, []);

        var same = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 5, []));
        var lower = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 4, []));
        await bench.RestartAsync();
        var afterRestart = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 5, []));

        Assert.All(new[] { same, lower, afterRestart }, r =>
        {
            Assert.Equal(SigningRefusalReason.CrlNotContinuous, r.Reason);
            Assert.Contains("carries number", r.Message, StringComparison.Ordinal);
            Assert.True(ModularCA.Core.Services.CrlService.IsNumberBehindJournal(r));
        });
        SignCrl(bench.Signer, ca, 6, []);
        Assert.Single(bench.Records(RecordType.Crl), r => CrlPayload.Decode(r.Payload).CrlNumber == 6);
        // Another CA key has its own numbers, and a first CRL has no predecessor.
        SignCrl(bench.Signer, bench.World["ca-rsa"], 1, []);
    }

    [Fact]
    public async Task Full_and_delta_crls_share_one_number_sequence()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        SignCrl(bench.Signer, ca, 10, []);

        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 10, [], deltaOfBase: 10));
        SignCrl(bench.Signer, ca, 11, [(BigInteger.ValueOf(7), CrlReason.KeyCompromise)], deltaOfBase: 10);
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 11, []));

        Assert.True(CrlPayload.Decode(bench.Records(RecordType.Crl)[1].Payload).Delta);
        Assert.NotNull(CrlPayload.Decode(bench.Records(RecordType.Crl)[1].Payload).Tbs);
    }

    [Fact]
    public async Task A_crl_that_drops_a_revoked_serial_is_refused()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var kept = (BigInteger.ValueOf(0xA1), CrlReason.KeyCompromise);
        var dropped = (BigInteger.ValueOf(0xB2), CrlReason.Superseded);
        SignCrl(bench.Signer, ca, 1, [kept, dropped]);

        var refused = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 2, [kept]));

        Assert.Equal(SigningRefusalReason.CrlNotContinuous, refused.Reason);
        Assert.Contains("b2", refused.Message, StringComparison.Ordinal);
        Assert.Contains("leaves out 1 serial", refused.Message, StringComparison.Ordinal);
        Assert.False(ModularCA.Core.Services.CrlService.IsNumberBehindJournal(refused));
        Assert.Single(bench.Records(RecordType.Crl));
        // The same after a restart: the newest journaled CRL is read back from the files.
        await bench.RestartAsync();
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 2, [kept]));
        // With the serial back, the CRL is signed.
        SignCrl(bench.Signer, ca, 2, [kept, dropped]);
    }

    [Fact]
    public async Task A_serial_that_was_on_hold_may_leave_the_crl()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var held = (BigInteger.ValueOf(0xC3), CrlReason.CertificateHold);
        var revoked = (BigInteger.ValueOf(0xD4), CrlReason.KeyCompromise);
        SignCrl(bench.Signer, ca, 1, [held, revoked]);

        // The hold is released: the serial is simply no longer listed.
        SignCrl(bench.Signer, ca, 2, [revoked]);
        // A hold made permanent stays listed under its new reason; that is no drop either.
        SignCrl(bench.Signer, ca, 3, [revoked, (BigInteger.ValueOf(0xE5), CrlReason.CertificateHold)]);
        SignCrl(bench.Signer, ca, 4, [revoked, (BigInteger.ValueOf(0xE5), CrlReason.KeyCompromise)]);

        Assert.Equal(4, bench.Records(RecordType.Crl).Count);
        // And from then on it cannot leave.
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 5, [revoked]));
    }

    [Fact]
    public async Task A_serial_whose_certificate_has_expired_may_leave_the_crl()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var expired = IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(0xF001), notBefore: DateTime.UtcNow.AddDays(-10), notAfter: DateTime.UtcNow.AddDays(-1));
        var stillValid = IssueLeaf(bench.Signer, ca, BigInteger.ValueOf(0xF002));
        // A row that claims to be expired and whose certificate this CA did not sign proves nothing.
        var forged = IssueLeaf(bench.Signer, bench.World["ca-rsa"], BigInteger.ValueOf(0xF003), notBefore: DateTime.UtcNow.AddDays(-10), notAfter: DateTime.UtcNow.AddDays(-1));
        using (var db = bench.World.OpenDb())
        {
            foreach (var certificate in new[] { expired, stillValid, forged })
                db.Certificates.Add(new CertificateEntity
                {
                    CertificateId = Guid.NewGuid(),
                    SerialNumber = CertificateUtil.FormatSerialNumber(certificate.SerialNumber),
                    SubjectDN = certificate.SubjectDN.ToString(), Issuer = ca.Certificate.SubjectDN.ToString(),
                    RawCertificate = certificate.GetEncoded(), Pem = CertificateUtil.ConvertDerToPem(certificate.GetEncoded(), "CERTIFICATE"),
                    NotBefore = certificate.NotBefore, NotAfter = certificate.NotAfter, Revoked = true,
                });
            db.SaveChanges();
        }
        var all = new[] { (expired.SerialNumber, CrlReason.Superseded), (stillValid.SerialNumber, CrlReason.Superseded), (forged.SerialNumber, CrlReason.Superseded) };
        SignCrl(bench.Signer, ca, 1, all);

        // The expired one leaves, as the node's own rule drops it.
        SignCrl(bench.Signer, ca, 2, [all[1], all[2]]);
        // One that is still valid does not.
        var valid = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 3, [all[2]]));
        Assert.Contains("f002", valid.Message, StringComparison.Ordinal);
        // Nor one whose row holds a certificate another CA signed.
        var other = Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 3, [all[1]]));
        Assert.Contains("f003", other.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_serial_revoked_without_a_certificate_leaves_the_crl_when_its_listing_has_run_out()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var past = BigInteger.ValueOf(0x7001);
        var running = BigInteger.ValueOf(0x7002);
        using (var db = bench.World.OpenDb())
        {
            db.SuppressSignerFacts = true;
            foreach (var (serial, until) in new[] { (past, DateTime.UtcNow.AddMinutes(-5)), (running, DateTime.UtcNow.AddDays(30)) })
                db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
                {
                    CaCertificateId = ca.Ref.CertificateId, CertificateAuthorityId = ca.CaId!.Value, IssuerDN = ca.Certificate.SubjectDN.ToString(),
                    SerialNumber = CertificateUtil.FormatSerialNumber(serial), RevocationDate = DateTime.UtcNow.AddDays(-400),
                    RevocationReason = "KeyCompromise", ListedUntil = until,
                });
            db.SaveChanges();
        }
        SignCrl(bench.Signer, ca, 1, [(past, CrlReason.KeyCompromise), (running, CrlReason.KeyCompromise)]);

        SignCrl(bench.Signer, ca, 2, [(running, CrlReason.KeyCompromise)]);
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 3, []));
    }

    [Fact]
    public async Task A_delta_crl_is_not_held_to_the_full_list()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var listed = (BigInteger.ValueOf(0x51), CrlReason.KeyCompromise);
        SignCrl(bench.Signer, ca, 1, [listed]);

        // A delta lists what changed since its base, which is not the full list.
        SignCrl(bench.Signer, ca, 2, [(BigInteger.ValueOf(0x52), CrlReason.Superseded)], deltaOfBase: 1);
        SignCrl(bench.Signer, ca, 3, [], deltaOfBase: 1);
        // The next full CRL is held to the last full one, not to a delta.
        Assert.Throws<SigningRefusedException>(() => SignCrl(bench.Signer, ca, 4, []));
        SignCrl(bench.Signer, ca, 4, [listed, (BigInteger.ValueOf(0x52), CrlReason.Superseded)]);
    }

    [Fact]
    public async Task A_crl_with_no_number_is_refused()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-ec"];
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetThisUpdate(DateTime.UtcNow);
        generator.SetNextUpdate(DateTime.UtcNow.AddHours(1));

        var refused = Assert.Throws<SigningRefusedException>(() =>
            generator.Generate(new SigningServiceSignatureFactory(bench.Signer, ca.Ref, AlgorithmOf(ca), Context(ca, SigningPurpose.Crl))));

        Assert.Equal(SigningRefusalReason.CrlNotContinuous, refused.Reason);
    }

    [Fact]
    public async Task Good_is_refused_for_a_serial_on_the_newest_journaled_crl()
    {
        await using var bench = new Bench();
        var ca = bench.World["ca-rsa"];
        var responder = bench.World["ocsp"];
        var revoked = BigInteger.ValueOf(0x9001);
        var held = BigInteger.ValueOf(0x9002);
        var good = BigInteger.ValueOf(0x9003);
        SignCrl(bench.Signer, ca, 1, [(revoked, CrlReason.KeyCompromise), (held, CrlReason.CertificateHold)]);

        // By the CA's own key and by its delegated responder alike.
        foreach (var key in new[] { ca, responder })
        {
            var refused = OcspRefused(() => SignOcsp(bench.Signer, key, ca, revoked, CertificateStatus.Good));
            Assert.Equal(SigningRefusalReason.RevokedOnJournaledCrl, refused.Reason);
            Assert.Contains("9001", refused.Message, StringComparison.Ordinal);
            // "revoked" for it, "good" for a serial that is not listed, and "good" for one whose hold may have been released, are signed.
            SignOcsp(bench.Signer, key, ca, revoked, new RevokedStatus(DateTime.UtcNow, CrlReason.KeyCompromise));
            SignOcsp(bench.Signer, key, ca, good, CertificateStatus.Good);
            SignOcsp(bench.Signer, key, ca, held, CertificateStatus.Good);
            SignOcsp(bench.Signer, key, ca, revoked, new UnknownStatus());
        }

        // After a restart the newest journaled CRL is still what "good" is held to.
        await bench.RestartAsync();
        OcspRefused(() => SignOcsp(bench.Signer, responder, ca, revoked, CertificateStatus.Good));
        // A serial revoked in a delta journaled after the full CRL counts too.
        SignCrl(bench.Signer, ca, 2, [(good, CrlReason.Superseded)], deltaOfBase: 1);
        OcspRefused(() => SignOcsp(bench.Signer, ca, ca, good, CertificateStatus.Good));
        // Another CA's key has no such CRL.
        SignOcsp(bench.Signer, bench.World["ca-ec"], bench.World["ca-ec"], revoked, CertificateStatus.Good);
    }

    [Fact]
    public async Task With_the_checks_set_to_warn_what_they_find_is_signed_and_recorded()
    {
        await using var bench = new Bench(enforce: false);
        var ca = bench.World["ca-ec"];
        var entry = (BigInteger.ValueOf(0x61), CrlReason.KeyCompromise);
        SignCrl(bench.Signer, ca, 5, [entry]);

        SignCrl(bench.Signer, ca, 6, []);
        SignCrl(bench.Signer, ca, 3, [entry]);
        SignOcsp(bench.Signer, ca, ca, entry.Item1, CertificateStatus.Good);

        Assert.Equal(new ulong[] { 5, 6, 3 }, bench.Records(RecordType.Crl).Select(r => CrlPayload.Decode(r.Payload).CrlNumber));
    }

    [Fact]
    public async Task An_ssh_certificate_is_recorded_whole()
    {
        await using var bench = new Bench();
        var (caId, key, caPublicKey) = bench.World.SeedBoundSshKey();
        var subject = ModularCA.Ssh.SshPublicKey.FromKeyParameter(KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var request = new SshCertificateRequest(key, subject.Blob, SshCertificateRequest.UserType, 4242, "journal-test", new[] { "alice" }, now, now + 3600);
        var context = SigningContext.ForCa("journal-test", SigningPurpose.SshCertificate, caId, spaceId: null) with
        {
            Issuance = new IssuanceOrigin(Answers: new IssuanceAnswers(AnswersKind.None, null), Belongs: new IssuanceBelongs(OwnerKind: OwnerKind.User, Owner: "user-9"), Protocol: "SSH", Requester: "user-9"),
        };

        var blob = await bench.Signer.SignSshCertificateAsync(request, context);

        var record = Assert.Single(bench.Records(RecordType.SshCertificate));
        var payload = SshCertificatePayload.Decode(record.Payload);
        Assert.Equal(blob, payload.Certificate);
        Assert.Equal(caId.ToString("D"), payload.Ca);
        Assert.Equal(SHA256.HashData(caPublicKey.Blob), payload.CaKey);
        Assert.Equal(new SigningContextInfo("SshCertificate", "SSH", "user-9"), payload.Context);
        Assert.Equal(new Answers(AnswersKind.None, null), payload.Answers);
        Assert.Equal(new Belongs(OwnerKind: OwnerKind.User, Owner: "user-9"), payload.Belongs);

        bench.Files.FailFlush = _ => new IOException("There is not enough space on the disk.");
        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.SignSshCertificateAsync(request with { Serial = 4243 }, context));
        Assert.Equal(SigningRefusalReason.JournalUnavailable, refused.Reason);
        bench.Files.FailFlush = null;
    }

    public static TheoryData<string, ushort, byte[]> EveryFact()
    {
        var key = Enumerable.Repeat((byte)3, 32).ToArray();
        return new TheoryData<string, ushort, byte[]>
        {
            { "a revocation", RecordType.Revocation, new RevocationPayload([1, 2], key, "ca", 1, 10, true, RevocationForm.Revoked).Encode() },
            { "a hold", RecordType.Revocation, new RevocationPayload([1, 2], key, "ca", 6, 10, true, RevocationForm.Hold).Encode() },
            { "a retirement", RecordType.Revocation, new RevocationPayload([1, 2], key, "ca", 0, 10, true, RevocationForm.Retired).Encode() },
            { "a serial with no certificate", RecordType.Revocation, new RevocationPayload([1, 2], key, "ca", 1, 10, false, RevocationForm.Revoked).Encode() },
            { "a released hold", RecordType.Unrevocation, new UnrevocationPayload([1, 2], key, "ca", 11).Encode() },
            { "an external account binding", RecordType.SpentWithoutCertificate, new SpentWithoutCertificatePayload(TokenKind.AcmeExternalAccountBinding, "eab-1", 12).Encode() },
            { "a claim token", RecordType.SpentWithoutCertificate, new SpentWithoutCertificatePayload(TokenKind.FirstAdministratorClaim, "claim-1", 12).Encode() },
            { "a restore", RecordType.RestoreMarker, new RestoreMarkerPayload("a.enc", "inst", 13, new HeadRef(4, key), 14).Encode() },
            { "a changed incarnation", RecordType.ContinuityEvent, new ContinuityEventPayload(key, new byte[32], 15).Encode() },
            { "a disabled CA", RecordType.Disabled, new DisabledPayload(DisabledKind.Ca, "ca-1", 16).Encode() },
            { "a disabled SSH CA key", RecordType.Disabled, new DisabledPayload(DisabledKind.SshCaKey, "k-1", 16).Encode() },
            { "a disabled space", RecordType.Disabled, new DisabledPayload(DisabledKind.Space, "s-1", 16).Encode() },
            { "a disabled account", RecordType.Disabled, new DisabledPayload(DisabledKind.Account, "u-1", 16).Encode() },
            { "a disabled sign-in credential", RecordType.Disabled, new DisabledPayload(DisabledKind.SignInCredential, "c-1", 16).Encode() },
            { "an SSH revocation list", RecordType.SshRevocationList, new SshRevocationListPayload("ssh-ca", key, [1, 2, 3]).Encode() },
        };
    }

    [Theory]
    [MemberData(nameof(EveryFact))]
    public async Task A_fact_the_node_asserts_is_recorded_with_flag_bit_0(string what, ushort type, byte[] payload)
    {
        await using var bench = new Bench();

        var seq = await bench.Signer.RecordFactAsync(type, payload, new SigningContext("node", SigningPurpose.JournalFact, null, null));

        var record = bench.Sandbox.Records().Single(r => r.Record.Seq == seq).Record;
        Assert.True(record.NodeAsserted, what);
        Assert.Equal(JournalFormat.FlagNodeAsserted, record.Flags);
        Assert.Equal(type, record.Type);
        Assert.Equal(payload, record.Payload);
        // The signer's own records never carry the flag.
        Assert.DoesNotContain(bench.Sandbox.Records(), r => r.Record.Seq != seq && r.Record.NodeAsserted);
    }

    [Fact]
    public async Task A_fact_is_refused_under_another_purpose_of_another_type_or_with_a_payload_that_is_not_its_own()
    {
        await using var bench = new Bench();
        var fact = new DisabledPayload(DisabledKind.Ca, "ca-1", 16).Encode();
        var context = new SigningContext("node", SigningPurpose.JournalFact, null, null);

        var purpose = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.Disabled, fact, context with { Purpose = SigningPurpose.Certificate }));
        // The node cannot write a record that says the signer signed something.
        var certificate = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.Certificate, fact, context));
        var checkpoint = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.Checkpoint, fact, context));
        var keyChange = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.CheckpointKeyChanged, fact, context));
        var malformed = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.Revocation, fact, context));
        var notCbor = await Assert.ThrowsAsync<SigningRefusedException>(() => bench.Signer.RecordFactAsync(RecordType.Disabled, [0xff, 0x00], context));

        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, purpose.Reason);
        Assert.All(new[] { certificate, checkpoint, keyChange, malformed, notCbor }, r => Assert.Equal(SigningRefusalReason.FactNotAccepted, r.Reason));
        Assert.DoesNotContain(bench.Sandbox.Records(), r => r.Record.NodeAsserted);

        // A signer that keeps no journal says so.
        var none = TestSigner.Over(bench.World.Keystore, bench.World.DatabaseName, bench.World.Persistence);
        var unsupported = await Assert.ThrowsAsync<SigningRefusedException>(() => none.RecordFactAsync(RecordType.Disabled, fact, context));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, unsupported.Reason);
        Assert.Null(await none.JournalInfoAsync());
    }

    [Fact]
    public async Task The_signer_reports_its_journals_head_and_room()
    {
        await using var bench = new Bench();
        IssueLeaf(bench.Signer, bench.World["ca-ec"], BigInteger.ValueOf(1));
        // Let the checkpoint that follows the record be written, so the head stands still while it is compared.
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while ((await bench.Signer.JournalInfoAsync())!.UncheckpointedRecords > 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);

        var info = (await bench.Signer.JournalInfoAsync())!;

        var last = bench.Sandbox.Records()[^1].Record;
        Assert.True(info.Available);
        Assert.Null(info.Fault);
        Assert.Equal(last.Seq, info.Seq);
        Assert.Equal(Convert.ToHexStringLower(last.Hash), info.Hash);
        Assert.Equal(new FileInfo(Path.Combine(bench.Sandbox.Directory, bench.Sandbox.Names()[0])).Length, info.SizeBytes);
        Assert.True(info.FreeBytes > 0);
        Assert.NotNull(info.LastCheckpointAtUtc);
        Assert.InRange((DateTime.UtcNow - info.LastCheckpointAtUtc!.Value).TotalSeconds, -1, 60);
    }

    [Fact]
    public async Task The_incarnation_in_a_record_is_the_hash_the_node_stores_for_its_continuity_check()
    {
        const string value = "  pod-7f3a/restore-2  ";
        var reading = ModularCA.Core.Services.Continuity.IncarnationReading.From("injected", value);

        Assert.Equal(reading.ValueHash, Convert.ToHexString(InstanceIncarnationHash.Of(value)));
        Assert.Equal(InstanceIncarnationHash.Of(value), InstanceIncarnationHash.FromStoredHex(reading.ValueHash));
        Assert.Equal(new byte[32], InstanceIncarnationHash.Of(null));
        Assert.Equal(new byte[32], InstanceIncarnationHash.Of("   "));
        Assert.Equal(ModularCA.Core.Services.Continuity.InjectedIncarnationSource.Variable, InstanceIncarnationHash.Variable);

        // And it is what every record of a signer started with that value carries.
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox { Incarnation = InstanceIncarnationHash.Of(value) };
        await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", sandbox.Incarnation), NullLogger.Instance);
        IssueLeaf(TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal), world["ca-ec"], BigInteger.ValueOf(1));
        Assert.All(sandbox.Records(), r => Assert.Equal(Convert.FromHexString(reading.ValueHash!), r.Record.Incarnation));
    }
}
