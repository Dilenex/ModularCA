using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The hash of the <c>Genesis</c> record in every <c>SegmentStart</c> and in the head, and how
/// far the signer's verification at start has got.
/// </summary>
public class JournalGenesisAndProgressTests
{
    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());

    private static string? GenesisOf(JournalHead head)
    {
        Assert.Equal(JournalHead.ExitOk, head.ExitCode);
        using var json = JsonDocument.Parse(head.Json!);
        return json.RootElement.GetProperty("genesisHash").GetString();
    }

    /// <summary>
    /// Writes a segment after the journal's last, as someone who holds the files can: a
    /// <c>SegmentStart</c> that chains to the last record and states what
    /// <paramref name="genesis"/> gives, then the records <paramref name="more"/> builds.
    /// </summary>
    internal static string AppendSegment(JournalSandbox sandbox, Func<byte[]?, byte[]?> genesis,
        Func<ulong, byte[], IEnumerable<(ushort Type, byte Flags, Func<ulong, byte[], byte[]> Payload)>>? more = null, bool open = false)
    {
        var verification = sandbox.Verify();
        var last = verification.Segments[^1];
        var head = verification.Head!;
        var start = new SegmentStartPayload(sandbox.InstanceId, head.Key!, new PreviousSegment(JournalFormat.SealedName(last.FirstSeq), last.WholeBytes, last.LastSeq, last.LastHash, last.EndsWithSeal),
            head.SystemPublicKey, genesis(head.GenesisHash));
        var seq = head.Seq + 1;
        var prev = head.Hash;
        using var bytes = new MemoryStream();
        void Add(ushort type, byte flags, byte[] payload)
        {
            var (record, hash) = JournalRecord.Encode(type, flags, seq, JournalFormat.ToMicros(DateTimeOffset.UtcNow), 0, head.Incarnation, prev, payload);
            bytes.Write(record);
            prev = hash;
            seq++;
        }
        Add(RecordType.SegmentStart, 0, start.Encode());
        foreach (var (type, flags, payload) in more?.Invoke(seq, prev) ?? [])
            Add(type, flags, payload(seq, prev));
        var name = open ? JournalFormat.OpenName(head.Seq + 1) : JournalFormat.SealedName(head.Seq + 1);
        File.WriteAllBytes(Path.Combine(sandbox.Directory, name), bytes.ToArray());
        return name;
    }

    [Fact]
    public async Task Every_segment_after_the_first_states_the_genesis_hash_and_the_short_head_gives_it()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 3; run++)
        {
            await using var writer = sandbox.Open(change: o => o.SegmentSealBytes = run == 1 ? 600 : JournalFormat.SegmentSealBytes);
            for (var i = 0; i < 4; i++)
                await AppendFact(writer, i);
            // While the newest segment is the journal's first, the head has the hash from the Genesis record itself.
            if (run == 0)
                Assert.Equal(Convert.ToHexStringLower(sandbox.Records().Single(r => r.Record.Type == RecordType.Genesis).Record.Hash), GenesisOf(JournalHead.Read(sandbox.Directory)));
        }
        var genesis = sandbox.Records().Single(r => r.Record.Type == RecordType.Genesis).Record.Hash;
        var starts = sandbox.Records().Where(r => r.Record.Type == RecordType.SegmentStart).Select(r => SegmentStartPayload.Decode(r.Record.Payload)).ToList();
        Assert.True(starts.Count >= 4, "the run should have several segments, some sealed by size and some by a stop");

        // The first SegmentStart precedes the Genesis and cannot name it; every later one does.
        Assert.Null(starts[0].GenesisHash);
        Assert.All(starts.Skip(1), s => Assert.Equal(genesis, s.GenesisHash));

        // The short head reads the newest segment alone and has it; so do the lists, and the verifier.
        var expected = Convert.ToHexStringLower(genesis);
        Assert.Equal(expected, GenesisOf(JournalHead.Read(sandbox.Directory)));
        Assert.Equal(expected, GenesisOf(JournalHead.Read(sandbox.Directory, includeSealed: true)));
        Assert.Equal(expected, GenesisOf(JournalHead.Read(sandbox.Directory, sealedFrom: sandbox.Verify().Segments[^1].FirstSeq)));
        var whole = sandbox.Verify();
        Assert.Null(whole.Fault);
        Assert.Equal(genesis, whole.Head!.GenesisHash);
        // Read from the newest segment only, as a pruned journal would be, it is still there.
        var newest = JournalReader.ListSegments(sandbox.Directory)[^1];
        Assert.Equal(genesis, JournalVerifier.Verify([newest], new JournalVerifyOptions { AllowMidChainStart = true }).Head!.GenesisHash);
    }

    [Fact]
    public async Task A_segment_that_states_another_genesis_than_the_journals_is_a_fault()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 2; run++)
        {
            await using var writer = sandbox.Open();
            await AppendFact(writer, run);
        }
        var name = AppendSegment(sandbox, _ => Enumerable.Repeat((byte)0x77, 32).ToArray());

        // With the first segment present, the real Genesis is what it is held to.
        var fault = sandbox.Verify().Fault!;
        Assert.Equal(name, fault.Segment);
        Assert.Contains("another Genesis record than the journal's", fault.Reason, StringComparison.Ordinal);
        // Without it, what the SegmentStart records before it stated.
        var tail = JournalReader.ListSegments(sandbox.Directory).Skip(1).ToList();
        Assert.Contains("another Genesis record", JournalVerifier.Verify(tail, new JournalVerifyOptions { AllowMidChainStart = true }).Fault!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_journal_written_before_segments_carried_it_gets_the_hash_from_its_first_segment()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var genesis = Convert.ToHexStringLower(sandbox.Records().Single(r => r.Record.Type == RecordType.Genesis).Record.Hash);
        // A second segment as the first version wrote them: its SegmentStart states no Genesis hash.
        AppendSegment(sandbox, _ => null, open: true);

        // The short head opens the newest segment only and prints null; with a sealed list it opens the first segment for it.
        Assert.Null(GenesisOf(JournalHead.Read(sandbox.Directory)));
        Assert.Equal(genesis, GenesisOf(JournalHead.Read(sandbox.Directory, includeSealed: true)));
        Assert.Equal(genesis, GenesisOf(JournalHead.Read(sandbox.Directory, sealedFrom: 1)));
        Assert.Null(sandbox.Verify().Fault);

        // The writer that goes on from it reads the first segment once and states the hash from then on.
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 2);
        var newest = SegmentStartPayload.Decode(sandbox.Records().Last(r => r.Record.Type == RecordType.SegmentStart).Record.Payload);
        Assert.Equal(genesis, Convert.ToHexStringLower(newest.GenesisHash!));
        Assert.Equal(genesis, GenesisOf(JournalHead.Read(sandbox.Directory)));
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task The_signer_says_how_far_its_verification_has_got_and_signs_meanwhile()
    {
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open(change: o => o.SegmentSealBytes = 8000))
            for (var i = 0; i < 200; i++)
                await AppendFact(writer, i);
        var onDisk = Directory.GetFiles(sandbox.Directory).Sum(f => new FileInfo(f).Length);

        await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
        // It can be asked at once, whatever the verification is doing.
        var early = (await signer.JournalInfoAsync())!;
        Assert.True(early.Available);
        Assert.True(early.VerifiedBytes == null || early.VerifiedBytes <= early.VerifyTotalBytes);

        // The merge's question waits for the verification; when it is answered the two figures have met.
        await signer.JournaledRevocationsAsync(world["ca-ec"].CaId!.Value, 0, 1);
        var done = (await signer.JournalInfoAsync())!;
        Assert.True(done.Verified);
        Assert.Equal(onDisk, done.VerifyTotalBytes);
        Assert.Equal(done.VerifyTotalBytes, done.VerifiedBytes);
    }

    [Fact]
    public async Task The_verifier_reports_its_progress_in_bytes_up_to_the_total()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open(change: o => o.SegmentSealBytes = 1 << 20))
            await Task.WhenAll(Enumerable.Range(0, 3000).Select(i =>
                writer.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Account, new string('x', 900), i).Encode())));
        var total = Directory.GetFiles(sandbox.Directory).Sum(f => new FileInfo(f).Length);
        var seen = new List<(long Done, long Total)>();
        var records = 0;

        var result = JournalVerifier.Verify(JournalReader.ListSegments(sandbox.Directory),
            new JournalVerifyOptions { Progress = (done, of) => seen.Add((done, of)), OnRecord = (_, _) => records++ });

        Assert.Null(result.Fault);
        Assert.Equal(result.Records, records);
        Assert.Equal((0L, total), seen[0]);
        Assert.Equal((total, total), seen[^1]);
        Assert.True(seen.Count > 4, "progress should be said more than once in three megabytes");
        Assert.Equal(seen.Select(s => s.Done).OrderBy(d => d), seen.Select(s => s.Done));
        Assert.All(seen, s => Assert.Equal(total, s.Total));
    }
}
