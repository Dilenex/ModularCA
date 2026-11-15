using Xunit;
using System.Text.Json;
using ModularCA.Journal;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The head, read from the files as <c>--role signer --journal-head</c> reads it: beside a
/// writer, on a copy nobody can write, with no open segment, with no journal and with a broken
/// one, and that reading creates and changes nothing.
/// </summary>
public class JournalHeadTests
{
    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());

    private static Dictionary<string, (long Length, DateTime Written)> Snapshot(string directory)
        => Directory.Exists(directory)
            ? Directory.GetFiles(directory, "*", SearchOption.AllDirectories).ToDictionary(f => f, f => (new FileInfo(f).Length, File.GetLastWriteTimeUtc(f)))
            : new();

    [Fact]
    public async Task Beside_a_signer_that_is_appending_it_reports_the_last_whole_record()
    {
        using var sandbox = new JournalSandbox { Incarnation = Enumerable.Repeat((byte)0x33, 32).ToArray() };
        await using var writer = sandbox.Open(change: o => o.CheckpointInterval = TimeSpan.FromMilliseconds(100));
        var appended = await AppendFact(writer, 1);
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (writer.Status.LastCheckpointSeq < appended.Seq && DateTime.UtcNow < deadline)
            await Task.Delay(25);
        var before = Snapshot(sandbox.Root);

        var head = JournalHead.Read(sandbox.Directory);

        Assert.Equal(JournalHead.ExitOk, head.ExitCode);
        Assert.DoesNotContain('\n', head.Json!);
        using var json = JsonDocument.Parse(head.Json!);
        var root = json.RootElement;
        Assert.Equal(new[] { "format", "instanceId", "genesisHash", "seq", "hash", "term", "incarnation", "open", "checkpoint", "checkpointKey" },
            root.EnumerateObject().Select(p => p.Name));
        // The hash of the Genesis record, which this segment, the journal's first, holds itself.
        Assert.Equal(Convert.ToHexStringLower(sandbox.Records().Single(r => r.Record.Type == RecordType.Genesis).Record.Hash), root.GetProperty("genesisHash").GetString());
        Assert.Equal(1, root.GetProperty("format").GetInt32());
        Assert.Equal(sandbox.InstanceId, root.GetProperty("instanceId").GetString());
        var last = sandbox.Records()[^1].Record;
        Assert.Equal(last.Seq, root.GetProperty("seq").GetUInt64());
        Assert.Equal(Convert.ToHexStringLower(last.Hash), root.GetProperty("hash").GetString());
        Assert.Equal(0ul, root.GetProperty("term").GetUInt64());
        Assert.Equal(new string('3', 64), root.GetProperty("incarnation").GetString());
        Assert.Equal("00000000000000000001.open.mcaj", root.GetProperty("open").GetProperty("segment").GetString());
        Assert.Equal(new FileInfo(Path.Combine(sandbox.Directory, "00000000000000000001.open.mcaj")).Length, root.GetProperty("open").GetProperty("wholeBytes").GetInt64());

        var checkpoint = root.GetProperty("checkpoint");
        Assert.Equal(new[] { "seq", "hash", "key", "algorithm", "signature" }, checkpoint.EnumerateObject().Select(p => p.Name));
        var record = sandbox.Records().Last(r => r.Record.Type == RecordType.Checkpoint).Record;
        Assert.Equal(record.Seq, checkpoint.GetProperty("seq").GetUInt64());
        // The hash the signature covers with seq: the record before the checkpoint.
        Assert.Equal(Convert.ToHexStringLower(record.Prev), checkpoint.GetProperty("hash").GetString());
        Assert.Equal(Convert.ToHexStringLower(JournalSignatures.KeyHash(sandbox.CheckpointKey.PublicKey)), checkpoint.GetProperty("key").GetString());
        Assert.Equal("SHA256WITHECDSA", checkpoint.GetProperty("algorithm").GetString());
        Assert.True(JournalSignatures.Verify(sandbox.CheckpointKey.PublicKey, "SHA256WITHECDSA",
            JournalSignatures.CheckpointMessage(sandbox.InstanceId, record.Seq, Convert.FromHexString(checkpoint.GetProperty("hash").GetString()!)),
            Convert.FromHexString(checkpoint.GetProperty("signature").GetString()!)));

        var key = root.GetProperty("checkpointKey");
        Assert.Equal(new[] { "key", "systemKey", "systemPublicKey", "systemSignature", "algorithm" }, key.EnumerateObject().Select(p => p.Name));
        // From the head alone, with the hash a holder has from hello: the key beside it is the
        // one the hash names, and it verifies the signature over the checkpoint key.
        var carried = Convert.FromHexString(key.GetProperty("systemPublicKey").GetString()!);
        Assert.Equal(key.GetProperty("systemKey").GetString(), Convert.ToHexStringLower(JournalSignatures.KeyHash(carried)));
        Assert.True(JournalSignatures.VerifyKeyBlock(
            new KeyBlock(Convert.FromHexString(key.GetProperty("key").GetString()!), Convert.FromHexString(key.GetProperty("systemKey").GetString()!),
                Convert.FromHexString(key.GetProperty("systemSignature").GetString()!), key.GetProperty("algorithm").GetString()!),
            root.GetProperty("instanceId").GetString()!, carried));
        Assert.Equal(Convert.ToHexStringLower(sandbox.CheckpointKey.PublicKey), key.GetProperty("key").GetString());
        Assert.Equal(Convert.ToHexStringLower(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey)), key.GetProperty("systemKey").GetString());
        var block = new KeyBlock(Convert.FromHexString(key.GetProperty("key").GetString()!), Convert.FromHexString(key.GetProperty("systemKey").GetString()!),
            Convert.FromHexString(key.GetProperty("systemSignature").GetString()!), key.GetProperty("algorithm").GetString()!);
        Assert.True(JournalSignatures.VerifyKeyBlock(block, sandbox.InstanceId, sandbox.SystemKey.PublicKey));

        // Reading created nothing and changed nothing.
        Assert.Equal(before, Snapshot(sandbox.Root));
    }

    [Fact]
    public async Task While_records_arrive_it_never_reports_a_torn_head()
    {
        using var sandbox = new JournalSandbox();
        await using var writer = sandbox.Open();
        using var stop = new CancellationTokenSource();
        var appending = Task.Run(async () =>
        {
            for (var i = 0; !stop.IsCancellationRequested; i++)
                await writer.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Account, new string('x', i % 700), i).Encode());
        });

        ulong lastSeen = 0;
        for (var i = 0; i < 60; i++)
        {
            var head = JournalHead.Read(sandbox.Directory);
            Assert.Equal(JournalHead.ExitOk, head.ExitCode);
            var seq = JsonDocument.Parse(head.Json!).RootElement.GetProperty("seq").GetUInt64();
            Assert.True(seq >= lastSeen, "the head went backwards");
            lastSeen = seq;
        }
        stop.Cancel();
        await appending;
        Assert.True(lastSeen > 4);
    }

    [Fact]
    public async Task On_a_copy_nobody_can_write_it_reads_the_same_head()
    {
        using var sandbox = new JournalSandbox();
        await using (var first = sandbox.Open())
            await AppendFact(first, 1);
        await using var writer = sandbox.Open();
        await AppendFact(writer, 2);
        var live = JournalHead.Read(sandbox.Directory, includeSealed: true);

        // A bare copy: the segment files and nothing else, every one read-only.
        var copy = Path.Combine(sandbox.Root, "copy");
        Directory.CreateDirectory(copy);
        foreach (var name in sandbox.Names())
        {
            using (var source = JournalReader.OpenRead(Path.Combine(sandbox.Directory, name)))
            using (var target = File.Create(Path.Combine(copy, name)))
                source.CopyTo(target);
            File.SetAttributes(Path.Combine(copy, name), FileAttributes.ReadOnly);
        }
        var before = Snapshot(copy);

        var head = JournalHead.Read(copy, includeSealed: true);

        Assert.Equal(JournalHead.ExitOk, head.ExitCode);
        Assert.Equal(live.Json, head.Json);
        Assert.Equal(before, Snapshot(copy));
        Assert.Equal(sandbox.Names(), Directory.GetFiles(copy).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal));
    }

    [Fact]
    public async Task With_no_open_segment_the_head_is_the_last_sealed_segments()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);

        var head = JournalHead.Read(sandbox.Directory);

        Assert.Equal(JournalHead.ExitOk, head.ExitCode);
        var root = JsonDocument.Parse(head.Json!).RootElement;
        Assert.Equal(JsonValueKind.Null, root.GetProperty("open").ValueKind);
        var last = sandbox.Records()[^1].Record;
        Assert.Equal(RecordType.Seal, last.Type);
        Assert.Equal(last.Seq, root.GetProperty("seq").GetUInt64());
        Assert.Equal(Convert.ToHexStringLower(last.Hash), root.GetProperty("hash").GetString());
    }

    [Fact]
    public async Task By_default_it_reads_the_newest_segment_only()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 3; run++)
        {
            await using var writer = sandbox.Open();
            await AppendFact(writer, run);
        }
        // An older segment that no longer verifies does not concern the default read.
        var oldest = Path.Combine(sandbox.Directory, sandbox.Names()[0]);
        var bytes = File.ReadAllBytes(oldest);
        bytes[40] ^= 0xFF;
        File.WriteAllBytes(oldest, bytes);

        var newestOnly = JournalHead.Read(sandbox.Directory);
        var all = JournalHead.Read(sandbox.Directory, includeSealed: true);

        Assert.Equal(JournalHead.ExitOk, newestOnly.ExitCode);
        Assert.Single(newestOnly.Verification!.Segments);
        Assert.DoesNotContain("\"sealed\"", newestOnly.Json!, StringComparison.Ordinal);
        Assert.Equal(JournalHead.ExitBrokenChain, all.ExitCode);
    }

    [Fact]
    public async Task With_sealed_it_lists_every_sealed_segment()
    {
        using var sandbox = new JournalSandbox();
        await using (var first = sandbox.Open())
            await AppendFact(first, 1);
        var crashed = sandbox.Open();
        await AppendFact(crashed, 2);
        await crashed.CrashAsync();
        var tornPath = Path.Combine(sandbox.Directory, sandbox.Names()[^1]);
        File.AppendAllBytes(tornPath, [0, 0, 0, 0x6b, 1, 2, 3]);
        await using var writer = sandbox.Open();
        await AppendFact(writer, 3);

        var head = JournalHead.Read(sandbox.Directory, includeSealed: true);

        Assert.Equal(JournalHead.ExitOk, head.ExitCode);
        var root = JsonDocument.Parse(head.Json!).RootElement;
        Assert.Equal("sealed", root.EnumerateObject().Last().Name);
        var segments = root.GetProperty("sealed").EnumerateArray().ToList();
        Assert.Equal(2, segments.Count);
        Assert.All(segments, s => Assert.Equal(new[] { "segment", "wholeBytes", "lastSeq", "lastHash", "torn" }, s.EnumerateObject().Select(p => p.Name)));
        Assert.Equal("00000000000000000001.mcaj", segments[0].GetProperty("segment").GetString());
        Assert.False(segments[0].GetProperty("torn").GetBoolean());
        Assert.True(segments[1].GetProperty("torn").GetBoolean());
        Assert.Equal(new FileInfo(Path.Combine(sandbox.Directory, segments[1].GetProperty("segment").GetString()!)).Length - 7,
            segments[1].GetProperty("wholeBytes").GetInt64());
        var records = sandbox.Records().Where(r => r.Segment == segments[1].GetProperty("segment").GetString()).ToList();
        Assert.Equal(records[^1].Record.Seq, segments[1].GetProperty("lastSeq").GetUInt64());
        Assert.Equal(Convert.ToHexStringLower(records[^1].Record.Hash), segments[1].GetProperty("lastHash").GetString());
        Assert.NotEqual(JsonValueKind.Null, root.GetProperty("open").ValueKind);
    }

    [Fact]
    public void A_directory_that_holds_no_journal_is_exit_3_and_is_not_created()
    {
        using var sandbox = new JournalSandbox();

        var missing = JournalHead.Read(sandbox.Directory);
        Assert.Equal(3, missing.ExitCode);
        Assert.Null(missing.Json);
        Assert.Contains("holds no journal", missing.Error!, StringComparison.Ordinal);
        Assert.False(Directory.Exists(sandbox.Directory));

        Directory.CreateDirectory(sandbox.Directory);
        File.WriteAllText(Path.Combine(sandbox.Directory, "notes.txt"), "not a segment");
        var empty = JournalHead.Read(sandbox.Directory, includeSealed: true);
        Assert.Equal(3, empty.ExitCode);
        Assert.Equal(new[] { "notes.txt" }, Directory.GetFiles(sandbox.Directory).Select(Path.GetFileName));

        // A file that holds no whole record is no journal either.
        File.WriteAllBytes(Path.Combine(sandbox.Directory, JournalFormat.OpenName(1)), [0, 0]);
        Assert.Equal(3, JournalHead.Read(sandbox.Directory).ExitCode);
    }

    [Fact]
    public async Task A_chain_that_does_not_hold_is_exit_4_with_the_reason()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            for (var i = 0; i < 3; i++)
                await AppendFact(writer, i);
        var name = sandbox.Names()[0];
        var records = sandbox.Records().Select(r => r.Record).ToList();
        // The fifth record removed, the rest left as they were.
        File.WriteAllBytes(Path.Combine(sandbox.Directory, name),
            records.Where((_, i) => i != 4).SelectMany(r => JournalRecord.Encode(r.Type, r.Flags, r.Seq, r.At, r.Term, r.Incarnation, r.Prev, r.Payload).Bytes).ToArray());

        var head = JournalHead.Read(sandbox.Directory);

        Assert.Equal(4, head.ExitCode);
        Assert.Null(head.Json);
        Assert.Contains(name, head.Error!, StringComparison.Ordinal);
        Assert.Contains($"sequence {records[4].Seq}", head.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_newest_checkpoint_that_does_not_verify_is_exit_4()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var name = sandbox.Names()[0];
        var records = sandbox.Records().Select(r => r.Record).ToList();
        var index = records.FindLastIndex(r => r.Type == RecordType.Checkpoint);
        var payload = CheckpointPayload.Decode(records[index].Payload);
        var forged = payload with { Signature = new TestJournalKey().Sign(JournalSignatures.CheckpointMessage(sandbox.InstanceId, records[index].Seq, records[index].Prev)) };
        // Rewritten and chained again from the checkpoint on.
        var bytes = new List<byte>();
        byte[] prev = records[index].Prev;
        for (var i = 0; i < records.Count; i++)
        {
            var r = records[i];
            var (encoded, hash) = JournalRecord.Encode(r.Type, r.Flags, r.Seq, r.At, r.Term, r.Incarnation, i >= index ? prev : r.Prev, i == index ? forged.Encode() : r.Payload);
            bytes.AddRange(encoded);
            prev = i >= index ? hash : r.Hash;
        }
        File.WriteAllBytes(Path.Combine(sandbox.Directory, name), bytes.ToArray());

        var head = JournalHead.Read(sandbox.Directory);

        Assert.Equal(4, head.ExitCode);
        Assert.Contains("signature does not verify", head.Error!, StringComparison.Ordinal);
    }
}
