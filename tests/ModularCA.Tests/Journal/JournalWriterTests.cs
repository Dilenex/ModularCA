using Xunit;
using ModularCA.Journal;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The writer: what it writes when it opens, the start-up rule in each of its forms, sealing,
/// group commit, checkpoints, and what it does when the directory cannot take a record.
/// </summary>
public class JournalWriterTests
{
    private static byte[] Fact(int i) => new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode();

    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, Fact(i));

    [Fact]
    public async Task A_new_journal_begins_with_SegmentStart_Genesis_Start_and_a_Checkpoint()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
        {
            Assert.Equal(new[] { "00000000000000000001.open.mcaj" }, sandbox.Names());
            var opening = sandbox.Records();
            Assert.Equal(new[] { RecordType.SegmentStart, RecordType.Genesis, RecordType.Start, RecordType.Checkpoint }, opening.Select(r => r.Record.Type));
            Assert.Equal(new ulong[] { 1, 2, 3, 4 }, opening.Select(r => r.Record.Seq));
            Assert.Equal(new byte[32], opening[0].Record.Prev);

            var start = SegmentStartPayload.Decode(opening[0].Record.Payload);
            Assert.Equal(sandbox.InstanceId, start.InstanceId);
            Assert.Null(start.Previous);
            Assert.Equal(sandbox.CheckpointKey.PublicKey, start.CheckpointKey.Key);
            Assert.Equal(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey), start.CheckpointKey.SystemKey);
            Assert.True(JournalSignatures.VerifyKeyBlock(start.CheckpointKey, sandbox.InstanceId, sandbox.SystemKey.PublicKey));
            Assert.Equal(sandbox.SystemKey.PublicKey, start.SystemPublicKey);

            var genesis = GenesisPayload.Decode(opening[1].Record.Payload);
            Assert.Equal(GenesisReason.FirstStart, genesis.Reason);
            Assert.True(genesis.CheckpointKey.SameAs(start.CheckpointKey));
            Assert.Equal(new StartPayload("0.0.0-test", false), StartPayload.Decode(opening[2].Record.Payload));
            Assert.Equal(4ul, writer.Status.Seq);
        }

        // Stopped in order: a Seal, and one rename.
        Assert.Equal(new[] { "00000000000000000001.mcaj" }, sandbox.Names());
        Assert.Equal(RecordType.Seal, sandbox.Records()[^1].Record.Type);
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task Every_record_carries_term_zero_and_the_incarnation_hash()
    {
        using var sandbox = new JournalSandbox { Incarnation = Enumerable.Repeat((byte)0x5a, 32).ToArray() };
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);

        Assert.All(sandbox.Records(), r =>
        {
            Assert.Equal(0ul, r.Record.Term);
            Assert.Equal(sandbox.Incarnation, r.Record.Incarnation);
            Assert.Equal(1, r.Record.Format);
        });
    }

    [Fact]
    public async Task A_second_start_opens_a_new_segment_that_names_the_sealed_one()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var first = sandbox.Records();
        var firstBytes = File.ReadAllBytes(Path.Combine(sandbox.Directory, "00000000000000000001.mcaj"));

        await using (var writer = sandbox.Open())
        {
            // The start alone begins nothing; its first record does.
            Assert.Single(sandbox.Names());
            await AppendFact(writer, 2);
            var names = sandbox.Names();
            Assert.Equal(2, names.Length);
            var next = first[^1].Record.Seq + 1;
            Assert.Equal(JournalFormat.OpenName(next), names[1]);

            var opening = sandbox.Records().Where(r => r.Segment == names[1]).Take(4).ToList();
            Assert.Equal(new[] { RecordType.SegmentStart, RecordType.Start, RecordType.Checkpoint, RecordType.Disabled }, opening.Select(r => r.Record.Type));
            var previous = SegmentStartPayload.Decode(opening[0].Record.Payload).Previous!;
            Assert.Equal(new PreviousSegment("00000000000000000001.mcaj", firstBytes.Length, first[^1].Record.Seq, first[^1].Record.Hash, true), previous with { LastHash = first[^1].Record.Hash });
            Assert.Equal(first[^1].Record.Hash, previous.LastHash);
            Assert.False(StartPayload.Decode(opening[1].Record.Payload).PreviousUnsealed);
        }

        Assert.Equal(firstBytes, File.ReadAllBytes(Path.Combine(sandbox.Directory, "00000000000000000001.mcaj")));
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(2, verification.Segments.Count);
    }

    /// <summary>Leaves a journal as a signer that stopped without warning leaves it: an open segment with records and no Seal.</summary>
    private static async Task<(string OpenPath, byte[] Bytes, List<(string Segment, JournalRecord Record)> Records)> CrashAsync(JournalSandbox sandbox, int facts = 3)
    {
        var files = new RecordingJournalFiles();
        var writer = sandbox.Open(files);
        for (var i = 0; i < facts; i++)
            await AppendFact(writer, i);
        var path = Path.Combine(sandbox.Directory, sandbox.Names().Single(n => n.EndsWith(JournalFormat.OpenSuffix, StringComparison.Ordinal)));
        await writer.CrashAsync();
        var bytes = File.ReadAllBytes(path);
        return (path, bytes, sandbox.Records());
    }

    [Fact]
    public async Task An_open_segment_of_whole_records_and_no_Seal_is_renamed_as_it_is()
    {
        using var sandbox = new JournalSandbox();
        var (openPath, bytes, records) = await CrashAsync(sandbox);

        await using (var writer = sandbox.Open())
        {
            var sealedPath = Path.Combine(sandbox.Directory, "00000000000000000001.mcaj");
            // Until the start has something to record, the file is left under its open name.
            Assert.True(File.Exists(openPath));
            Assert.Equal(bytes, File.ReadAllBytes(openPath));
            await AppendFact(writer, 9);
            Assert.False(File.Exists(openPath));
            Assert.Equal(bytes, File.ReadAllBytes(sealedPath));

            var opening = sandbox.Records().Where(r => r.Segment != "00000000000000000001.mcaj").ToList();
            var previous = SegmentStartPayload.Decode(opening[0].Record.Payload).Previous!;
            Assert.Equal("00000000000000000001.mcaj", previous.Name);
            Assert.Equal(bytes.Length, previous.WholeBytes);
            Assert.Equal(records[^1].Record.Seq, previous.LastSeq);
            Assert.Equal(records[^1].Record.Hash, previous.LastHash);
            Assert.False(previous.Sealed);
            Assert.Equal(records[^1].Record.Seq + 1, opening[0].Record.Seq);
            Assert.Equal(records[^1].Record.Hash, opening[0].Record.Prev);
            Assert.True(StartPayload.Decode(opening.Single(r => r.Record.Type == RecordType.Start).Record.Payload).PreviousUnsealed);
        }
        Assert.Null(sandbox.Verify().Fault);
        Assert.Contains(sandbox.Log, line => line.Contains("was not sealed", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(40)]
    [InlineData(135)]
    public async Task An_open_segment_that_ends_in_a_torn_record_is_renamed_as_it_is_and_read_only_to_its_whole_records(int tornBytes)
    {
        using var sandbox = new JournalSandbox();
        var (openPath, bytes, records) = await CrashAsync(sandbox);
        var (torn, _) = JournalRecord.Encode(RecordType.Disabled, 1, records[^1].Record.Seq + 1, 0, 0, new byte[32], records[^1].Record.Hash, Fact(99));
        var withTail = bytes.Concat(torn.Take(tornBytes)).ToArray();
        using (var stream = new FileStream(openPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            stream.Write(torn, 0, tornBytes);

        await using (var writer = sandbox.Open())
        {
            await AppendFact(writer, 7);
            var sealedPath = Path.Combine(sandbox.Directory, "00000000000000000001.mcaj");
            // The torn bytes stay where they are: nothing is truncated.
            Assert.Equal(withTail, File.ReadAllBytes(sealedPath));
            var opening = sandbox.Records().Where(r => r.Segment != "00000000000000000001.mcaj").ToList();
            var previous = SegmentStartPayload.Decode(opening[0].Record.Payload).Previous!;
            Assert.Equal(bytes.Length, previous.WholeBytes);
            Assert.Equal(records[^1].Record.Seq, previous.LastSeq);
            Assert.False(previous.Sealed);
        }

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.True(verification.Segments[0].Torn);
        Assert.Equal(bytes.Length, verification.Segments[0].WholeBytes);
    }

    [Fact]
    public async Task A_segment_renamed_at_a_start_that_then_stopped_before_its_successor_gets_one_at_the_next()
    {
        using var sandbox = new JournalSandbox();
        var (openPath, bytes, records) = await CrashAsync(sandbox);
        // A start renamed the segment and stopped before it created the next: a sealed name, no Seal, nothing after.
        var sealedPath = Path.Combine(sandbox.Directory, "00000000000000000001.mcaj");
        File.Move(openPath, sealedPath);

        await using (var writer = sandbox.Open())
        {
            await AppendFact(writer, 9);
            Assert.Equal(bytes, File.ReadAllBytes(sealedPath));
            var names = sandbox.Names();
            Assert.Equal(new[] { "00000000000000000001.mcaj", JournalFormat.OpenName(records[^1].Record.Seq + 1) }, names);
            var previous = SegmentStartPayload.Decode(sandbox.Records().First(r => r.Segment == names[1]).Record.Payload).Previous!;
            Assert.Equal(bytes.Length, previous.WholeBytes);
            Assert.False(previous.Sealed);
        }
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_file_whose_first_record_never_reached_the_disk_is_no_part_of_the_chain()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var last = sandbox.Records()[^1].Record;
        // The next start created its segment and stopped before the SegmentStart was whole.
        var stub = Path.Combine(sandbox.Directory, JournalFormat.OpenName(last.Seq + 1));
        File.WriteAllBytes(stub, [0, 0, 0, 0x6b, 0x4d, 0x43]);

        await using (var writer = sandbox.Open())
        {
            await AppendFact(writer, 2);
            Assert.Equal(new[] { "00000000000000000001.mcaj", JournalFormat.OpenName(last.Seq + 1) }, sandbox.Names());
        }

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(2, verification.Segments.Count);
        Assert.Equal(last.Seq + 1, verification.Segments[1].FirstSeq);
    }

    [Fact]
    public async Task A_segment_is_sealed_at_its_size_by_a_Seal_and_one_rename_with_its_bytes_untouched()
    {
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using (var writer = sandbox.Open(files, o => o.SegmentSealBytes = 4096))
        {
            for (var i = 0; i < 60; i++)
                await AppendFact(writer, i);

            var sealedNames = sandbox.Names().Where(n => !n.EndsWith(JournalFormat.OpenSuffix, StringComparison.Ordinal)).ToList();
            Assert.True(sealedNames.Count >= 2, "the run should have sealed more than one segment");
            foreach (var name in sealedNames)
            {
                var path = Path.Combine(sandbox.Directory, name);
                // What is on disk under the sealed name is exactly what was appended under the open name.
                Assert.Equal(files.Appended(path), File.ReadAllBytes(path));
                var records = new List<JournalRecord>();
                JournalFormat.TryParseName(name, out var firstSeq, out _);
                var scan = JournalReader.Read(new SegmentFile(path, name, firstSeq, false), (r, _) => { records.Add(r); return true; });
                Assert.False(scan.Torn);
                Assert.Equal(RecordType.SegmentStart, records[0].Type);
                Assert.Equal(RecordType.Seal, records[^1].Type);
                // A segment passes the size by at most the record that crosses it, and its closing records.
                Assert.InRange(scan.WholeBytes, 4096, 4096 + 1024);
            }
            // One rename per sealed segment, from its open name to its sealed name, and no other.
            var renames = files.Events.Where(e => e.StartsWith("rename ", StringComparison.Ordinal)).ToList();
            Assert.Equal(sealedNames.Count, renames.Count);
            Assert.All(renames, r => Assert.Matches(@"^rename (\d{20})\.open\.mcaj -> \1\.mcaj$", r));
        }

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.All(verification.Segments, s => Assert.True(s.EndsWithSeal));
    }

    [Fact]
    public async Task A_segment_that_has_taken_records_is_sealed_at_its_age()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open(change: o => o.SegmentSealAge = TimeSpan.FromMilliseconds(300)))
        {
            await AppendFact(writer, 1);
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (sandbox.Names().Length < 2 && DateTime.UtcNow < deadline)
                await Task.Delay(50);
            Assert.Equal(2, sandbox.Names().Length);
            // The new segment has taken nothing, so it is not sealed for its age alone.
            await Task.Delay(900);
            Assert.Equal(2, sandbox.Names().Length);
        }
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task No_record_is_reported_written_before_the_flush_that_covers_it()
    {
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using var writer = sandbox.Open(files);
        var flushesAfterOpen = files.Flushes;

        files.FlushEntered.Reset();
        files.FlushGate.Reset();
        var first = AppendFact(writer, 1);
        Assert.True(files.FlushEntered.Wait(TimeSpan.FromSeconds(20)), "the writer should have reached its flush");

        // The bytes are appended and the flush has not returned: the record is not reported.
        Assert.Contains(files.Events, e => e.StartsWith("append ", StringComparison.Ordinal));
        Assert.False(first.IsCompleted);
        // More records arrive while the device is busy; none is reported either.
        var waiting = Enumerable.Range(2, 20).Select(i => AppendFact(writer, i)).ToList();
        await Task.Delay(200);
        Assert.False(first.IsCompleted);
        Assert.All(waiting, t => Assert.False(t.IsCompleted));

        files.FlushGate.Set();
        var done = await first;
        var rest = await Task.WhenAll(waiting);

        // Twenty records shared flushes: far fewer flushes than records.
        Assert.InRange(files.Flushes - flushesAfterOpen, 2, 6);
        // In the order they were offered, each chained to the one before.
        Assert.Equal(Enumerable.Range(0, 20).Select(i => rest[0].Seq + (ulong)i), rest.Select(r => r.Seq));
        Assert.True(rest[0].Seq > done.Seq);
        // Every append of a batch precedes the flush that completed it.
        var lastAppend = files.Events.FindLastIndex(e => e.StartsWith("append ", StringComparison.Ordinal));
        var lastFlush = files.Events.FindLastIndex(e => e.StartsWith("flush ", StringComparison.Ordinal));
        Assert.True(lastFlush > lastAppend);
    }

    [Fact]
    public async Task Records_offered_together_are_written_in_one_chain()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
        {
            var tasks = Enumerable.Range(0, 500).Select(i => Task.Run(() => AppendFact(writer, i))).ToList();
            var results = await Task.WhenAll(tasks);
            Assert.Equal(500, results.Select(r => r.Seq).Distinct().Count());
        }
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(500, sandbox.Records().Count(r => r.Record.Type == RecordType.Disabled));
    }

    [Fact]
    public async Task A_checkpoint_follows_activity_within_the_interval_and_signs_the_chain_before_it()
    {
        using var sandbox = new JournalSandbox();
        await using var writer = sandbox.Open(change: o => o.CheckpointInterval = TimeSpan.FromMilliseconds(200));
        var appended = await AppendFact(writer, 1);

        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (writer.Status.LastCheckpointSeq < appended.Seq && DateTime.UtcNow < deadline)
            await Task.Delay(25);

        var records = sandbox.Records();
        var checkpoint = records.Last(r => r.Record.Type == RecordType.Checkpoint).Record;
        Assert.Equal(appended.Seq + 1, checkpoint.Seq);
        Assert.Equal(appended.Hash, checkpoint.Prev);
        var payload = CheckpointPayload.Decode(checkpoint.Payload);
        Assert.Equal(JournalSignatures.KeyHash(sandbox.CheckpointKey.PublicKey), payload.KeyHash);
        Assert.True(JournalSignatures.Verify(sandbox.CheckpointKey.PublicKey, payload.Algorithm,
            JournalSignatures.CheckpointMessage(sandbox.InstanceId, checkpoint.Seq, checkpoint.Prev), payload.Signature));
        // The message is the prefix, the instance identifier with its length, the sequence and the hash before.
        var message = JournalSignatures.CheckpointMessage("ab", 0x0102, new byte[] { 9, 9 });
        Assert.Equal(System.Text.Encoding.ASCII.GetBytes("ModularCA.Journal.Checkpoint.v1\0").Concat(new byte[] { 0, 2, (byte)'a', (byte)'b', 0, 0, 0, 0, 0, 0, 1, 2, 9, 9 }), message);

        // With no activity there is no further checkpoint.
        var signatures = sandbox.CheckpointKey.Signatures;
        await Task.Delay(700);
        Assert.Equal(signatures, sandbox.CheckpointKey.Signatures);
        Assert.Equal(0, writer.Status.Uncheckpointed);
    }

    [Fact]
    public async Task A_checkpoint_is_written_every_so_many_records_without_waiting_for_the_interval()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open(change: o => { o.CheckpointRecords = 10; o.CheckpointInterval = TimeSpan.FromHours(1); }))
            await Task.WhenAll(Enumerable.Range(0, 95).Select(i => AppendFact(writer, i)));

        var types = sandbox.Records().Select(r => r.Record.Type).ToList();
        var run = 0;
        var longest = 0;
        foreach (var type in types)
        {
            run = type == RecordType.Checkpoint ? 0 : type == RecordType.Disabled ? run + 1 : run;
            longest = Math.Max(longest, run);
        }
        Assert.Equal(10, longest);
        Assert.True(types.Count(t => t == RecordType.Checkpoint) >= 10);
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(types.Count(t => t == RecordType.Checkpoint), verification.Checkpoints);
    }

    [Fact]
    public void A_directory_that_cannot_be_written_opens_no_journal()
    {
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles { FailCreate = _ => new UnauthorizedAccessException("Access to the path is denied.") };

        var ex = Assert.Throws<JournalUnavailableException>(() => sandbox.Open(files));

        Assert.Contains("could not be opened", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_record_whose_flush_fails_is_not_reported_written_and_the_next_goes_to_a_new_segment()
    {
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using (var writer = sandbox.Open(files))
        {
            var before = await AppendFact(writer, 1);

            files.FailFlush = _ => new IOException("There is not enough space on the disk.");
            var failed = await Assert.ThrowsAsync<JournalUnavailableException>(() => AppendFact(writer, 2));
            Assert.Contains("not enough space", failed.Message, StringComparison.Ordinal);
            Assert.False(writer.Status.Available);
            // While the volume is full every record is refused, without a new file for each.
            await Assert.ThrowsAsync<JournalUnavailableException>(() => AppendFact(writer, 3));
            var names = sandbox.Names();

            // Space comes back.
            files.FailFlush = null;
            await Task.Delay(1100);
            var after = await AppendFact(writer, 4);
            Assert.True(writer.Status.Available);
            Assert.True(after.Seq > before.Seq);
            // The segment the failure hit was left as it was and renamed; a new one took over.
            Assert.Equal(names.Length + 1, sandbox.Names().Length);
            Assert.Contains("00000000000000000001.mcaj", sandbox.Names());
        }

        Assert.Null(sandbox.Verify().Fault);
        files.AssertNothingShrank();
    }

    [Fact]
    public async Task A_write_that_lands_in_part_leaves_a_torn_tail_that_is_never_appended_to()
    {
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using (var writer = sandbox.Open(files))
        {
            await AppendFact(writer, 1);
            var good = new FileInfo(Path.Combine(sandbox.Directory, sandbox.Names()[0])).Length;

            files.FailAppend = (_, _) => new IOException("There is not enough space on the disk.");
            await Assert.ThrowsAsync<JournalUnavailableException>(() => AppendFact(writer, 2));
            files.FailAppend = null;
            await Task.Delay(1100);
            await AppendFact(writer, 3);

            var first = new FileInfo(Path.Combine(sandbox.Directory, "00000000000000000001.mcaj"));
            Assert.True(first.Length > good, "half of the failed batch should still be in the file");
        }

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.True(verification.Segments[0].Torn);
        Assert.DoesNotContain(sandbox.Records(), r => r.Record.Type == RecordType.Disabled && DisabledPayload.Decode(r.Record.Payload).Id == "space-2");
        Assert.Contains(sandbox.Records(), r => r.Record.Type == RecordType.Disabled && DisabledPayload.Decode(r.Record.Payload).Id == "space-3");
    }

    [Fact]
    public async Task A_payload_that_cannot_be_built_refuses_that_record_alone()
    {
        using var sandbox = new JournalSandbox();
        await using var writer = sandbox.Open();

        var refused = writer.AppendAsync(RecordType.Crl, 0, _ => throw new InvalidOperationException("refused by its own rule"));
        var accepted = AppendFact(writer, 1);

        await Assert.ThrowsAsync<InvalidOperationException>(() => refused);
        await accepted;
        Assert.True(writer.Status.Available);
        Assert.DoesNotContain(sandbox.Records(), r => r.Record.Type == RecordType.Crl);
    }

    [Fact]
    public async Task The_payload_is_built_with_the_records_own_place_in_the_chain()
    {
        using var sandbox = new JournalSandbox();
        await using var writer = sandbox.Open();
        AppendContext? seen = null;

        var appended = await writer.AppendAsync(RecordType.Disabled, 1, context => { seen = context; return Fact(1); });

        Assert.Equal(appended.Seq, seen!.Seq);
        Assert.Equal(1ul, seen.SegmentFirstSeq);
        var record = sandbox.Records().Single(r => r.Record.Seq == appended.Seq).Record;
        Assert.Equal(record.Prev, seen.Prev);
        Assert.Equal(record.At, seen.At);
    }

    [Fact]
    public async Task A_journal_of_another_instance_is_not_appended_to()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var before = sandbox.Names();

        sandbox.InstanceId = new string('b', 64);
        var ex = Assert.Throws<JournalUnavailableException>(() => sandbox.Open());

        Assert.Contains("belongs to instance", ex.Message, StringComparison.Ordinal);
        Assert.Equal(before, sandbox.Names());
    }

    /// <summary>
    /// A randomized run: appends of every size, stops in order, stops without warning, torn
    /// tails and failing flushes. After every step no file is shorter than it has ever been, and
    /// at the end the whole directory verifies.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Over_a_random_run_no_file_ever_gets_shorter(int seed)
    {
        using var sandbox = new JournalSandbox();
        var random = new Random(seed);
        var files = new RecordingJournalFiles();
        var lengths = new Dictionary<string, long>(StringComparer.Ordinal);
        JournalWriter? writer = null;

        void Check()
        {
            // By content identity: a file keeps its first sequence through its rename.
            foreach (var name in sandbox.Names())
            {
                var key = name[..20];
                // A segment may take its sealed name between the listing and the look.
                var info = new FileInfo(Path.Combine(sandbox.Directory, name));
                if (!info.Exists)
                    info = new FileInfo(Path.Combine(sandbox.Directory, key + JournalFormat.SealedSuffix));
                var length = info.Length;
                if (lengths.TryGetValue(key, out var known))
                    Assert.True(length >= known, $"segment {key} was {known} bytes and is now {length}");
                lengths[key] = length;
            }
            Assert.True(sandbox.Names().Length >= lengths.Count, "a segment file disappeared");
        }

        for (var step = 0; step < 120; step++)
        {
            writer ??= sandbox.Open(files, o => { o.SegmentSealBytes = 6000; o.CheckpointRecords = 7; });
            switch (random.Next(10))
            {
                case 0: // a stop in order
                    await writer.DisposeAsync();
                    writer = null;
                    break;
                case 1: // a stop without warning, sometimes in the middle of a record
                    await writer.CrashAsync();
                    // A start that recorded nothing left no open segment of its own; an older one may still lie there.
                    var open = sandbox.Names().LastOrDefault(n => n.EndsWith(JournalFormat.OpenSuffix, StringComparison.Ordinal));
                    if (open != null && random.Next(2) == 0)
                    {
                        using var stream = new FileStream(Path.Combine(sandbox.Directory, open), FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                        var junk = new byte[random.Next(1, 200)];
                        random.NextBytes(junk);
                        junk[0] = 0;
                        stream.Write(junk);
                    }
                    writer = null;
                    break;
                case 2: // the device refuses once
                    files.FailFlush = _ => new IOException("There is not enough space on the disk.");
                    await Assert.ThrowsAsync<JournalUnavailableException>(() => AppendFact(writer, step));
                    files.FailFlush = null;
                    await writer.DisposeAsync();
                    writer = null;
                    break;
                default:
                    var count = random.Next(1, 12);
                    await Task.WhenAll(Enumerable.Range(0, count).Select(i =>
                        writer.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Account, new string('x', random.Next(0, 900)), i).Encode())));
                    break;
            }
            Check();
        }
        if (writer != null)
            await writer.DisposeAsync();
        Check();

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.True(verification.Segments.Count > 3);
    }
}
