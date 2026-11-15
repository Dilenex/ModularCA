using Xunit;
using ModularCA.Journal;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The verifier, on journals damaged the ways a journal can be: a changed bit, a removed
/// record, two records swapped, a record rewritten with its hash, a tail rewritten whole, and a
/// key change nobody vouched for. And the checkpoint key block and each form of
/// <c>CheckpointKeyChanged</c>, on journals made by a signer whose keys differ from one start to
/// the next.
/// </summary>
public class JournalVerifierTests
{
    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());

    /// <summary>Three sealed segments of a few facts each.</summary>
    private static async Task<JournalSandbox> ThreeSegmentsAsync()
    {
        var sandbox = new JournalSandbox();
        for (var run = 0; run < 3; run++)
        {
            await using var writer = sandbox.Open();
            for (var i = 0; i < 4; i++)
                await AppendFact(writer, run * 10 + i);
        }
        Assert.Null(sandbox.Verify().Fault);
        return sandbox;
    }

    private static List<JournalRecord> RecordsOf(JournalSandbox sandbox, string name)
        => sandbox.Records().Where(r => r.Segment == name).Select(r => r.Record).ToList();

    private static byte[] Raw(JournalRecord r, byte[]? payload = null, byte[]? prev = null, ulong? seq = null, byte? flags = null, ushort? type = null)
        => JournalRecord.Encode(type ?? r.Type, flags ?? r.Flags, seq ?? r.Seq, r.At, r.Term, r.Incarnation, prev ?? r.Prev, payload ?? r.Payload).Bytes;

    private static void Rewrite(JournalSandbox sandbox, string name, IEnumerable<byte[]> records)
        => File.WriteAllBytes(Path.Combine(sandbox.Directory, name), records.SelectMany(b => b).ToArray());

    /// <summary>Appends a record to the newest segment, chained as a forger who holds a copy would chain it.</summary>
    private static JournalRecord Forge(JournalSandbox sandbox, ushort type, byte flags, byte[] payload, byte[]? incarnation = null, byte format = 1)
    {
        var head = sandbox.Verify().Head!;
        var (bytes, _) = JournalRecord.Encode(type, flags, head.Seq + 1, head.At + 1, 0, incarnation ?? head.Incarnation, head.Hash, payload);
        if (format != 1)
        {
            // Another format byte, with the hash made to match: whole, and not this reader's.
            bytes[8] = format;
            System.Security.Cryptography.SHA256.HashData(bytes.AsSpan(4, bytes.Length - 36)).CopyTo(bytes.AsSpan(bytes.Length - 32));
        }
        var newest = Path.Combine(sandbox.Directory, sandbox.Names()[^1]);
        using (var stream = new FileStream(newest, FileMode.Append, FileAccess.Write))
            stream.Write(bytes);
        JournalRecord.TryRead(bytes, out var record, out _);
        return record!;
    }

    [Fact]
    public async Task A_whole_journal_verifies_and_reports_what_it_checked()
    {
        using var sandbox = await ThreeSegmentsAsync();

        var verification = sandbox.Verify();

        Assert.Null(verification.Fault);
        Assert.True(verification.HasJournal);
        Assert.Equal(3, verification.Segments.Count);
        Assert.Equal(sandbox.Records().Count, verification.Records);
        Assert.Equal(sandbox.Records().Count(r => r.Record.Type == RecordType.Checkpoint), verification.Checkpoints);
        Assert.Empty(verification.Unvouched);
        Assert.Empty(verification.Notes);
        Assert.Equal(sandbox.Records()[^1].Record.Hash, verification.Head!.Hash);
        Assert.Equal(sandbox.InstanceId, verification.Head.InstanceId);
    }

    [Fact]
    public async Task A_changed_bit_in_a_segment_that_has_a_successor_is_found_at_its_record()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var name = sandbox.Names()[0];
        var records = RecordsOf(sandbox, name);
        var path = Path.Combine(sandbox.Directory, name);
        var bytes = File.ReadAllBytes(path);
        // A bit inside the fourth record's payload.
        var offset = records.Take(3).Sum(r => (int)r.EncodedLength) + 4 + 96 + 2;
        bytes[offset] ^= 0x10;
        File.WriteAllBytes(path, bytes);

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(name, fault.Segment);
        Assert.Equal(records[3].Seq, fault.Seq);
        Assert.Contains("bytes of whole records", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_changed_bit_in_the_newest_segment_ends_its_whole_records_there_and_is_said()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var name = sandbox.Names()[^1];
        var records = RecordsOf(sandbox, name);
        var path = Path.Combine(sandbox.Directory, name);
        var bytes = File.ReadAllBytes(path);
        bytes[records.Take(2).Sum(r => (int)r.EncodedLength) + 50] ^= 0x01;
        File.WriteAllBytes(path, bytes);

        var verification = sandbox.Verify();

        // Nothing follows the newest segment to say how long it was, so this reads as a torn
        // tail: the head goes back to the last whole record and the segment is reported torn.
        Assert.Null(verification.Fault);
        Assert.True(verification.Segments[^1].Torn);
        Assert.Equal(records[1].Seq, verification.Head!.Seq);
        Assert.Contains(verification.Notes, n => n.Contains(name, StringComparison.Ordinal) && n.Contains("after its last whole record", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_removed_record_is_found_where_it_was()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var name = sandbox.Names()[1];
        var records = RecordsOf(sandbox, name);
        Rewrite(sandbox, name, records.Where((_, i) => i != 3).Select(r => Raw(r)));

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(name, fault.Segment);
        Assert.Equal(records[3].Seq, fault.Seq);
        Assert.Contains("missing or out of place", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Two_records_swapped_are_found_at_the_first_of_them()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var name = sandbox.Names()[1];
        var records = RecordsOf(sandbox, name);
        (records[3], records[4]) = (records[4], records[3]);
        Rewrite(sandbox, name, records.Select(r => Raw(r)));

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(name, fault.Segment);
        Assert.Equal(records[4].Seq, fault.Seq);
    }

    [Fact]
    public async Task A_record_rewritten_with_a_hash_that_matches_breaks_the_chain_at_the_next()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var name = sandbox.Names()[1];
        var records = RecordsOf(sandbox, name);
        var target = records.FindIndex(r => r.Type == RecordType.Disabled);
        var forged = Raw(records[target], payload: new DisabledPayload(DisabledKind.Ca, "another", 1).Encode());
        // The same length, so the segment's size still matches what its successor states.
        Assert.NotEqual(Raw(records[target]), forged);
        Rewrite(sandbox, name, records.Select((r, i) => i == target ? forged : Raw(r)));

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(name, fault.Segment);
        Assert.True(fault.Seq == records[target + 1].Seq || fault.Seq == records[target].Seq + 1, fault.ToString());
    }

    [Fact]
    public async Task A_tail_rewritten_and_chained_again_fails_at_the_checkpoint_it_cannot_sign()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            for (var i = 0; i < 4; i++)
                await AppendFact(writer, i);
        var name = sandbox.Names()[0];
        var records = RecordsOf(sandbox, name);
        var target = records.FindIndex(r => r.Type == RecordType.Disabled);

        // Rewrite one fact and every record after it, each chained to the forged one before.
        var rewritten = new List<byte[]>();
        byte[]? prev = null;
        for (var i = 0; i < records.Count; i++)
        {
            var payload = i == target ? new DisabledPayload(DisabledKind.Space, "space-X", 0).Encode() : records[i].Payload;
            var (bytes, hash) = JournalRecord.Encode(records[i].Type, records[i].Flags, records[i].Seq, records[i].At, 0, records[i].Incarnation,
                i <= target ? records[i].Prev : prev!, payload);
            rewritten.Add(bytes);
            prev = hash;
        }
        Rewrite(sandbox, name, rewritten);

        var fault = sandbox.Verify().Fault!;

        var firstCheckpointAfter = records.Skip(target + 1).First(r => r.Type == RecordType.Checkpoint);
        Assert.Equal(firstCheckpointAfter.Seq, fault.Seq);
        Assert.Contains("signature does not verify", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_first_segment_is_a_fault_unless_a_partial_copy_was_asked_for()
    {
        using var sandbox = await ThreeSegmentsAsync();
        File.Delete(Path.Combine(sandbox.Directory, sandbox.Names()[0]));

        var fault = sandbox.Verify().Fault!;
        var partial = JournalVerifier.Verify(sandbox.Directory, new JournalVerifyOptions { AllowMidChainStart = true });

        Assert.Contains("earlier records are missing", fault.Reason, StringComparison.Ordinal);
        Assert.Null(partial.Fault);
        Assert.Equal(2, partial.Segments.Count);
    }

    [Fact]
    public async Task A_missing_middle_segment_is_found()
    {
        using var sandbox = await ThreeSegmentsAsync();
        File.Delete(Path.Combine(sandbox.Directory, sandbox.Names()[1]));

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(sandbox.Names()[1], fault.Segment);
    }

    [Fact]
    public async Task A_type_this_reader_does_not_know_is_checked_in_the_chain_and_skipped()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        Forge(sandbox, type: 999, flags: 0, new CborMapBuilder().Text(1, "from a later version").Encode());
        Forge(sandbox, type: RecordType.ReservedKeyOperations, flags: 0, [0xA0]);
        // Not even a map: the payload of an unknown type is not decoded at all.
        var last = Forge(sandbox, type: 1000, flags: 0, [0x01, 0x02, 0x03]);

        var verification = sandbox.Verify();

        Assert.Null(verification.Fault);
        Assert.Equal(last.Seq, verification.Head!.Seq);
    }

    [Fact]
    public async Task A_flag_bit_this_reader_does_not_know_is_ignored()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var record = Forge(sandbox, RecordType.Disabled, flags: 0xFE, new DisabledPayload(DisabledKind.Ca, "c", 1).Encode());

        Assert.Null(sandbox.Verify().Fault);
        Assert.False(record.NodeAsserted);
        Assert.Equal(0xFE, record.Flags);
    }

    [Fact]
    public async Task Another_format_stops_the_reading_and_is_said()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var record = Forge(sandbox, RecordType.Disabled, 0, new DisabledPayload(DisabledKind.Ca, "c", 1).Encode(), format: 2);

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(record.Seq, fault.Seq);
        Assert.Contains("format 2 was found", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_record_after_a_Seal_in_the_same_segment_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        var record = Forge(sandbox, RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Ca, "c", 1).Encode());

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(record.Seq, fault.Seq);
        Assert.Contains("follows the Seal", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_journal_that_begins_under_another_system_key_than_expected_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();

        var expected = JournalVerifier.Verify(sandbox.Directory, new JournalVerifyOptions { ExpectedSystemKey = JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey) });
        var other = JournalVerifier.Verify(sandbox.Directory, new JournalVerifyOptions { ExpectedSystemKey = new byte[32] });

        Assert.Null(expected.Fault);
        Assert.Contains("another system key", other.Fault!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_key_block_verifies_only_under_the_system_key_that_signed_it_for_this_instance_and_key()
    {
        var system = new TestJournalKey();
        var checkpoint = new TestJournalKey();
        var block = JournalSignatures.MakeKeyBlock("instance-1", checkpoint.PublicKey, system);

        Assert.True(JournalSignatures.VerifyKeyBlock(block, "instance-1", system.PublicKey));
        Assert.False(JournalSignatures.VerifyKeyBlock(block, "instance-2", system.PublicKey));
        Assert.False(JournalSignatures.VerifyKeyBlock(block, "instance-1", new TestJournalKey().PublicKey));
        Assert.False(JournalSignatures.VerifyKeyBlock(block with { Key = new TestJournalKey().PublicKey }, "instance-1", system.PublicKey));
        Assert.Equal(JournalSignatures.KeyHash(system.PublicKey), block.SystemKey);
        Assert.Equal("SHA256WITHECDSA", block.Algorithm);
        // A checkpoint signature is not a key block signature, though the bytes after the prefix could be made equal.
        var asCheckpoint = system.Sign(JournalSignatures.CheckpointMessage("instance-1", 1, checkpoint.PublicKey));
        Assert.False(JournalSignatures.VerifyKeyBlock(block with { SystemSignature = asCheckpoint }, "instance-1", system.PublicKey));
    }

    [Fact]
    public async Task A_key_block_the_system_key_did_not_sign_is_a_fault()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var name = sandbox.Names()[0];
        var records = RecordsOf(sandbox, name);
        var start = SegmentStartPayload.Decode(records[0].Payload);
        var forgedBlock = JournalSignatures.MakeKeyBlock(sandbox.InstanceId, start.CheckpointKey.Key, new TestJournalKey()) with { SystemKey = start.CheckpointKey.SystemKey };
        Rewrite(sandbox, name, new[] { Raw(records[0], payload: (start with { CheckpointKey = forgedBlock }).Encode()) });

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(1ul, fault.Seq);
        Assert.Contains("system signature does not verify", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_new_checkpoint_key_under_the_same_system_key_is_vouched_for_by_the_system_key()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var oldKey = sandbox.CheckpointKey;
        sandbox.CheckpointKey = new TestJournalKey();

        await using (var writer = sandbox.Open())
            await AppendFact(writer, 2);

        var changed = sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged);
        var payload = CheckpointKeyChangedPayload.Decode(changed.Record.Payload);
        Assert.Equal(sandbox.CheckpointKey.PublicKey, payload.NewKey.Key);
        Assert.Null(payload.OldKeySignature);
        Assert.Null(payload.OldSystemKeySignature);
        Assert.Null(payload.Explains);
        // The segment it is in began under the key that was in force.
        var segmentStart = sandbox.Records().First(r => r.Segment == changed.Segment);
        Assert.Equal(oldKey.PublicKey, SegmentStartPayload.Decode(segmentStart.Record.Payload).CheckpointKey.Key);
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        Assert.Equal(sandbox.CheckpointKey.PublicKey, verification.Head!.Key!.Key);
        // Checkpoints after the change are the new key's.
        var after = sandbox.Records().SkipWhile(r => r.Record.Seq <= changed.Record.Seq).First(r => r.Record.Type == RecordType.Checkpoint);
        Assert.Equal(JournalSignatures.KeyHash(sandbox.CheckpointKey.PublicKey), CheckpointPayload.Decode(after.Record.Payload).KeyHash);
    }

    [Fact]
    public async Task A_new_checkpoint_key_carries_the_old_keys_signature_when_the_signer_holds_the_old_key()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var oldKey = sandbox.CheckpointKey;
        sandbox.CheckpointKey = new TestJournalKey();

        await using (var writer = sandbox.Open(change: o => o.FindHeldKey = hash => hash.AsSpan().SequenceEqual(JournalSignatures.KeyHash(oldKey.PublicKey)) ? oldKey : null))
            await AppendFact(writer, 1);

        var payload = CheckpointKeyChangedPayload.Decode(sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record.Payload);
        Assert.True(JournalSignatures.Verify(oldKey.PublicKey, payload.OldKeyAlgorithm,
            JournalSignatures.CheckpointKeyChangedMessage(sandbox.InstanceId, sandbox.CheckpointKey.PublicKey), payload.OldKeySignature!));
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task An_old_key_signature_that_does_not_verify_is_a_fault()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var impostor = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();
        // The signer is handed a key that is not the old checkpoint key.
        await using (var writer = sandbox.Open(change: o => o.FindHeldKey = _ => impostor))
            await AppendFact(writer, 1);

        var fault = sandbox.Verify().Fault!;

        Assert.Contains("old checkpoint key's signature", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_new_system_key_signed_by_the_old_system_key_is_vouched_for()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var oldSystem = sandbox.SystemKey;
        sandbox.SystemKey = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();

        await using (var writer = sandbox.Open(change: o => o.FindHeldKey = hash => hash.AsSpan().SequenceEqual(JournalSignatures.KeyHash(oldSystem.PublicKey)) ? oldSystem : null))
            await AppendFact(writer, 1);

        var payload = CheckpointKeyChangedPayload.Decode(sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record.Payload);
        Assert.Equal(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey), payload.NewKey.SystemKey);
        Assert.Equal(sandbox.SystemKey.PublicKey, payload.SystemPublicKey);
        Assert.True(JournalSignatures.Verify(oldSystem.PublicKey, payload.OldSystemKeyAlgorithm,
            JournalSignatures.SystemKeyChangedMessage(sandbox.InstanceId, payload.NewKey.SystemKey), payload.OldSystemKeySignature!));
        Assert.Null(payload.Explains);
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        Assert.Equal(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey), verification.Head!.Key!.SystemKey);
    }

    [Fact]
    public async Task A_new_system_key_the_old_one_did_not_sign_names_the_changed_incarnation_and_is_reported_unvouched()
    {
        using var sandbox = new JournalSandbox { Incarnation = Enumerable.Repeat((byte)1, 32).ToArray() };
        await using (sandbox.Open()) { }
        var before = sandbox.Incarnation;
        sandbox.SystemKey = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();
        sandbox.Incarnation = Enumerable.Repeat((byte)2, 32).ToArray();

        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);

        var changed = sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record;
        var payload = CheckpointKeyChangedPayload.Decode(changed.Payload);
        Assert.Null(payload.OldSystemKeySignature);
        Assert.Equal(ExplanationKind.ChangedIncarnation, payload.Explains!.Kind);
        Assert.Equal(before, payload.Explains.OldIncarnation);
        Assert.Equal(sandbox.Incarnation, payload.Explains.NewIncarnation);
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        var unvouched = Assert.Single(verification.Unvouched);
        Assert.Equal(changed.Seq, unvouched.Seq);
        Assert.Equal(ExplanationKind.ChangedIncarnation, unvouched.Explains.Kind);
        Assert.Equal(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey), unvouched.NewSystemKey);
    }

    [Fact]
    public async Task A_new_system_key_with_the_same_incarnation_waits_for_the_restore_marker_and_names_that_restore()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        sandbox.SystemKey = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();

        await using (var writer = sandbox.Open(change: o => o.CheckpointInterval = TimeSpan.FromMilliseconds(100)))
        {
            // Records are taken while the change waits, and no checkpoint is signed with a key the chain does not know yet.
            await AppendFact(writer, 1);
            await Task.Delay(400);
            Assert.DoesNotContain(sandbox.Records().Where(r => r.Segment == sandbox.Names()[^1]), r => r.Record.Type == RecordType.Checkpoint);
            Assert.DoesNotContain(sandbox.Records(), r => r.Record.Type == RecordType.CheckpointKeyChanged);

            var marker = await writer.AppendAsync(RecordType.RestoreMarker, JournalFormat.FlagNodeAsserted,
                new RestoreMarkerPayload("modularca-backup-20261112-010000.enc", sandbox.InstanceId, 1_700_000_000_000_000, null).Encode());

            var changed = sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record;
            Assert.Equal(marker.Seq + 1, changed.Seq);
            var explains = CheckpointKeyChangedPayload.Decode(changed.Payload).Explains!;
            Assert.Equal(new ChangeExplanation(ExplanationKind.Restore, "modularca-backup-20261112-010000.enc", sandbox.InstanceId, 1_700_000_000_000_000), explains);
        }

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(ExplanationKind.Restore, Assert.Single(verification.Unvouched).Explains.Kind);
        Assert.Contains(sandbox.Records().Where(r => r.Segment == sandbox.Names()[^1]), r => r.Record.Type == RecordType.Checkpoint);
    }

    [Fact]
    public async Task A_new_system_key_that_nothing_explains_is_recorded_so_and_the_verifier_reports_it()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        sandbox.SystemKey = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();

        await using (var writer = sandbox.Open(change: o => o.UnexplainedKeyChangeWait = TimeSpan.FromMilliseconds(200)))
        {
            // The wait is counted from the start; the change is written once there is a segment to write it in.
            await AppendFact(writer, 1);
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (!sandbox.Records().Any(r => r.Record.Type == RecordType.CheckpointKeyChanged) && DateTime.UtcNow < deadline)
                await Task.Delay(50);
        }

        var changed = sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record;
        Assert.Null(CheckpointKeyChangedPayload.Decode(changed.Payload).Explains);
        var fault = sandbox.Verify().Fault!;
        Assert.Equal(changed.Seq, fault.Seq);
        Assert.Contains("says nothing that explains it", fault.Reason, StringComparison.Ordinal);
    }

    private static CheckpointKeyChangedPayload ForgedChange(JournalSandbox sandbox, ChangeExplanation? explains)
    {
        var system = new TestJournalKey();
        var block = JournalSignatures.MakeKeyBlock(sandbox.InstanceId, new TestJournalKey().PublicKey, system);
        return new CheckpointKeyChangedPayload(block, Explains: explains, SystemPublicKey: system.PublicKey);
    }

    [Fact]
    public async Task A_forged_key_change_with_no_explanation_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var forged = Forge(sandbox, RecordType.CheckpointKeyChanged, 0, ForgedChange(sandbox, null).Encode());

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(forged.Seq, fault.Seq);
        Assert.Contains("says nothing that explains it", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_forged_key_change_that_names_a_restore_with_no_marker_before_it_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var forged = Forge(sandbox, RecordType.CheckpointKeyChanged, 0,
            ForgedChange(sandbox, new ChangeExplanation(ExplanationKind.Restore, "a.enc", sandbox.InstanceId, 5)).Encode());

        var fault = sandbox.Verify().Fault!;

        Assert.Equal(forged.Seq, fault.Seq);
        Assert.Contains("not a RestoreMarker", fault.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_forged_key_change_that_names_another_restore_than_the_marker_before_it_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        Forge(sandbox, RecordType.RestoreMarker, 1, new RestoreMarkerPayload("real.enc", sandbox.InstanceId, 5, null).Encode());
        Forge(sandbox, RecordType.CheckpointKeyChanged, 0,
            ForgedChange(sandbox, new ChangeExplanation(ExplanationKind.Restore, "other.enc", sandbox.InstanceId, 5)).Encode());

        Assert.Contains("another restore", sandbox.Verify().Fault!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_forged_key_change_that_names_an_incarnation_the_records_do_not_carry_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var two = Enumerable.Repeat((byte)2, 32).ToArray();
        Forge(sandbox, RecordType.CheckpointKeyChanged, 0,
            ForgedChange(sandbox, new ChangeExplanation(ExplanationKind.ChangedIncarnation, OldIncarnation: Enumerable.Repeat((byte)9, 32).ToArray(), NewIncarnation: two)).Encode(),
            incarnation: two);

        Assert.Contains("do not carry the old one", sandbox.Verify().Fault!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_key_change_whose_new_block_its_own_system_key_did_not_sign_is_a_fault()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        var change = ForgedChange(sandbox, new ChangeExplanation(ExplanationKind.Restore, "a.enc", sandbox.InstanceId, 5));
        Forge(sandbox, RecordType.RestoreMarker, 1, new RestoreMarkerPayload("a.enc", sandbox.InstanceId, 5, null).Encode());
        Forge(sandbox, RecordType.CheckpointKeyChanged, 0, (change with { NewKey = change.NewKey with { Key = new TestJournalKey().PublicKey } }).Encode());

        Assert.Contains("new checkpoint key block's system signature does not verify", sandbox.Verify().Fault!.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// What the layout says of an unvouched change: a forger with a copy can append a marker and
    /// a change that chain. The verifier does not call that a fault; it reports the change for
    /// whoever verifies to match against a restore they know of.
    /// </summary>
    [Fact]
    public async Task A_marker_and_a_key_change_appended_by_someone_with_a_copy_chain_and_are_reported_for_matching()
    {
        using var sandbox = await ThreeSegmentsAsync();
        TrimSeal(sandbox);
        Forge(sandbox, RecordType.RestoreMarker, 1, new RestoreMarkerPayload("never-happened.enc", sandbox.InstanceId, 5, null).Encode());
        var forged = Forge(sandbox, RecordType.CheckpointKeyChanged, 0,
            ForgedChange(sandbox, new ChangeExplanation(ExplanationKind.Restore, "never-happened.enc", sandbox.InstanceId, 5)).Encode());

        var verification = sandbox.Verify();

        Assert.Null(verification.Fault);
        var unvouched = Assert.Single(verification.Unvouched);
        Assert.Equal(forged.Seq, unvouched.Seq);
        Assert.Equal("never-happened.enc", unvouched.Explains.Archive);
    }

    /// <summary>Removes the newest segment's Seal, so that a test can append to it as to a segment still being written.</summary>
    private static void TrimSeal(JournalSandbox sandbox)
    {
        var name = sandbox.Names()[^1];
        var records = RecordsOf(sandbox, name);
        Assert.Equal(RecordType.Seal, records[^1].Type);
        Rewrite(sandbox, name, records.Take(records.Count - 1).Select(r => Raw(r)));
    }
}
