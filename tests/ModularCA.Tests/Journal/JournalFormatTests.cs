using Xunit;
using System.Buffers.Binary;
using System.Security.Cryptography;
using ModularCA.Journal;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The journal's bytes: the framing against a vector worked out by hand (and by an independent
/// script), the chain, the deterministic payload encoding, where a record stops being whole,
/// and what a reader does with what it does not know.
/// </summary>
public class JournalFormatTests
{
    /// <summary>
    /// A Disabled record, type 37, flag bit 0, sequence 2, at 1,700,000,000,000,000 microseconds,
    /// term 0, incarnation 0x11.., prev 0x22.., payload {61: 5, 64: 1, 65: "x"}. The bytes were
    /// produced outside this code: the length is 96 + 11 = 0x6B, every integer is big-endian, and
    /// the hash is SHA-256 of the body.
    /// </summary>
    private const string VectorHex =
        "0000006b" +
        "4d43414a" + "01" + "0025" + "01" +
        "0000000000000002" +
        "00060a24181e4000" +
        "0000000000000000" +
        "1111111111111111111111111111111111111111111111111111111111111111" +
        "2222222222222222222222222222222222222222222222222222222222222222" +
        "a3183d0518400118416178" +
        "44e006789d3f86b579ecf42ec3ccd75992bc852ba5f4c4b24774e0d4040d4402";

    private static readonly byte[] Incarnation = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] Prev = Enumerable.Repeat((byte)0x22, 32).ToArray();

    [Fact]
    public void A_record_is_encoded_byte_for_byte_as_the_layout_says()
    {
        var payload = new DisabledPayload(DisabledKind.Ca, "x", 5).Encode();
        Assert.Equal("a3183d0518400118416178", Convert.ToHexStringLower(payload));

        var (bytes, hash) = JournalRecord.Encode(RecordType.Disabled, JournalFormat.FlagNodeAsserted, seq: 2,
            at: 1_700_000_000_000_000, term: 0, Incarnation, Prev, payload);

        Assert.Equal(VectorHex, Convert.ToHexStringLower(bytes));
        Assert.Equal(VectorHex[^64..], Convert.ToHexStringLower(hash));
    }

    [Fact]
    public void The_fixed_part_is_96_bytes_and_a_record_costs_132_before_its_payload()
    {
        Assert.Equal(96, JournalFormat.FixedPartLength);
        Assert.Equal(132, JournalFormat.RecordOverhead);

        var (bytes, _) = JournalRecord.Encode(RecordType.Seal, 0, 1, 0, 0, new byte[32], new byte[32], SealPayload.Encode());
        // The Seal payload is the empty map, one byte.
        Assert.Equal(133, bytes.Length);
        Assert.Equal(97u, BinaryPrimitives.ReadUInt32BigEndian(bytes));
        Assert.Equal(0xA0, bytes[4 + 96]);
        Assert.Equal(SHA256.HashData(bytes.AsSpan(4, 97)), bytes[^32..]);
    }

    [Fact]
    public void A_record_read_back_states_every_field()
    {
        var bytes = Convert.FromHexString(VectorHex);

        Assert.Equal(RecordRead.Whole, JournalRecord.TryRead(bytes, out var record, out var consumed));

        Assert.Equal(bytes.Length, consumed);
        Assert.Equal(1, record!.Format);
        Assert.Equal(RecordType.Disabled, record.Type);
        Assert.True(record.NodeAsserted);
        Assert.Equal(2ul, record.Seq);
        Assert.Equal(1_700_000_000_000_000, record.At);
        Assert.Equal(new DateTimeOffset(2023, 11, 14, 22, 13, 20, TimeSpan.Zero), JournalFormat.FromMicros(record.At));
        Assert.Equal(0ul, record.Term);
        Assert.Equal(Incarnation, record.Incarnation);
        Assert.Equal(Prev, record.Prev);
        var payload = DisabledPayload.Decode(record.Payload);
        Assert.Equal(new DisabledPayload(DisabledKind.Ca, "x", 5), payload);
    }

    [Fact]
    public void The_hash_of_a_record_is_the_prev_of_the_next()
    {
        var (first, firstHash) = JournalRecord.Encode(RecordType.Start, 0, 1, 10, 0, new byte[32], new byte[32], new StartPayload("v", false).Encode());
        var (second, _) = JournalRecord.Encode(RecordType.Seal, 0, 2, 11, 0, new byte[32], firstHash, SealPayload.Encode());

        JournalRecord.TryRead(first, out var a, out _);
        JournalRecord.TryRead(second, out var b, out _);

        Assert.Equal(new byte[32], a!.Prev);
        Assert.Equal(a.Hash, b!.Prev);
        Assert.Equal(SHA256.HashData(first.AsSpan(4, first.Length - 36)), b.Prev);
    }

    [Fact]
    public void A_record_is_torn_at_every_length_short_of_whole()
    {
        var whole = Convert.FromHexString(VectorHex);
        for (var length = 0; length < whole.Length; length++)
        {
            var read = JournalRecord.TryRead(whole.AsSpan(0, length), out var record, out var consumed);
            Assert.True(read == RecordRead.Torn, $"{length} of {whole.Length} bytes read as {read}");
            Assert.Null(record);
            Assert.Equal(0, consumed);
        }
        Assert.Equal(RecordRead.Whole, JournalRecord.TryRead(whole, out _, out _));
    }

    [Fact]
    public void A_record_with_any_one_bit_changed_is_not_whole()
    {
        var whole = Convert.FromHexString(VectorHex);
        // Every byte after the length: one changed bit breaks the hash. A changed length either
        // reaches past the bytes there are or frames other bytes, whose hash does not match.
        for (var i = 0; i < whole.Length; i++)
        {
            var changed = (byte[])whole.Clone();
            changed[i] ^= 0x04;
            Assert.True(JournalRecord.TryRead(changed, out _, out _) == RecordRead.Torn, $"a changed bit in byte {i} went unnoticed");
        }
    }

    [Fact]
    public void A_segment_cut_at_any_byte_of_its_last_record_ends_before_it()
    {
        using var sandbox = new JournalSandbox();
        Directory.CreateDirectory(sandbox.Directory);
        var prev = new byte[32];
        var records = new List<byte[]>();
        for (ulong seq = 1; seq <= 3; seq++)
        {
            var (bytes, hash) = JournalRecord.Encode(RecordType.Disabled, 1, seq, (long)seq, 0, new byte[32], prev, new DisabledPayload(DisabledKind.Space, "s" + seq, 7).Encode());
            records.Add(bytes);
            prev = hash;
        }
        var twoWhole = records[0].Length + records[1].Length;
        var path = Path.Combine(sandbox.Directory, JournalFormat.OpenName(1));
        var file = new SegmentFile(path, Path.GetFileName(path), 1, true);

        for (var cut = 0; cut <= records[2].Length; cut++)
        {
            File.WriteAllBytes(path, records[0].Concat(records[1]).Concat(records[2].Take(cut)).ToArray());

            var scan = JournalReader.Read(file);

            if (cut == records[2].Length)
            {
                Assert.Equal(3, scan.Records);
                Assert.False(scan.Torn);
                continue;
            }
            Assert.Equal(2, scan.Records);
            Assert.Equal(twoWhole, scan.WholeBytes);
            Assert.Equal(2ul, scan.Last!.Seq);
            Assert.Equal(cut > 0, scan.Torn);
        }
    }

    [Fact]
    public void A_payload_is_encoded_the_same_whatever_order_its_members_are_given_in()
    {
        var ascending = new CborMapBuilder().UInt(1, 7).Text(24, "a").Bytes(300, [1, 2]).Bool(70000, true).Encode();
        var descending = new CborMapBuilder().Bool(70000, true).Bytes(300, [1, 2]).Text(24, "a").UInt(1, 7).Encode();

        Assert.Equal(ascending, descending);
        // map(4) | 1: 7 | 24: "a" | 300: h'0102' | 70000: true, shortest integers, definite lengths.
        Assert.Equal("a40107181861611901" + "2c420102" + "1a00011170f5", Convert.ToHexStringLower(ascending));
    }

    [Fact]
    public void A_member_that_is_absent_is_left_out_and_not_written_as_null()
    {
        var withNothing = new CborMapBuilder().Text(1, null).Bytes(2, null).UInt(3, null).Int(4, null).Bool(5, null).Map(6, null).MapArray(7, null).Encode();

        Assert.Equal(new byte[] { 0xA0 }, withNothing);
    }

    [Fact]
    public void Negative_and_large_integers_take_their_shortest_form()
    {
        Assert.Equal("a1" + "01" + "20", Convert.ToHexStringLower(new CborMapBuilder().Int(1, -1).Encode()));
        Assert.Equal("a1" + "01" + "1b00060a24181e4000", Convert.ToHexStringLower(new CborMapBuilder().Int(1, 1_700_000_000_000_000).Encode()));
        Assert.Equal("a1" + "01" + "17", Convert.ToHexStringLower(new CborMapBuilder().UInt(1, 23).Encode()));
        Assert.Equal("a1" + "01" + "1818", Convert.ToHexStringLower(new CborMapBuilder().UInt(1, 24).Encode()));
    }

    [Fact]
    public void A_reader_ignores_a_payload_key_it_does_not_know()
    {
        // A Disabled payload with two members this build has no name for, one of them a nested map.
        var payload = new CborMapBuilder().UInt(JournalKeys.Kind, DisabledKind.Account).Text(JournalKeys.Id, "u1").Int(JournalKeys.Time, 9)
            .Text(9000, "from a later version").Map(9001, new CborMapBuilder().UInt(1, 2)).Encode();

        Assert.Equal(new DisabledPayload(DisabledKind.Account, "u1", 9), DisabledPayload.Decode(payload));
    }

    [Fact]
    public void A_payload_that_is_not_one_map_does_not_decode()
    {
        Assert.Throws<FormatException>(() => CborMap.Decode(new byte[] { 0x01 }));
        Assert.Throws<FormatException>(() => CborMap.Decode(new byte[] { 0xA0, 0xA0 }));
        Assert.Throws<FormatException>(() => CborMap.Decode(new byte[] { 0xA1, 0x01 }));
    }

    [Theory]
    [InlineData("00000000000000000001.open.mcaj", 1ul, true)]
    [InlineData("00000000000000017001.mcaj", 17001ul, false)]
    [InlineData("18446744073709551615.mcaj", ulong.MaxValue, false)]
    public void A_segment_name_is_twenty_digits_and_a_suffix(string name, ulong firstSeq, bool open)
    {
        Assert.True(JournalFormat.TryParseName(name, out var parsed, out var isOpen));
        Assert.Equal(firstSeq, parsed);
        Assert.Equal(open, isOpen);
        Assert.Equal(name, open ? JournalFormat.OpenName(firstSeq) : JournalFormat.SealedName(firstSeq));
    }

    [Theory]
    [InlineData("1.mcaj")]
    [InlineData("0000000000000000000a.mcaj")]
    [InlineData("00000000000000000001.mcaj.br")]
    [InlineData("00000000000000000001.open")]
    [InlineData("00000000000000000001.tmp.mcaj")]
    public void Any_other_name_is_not_a_segment(string name)
    {
        Assert.False(JournalFormat.TryParseName(name, out _, out _));
    }

    [Fact]
    public void The_type_numbers_are_the_layouts()
    {
        Assert.Equal(
            new ushort[] { 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 32, 33, 34, 35, 36, 37, 48, 49, 50, 51, 64, 80 },
            new[]
            {
                RecordType.Genesis, RecordType.SegmentStart, RecordType.Checkpoint, RecordType.Seal, RecordType.Pruned, RecordType.Start,
                RecordType.CheckpointKeyChanged, RecordType.Certificate, RecordType.Crl, RecordType.OcspSummary, RecordType.OtherSignature,
                RecordType.SshCertificate, RecordType.SshRevocationList, RecordType.Revocation, RecordType.Unrevocation,
                RecordType.SpentWithoutCertificate, RecordType.RestoreMarker, RecordType.ContinuityEvent, RecordType.Disabled,
                RecordType.ReservedKeyOperations, RecordType.ReservedSecretWrap, RecordType.ReservedCeremonies, RecordType.ReservedRegistry,
                RecordType.ReservedRefusals, RecordType.ReservedRestoreRecovered,
            });
    }

    /// <summary>
    /// The key numbers, pinned: a number that changed would make every journal already written
    /// mean something else. A new member takes a new number and a new line here.
    /// </summary>
    [Fact]
    public void The_payload_key_numbers_never_change()
    {
        var pinned = new Dictionary<string, ulong>
        {
            ["Ca"] = 1, ["CaKey"] = 2, ["CaCert"] = 3, ["Context"] = 4, ["Version"] = 5,
            ["InstanceId"] = 10, ["CheckpointKey"] = 11, ["GenesisReason"] = 12, ["Continues"] = 13, ["Previous"] = 14,
            ["KeyHash"] = 15, ["Algorithm"] = 16, ["Signature"] = 17, ["PreviousUnsealed"] = 18,
            ["OldKeySignature"] = 19, ["OldKeyAlgorithm"] = 20, ["OldSystemKeySignature"] = 21, ["OldSystemKeyAlgorithm"] = 22,
            ["Explains"] = 23, ["LastRemoved"] = 24, ["SystemPublicKey"] = 25, ["GenesisHash"] = 26,
            ["Tbs"] = 30, ["Serial"] = 32, ["NotBefore"] = 33, ["NotAfter"] = 34, ["SubjectKey"] = 35, ["IsCa"] = 36,
            ["Spent"] = 37, ["Answers"] = 38, ["Replaces"] = 39, ["Belongs"] = 40,
            ["CrlNumber"] = 42, ["ThisUpdate"] = 43, ["NextUpdate"] = 44, ["SameSetAs"] = 45, ["TbsHash"] = 46, ["Delta"] = 47,
            ["SshCertificate"] = 50, ["SshRevocationList"] = 51,
            ["RevocationReason"] = 60, ["Time"] = 61, ["Known"] = 62, ["Form"] = 63, ["Kind"] = 64, ["Id"] = 65,
            ["Archive"] = 66, ["ArchiveInstanceId"] = 67, ["ArchiveCreatedAt"] = 68, ["ArchiveHead"] = 69,
            ["OldIncarnation"] = 70, ["NewIncarnation"] = 71,
        };

        var actual = typeof(JournalKeys).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .ToDictionary(f => f.Name, f => (ulong)f.GetRawConstantValue()!);

        Assert.Equal(pinned.OrderBy(p => p.Value), actual.OrderBy(p => p.Value));
        Assert.Equal(actual.Count, actual.Values.Distinct().Count());
    }

    public static TheoryData<string, ushort, byte[]> EveryPayload()
    {
        var block = new KeyBlock([1, 2, 3], new byte[32], [4, 5], "SHA256WITHECDSA");
        var context = new SigningContextInfo("Certificate", "ACME", "user:42");
        var spent = new[] { new SpentToken(TokenKind.EnrollmentToken, "tok-1", 2) };
        var hash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        return new TheoryData<string, ushort, byte[]>
        {
            { "Genesis", RecordType.Genesis, new GenesisPayload("inst", block, GenesisReason.ContinuesAnother, new HeadRef(9, hash), "0.4.5", [9, 9]).Encode() },
            { "SegmentStart", RecordType.SegmentStart, new SegmentStartPayload("inst", block, new PreviousSegment("00000000000000000001.mcaj", 1234, 17, hash, true), [9]).Encode() },
            { "Checkpoint", RecordType.Checkpoint, new CheckpointPayload(hash, "ED25519", [7, 7, 7]).Encode() },
            { "Start", RecordType.Start, new StartPayload("0.4.5", true).Encode() },
            { "CheckpointKeyChanged", RecordType.CheckpointKeyChanged, new CheckpointKeyChangedPayload(block, [1], "ED25519", [2], "ML-DSA-65",
                new ChangeExplanation(ExplanationKind.Restore, "a.enc", "inst", 77), [3]).Encode() },
            { "Certificate", RecordType.Certificate, new CertificatePayload("ca-1", hash, hash, context, "0.4.5", [0x30, 0], [1, 2], [0x7f], 1, 2, hash, true,
                spent, new Answers(AnswersKind.AcmeOrder, "order-1"), new Replaces([5], hash), new Belongs("p", "s", OwnerKind.Badge, "b", "t")).Encode() },
            { "Crl", RecordType.Crl, new CrlPayload("ca-1", hash, hash, context, "0.4.5", 412, 5, 6, [1], null, 100, hash, true).Encode() },
            { "SshCertificate", RecordType.SshCertificate, new SshCertificatePayload("ssh-1", hash, context, "0.4.5", [1, 2, 3], spent,
                new Answers(AnswersKind.None, null), new Replaces([1], hash), new Belongs(Owner: "u", OwnerKind: OwnerKind.User)).Encode() },
            { "SshRevocationList", RecordType.SshRevocationList, new SshRevocationListPayload("ssh-1", hash, [9, 8]).Encode() },
            { "Revocation", RecordType.Revocation, new RevocationPayload([1, 2], hash, "ca-1", 6, 99, false, RevocationForm.Hold).Encode() },
            { "Unrevocation", RecordType.Unrevocation, new UnrevocationPayload([1, 2], hash, "ca-1", 100).Encode() },
            { "SpentWithoutCertificate", RecordType.SpentWithoutCertificate, new SpentWithoutCertificatePayload(TokenKind.AcmeExternalAccountBinding, "kid", 5).Encode() },
            { "RestoreMarker", RecordType.RestoreMarker, new RestoreMarkerPayload("a.enc", "inst", 5, new HeadRef(3, hash), 6).Encode() },
            { "ContinuityEvent", RecordType.ContinuityEvent, new ContinuityEventPayload(hash, new byte[32], 7).Encode() },
            { "Disabled", RecordType.Disabled, new DisabledPayload(DisabledKind.SignInCredential, "cred", 8).Encode() },
        };
    }

    [Theory]
    [MemberData(nameof(EveryPayload))]
    public void Every_payload_decodes_and_encodes_to_the_same_bytes(string name, ushort type, byte[] encoded)
    {
        byte[] again = type switch
        {
            RecordType.Genesis => GenesisPayload.Decode(encoded).Encode(),
            RecordType.SegmentStart => SegmentStartPayload.Decode(encoded).Encode(),
            RecordType.Checkpoint => CheckpointPayload.Decode(encoded).Encode(),
            RecordType.Start => StartPayload.Decode(encoded).Encode(),
            RecordType.CheckpointKeyChanged => CheckpointKeyChangedPayload.Decode(encoded).Encode(),
            RecordType.Certificate => CertificatePayload.Decode(encoded).Encode(),
            RecordType.Crl => CrlPayload.Decode(encoded).Encode(),
            RecordType.SshCertificate => SshCertificatePayload.Decode(encoded).Encode(),
            RecordType.SshRevocationList => SshRevocationListPayload.Decode(encoded).Encode(),
            RecordType.Revocation => RevocationPayload.Decode(encoded).Encode(),
            RecordType.Unrevocation => UnrevocationPayload.Decode(encoded).Encode(),
            RecordType.SpentWithoutCertificate => SpentWithoutCertificatePayload.Decode(encoded).Encode(),
            RecordType.RestoreMarker => RestoreMarkerPayload.Decode(encoded).Encode(),
            RecordType.ContinuityEvent => ContinuityEventPayload.Decode(encoded).Encode(),
            RecordType.Disabled => DisabledPayload.Decode(encoded).Encode(),
            _ => throw new InvalidOperationException(name),
        };

        Assert.Equal(encoded, again);
    }

    [Fact]
    public void A_certificate_payload_keeps_every_member_it_was_given()
    {
        var hash = Enumerable.Repeat((byte)7, 32).ToArray();
        var original = new CertificatePayload("ca-1", hash, hash, new SigningContextInfo("Certificate", "EST", "alice"), "0.4.5",
            [0x30, 0x03, 1, 2, 3], [9, 9], [0x01, 0x00], 1000, 2000, hash, false,
            new[] { new SpentToken(TokenKind.CmpSharedSecret, "secret-row-7", 1), new SpentToken(TokenKind.EnrollmentToken, "t", 3) },
            new Answers(AnswersKind.EnrollmentTransaction, "txn-9"), new Replaces([0x0a], hash), new Belongs("profile", "space", OwnerKind.User, "user", "template"));

        var decoded = CertificatePayload.Decode(original.Encode());

        Assert.Equal(original.Ca, decoded.Ca);
        Assert.Equal(original.Tbs, decoded.Tbs);
        Assert.Equal(original.Signature, decoded.Signature);
        Assert.Equal(original.Serial, decoded.Serial);
        Assert.Equal((original.NotBefore, original.NotAfter, original.IsCa), (decoded.NotBefore, decoded.NotAfter, decoded.IsCa));
        Assert.Equal(original.Context, decoded.Context);
        Assert.Equal(original.Spent!, decoded.Spent!);
        Assert.Equal(original.Answers, decoded.Answers);
        Assert.Equal(original.Replaces!.Serial, decoded.Replaces!.Serial);
        Assert.Equal(original.Belongs, decoded.Belongs);
    }

    [Fact]
    public void A_fact_the_node_offers_is_checked_and_re_encoded()
    {
        var hash = new byte[32];
        // Members in a non-canonical order, with one the type does not have.
        var offered = new CborMapBuilder().Int(JournalKeys.Time, 5).Bytes(JournalKeys.Serial, [1]).Bytes(JournalKeys.CaKey, hash)
            .Text(4242, "extra").Encode();

        var normalized = NodeFacts.Normalize(RecordType.Unrevocation, offered);

        Assert.Equal(new UnrevocationPayload([1], hash, null, 5).Encode(), normalized);
        Assert.Throws<FormatException>(() => NodeFacts.Normalize(RecordType.Certificate, offered));
        Assert.Throws<FormatException>(() => NodeFacts.Normalize(RecordType.Checkpoint, offered));
        Assert.Throws<FormatException>(() => NodeFacts.Normalize(RecordType.Revocation, new CborMapBuilder().Bytes(JournalKeys.Serial, [1]).Encode()));
        Assert.Throws<FormatException>(() => NodeFacts.Normalize(RecordType.Unrevocation,
            new UnrevocationPayload([1], [1, 2, 3], null, 5).Encode()));
    }
}
