using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ModularCA.Journal;

/// <summary>
/// One record of the journal, as its bytes state it. All integers are big-endian.
/// <code>
/// record  = length (u32) | body | hash (32 bytes)      hash = SHA-256(body)
/// body    = "MCAJ" | format u8 | type u16 | flags u8 | seq u64 | at i64 | term u64
///           | incarnation (32) | prev (32) | payload (one CBOR map)
/// </code>
/// The fixed part of the body is 96 bytes. The hash is both the checksum and the link: the
/// next record carries it as <c>prev</c>.
/// </summary>
/// <param name="Format">The <c>format</c> byte.</param>
/// <param name="Type">The record type (<see cref="RecordType"/>).</param>
/// <param name="Flags">The flag bits; bit 0 is <see cref="JournalFormat.FlagNodeAsserted"/>.</param>
/// <param name="Seq">The sequence: 1 for the first record of the journal, one more for each record.</param>
/// <param name="At">The signer's clock when the record was made, in microseconds since 1970-01-01 UTC.</param>
/// <param name="Term">0 until terms exist.</param>
/// <param name="Incarnation">SHA-256 of the incarnation value; all zero when none is set.</param>
/// <param name="Prev">The hash of record <c>seq - 1</c>; all zero for sequence 1.</param>
/// <param name="Payload">The payload: one CBOR map.</param>
/// <param name="Hash">SHA-256 of the body.</param>
public sealed record JournalRecord(
    byte Format,
    ushort Type,
    byte Flags,
    ulong Seq,
    long At,
    ulong Term,
    byte[] Incarnation,
    byte[] Prev,
    byte[] Payload,
    byte[] Hash)
{
    /// <summary>The bytes this record takes in a segment: length prefix, body and hash.</summary>
    public long EncodedLength => JournalFormat.RecordOverhead + Payload.Length;

    /// <summary>Whether the node asserted this record's fact (flag bit 0).</summary>
    public bool NodeAsserted => (Flags & JournalFormat.FlagNodeAsserted) != 0;

    /// <summary>
    /// Encodes a record: builds the body, hashes it and returns the bytes to append with the
    /// hash, which is the <c>prev</c> of the record that follows.
    /// </summary>
    /// <exception cref="ArgumentException">The incarnation or prev is not 32 bytes, or the record would pass <see cref="JournalFormat.MaxRecordLength"/>.</exception>
    public static (byte[] Bytes, byte[] Hash) Encode(ushort type, byte flags, ulong seq, long at, ulong term,
        ReadOnlySpan<byte> incarnation, ReadOnlySpan<byte> prev, ReadOnlySpan<byte> payload)
    {
        if (incarnation.Length != JournalFormat.HashLength)
            throw new ArgumentException("The incarnation is 32 bytes.", nameof(incarnation));
        if (prev.Length != JournalFormat.HashLength)
            throw new ArgumentException("The previous hash is 32 bytes.", nameof(prev));
        var bodyLength = JournalFormat.FixedPartLength + payload.Length;
        long total = JournalFormat.LengthPrefixLength + (long)bodyLength + JournalFormat.HashLength;
        if (total > JournalFormat.MaxRecordLength)
            throw new ArgumentException($"A record is at most {JournalFormat.MaxRecordLength} bytes; this one would be {total}.", nameof(payload));

        var bytes = new byte[total];
        var span = bytes.AsSpan();
        BinaryPrimitives.WriteUInt32BigEndian(span, (uint)bodyLength);
        var body = span.Slice(JournalFormat.LengthPrefixLength, bodyLength);
        JournalFormat.Magic.CopyTo(body);
        body[4] = JournalFormat.Format;
        BinaryPrimitives.WriteUInt16BigEndian(body[5..], type);
        body[7] = flags;
        BinaryPrimitives.WriteUInt64BigEndian(body[8..], seq);
        BinaryPrimitives.WriteInt64BigEndian(body[16..], at);
        BinaryPrimitives.WriteUInt64BigEndian(body[24..], term);
        incarnation.CopyTo(body[32..]);
        prev.CopyTo(body[64..]);
        payload.CopyTo(body[JournalFormat.FixedPartLength..]);
        var hash = SHA256.HashData(body);
        hash.CopyTo(span[(JournalFormat.LengthPrefixLength + bodyLength)..]);
        return (bytes, hash);
    }

    /// <summary>
    /// Reads the record that begins at the start of <paramref name="source"/>. A record is
    /// whole when its length, its body and its hash are all there and the hash is SHA-256 of
    /// the body; anything else is <see cref="RecordRead.Torn"/>, and nothing after that point
    /// in a file is a record. A whole record whose body does not begin with the magic, or is
    /// shorter than the fixed part, is <see cref="RecordRead.Malformed"/>: the bytes were
    /// written whole by something that is not this layout.
    /// </summary>
    /// <param name="source">The bytes from the record's first byte to at least its last.</param>
    /// <param name="record">The record, when whole.</param>
    /// <param name="consumed">The bytes the record takes, when whole.</param>
    public static RecordRead TryRead(ReadOnlySpan<byte> source, out JournalRecord? record, out int consumed)
    {
        record = null;
        consumed = 0;
        if (source.Length < JournalFormat.LengthPrefixLength)
            return RecordRead.Torn;
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(source);
        long total = JournalFormat.LengthPrefixLength + (long)bodyLength + JournalFormat.HashLength;
        if (total > JournalFormat.MaxRecordLength || source.Length < total)
            return RecordRead.Torn;
        var body = source.Slice(JournalFormat.LengthPrefixLength, (int)bodyLength);
        var stored = source.Slice(JournalFormat.LengthPrefixLength + (int)bodyLength, JournalFormat.HashLength);
        Span<byte> computed = stackalloc byte[JournalFormat.HashLength];
        SHA256.HashData(body, computed);
        if (!computed.SequenceEqual(stored))
            return RecordRead.Torn;

        consumed = (int)total;
        if (body.Length < JournalFormat.FixedPartLength || !body[..4].SequenceEqual(JournalFormat.Magic))
            return RecordRead.Malformed;
        record = new JournalRecord(
            Format: body[4],
            Type: BinaryPrimitives.ReadUInt16BigEndian(body[5..]),
            Flags: body[7],
            Seq: BinaryPrimitives.ReadUInt64BigEndian(body[8..]),
            At: BinaryPrimitives.ReadInt64BigEndian(body[16..]),
            Term: BinaryPrimitives.ReadUInt64BigEndian(body[24..]),
            Incarnation: body.Slice(32, 32).ToArray(),
            Prev: body.Slice(64, 32).ToArray(),
            Payload: body[JournalFormat.FixedPartLength..].ToArray(),
            Hash: stored.ToArray());
        return RecordRead.Whole;
    }
}

/// <summary>What reading at a position of a segment found.</summary>
public enum RecordRead
{
    /// <summary>A whole record: its length, body and hash are there and the hash matches.</summary>
    Whole,
    /// <summary>Not a whole record: the file's whole records end before this position.</summary>
    Torn,
    /// <summary>Whole by its length and hash, but not a record of this layout.</summary>
    Malformed,
}
