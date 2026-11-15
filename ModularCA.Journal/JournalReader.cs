using System.Buffers;
using System.Buffers.Binary;

namespace ModularCA.Journal;

/// <summary>What reading one segment file found.</summary>
/// <param name="Name">The file's name.</param>
/// <param name="Open">Whether the name is the open form.</param>
/// <param name="FirstSeqInName">The first sequence the name states.</param>
/// <param name="FileLength">The file's length when it was opened.</param>
/// <param name="WholeBytes">The bytes of whole records from the first byte.</param>
/// <param name="Records">How many whole records.</param>
/// <param name="First">The first whole record, or null when there is none.</param>
/// <param name="Last">The last whole record, or null when there is none.</param>
public sealed record SegmentScan(string Name, bool Open, ulong FirstSeqInName, long FileLength, long WholeBytes, long Records, JournalRecord? First, JournalRecord? Last)
{
    /// <summary>Whether bytes follow the whole records: a record that was being written when the signer stopped.</summary>
    public bool Torn => FileLength > WholeBytes;

    /// <summary>Whether the last whole record is a <c>Seal</c>.</summary>
    public bool EndsWithSeal => Last?.Type == RecordType.Seal;
}

/// <summary>A segment file found in a journal directory.</summary>
/// <param name="Path">Its full path.</param>
/// <param name="Name">Its file name.</param>
/// <param name="FirstSeq">The first sequence its name states.</param>
/// <param name="Open">Whether the name is the open form.</param>
public sealed record SegmentFile(string Path, string Name, ulong FirstSeq, bool Open);

/// <summary>
/// Reads segment files. Every file is opened for reading only, shared with a writer that is
/// appending and with a rename, and nothing is created, locked or changed, so this works on a
/// read-only mount and on a bare copy of the directory.
/// </summary>
public static class JournalReader
{
    /// <summary>
    /// The segment files of <paramref name="directory"/>, oldest first. A name that is not a
    /// segment's is not listed. An open segment sorts after a sealed one of the same number.
    /// Empty when the directory does not exist.
    /// </summary>
    public static IReadOnlyList<SegmentFile> ListSegments(string directory)
    {
        if (!Directory.Exists(directory))
            return Array.Empty<SegmentFile>();
        var files = new List<SegmentFile>();
        foreach (var path in Directory.EnumerateFiles(directory, "*" + JournalFormat.SealedSuffix, SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(path);
            if (JournalFormat.TryParseName(name, out var firstSeq, out var open))
                files.Add(new SegmentFile(path, name, firstSeq, open));
        }
        files.Sort((a, b) => a.FirstSeq != b.FirstSeq ? a.FirstSeq.CompareTo(b.FirstSeq) : a.Open.CompareTo(b.Open));
        return files;
    }

    /// <summary>Opens a segment for reading only, sharing it with a writer and with a rename.</summary>
    public static FileStream OpenRead(string path)
        => new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);

    /// <summary>
    /// Reads the whole records of a segment from its first byte and stops at the first position
    /// that does not hold one. <paramref name="onRecord"/> is given each record and its offset;
    /// returning false stops the reading there.
    /// </summary>
    /// <param name="file">The segment.</param>
    /// <param name="onRecord">Called for each whole record, or null to only measure.</param>
    /// <param name="limitBytes">
    /// Read this many bytes and no more: what the next segment's <c>SegmentStart</c> states for
    /// this file. Null reads to the end of the file as it was when opened.
    /// </param>
    /// <exception cref="JournalFormatException">A whole record is not this layout's, or names another <c>format</c>.</exception>
    public static SegmentScan Read(SegmentFile file, Func<JournalRecord, long, bool>? onRecord = null, long? limitBytes = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        using var stream = OpenRead(file.Path);
        var fileLength = stream.Length;
        var length = fileLength;
        if (limitBytes is long limit && limit < length)
            length = limit;

        long offset = 0;
        long records = 0;
        JournalRecord? first = null, last = null;
        Span<byte> prefix = stackalloc byte[JournalFormat.LengthPrefixLength];
        var buffer = ArrayPool<byte>.Shared.Rent(1 << 16);
        try
        {
            while (true)
            {
                if (length - offset < JournalFormat.LengthPrefixLength)
                    break;
                stream.Position = offset;
                if (!ReadExactly(stream, prefix))
                    break;
                long total = JournalFormat.LengthPrefixLength + (long)BinaryPrimitives.ReadUInt32BigEndian(prefix) + JournalFormat.HashLength;
                if (total > JournalFormat.MaxRecordLength || length - offset < total)
                    break;
                if (buffer.Length < total)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = ArrayPool<byte>.Shared.Rent((int)total);
                }
                prefix.CopyTo(buffer);
                if (!ReadExactly(stream, buffer.AsSpan(JournalFormat.LengthPrefixLength, (int)total - JournalFormat.LengthPrefixLength)))
                    break;
                var read = JournalRecord.TryRead(buffer.AsSpan(0, (int)total), out var record, out _);
                if (read == RecordRead.Torn)
                    break;
                if (read == RecordRead.Malformed)
                    throw new JournalFormatException(file.Name, last?.Seq + 1 ?? file.FirstSeq,
                        $"the bytes at offset {offset} are whole by their length and hash but are not a journal record");
                if (record!.Format != JournalFormat.Format)
                    throw new JournalFormatException(file.Name, record.Seq,
                        $"format {record.Format} was found; this reader knows format {JournalFormat.Format}");

                first ??= record;
                last = record;
                records++;
                var recordOffset = offset;
                offset += total;
                if (onRecord != null && !onRecord(record, recordOffset))
                    break;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
        return new SegmentScan(file.Name, file.Open, file.FirstSeq, fileLength, offset, records, first, last);
    }

    private static bool ReadExactly(Stream stream, Span<byte> destination)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = stream.Read(destination[read..]);
            if (n == 0)
                return false;
            read += n;
        }
        return true;
    }

    /// <summary>
    /// Walks a segment's records by their lengths without checking hashes or reading payloads,
    /// and hands <paramref name="onRecord"/> the type, sequence and a way to load the payload of
    /// the ones it wants. For an index built over a journal that was already verified or is the
    /// signer's own; it reads a fraction of the file. Stops at the end of the file or at a
    /// length that does not fit.
    /// </summary>
    public static void Skim(SegmentFile file, Action<ushort, ulong, Func<byte[]>> onRecord, long? limitBytes = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(onRecord);
        using var stream = new FileStream(file.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.RandomAccess);
        var length = stream.Length;
        if (limitBytes is long limit && limit < length)
            length = limit;
        long offset = 0;
        var head = new byte[JournalFormat.LengthPrefixLength + 16];
        while (length - offset >= JournalFormat.RecordOverhead)
        {
            stream.Position = offset;
            if (!ReadExactly(stream, head))
                break;
            var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(head);
            long total = JournalFormat.LengthPrefixLength + (long)bodyLength + JournalFormat.HashLength;
            if (bodyLength < JournalFormat.FixedPartLength || total > JournalFormat.MaxRecordLength || length - offset < total)
                break;
            if (!head.AsSpan(4, 4).SequenceEqual(JournalFormat.Magic))
                break;
            var type = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(9));
            var seq = BinaryPrimitives.ReadUInt64BigEndian(head.AsSpan(12));
            var payloadOffset = offset + JournalFormat.LengthPrefixLength + JournalFormat.FixedPartLength;
            var payloadLength = (int)bodyLength - JournalFormat.FixedPartLength;
            onRecord(type, seq, () =>
            {
                var payload = new byte[payloadLength];
                stream.Position = payloadOffset;
                if (!ReadExactly(stream, payload))
                    throw new EndOfStreamException("The segment ended inside a record.");
                return payload;
            });
            offset += total;
        }
    }
}

/// <summary>A segment holds bytes this reader must not go past: another <c>format</c>, or a whole record that is not this layout's.</summary>
public sealed class JournalFormatException : Exception
{
    /// <summary>Creates the exception.</summary>
    public JournalFormatException(string segment, ulong seq, string reason)
        : base($"{segment}, sequence {seq}: {reason}")
    {
        Segment = segment;
        Seq = seq;
        Reason = reason;
    }

    /// <summary>The segment file's name.</summary>
    public string Segment { get; }

    /// <summary>The sequence at which reading stopped.</summary>
    public ulong Seq { get; }

    /// <summary>What was found.</summary>
    public string Reason { get; }
}
