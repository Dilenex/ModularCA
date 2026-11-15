using System.Text;
using System.Text.Json;

namespace ModularCA.Journal;

/// <summary>
/// The journal's head, read from the files: what <c>--role signer --journal-head</c> prints.
/// It opens files for reading only, creates and locks nothing, and needs no signer, keystore,
/// database or credentials. By default it reads the newest segment only.
/// </summary>
public sealed class JournalHead
{
    /// <summary>The exit status for a head that was read.</summary>
    public const int ExitOk = 0;
    /// <summary>The exit status when the directory holds no journal.</summary>
    public const int ExitNoJournal = 3;
    /// <summary>The exit status when the chain in what was read does not hold.</summary>
    public const int ExitBrokenChain = 4;

    private JournalHead(int exitCode, string? json, string? error, JournalVerification? verification)
    {
        ExitCode = exitCode;
        Json = json;
        Error = error;
        Verification = verification;
    }

    /// <summary>0 with the line, 3 when the directory holds no journal, 4 when the chain read does not hold.</summary>
    public int ExitCode { get; }

    /// <summary>The one line of JSON, when <see cref="ExitCode"/> is 0.</summary>
    public string? Json { get; }

    /// <summary>The reason, for standard error, when <see cref="ExitCode"/> is not 0.</summary>
    public string? Error { get; }

    /// <summary>What was read, for a caller in process.</summary>
    public JournalVerification? Verification { get; }

    /// <summary>
    /// Reads the head of the journal in <paramref name="directory"/>. With
    /// <paramref name="includeSealed"/> every sealed segment is read too and listed; with
    /// <paramref name="sealedFrom"/> the sealed segments whose first sequence is at or after
    /// it are read and listed, and no older one is opened; otherwise only the newest segment
    /// that holds a record. Run beside a signer that is appending, it may report a head a few
    /// records old, never a torn one.
    /// </summary>
    /// <param name="directory">The journal directory, or a copy of one, or one that was set aside.</param>
    /// <param name="includeSealed">Read and list every sealed segment.</param>
    /// <param name="sealedFrom">Read and list the sealed segments that begin at this sequence or later. Ignored with <paramref name="includeSealed"/>.</param>
    public static JournalHead Read(string directory, bool includeSealed = false, ulong? sealedFrom = null)
    {
        IReadOnlyList<SegmentFile> all;
        try
        {
            all = JournalReader.ListSegments(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new JournalHead(ExitNoJournal, null, $"the journal directory '{directory}' could not be listed: {ex.Message}", null);
        }
        if (all.Count == 0)
            return new JournalHead(ExitNoJournal, null, $"the directory '{directory}' holds no journal", null);

        var options = new JournalVerifyOptions { EveryCheckpoint = false, AllowMidChainStart = true };
        JournalVerification result;
        if (includeSealed)
        {
            result = JournalVerifier.Verify(all, options);
        }
        else
        {
            // The newest segment that holds a whole record; a newer file that holds none (its
            // creation was interrupted) is read with it so it is seen, and nothing older is.
            // With a first sequence, the reading begins at the oldest segment that starts at
            // or after it, when that is older: segments are in order, so what is read is one
            // unbroken run up to the head.
            var start = all.Count - 1;
            if (sealedFrom is ulong from)
            {
                for (var i = 0; i < all.Count; i++)
                {
                    if (all[i].FirstSeq < from)
                        continue;
                    start = Math.Min(start, i);
                    break;
                }
            }
            while (true)
            {
                result = JournalVerifier.Verify(all.Skip(start).ToList(), options);
                if (result.Fault != null || result.HasJournal || start == 0)
                    break;
                start--;
            }
        }

        if (result.Fault != null)
            return new JournalHead(ExitBrokenChain, null, result.Fault.ToString(), result);
        if (!result.HasJournal || result.Head == null)
            return new JournalHead(ExitNoJournal, null, $"the directory '{directory}' holds no journal", result);
        // A journal written before every SegmentStart carried the Genesis hash: with a sealed
        // list asked for, the first segment is opened for it; the short head does not.
        var genesis = result.Head.GenesisHash;
        if (genesis == null && (includeSealed || sealedFrom != null))
            genesis = GenesisOfFirstSegment(all);
        return new JournalHead(ExitOk, Render(result, includeSealed, includeSealed ? null : sealedFrom, genesis), null, result);
    }

    /// <summary>
    /// The hash of the <c>Genesis</c> record, read from the journal's first segment: its second
    /// record. Null when the first segment is not among <paramref name="segments"/> or does not
    /// hold one.
    /// </summary>
    public static byte[]? GenesisOfFirstSegment(IReadOnlyList<SegmentFile> segments)
    {
        if (segments.Count == 0 || segments[0].FirstSeq != 1)
            return null;
        byte[]? hash = null;
        try
        {
            var seen = 0;
            JournalReader.Read(segments[0], (record, _) =>
            {
                if (record.Type == RecordType.Genesis)
                    hash = record.Hash;
                return hash == null && ++seen < 4;
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JournalFormatException)
        {
            return null;
        }
        return hash;
    }

    private static string Render(JournalVerification result, bool includeSealed, ulong? sealedFrom, byte[]? genesis)
    {
        var head = result.Head!;
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("format", JournalFormat.Format);
            json.WriteString("instanceId", head.InstanceId);
            // What tells this journal from another journal of the same instance.
            if (genesis != null)
                json.WriteString("genesisHash", Hex(genesis));
            else
                json.WriteNull("genesisHash");
            json.WriteNumber("seq", head.Seq);
            json.WriteString("hash", Hex(head.Hash));
            json.WriteNumber("term", head.Term);
            json.WriteString("incarnation", Hex(head.Incarnation));

            var open = result.Segments.LastOrDefault(s => s.Open);
            if (open == null)
            {
                json.WriteNull("open");
            }
            else
            {
                json.WriteStartObject("open");
                json.WriteString("segment", open.Name);
                json.WriteNumber("wholeBytes", open.WholeBytes);
                json.WriteEndObject();
            }

            if (head.Checkpoint is { } checkpoint)
            {
                json.WriteStartObject("checkpoint");
                json.WriteNumber("seq", checkpoint.Seq);
                json.WriteString("hash", Hex(checkpoint.Hash));
                json.WriteString("key", Hex(checkpoint.KeyHash));
                json.WriteString("algorithm", checkpoint.Algorithm);
                json.WriteString("signature", Hex(checkpoint.Signature));
                json.WriteEndObject();
            }
            else
            {
                json.WriteNull("checkpoint");
            }

            if (head.Key is { } key)
            {
                json.WriteStartObject("checkpointKey");
                json.WriteString("key", Hex(key.Key));
                json.WriteString("systemKey", Hex(key.SystemKey));
                // The system public key itself, as the journal carries it beside the block:
                // with it the holder of the hash checks systemSignature from this line alone.
                // Null for a journal whose records do not carry it.
                if (head.SystemPublicKey is { } systemPublicKey)
                    json.WriteString("systemPublicKey", Hex(systemPublicKey));
                else
                    json.WriteNull("systemPublicKey");
                json.WriteString("systemSignature", Hex(key.SystemSignature));
                json.WriteString("algorithm", key.Algorithm);
                json.WriteEndObject();
            }
            else
            {
                json.WriteNull("checkpointKey");
            }

            if (includeSealed || sealedFrom != null)
            {
                json.WriteStartArray("sealed");
                foreach (var segment in result.Segments.Where(s => !s.Open && (sealedFrom is not ulong from || s.FirstSeq >= from)))
                {
                    json.WriteStartObject();
                    json.WriteString("segment", segment.Name);
                    json.WriteNumber("wholeBytes", segment.WholeBytes);
                    json.WriteNumber("lastSeq", segment.LastSeq);
                    json.WriteString("lastHash", Hex(segment.LastHash));
                    json.WriteBoolean("torn", segment.Torn);
                    json.WriteEndObject();
                }
                json.WriteEndArray();
            }
            json.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>Lower-case hex, the form of every hash, key and signature in the head's answer.</summary>
    public static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
}
