using System.Diagnostics;
using System.Threading.Channels;

namespace ModularCA.Journal;

/// <summary>What a <see cref="JournalWriter"/> is opened with.</summary>
public sealed class JournalWriterOptions
{
    /// <summary>The journal directory. It holds segment files and nothing else.</summary>
    public required string Directory { get; init; }

    /// <summary>The instance identifier every structure record and signature names.</summary>
    public required string InstanceId { get; init; }

    /// <summary>The key that signs checkpoints.</summary>
    public required IJournalSigningKey CheckpointKey { get; init; }

    /// <summary>The system key, which signs the checkpoint key block when one is made or changed.</summary>
    public required IJournalSigningKey SystemKey { get; init; }

    /// <summary>SHA-256 of the incarnation value, 32 bytes; all zero when none is set.</summary>
    public byte[] Incarnation { get; init; } = new byte[JournalFormat.HashLength];

    /// <summary>The product version, written in <c>Genesis</c> and <c>Start</c>.</summary>
    public string Version { get; init; } = string.Empty;

    /// <summary>
    /// Finds a key the signer still holds by the SHA-256 of its public key: an old checkpoint
    /// key or an old system key, to sign for the key that replaces it. Null when it holds none.
    /// </summary>
    public Func<byte[], IJournalSigningKey?>? FindHeldKey { get; init; }

    /// <summary>The file operations; the real file system unless a test substitutes another.</summary>
    public IJournalFiles Files { get; init; } = JournalFiles.Default;

    /// <summary>The signer's clock.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>The size at which a segment is sealed.</summary>
    public long SegmentSealBytes { get; init; } = JournalFormat.SegmentSealBytes;

    /// <summary>The age at which a segment that has taken records is sealed.</summary>
    public TimeSpan SegmentSealAge { get; init; } = JournalFormat.SegmentSealAge;

    /// <summary>The longest a record waits for its checkpoint.</summary>
    public TimeSpan CheckpointInterval { get; init; } = JournalFormat.CheckpointInterval;

    /// <summary>The most records between two checkpoints.</summary>
    public int CheckpointRecords { get; init; } = JournalFormat.CheckpointRecords;

    /// <summary>
    /// How long a system key change that neither the old key nor a changed incarnation explains
    /// waits for the node's <c>RestoreMarker</c> before it is written without an explanation.
    /// </summary>
    public TimeSpan UnexplainedKeyChangeWait { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>The most bytes gathered into one flush before the batch is cut.</summary>
    public int MaxBatchBytes { get; init; } = 1 << 20;

    /// <summary>Whether this open is a start of the signer, which writes a <c>Start</c> record.</summary>
    public bool WriteStart { get; init; } = true;

    /// <summary>Receives what an operator should read: a segment renamed at start, a fault, a recovery.</summary>
    public Action<string>? Log { get; init; }
}

/// <summary>Where a record went: its sequence and its hash, known once the flush that covers it returned.</summary>
public sealed record JournalAppended(ulong Seq, byte[] Hash);

/// <summary>What a payload is built with: the place the record takes in the chain.</summary>
/// <param name="Seq">The record's sequence.</param>
/// <param name="Prev">The hash of the record before it.</param>
/// <param name="SegmentFirstSeq">The first sequence of the segment the record goes into.</param>
/// <param name="At">The record's time, microseconds since 1970-01-01 UTC.</param>
public sealed record AppendContext(ulong Seq, byte[] Prev, ulong SegmentFirstSeq, long At);

/// <summary>The journal as its writer knows it, for a health answer.</summary>
/// <param name="Available">Whether the journal can take a record now.</param>
/// <param name="Fault">Why not, when it cannot.</param>
/// <param name="Seq">The last flushed record's sequence.</param>
/// <param name="Hash">The last flushed record's hash.</param>
/// <param name="LastCheckpointAt">When the newest checkpoint was written, or null when this run wrote none.</param>
/// <param name="LastCheckpointSeq">The newest checkpoint's sequence.</param>
/// <param name="Uncheckpointed">Records written since the newest checkpoint.</param>
/// <param name="DirectoryBytes">The bytes the journal's segments take.</param>
/// <param name="OpenSegment">The open segment's file name; null when this start has not begun one yet.</param>
/// <param name="AwaitingRestoreMarkerUntil">
/// When the system key changed, nothing the signer holds explains it, and the writer still
/// waits for the node's <c>RestoreMarker</c>: the time at which it stops waiting and records
/// the change without an explanation. Null otherwise. Records are taken and flushed during the
/// wait; only checkpoints are held back.
/// </param>
public sealed record JournalStatus(bool Available, string? Fault, ulong Seq, byte[] Hash, DateTimeOffset? LastCheckpointAt,
    ulong LastCheckpointSeq, long Uncheckpointed, long DirectoryBytes, string? OpenSegment, DateTimeOffset? AwaitingRestoreMarkerUntil = null);

/// <summary>
/// The journal's writer. One open segment; records are appended in the order they are offered,
/// each chained to the one before; one flush to disk covers a batch, and a record's task
/// completes only after the flush that covers it. The writer creates, appends and renames. It
/// never truncates, rewrites, compresses or deletes a record.
/// </summary>
/// <remarks>
/// <para>
/// <b>Opening.</b> If the newest segment's last whole record is not a <c>Seal</c>, with or
/// without a torn record after it and whether or not the file still has its open name, it is
/// renamed to its sealed name as it is and a new segment begins, whose <c>SegmentStart</c> gives
/// the bytes of whole records in the previous file. A newest file that holds no whole record at
/// all (its creation was interrupted before its first record reached the disk) is no part of
/// the chain; the new segment takes its name over it.
/// </para>
/// <para>
/// <b>When the segment begins.</b> A directory with no journal gets one at once: the first
/// segment, with its <c>Genesis</c>. A directory that holds a journal is only read when the
/// writer opens (its tail is checked, and that it is this instance's); the rename and the new
/// segment, with this start's <c>Start</c> record, wait for the first record offered. A start
/// that records nothing therefore creates, renames and writes nothing, and a signer that is
/// started and stopped in a loop leaves the directory as it found it. The file a start finds
/// open and unsealed is never appended to, by this start or any other.
/// </para>
/// <para>
/// <b>Failing.</b> A write or flush that fails fails every record in its batch with
/// <see cref="JournalUnavailableException"/>, and the segment is abandoned as it is: the next
/// append opens a new segment by the same rule as a start, so nothing is ever appended after
/// bytes that may be torn.
/// </para>
/// </remarks>
public sealed class JournalWriter : IAsyncDisposable
{
    private readonly JournalWriterOptions _options;
    private readonly Channel<Request> _channel = Channel.CreateUnbounded<Request>(new UnboundedChannelOptions { SingleReader = true });
    private readonly MemoryStream _buffer = new();
    private readonly Task _loop;

    private IJournalAppendFile? _file;
    private string? _openPath;
    private ulong _segmentFirstSeq;
    private long _segmentBytes;
    private long _segmentActivity;
    private long _segmentOpenedAt;
    private ulong _seq;
    private byte[] _prev = new byte[JournalFormat.HashLength];
    private KeyBlock _block = null!;
    private byte[]? _blockSystemPublicKey;
    private long _uncheckpointed;
    private long _firstUncheckpointedAt;
    private DeferredKeyChange? _deferred;
    private long _directoryBytes;
    private DateTimeOffset? _lastCheckpointAt;
    private ulong _lastCheckpointSeq;
    private long _lastFailedOpenAt = -1;
    private string? _fault;
    private volatile JournalStatus _status;
    private bool _startWritten;
    private bool _dormant;
    private bool _dormantWouldDefer;
    private long? _deferDeadline;
    private DateTimeOffset _deferUntil;

    private JournalWriter(JournalWriterOptions options)
    {
        _options = options;
        _status = new JournalStatus(false, "The journal is not open.", 0, new byte[JournalFormat.HashLength], null, 0, 0, 0, null);
        OpenSegment(begin: false);
        Publish();
        _loop = Task.Run(RunAsync);
    }

    /// <summary>
    /// Opens the journal in the directory the options name. A directory with no journal gets
    /// its first segment at once (<c>SegmentStart</c>, <c>Genesis</c>, <c>Start</c>, a
    /// <c>Checkpoint</c>). A directory that holds one is read and tested for taking a new file (an
    /// empty probe file is made and removed; the open fails when it cannot be), and no segment is
    /// created, renamed or written until the first record is offered: then the start-up rule is applied
    /// and the opening records are written before it (<c>SegmentStart</c>, <c>Start</c>,
    /// <c>CheckpointKeyChanged</c> when the key differs from the one in force, a
    /// <c>Checkpoint</c>).
    /// </summary>
    /// <exception cref="JournalUnavailableException">The directory cannot be written, or what it holds is not a journal this instance may continue.</exception>
    public static JournalWriter Open(JournalWriterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Incarnation.Length != JournalFormat.HashLength)
            throw new ArgumentException("The incarnation is 32 bytes.", nameof(options));
        try
        {
            return new JournalWriter(options);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JournalFormatException or NotSupportedException)
        {
            throw new JournalUnavailableException($"The journal in '{options.Directory}' could not be opened: {ex.Message}", ex);
        }
    }

    /// <summary>The checkpoint key block in force.</summary>
    public KeyBlock KeyBlock => _block;

    /// <summary>The journal as the writer knows it now.</summary>
    public JournalStatus Status => _status;

    /// <summary>The journal directory.</summary>
    public string Directory => _options.Directory;

    /// <summary>
    /// Appends a record whose payload is built once its place in the chain is known. The task
    /// completes after the flush to disk that covers the record, and not before. A payload
    /// factory that throws fails this record only and appends nothing.
    /// </summary>
    /// <exception cref="JournalUnavailableException">The record could not be appended and flushed.</exception>
    public Task<JournalAppended> AppendAsync(ushort type, byte flags, Func<AppendContext, byte[]> payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var request = new Request(type, flags, payload);
        if (!_channel.Writer.TryWrite(request))
            request.Done.TrySetException(new JournalUnavailableException("The journal is closed."));
        return request.Done.Task;
    }

    /// <summary>Appends a record with a payload that does not depend on its place.</summary>
    public Task<JournalAppended> AppendAsync(ushort type, byte flags, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return AppendAsync(type, flags, _ => payload);
    }

    /// <summary>
    /// Stops the writer: what was offered is written, then a final <c>Checkpoint</c> and a
    /// <c>Seal</c>, and the segment takes its sealed name.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        await _loop.ConfigureAwait(false);
    }

    /// <summary>
    /// Stops the writer as a signer that stops without warning does: nothing more is written,
    /// no <c>Seal</c>, no rename. For tests of the start-up rule.
    /// </summary>
    internal async Task CrashAsync()
    {
        _crashed = true;
        _channel.Writer.TryComplete();
        await _loop.ConfigureAwait(false);
    }

    private volatile bool _crashed;

    private sealed class Request(ushort type, byte flags, Func<AppendContext, byte[]> payload)
    {
        public ushort Type { get; } = type;
        public byte Flags { get; } = flags;
        public Func<AppendContext, byte[]> Payload { get; } = payload;
        public JournalAppended? Result { get; set; }
        public TaskCompletionSource<JournalAppended> Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed record DeferredKeyChange(KeyBlock NewBlock, byte[]? OldKeySignature, string? OldKeyAlgorithm, long Deadline);

    private async Task RunAsync()
    {
        var reader = _channel.Reader;
        while (true)
        {
            bool more;
            var wait = NextWait();
            if (wait is TimeSpan timeout)
            {
                using var cts = new CancellationTokenSource(timeout);
                try
                {
                    more = await reader.WaitToReadAsync(cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    more = true;
                }
            }
            else
            {
                more = await reader.WaitToReadAsync().ConfigureAwait(false);
            }
            if (!more)
                break;
            Cycle(reader);
        }
        Close();
    }

    /// <summary>How long the loop may sleep before something is due with no record arriving.</summary>
    private TimeSpan? NextWait()
    {
        if (_file == null)
            return null;
        long? due = null;
        if (_uncheckpointed > 0 && _deferred == null)
            due = _firstUncheckpointedAt + Ticks(_options.CheckpointInterval);
        if (_deferred != null)
            due = Math.Min(due ?? long.MaxValue, _deferred.Deadline);
        if (_segmentActivity > 0)
            due = Math.Min(due ?? long.MaxValue, _segmentOpenedAt + Ticks(_options.SegmentSealAge));
        if (due is not long at)
            return null;
        var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), at);
        return remaining <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(1) : remaining;
    }

    private static long Ticks(TimeSpan span) => (long)(span.TotalSeconds * Stopwatch.Frequency);

    private void Cycle(ChannelReader<Request> reader)
    {
        var batch = new List<Request>();
        try
        {
            EnsureOpen();
            _buffer.SetLength(0);
            while (_buffer.Length < _options.MaxBatchBytes && reader.TryRead(out var request))
            {
                byte[] placedPayload;
                try
                {
                    request.Result = Place(request.Type, request.Flags, request.Payload, activity: true, out placedPayload);
                    batch.Add(request);
                }
                catch (Exception ex) when (ex is not IOException and not UnauthorizedAccessException and not OutOfMemoryException)
                {
                    // The payload could not be built: this record is refused and nothing was appended for it.
                    request.Done.TrySetException(ex);
                    continue;
                }

                if (_deferred != null && request.Type == RecordType.RestoreMarker)
                    PlaceDeferredKeyChange(RestoreExplanation(placedPayload));
                if (_uncheckpointed >= _options.CheckpointRecords)
                    PlaceCheckpoint();
            }

            var now = Stopwatch.GetTimestamp();
            if (_deferred != null && now >= _deferred.Deadline)
            {
                _options.Log?.Invoke("The journal's system key changed and nothing explained it in time; the change is recorded without an explanation.");
                PlaceDeferredKeyChange(null);
            }
            if (_uncheckpointed > 0 && _deferred == null && now >= _firstUncheckpointedAt + Ticks(_options.CheckpointInterval))
                PlaceCheckpoint();

            FlushBuffer();
            // The status is current before a record is reported: whoever is told a record is
            // written and then asks sees the journal with that record in it.
            Publish();
            foreach (var request in batch)
                request.Done.TrySetResult(request.Result!);
            batch.Clear();

            if (_segmentBytes >= _options.SegmentSealBytes
                || (_segmentActivity > 0 && Stopwatch.GetTimestamp() >= _segmentOpenedAt + Ticks(_options.SegmentSealAge)))
                SealAndContinue();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            var failure = ex as JournalUnavailableException ?? new JournalUnavailableException($"The journal could not take the record: {ex.Message}", ex);
            Abandon(failure.Message);
            foreach (var request in batch)
                request.Done.TrySetException(failure);
            while (reader.TryRead(out var queued))
                queued.Done.TrySetException(failure);
        }
        Publish();
    }

    private static ChangeExplanation RestoreExplanation(byte[] markerPayload)
    {
        var payload = RestoreMarkerPayload.Decode(markerPayload);
        return new ChangeExplanation(ExplanationKind.Restore, payload.Archive, payload.ArchiveInstanceId, payload.ArchiveCreatedAt);
    }

    /// <summary>Builds a record at the chain's tail and adds its bytes to the batch.</summary>
    private JournalAppended Place(ushort type, byte flags, Func<AppendContext, byte[]> payload, bool activity)
        => Place(type, flags, payload, activity, out _);

    private JournalAppended Place(ushort type, byte flags, Func<AppendContext, byte[]> payload, bool activity, out byte[] body)
    {
        var seq = _seq + 1;
        var at = JournalFormat.ToMicros(_options.Clock());
        body = payload(new AppendContext(seq, _prev, _segmentFirstSeq, at));
        var (bytes, hash) = JournalRecord.Encode(type, flags, seq, at, term: 0, _options.Incarnation, _prev, body);
        _buffer.Write(bytes);
        _seq = seq;
        _prev = hash;
        _segmentBytes += bytes.Length;
        if (activity)
        {
            _segmentActivity++;
            if (_uncheckpointed++ == 0)
                _firstUncheckpointedAt = Stopwatch.GetTimestamp();
        }
        return new JournalAppended(seq, hash);
    }

    private void PlaceCheckpoint()
    {
        var key = _options.CheckpointKey;
        var placed = Place(RecordType.Checkpoint, 0, context => new CheckpointPayload(
            JournalSignatures.KeyHash(key.PublicKey), key.Algorithm,
            key.Sign(JournalSignatures.CheckpointMessage(_options.InstanceId, context.Seq, context.Prev))).Encode(), activity: false);
        _uncheckpointed = 0;
        _lastCheckpointAt = _options.Clock();
        _lastCheckpointSeq = placed.Seq;
    }

    private void PlaceDeferredKeyChange(ChangeExplanation? explains)
    {
        var deferred = _deferred!;
        _deferred = null;
        PlaceKeyChange(new CheckpointKeyChangedPayload(deferred.NewBlock, deferred.OldKeySignature, deferred.OldKeyAlgorithm,
            Explains: explains, SystemPublicKey: _options.SystemKey.PublicKey));
    }

    private void PlaceKeyChange(CheckpointKeyChangedPayload payload)
    {
        Place(RecordType.CheckpointKeyChanged, 0, _ => payload.Encode(), activity: true);
        _block = payload.NewKey;
        _blockSystemPublicKey = _options.SystemKey.PublicKey;
    }

    private void FlushBuffer()
    {
        if (_buffer.Length == 0)
            return;
        _file!.Append(_buffer.GetBuffer().AsSpan(0, (int)_buffer.Length));
        _file.Flush();
        _directoryBytes += _buffer.Length;
        _buffer.SetLength(0);
    }

    /// <summary>Seals the open segment (a checkpoint, a <c>Seal</c>, one flush, one rename) and begins the next.</summary>
    private void SealAndContinue()
    {
        var previous = SealOpenSegment();
        BeginSegment(previous, newJournal: false, start: false, previousUnsealed: false);
        FlushBuffer();
    }

    private PreviousSegment SealOpenSegment()
    {
        if (_uncheckpointed > 0 && _deferred == null)
            PlaceCheckpoint();
        Place(RecordType.Seal, 0, _ => SealPayload.Encode(), activity: false);
        FlushBuffer();
        _file!.Dispose();
        _file = null;
        var sealedName = JournalFormat.SealedName(_segmentFirstSeq);
        var sealedPath = Path.Combine(_options.Directory, sealedName);
        _options.Files.Rename(_openPath!, sealedPath, overStub: IsStub(sealedPath));
        return new PreviousSegment(sealedName, _segmentBytes, _seq, _prev, Sealed: true);
    }

    private void Close()
    {
        try
        {
            if (_file == null)
                return;
            if (_crashed)
            {
                _file.Dispose();
                _file = null;
                return;
            }
            _buffer.SetLength(0);
            SealOpenSegment();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _options.Log?.Invoke($"The journal's open segment was not sealed at stop ({ex.Message}); the next start renames it as it is.");
            try { _file?.Dispose(); } catch { /* the handle is gone either way */ }
            _file = null;
        }
        finally
        {
            _dormant = false;
            _fault = "The journal is closed.";
            Publish();
        }
    }

    private void Abandon(string reason)
    {
        _options.Log?.Invoke($"{reason} The open segment is left as it is; the next record opens a new one.");
        try { _file?.Dispose(); } catch { /* the handle is gone either way */ }
        _file = null;
        _fault = reason;
        _buffer.SetLength(0);
        _lastFailedOpenAt = Stopwatch.GetTimestamp();
    }

    private void EnsureOpen()
    {
        if (_file != null)
            return;
        // A directory that stays unwritable is not rescanned for every record.
        if (_lastFailedOpenAt >= 0 && Stopwatch.GetElapsedTime(_lastFailedOpenAt) < TimeSpan.FromSeconds(1))
            throw new JournalUnavailableException(_fault ?? "The journal is not open.");
        try
        {
            OpenSegment(begin: true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not JournalUnavailableException)
        {
            throw new JournalUnavailableException($"The journal in '{_options.Directory}' could not be opened: {ex.Message}", ex);
        }
    }

    private bool IsStub(string path)
    {
        if (!File.Exists(path))
            return false;
        var name = Path.GetFileName(path);
        if (!JournalFormat.TryParseName(name, out var firstSeq, out var open))
            return false;
        return JournalReader.Read(new SegmentFile(path, name, firstSeq, open), (_, _) => false).Records == 0;
    }

    /// <summary>
    /// The start-up rule: finds the chain's tail on disk, renames what is left open, and begins
    /// a new segment. Without <paramref name="begin"/>, a directory that holds a journal is only
    /// read: the writer then knows the tail and waits for the first record to do the rest.
    /// </summary>
    private void OpenSegment(bool begin)
    {
        _dormant = false;
        var files = _options.Files;
        files.EnsureDirectory(_options.Directory);
        var segments = JournalReader.ListSegments(_options.Directory);
        _directoryBytes = segments.Sum(s => new FileInfo(s.Path).Length);

        // The newest segment that holds a whole record is the chain's tail.
        SegmentFile? tailFile = null;
        JournalVerification? tail = null;
        for (var i = segments.Count - 1; i >= 0; i--)
        {
            // A change of system key that nothing explains is the signer's own record of what it
            // met, and no reason to stop appending after it.
            var check = JournalVerifier.Verify(new[] { segments[i] },
                new JournalVerifyOptions { EveryCheckpoint = false, AllowMidChainStart = true, TolerateUnexplainedKeyChange = true });
            if (check.Fault != null)
                throw new JournalUnavailableException($"The journal's newest records do not hold ({check.Fault}); the signer does not append to it. Run --journal-verify and keep the directory as it is.");
            if (check.HasJournal)
            {
                tailFile = segments[i];
                tail = check;
                break;
            }
        }

        PreviousSegment? previous = null;
        var previousUnsealed = false;
        if (tail != null)
        {
            var head = tail.Head!;
            var summary = tail.Segments[^1];
            if (!string.Equals(head.InstanceId, _options.InstanceId, StringComparison.Ordinal))
                throw new JournalUnavailableException(
                    $"The journal in '{_options.Directory}' belongs to instance {head.InstanceId}, not to this one ({_options.InstanceId}); the signer does not append to it.")
                {
                    OtherInstanceId = head.InstanceId,
                };

            _seq = head.Seq;
            _prev = head.Hash;
            _block = head.Key!;
            _blockSystemPublicKey = head.SystemPublicKey;
            _lastIncarnationOnDisk = head.Incarnation;
            // From the tail's own records; for a journal written before segments carried it, from the first segment.
            _genesisHash = head.GenesisHash ?? JournalHead.GenesisOfFirstSegment(segments);
            // The newest checkpoint on disk is this journal's last checkpoint until this start makes one.
            // Without it a start that has recorded nothing yet reported no checkpoint at all, and whoever
            // reads the journal's state (the health check, the hub's inventory) saw its age as unknown.
            if (head.Checkpoint is { } onDisk)
            {
                _lastCheckpointAt = JournalFormat.FromMicros(onDisk.At);
                _lastCheckpointSeq = onDisk.Seq;
            }
            if (!begin)
            {
                // Nothing to record yet, so no segment is begun. The directory is still tested for
                // taking a new file, which is what the first record will need: a journal that cannot
                // be appended to is then known at the start and not at the first failed write. The
                // probe file is removed, and the directory is otherwise left exactly as it was found.
                files.ProbeWritable(_options.Directory);
                _uncheckpointed = 0;
                _deferred = null;
                _buffer.SetLength(0);
                _fault = null;
                _lastFailedOpenAt = -1;
                _dormant = true;
                _dormantWouldDefer = WouldDeferKeyChange();
                if (_dormantWouldDefer)
                {
                    DeferDeadline();
                    _options.Log?.Invoke("The journal's system key changed and the key before it is not held; a restore marker from the node is waited for before the change is recorded.");
                }
                return;
            }

            var sealedName = JournalFormat.SealedName(tailFile!.FirstSeq);
            foreach (var open in segments.Where(s => s.Open && s.FirstSeq <= tailFile.FirstSeq))
            {
                var target = Path.Combine(_options.Directory, JournalFormat.SealedName(open.FirstSeq));
                files.Rename(open.Path, target, overStub: IsStub(target));
                if (open.FirstSeq == tailFile.FirstSeq && !summary.EndsWithSeal)
                    _options.Log?.Invoke($"The journal segment {open.Name} was not sealed when the signer last stopped{(summary.Torn ? ", and ends in a torn record" : string.Empty)}; it was renamed as it is.");
            }
            previous = new PreviousSegment(sealedName, summary.WholeBytes, summary.LastSeq, summary.LastHash, summary.EndsWithSeal);
            previousUnsealed = !summary.EndsWithSeal;
        }
        else
        {
            _seq = 0;
            _prev = new byte[JournalFormat.HashLength];
            _block = JournalSignatures.MakeKeyBlock(_options.InstanceId, _options.CheckpointKey.PublicKey, _options.SystemKey);
            _blockSystemPublicKey = _options.SystemKey.PublicKey;
            _lastIncarnationOnDisk = null;
            _genesisHash = null;
        }

        _uncheckpointed = 0;
        _deferred = null;
        _buffer.SetLength(0);
        BeginSegment(previous, newJournal: tail == null, start: _options.WriteStart && !_startWritten, previousUnsealed);
        FlushBuffer();
        _startWritten = true;
        _fault = null;
        _lastFailedOpenAt = -1;
    }

    private byte[]? _lastIncarnationOnDisk;
    private byte[]? _genesisHash;

    /// <summary>
    /// Creates the next open segment and places its opening records in the batch: the
    /// <c>SegmentStart</c>, a <c>Genesis</c> for a new journal, a <c>Start</c> at a start of the
    /// signer, the key change if the signer's key is not the one in force, and a checkpoint.
    /// </summary>
    private void BeginSegment(PreviousSegment? previous, bool newJournal, bool start, bool previousUnsealed)
    {
        _segmentFirstSeq = _seq + 1;
        var name = JournalFormat.OpenName(_segmentFirstSeq);
        _openPath = Path.Combine(_options.Directory, name);
        _file = _options.Files.Create(_openPath, overStub: IsStub(_openPath));
        _segmentBytes = 0;
        _segmentActivity = 0;
        _segmentOpenedAt = Stopwatch.GetTimestamp();

        // Every SegmentStart but the journal's first states the hash of the Genesis record.
        Place(RecordType.SegmentStart, 0, _ => new SegmentStartPayload(_options.InstanceId, _block, previous, _blockSystemPublicKey, newJournal ? null : _genesisHash).Encode(), activity: false);
        if (newJournal)
            _genesisHash = Place(RecordType.Genesis, 0, _ => new GenesisPayload(_options.InstanceId, _block, GenesisReason.FirstStart, null, _options.Version, _blockSystemPublicKey).Encode(), activity: false).Hash;
        if (start)
            Place(RecordType.Start, 0, _ => new StartPayload(_options.Version, previousUnsealed).Encode(), activity: false);
        if (!newJournal)
            ReconcileKey();
        if (_deferred == null)
            PlaceCheckpoint();
    }

    /// <summary>
    /// Compares the signer's checkpoint key and system key with the block in force and writes
    /// the change, in the form the keys the signer holds allow.
    /// </summary>
    private void ReconcileKey()
    {
        var checkpointKey = _options.CheckpointKey;
        var systemKey = _options.SystemKey;
        var systemKeyHash = JournalSignatures.KeyHash(systemKey.PublicKey);
        var sameKey = checkpointKey.PublicKey.AsSpan().SequenceEqual(_block.Key);
        var sameSystemKey = systemKeyHash.AsSpan().SequenceEqual(_block.SystemKey);
        if (sameKey && sameSystemKey)
            return;

        var newBlock = JournalSignatures.MakeKeyBlock(_options.InstanceId, checkpointKey.PublicKey, systemKey);
        byte[]? oldKeySignature = null;
        string? oldKeyAlgorithm = null;
        if (!sameKey && _options.FindHeldKey?.Invoke(JournalSignatures.KeyHash(_block.Key)) is { } oldKey)
        {
            oldKeySignature = oldKey.Sign(JournalSignatures.CheckpointKeyChangedMessage(_options.InstanceId, newBlock.Key));
            oldKeyAlgorithm = oldKey.Algorithm;
        }

        if (sameSystemKey)
        {
            PlaceKeyChange(new CheckpointKeyChangedPayload(newBlock, oldKeySignature, oldKeyAlgorithm, SystemPublicKey: systemKey.PublicKey));
            _options.Log?.Invoke("The journal's checkpoint key changed; the system key signed the new one.");
            return;
        }

        if (_options.FindHeldKey?.Invoke(_block.SystemKey) is { } oldSystemKey)
        {
            PlaceKeyChange(new CheckpointKeyChangedPayload(newBlock, oldKeySignature, oldKeyAlgorithm,
                oldSystemKey.Sign(JournalSignatures.SystemKeyChangedMessage(_options.InstanceId, newBlock.SystemKey)), oldSystemKey.Algorithm,
                SystemPublicKey: systemKey.PublicKey));
            _options.Log?.Invoke("The journal's system key changed; the system key before it signed the new one.");
            return;
        }

        if (_lastIncarnationOnDisk != null && !_lastIncarnationOnDisk.AsSpan().SequenceEqual(_options.Incarnation))
        {
            PlaceKeyChange(new CheckpointKeyChangedPayload(newBlock, oldKeySignature, oldKeyAlgorithm,
                Explains: new ChangeExplanation(ExplanationKind.ChangedIncarnation, OldIncarnation: _lastIncarnationOnDisk, NewIncarnation: _options.Incarnation),
                SystemPublicKey: systemKey.PublicKey));
            _options.Log?.Invoke("The journal's system key changed and the key before it is not held; the changed incarnation is recorded as what explains it.");
            return;
        }

        // Neither the old key nor a changed incarnation: wait for the node's RestoreMarker.
        _deferred = new DeferredKeyChange(newBlock, oldKeySignature, oldKeyAlgorithm, DeferDeadline());
        _options.Log?.Invoke("The journal's system key changed and the key before it is not held; records are taken, and no checkpoint is written until a restore explains it or the wait is over.");
    }

    /// <summary>
    /// Whether <see cref="ReconcileKey"/> would wait for a <c>RestoreMarker</c>: the system key
    /// is not the one in force, the signer does not hold the one that is, and the incarnation
    /// has not changed.
    /// </summary>
    private bool WouldDeferKeyChange()
    {
        var systemKeyHash = JournalSignatures.KeyHash(_options.SystemKey.PublicKey);
        if (systemKeyHash.AsSpan().SequenceEqual(_block.SystemKey))
            return false;
        if (_options.FindHeldKey?.Invoke(_block.SystemKey) != null)
            return false;
        return _lastIncarnationOnDisk == null || _lastIncarnationOnDisk.AsSpan().SequenceEqual(_options.Incarnation);
    }

    /// <summary>
    /// When the wait for a <c>RestoreMarker</c> ends. It is counted once, from the moment this
    /// writer first saw the unexplained change, and not again when a segment is begun or begun
    /// again after a failure.
    /// </summary>
    private long DeferDeadline()
    {
        if (_deferDeadline is long known)
            return known;
        _deferUntil = _options.Clock() + _options.UnexplainedKeyChangeWait;
        _deferDeadline = Stopwatch.GetTimestamp() + Ticks(_options.UnexplainedKeyChangeWait);
        return _deferDeadline.Value;
    }

    private void Publish()
    {
        var available = _file != null || _dormant;
        var waiting = _deferred != null || (_dormant && _dormantWouldDefer);
        _status = new JournalStatus(available, available ? null : _fault, _seq, _prev, _lastCheckpointAt, _lastCheckpointSeq,
            _uncheckpointed, _directoryBytes, _openPath != null && _file != null ? Path.GetFileName(_openPath) : null,
            waiting && _deferDeadline is long deadline && Stopwatch.GetTimestamp() < deadline ? _deferUntil : null);
    }
}
