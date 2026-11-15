namespace ModularCA.Journal;

/// <summary>The first fault a verification found: where, and what.</summary>
/// <param name="Segment">The segment file's name.</param>
/// <param name="Seq">The sequence of the record at fault, or the one that was expected there.</param>
/// <param name="Reason">What does not hold.</param>
public sealed record JournalFault(string Segment, ulong Seq, string Reason)
{
    /// <inheritdoc />
    public override string ToString() => $"{Segment}, sequence {Seq}: {Reason}";
}

/// <summary>
/// A key change the key before did not sign. The chain holds across it, and it is not believed
/// on the journal's word: whoever verifies matches what explains it against a restore or a
/// roll-back they know of, from outside the journal.
/// </summary>
/// <param name="Segment">The segment file's name.</param>
/// <param name="Seq">The <c>CheckpointKeyChanged</c> record's sequence.</param>
/// <param name="Explains">What the record says explains the change.</param>
/// <param name="NewSystemKey">SHA-256 of the system key the new block names.</param>
public sealed record UnvouchedKeyChange(string Segment, ulong Seq, ChangeExplanation Explains, byte[] NewSystemKey);

/// <summary>One segment, as a verification or the head command reports it.</summary>
/// <param name="Name">The file's name.</param>
/// <param name="Open">Whether the name is the open form.</param>
/// <param name="WholeBytes">The bytes of whole records.</param>
/// <param name="FirstSeq">Its first record's sequence; 0 when it holds none.</param>
/// <param name="LastSeq">Its last whole record's sequence; 0 when it holds none.</param>
/// <param name="LastHash">Its last whole record's hash; empty when it holds none.</param>
/// <param name="Torn">Whether bytes follow the whole records.</param>
/// <param name="EndsWithSeal">Whether its last whole record is a <c>Seal</c>.</param>
public sealed record SegmentSummary(string Name, bool Open, long WholeBytes, ulong FirstSeq, ulong LastSeq, byte[] LastHash, bool Torn, bool EndsWithSeal);

/// <summary>The newest checkpoint in what was read.</summary>
/// <param name="Seq">The checkpoint record's sequence.</param>
/// <param name="Hash">The hash its signature covers with <paramref name="Seq"/>: the record's <c>prev</c>.</param>
/// <param name="KeyHash">SHA-256 of the public key that signed.</param>
/// <param name="Algorithm">The signature algorithm.</param>
/// <param name="Signature">The signature.</param>
/// <param name="At">The checkpoint record's time, microseconds since 1970-01-01 UTC.</param>
public sealed record CheckpointInfo(ulong Seq, byte[] Hash, byte[] KeyHash, string Algorithm, byte[] Signature, long At);

/// <summary>What a verification found.</summary>
public sealed class JournalVerification
{
    /// <summary>The first fault, or null when everything read holds.</summary>
    public JournalFault? Fault { get; init; }

    /// <summary>Whether the directory holds a journal at all: at least one whole record.</summary>
    public bool HasJournal { get; init; }

    /// <summary>The segments read, oldest first.</summary>
    public IReadOnlyList<SegmentSummary> Segments { get; init; } = Array.Empty<SegmentSummary>();

    /// <summary>How many records were checked.</summary>
    public long Records { get; init; }

    /// <summary>How many checkpoint signatures were verified.</summary>
    public long Checkpoints { get; init; }

    /// <summary>The key changes the key before did not sign, for matching from outside.</summary>
    public IReadOnlyList<UnvouchedKeyChange> Unvouched { get; init; } = Array.Empty<UnvouchedKeyChange>();

    /// <summary>
    /// The changes of system key that nothing signed for and nothing explains, read past because
    /// <see cref="JournalVerifyOptions.TolerateUnexplainedKeyChange"/> was set; each would
    /// otherwise have been the fault.
    /// </summary>
    public IReadOnlyList<JournalFault> Unexplained { get; init; } = Array.Empty<JournalFault>();

    /// <summary>What could not be checked and why, without being a fault: for instance a key block whose system public key the journal does not carry.</summary>
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();

    /// <summary>The state at the last whole record read; null when no record was read.</summary>
    public JournalChainState? Head { get; init; }
}

/// <summary>Where a chain stands after the records checked so far.</summary>
public sealed class JournalChainState
{
    /// <summary>The instance identifier the journal names.</summary>
    public string InstanceId { get; internal set; } = string.Empty;

    /// <summary>The last record's sequence.</summary>
    public ulong Seq { get; internal set; }

    /// <summary>The last record's hash.</summary>
    public byte[] Hash { get; internal set; } = new byte[JournalFormat.HashLength];

    /// <summary>The last record's term.</summary>
    public ulong Term { get; internal set; }

    /// <summary>The last record's incarnation.</summary>
    public byte[] Incarnation { get; internal set; } = new byte[JournalFormat.HashLength];

    /// <summary>The newest incarnation that differs from <see cref="Incarnation"/>, or null when every record read carries the same.</summary>
    public byte[]? IncarnationBefore { get; internal set; }

    /// <summary>The last record's time, microseconds since 1970-01-01 UTC.</summary>
    public long At { get; internal set; }

    /// <summary>The last record's type.</summary>
    public ushort LastType { get; internal set; }

    /// <summary>The checkpoint key block in force.</summary>
    public KeyBlock? Key { get; internal set; }

    /// <summary>The system key's public key, when the journal carried it for the block in force.</summary>
    public byte[]? SystemPublicKey { get; internal set; }

    /// <summary>The newest checkpoint read.</summary>
    public CheckpointInfo? Checkpoint { get; internal set; }

    /// <summary>
    /// The hash of the journal's <c>Genesis</c> record: from the record itself when the first
    /// segment was read, otherwise as the <c>SegmentStart</c> records read state it. Null for a
    /// journal whose segments do not carry it and whose first segment was not read.
    /// </summary>
    public byte[]? GenesisHash { get; internal set; }
}

/// <summary>How much a verification checks.</summary>
public sealed class JournalVerifyOptions
{
    /// <summary>Verify every checkpoint's signature. Off, only the newest checkpoint read is verified.</summary>
    public bool EveryCheckpoint { get; init; } = true;

    /// <summary>
    /// The first segment read may begin anywhere in the chain. Off, the first segment must begin
    /// the journal at sequence 1, so a removed first segment is a fault.
    /// </summary>
    public bool AllowMidChainStart { get; init; }

    /// <summary>SHA-256 of the system key the verifier expects the journal to begin under, or null to take the journal's own.</summary>
    public byte[]? ExpectedSystemKey { get; init; }

    /// <summary>The system key's public key (SubjectPublicKeyInfo), for a journal that does not carry it.</summary>
    public byte[]? SystemPublicKey { get; init; }

    /// <summary>
    /// Go on past a change of system key that neither the key before signed nor the record
    /// explains, listing it in <see cref="JournalVerification.Unexplained"/>, where it is
    /// otherwise the fault the reading stops at. The chain holds across such a record: what does
    /// not hold is its claim. The signer reads its own journal this way, so that one such record
    /// does not stop it from going on; the verify command does not.
    /// </summary>
    public bool TolerateUnexplainedKeyChange { get; init; }

    /// <summary>Called with each record once it has been checked, and the segment it is in, in order.</summary>
    public Action<SegmentFile, JournalRecord>? OnRecord { get; init; }

    /// <summary>Called as the reading goes on with the bytes of whole records read so far and the bytes of all the segments.</summary>
    public Action<long, long>? Progress { get; init; }
}

/// <summary>
/// Checks a journal offline, from its files: every record's hash, the sequence and the chain,
/// every checkpoint's signature, and each checkpoint key block's system-key signature. It
/// reports the first fault with its segment and sequence. What a reader does not know it treats
/// as the layout says: an unknown type is checked in the chain and skipped, an unknown payload
/// key or flag bit is ignored, and another <c>format</c> stops the reading and is said.
/// </summary>
public static class JournalVerifier
{
    /// <summary>Verifies every segment of <paramref name="directory"/>.</summary>
    public static JournalVerification Verify(string directory, JournalVerifyOptions? options = null)
        => Verify(JournalReader.ListSegments(directory), options ?? new JournalVerifyOptions());

    /// <summary>Verifies <paramref name="segments"/>, which must be in order, oldest first.</summary>
    public static JournalVerification Verify(IReadOnlyList<SegmentFile> segments, JournalVerifyOptions options)
    {
        ArgumentNullException.ThrowIfNull(segments);
        ArgumentNullException.ThrowIfNull(options);
        var run = new Run(options);
        JournalFault? fault = null;
        try
        {
            fault = run.Walk(segments);
        }
        catch (JournalFormatException ex)
        {
            fault = new JournalFault(ex.Segment, ex.Seq, ex.Reason);
        }
        catch (IOException ex)
        {
            fault = new JournalFault(run.CurrentSegment, run.State?.Seq + 1 ?? 0, $"the segment could not be read: {ex.Message}");
        }
        return new JournalVerification
        {
            Fault = fault,
            HasJournal = run.Records > 0,
            Segments = run.Segments,
            Records = run.Records,
            Checkpoints = run.CheckpointsVerified,
            Unvouched = run.Unvouched,
            Unexplained = run.Unexplained,
            Notes = run.Notes,
            Head = run.State,
        };
    }

    private sealed class Run
    {
        private readonly JournalVerifyOptions _options;
        private JournalRecord? _previous;
        private JournalRecord? _lastCheckpointRecord;
        private CheckpointPayload? _lastCheckpointPayload;
        private KeyBlock? _lastCheckpointKey;
        private bool _notedMissingSystemKey;
        private bool _startedMidChain;

        public Run(JournalVerifyOptions options) => _options = options;

        public JournalChainState? State { get; private set; }
        public List<SegmentSummary> Segments { get; } = new();
        public List<UnvouchedKeyChange> Unvouched { get; } = new();
        public List<JournalFault> Unexplained { get; } = new();
        public List<string> Notes { get; } = new();
        public long Records { get; private set; }
        public long CheckpointsVerified { get; private set; }
        public string CurrentSegment { get; private set; } = string.Empty;

        public JournalFault? Walk(IReadOnlyList<SegmentFile> segments)
        {
            long total = 0, before = 0;
            if (_options.Progress != null)
            {
                foreach (var segment in segments)
                {
                    try { total += new FileInfo(segment.Path).Length; }
                    catch (IOException) { /* renamed or gone: counted as nothing */ }
                }
                _options.Progress(0, total);
            }
            for (var i = 0; i < segments.Count; i++)
            {
                var file = segments[i];
                CurrentSegment = file.Name;
                if (file.Open && i != segments.Count - 1)
                    return new JournalFault(file.Name, file.FirstSeq, "an open segment is followed by another segment; at most the newest is open");

                // What the next segment says of this one bounds what is read of it.
                PreviousSegment? stated = null;
                if (i + 1 < segments.Count)
                {
                    var next = JournalReader.Read(segments[i + 1], (_, _) => false);
                    if (next.First is { Type: RecordType.SegmentStart } start)
                    {
                        try { stated = SegmentStartPayload.Decode(start.Payload).Previous; }
                        catch (FormatException) { /* reported when that segment is walked */ }
                    }
                }

                JournalFault? fault = null;
                var firstOfSegment = true;
                var afterSeal = false;
                var reported = 0L;
                var scan = JournalReader.Read(file, (record, offset) =>
                {
                    if (afterSeal)
                    {
                        fault = new JournalFault(file.Name, record.Seq, "a record follows the Seal of its segment");
                        return false;
                    }
                    fault = Accept(file, record, firstOfSegment);
                    firstOfSegment = false;
                    afterSeal = record.Type == RecordType.Seal;
                    if (fault == null)
                    {
                        _options.OnRecord?.Invoke(file, record);
                        // Said about every megabyte: often enough to be watched, seldom enough to cost nothing.
                        if (_options.Progress != null && offset - reported >= 1 << 20)
                        {
                            reported = offset;
                            _options.Progress(before + offset, total);
                        }
                    }
                    return fault == null;
                }, stated?.WholeBytes);
                if (fault != null)
                    return fault;
                before += scan.WholeBytes;
                _options.Progress?.Invoke(i == segments.Count - 1 ? total : Math.Min(before, total), total);
                if (scan.Torn)
                    Notes.Add($"{file.Name} holds {scan.FileLength - scan.WholeBytes} bytes after its last whole record; they are no part of the chain.");

                if (scan.Records == 0)
                {
                    // A file that holds no whole record: its creation was interrupted. It is no
                    // part of the chain; only the newest file may be one.
                    if (i != segments.Count - 1)
                        return new JournalFault(file.Name, file.FirstSeq, "the segment holds no whole record and is not the newest");
                    Segments.Add(new SegmentSummary(file.Name, file.Open, 0, 0, 0, Array.Empty<byte>(), scan.Torn, false));
                    continue;
                }

                Segments.Add(new SegmentSummary(file.Name, file.Open, scan.WholeBytes, scan.First!.Seq, scan.Last!.Seq, scan.Last.Hash, scan.Torn, scan.EndsWithSeal));
                if (stated != null)
                {
                    if (!string.Equals(stated.Name, file.Name, StringComparison.Ordinal)
                        && !string.Equals(stated.Name, JournalFormat.SealedName(file.FirstSeq), StringComparison.Ordinal))
                        return new JournalFault(segments[i + 1].Name, segments[i + 1].FirstSeq, $"its SegmentStart names the previous segment '{stated.Name}', and the segment before it is '{file.Name}'");
                    if (stated.WholeBytes != scan.WholeBytes)
                        return new JournalFault(file.Name, scan.Last.Seq + 1, $"the segment holds {scan.WholeBytes} bytes of whole records and the next segment states {stated.WholeBytes}");
                    if (stated.LastSeq != scan.Last.Seq || !stated.LastHash.AsSpan().SequenceEqual(scan.Last.Hash))
                        return new JournalFault(file.Name, scan.Last.Seq, "the next segment states another last record for this segment than it holds");
                    if (stated.Sealed != scan.EndsWithSeal)
                        return new JournalFault(file.Name, scan.Last.Seq, "the next segment's statement of whether this segment ended with a Seal does not match it");
                }
            }

            // The newest checkpoint is verified even when not every one is.
            if (!_options.EveryCheckpoint && _lastCheckpointRecord != null && State != null)
            {
                var fault = VerifyCheckpoint(CurrentSegment, _lastCheckpointRecord, _lastCheckpointPayload!, _lastCheckpointKey!);
                if (fault != null)
                    return fault;
            }
            return null;
        }

        private JournalFault? Accept(SegmentFile file, JournalRecord record, bool firstOfSegment)
        {
            Records++;
            if (firstOfSegment && record.Seq != file.FirstSeq)
                return new JournalFault(file.Name, record.Seq, $"the segment's name states first sequence {file.FirstSeq} and its first record has {record.Seq}");

            if (_previous == null)
            {
                if (!_options.AllowMidChainStart && (record.Seq != 1 || !IsZero(record.Prev)))
                    return new JournalFault(file.Name, record.Seq, "the first segment does not begin the journal at sequence 1; earlier records are missing");
                _startedMidChain = record.Seq != 1;
            }
            else
            {
                if (record.Seq != _previous.Seq + 1)
                    return new JournalFault(file.Name, _previous.Seq + 1, $"sequence {record.Seq} follows {_previous.Seq}; a record is missing or out of place");
                if (!record.Prev.AsSpan().SequenceEqual(_previous.Hash))
                    return new JournalFault(file.Name, record.Seq, "the record does not carry the hash of the record before it");
            }

            if (firstOfSegment && record.Type != RecordType.SegmentStart)
                return new JournalFault(file.Name, record.Seq, $"the segment's first record is a {RecordType.Name(record.Type)}, not a SegmentStart");

            var state = State ??= new JournalChainState();
            JournalFault? fault = null;
            try
            {
                fault = record.Type switch
                {
                    RecordType.SegmentStart => AcceptSegmentStart(file, record, state, firstOfSegment),
                    RecordType.Genesis => AcceptGenesis(file, record, state),
                    RecordType.Checkpoint => AcceptCheckpoint(file, record, state),
                    RecordType.CheckpointKeyChanged => AcceptKeyChange(file, record, state),
                    _ => null,
                };
            }
            catch (FormatException ex)
            {
                fault = new JournalFault(file.Name, record.Seq, $"the {RecordType.Name(record.Type)} payload does not decode: {ex.Message}");
            }
            if (fault != null)
                return fault;

            if (_previous != null && !record.Incarnation.AsSpan().SequenceEqual(_previous.Incarnation))
                state.IncarnationBefore = _previous.Incarnation;
            state.Seq = record.Seq;
            state.Hash = record.Hash;
            state.Term = record.Term;
            state.Incarnation = record.Incarnation;
            state.At = record.At;
            state.LastType = record.Type;
            _previous = record;
            return null;
        }

        private JournalFault? AcceptSegmentStart(SegmentFile file, JournalRecord record, JournalChainState state, bool firstOfSegment)
        {
            if (!firstOfSegment)
                return new JournalFault(file.Name, record.Seq, "a SegmentStart is not the first record of its segment");
            var payload = SegmentStartPayload.Decode(record.Payload);
            if (state.Key == null)
            {
                // The first record read: the journal's own statement of who it is.
                state.InstanceId = payload.InstanceId;
                if (_options.ExpectedSystemKey is { } expected && !expected.AsSpan().SequenceEqual(payload.CheckpointKey.SystemKey))
                    return new JournalFault(file.Name, record.Seq, "the checkpoint key block names another system key than the one expected");
                state.SystemPublicKey = payload.SystemPublicKey ?? _options.SystemPublicKey;
                state.Key = payload.CheckpointKey;
                state.GenesisHash = payload.GenesisHash;
                return VerifyBlock(file.Name, record.Seq, payload.CheckpointKey, state);
            }
            if (!string.Equals(payload.InstanceId, state.InstanceId, StringComparison.Ordinal))
                return new JournalFault(file.Name, record.Seq, "the SegmentStart names another instance than the journal began with");
            if (!payload.CheckpointKey.SameAs(state.Key))
                return new JournalFault(file.Name, record.Seq, "the SegmentStart carries another checkpoint key block than the one in force");
            // The Genesis hash a SegmentStart states is the hash of the Genesis record read, when
            // the first segment was read, and otherwise what the SegmentStart records before it stated.
            if (payload.GenesisHash != null)
            {
                if (state.GenesisHash != null && !payload.GenesisHash.AsSpan().SequenceEqual(state.GenesisHash))
                    return new JournalFault(file.Name, record.Seq, "the SegmentStart states another Genesis record than the journal's");
                state.GenesisHash = payload.GenesisHash;
            }
            return null;
        }

        private static JournalFault? AcceptGenesis(SegmentFile file, JournalRecord record, JournalChainState state)
        {
            var payload = GenesisPayload.Decode(record.Payload);
            state.GenesisHash = record.Hash;
            if (!string.Equals(payload.InstanceId, state.InstanceId, StringComparison.Ordinal))
                return new JournalFault(file.Name, record.Seq, "the Genesis names another instance than the segment it is in");
            if (state.Key != null && !payload.CheckpointKey.SameAs(state.Key))
                return new JournalFault(file.Name, record.Seq, "the Genesis carries another checkpoint key block than the one in force");
            return null;
        }

        private JournalFault? AcceptCheckpoint(SegmentFile file, JournalRecord record, JournalChainState state)
        {
            var payload = CheckpointPayload.Decode(record.Payload);
            if (state.Key == null)
                return new JournalFault(file.Name, record.Seq, "a Checkpoint precedes any checkpoint key");
            if (!payload.KeyHash.AsSpan().SequenceEqual(JournalSignatures.KeyHash(state.Key.Key)))
                return new JournalFault(file.Name, record.Seq, "the Checkpoint is signed by another key than the checkpoint key in force");
            _lastCheckpointRecord = record;
            _lastCheckpointPayload = payload;
            _lastCheckpointKey = state.Key;
            state.Checkpoint = new CheckpointInfo(record.Seq, record.Prev, payload.KeyHash, payload.Algorithm, payload.Signature, record.At);
            return _options.EveryCheckpoint ? VerifyCheckpoint(file.Name, record, payload, state.Key) : null;
        }

        private JournalFault? VerifyCheckpoint(string segment, JournalRecord record, CheckpointPayload payload, KeyBlock key)
        {
            var message = JournalSignatures.CheckpointMessage(State!.InstanceId, record.Seq, record.Prev);
            if (!JournalSignatures.Verify(key.Key, payload.Algorithm, message, payload.Signature))
                return new JournalFault(segment, record.Seq, "the Checkpoint's signature does not verify under the checkpoint key in force");
            CheckpointsVerified++;
            return null;
        }

        private JournalFault? VerifyBlock(string segment, ulong seq, KeyBlock block, JournalChainState state)
        {
            if (state.SystemPublicKey == null)
            {
                if (!_notedMissingSystemKey)
                {
                    _notedMissingSystemKey = true;
                    Notes.Add("The journal does not carry the system key's public key, and none was given, so the checkpoint key block's system signature was not checked.");
                }
                return null;
            }
            return JournalSignatures.VerifyKeyBlock(block, state.InstanceId, state.SystemPublicKey)
                ? null
                : new JournalFault(segment, seq, "the checkpoint key block's system signature does not verify under the system key it names");
        }

        private JournalFault? AcceptKeyChange(SegmentFile file, JournalRecord record, JournalChainState state)
        {
            var payload = CheckpointKeyChangedPayload.Decode(record.Payload);
            if (state.Key == null)
                return new JournalFault(file.Name, record.Seq, "a CheckpointKeyChanged precedes any checkpoint key");
            var old = state.Key;
            var block = payload.NewKey;
            var sameSystemKey = block.SystemKey.AsSpan().SequenceEqual(old.SystemKey);
            var oldSystemPublicKey = state.SystemPublicKey;

            if (payload.OldKeySignature != null
                && !JournalSignatures.Verify(old.Key, payload.OldKeyAlgorithm,
                    JournalSignatures.CheckpointKeyChangedMessage(state.InstanceId, block.Key), payload.OldKeySignature))
                return new JournalFault(file.Name, record.Seq, "the old checkpoint key's signature over the new key does not verify");

            if (sameSystemKey)
            {
                // The same system key signs the new block: that is the key before vouching for it.
                state.SystemPublicKey = payload.SystemPublicKey ?? oldSystemPublicKey;
                state.Key = block;
                return VerifyBlock(file.Name, record.Seq, block, state);
            }

            // Another system key. The new block must verify under the key it names, which the
            // record has to carry; then either the old system key signed the new one, or the
            // record says what explains the change.
            if (payload.SystemPublicKey == null
                || !JournalSignatures.KeyHash(payload.SystemPublicKey).AsSpan().SequenceEqual(block.SystemKey))
                return new JournalFault(file.Name, record.Seq, "the CheckpointKeyChanged names a new system key and does not carry its public key");
            if (!JournalSignatures.VerifyKeyBlock(block, state.InstanceId, payload.SystemPublicKey))
                return new JournalFault(file.Name, record.Seq, "the new checkpoint key block's system signature does not verify under the system key it names");

            if (payload.OldSystemKeySignature != null)
            {
                if (oldSystemPublicKey == null)
                {
                    Notes.Add($"Sequence {record.Seq}: the old system key's public key is not known, so its signature over the new system key was not checked.");
                }
                else if (!JournalSignatures.Verify(oldSystemPublicKey, payload.OldSystemKeyAlgorithm,
                             JournalSignatures.SystemKeyChangedMessage(state.InstanceId, block.SystemKey), payload.OldSystemKeySignature))
                {
                    return new JournalFault(file.Name, record.Seq, "the old system key's signature over the new system key does not verify");
                }
            }
            else
            {
                var explains = payload.Explains;
                if (explains == null)
                {
                    var unexplained = new JournalFault(file.Name, record.Seq, "the system key changed, the key before did not sign the change, and the record says nothing that explains it");
                    if (!_options.TolerateUnexplainedKeyChange)
                        return unexplained;
                    Unexplained.Add(unexplained);
                    state.SystemPublicKey = payload.SystemPublicKey;
                    state.Key = block;
                    return null;
                }
                switch (explains.Kind)
                {
                    case ExplanationKind.Restore:
                        if (_previous is not { Type: RecordType.RestoreMarker })
                            return new JournalFault(file.Name, record.Seq, "the key change names a restore, and the record directly before it is not a RestoreMarker");
                        var marker = RestoreMarkerPayload.Decode(_previous.Payload);
                        if (!string.Equals(marker.Archive, explains.Archive, StringComparison.Ordinal)
                            || !string.Equals(marker.ArchiveInstanceId, explains.ArchiveInstanceId, StringComparison.Ordinal)
                            || marker.ArchiveCreatedAt != explains.ArchiveCreatedAt)
                            return new JournalFault(file.Name, record.Seq, "the key change names another restore than the RestoreMarker directly before it");
                        break;
                    case ExplanationKind.ChangedIncarnation:
                        if (explains.NewIncarnation == null || explains.OldIncarnation == null
                            || !explains.NewIncarnation.AsSpan().SequenceEqual(record.Incarnation)
                            || explains.NewIncarnation.AsSpan().SequenceEqual(explains.OldIncarnation))
                            return new JournalFault(file.Name, record.Seq, "the key change names a changed incarnation, and its hashes are not the record's own and a different one");
                        var before = _previous != null && !_previous.Incarnation.AsSpan().SequenceEqual(record.Incarnation)
                            ? _previous.Incarnation
                            : state.IncarnationBefore;
                        if (before == null && _startedMidChain)
                        {
                            // The reading began after the records that carried the old incarnation
                            // (the newest segment alone, where the change is among its first
                            // records): there is nothing here to hold the claim to.
                            Notes.Add($"Sequence {record.Seq}: the key change names a changed incarnation, and the records before it are not among those read, so the old one was not checked.");
                        }
                        else if (before == null || !before.AsSpan().SequenceEqual(explains.OldIncarnation))
                            return new JournalFault(file.Name, record.Seq, "the key change names a changed incarnation, and the records before it do not carry the old one");
                        break;
                    default:
                        return new JournalFault(file.Name, record.Seq, $"the key change gives an explanation of a kind ({explains.Kind}) this reader does not know");
                }
                Unvouched.Add(new UnvouchedKeyChange(file.Name, record.Seq, explains, block.SystemKey));
            }

            state.SystemPublicKey = payload.SystemPublicKey;
            state.Key = block;
            return null;
        }

        private static bool IsZero(ReadOnlySpan<byte> bytes)
        {
            foreach (var b in bytes)
                if (b != 0)
                    return false;
            return true;
        }
    }
}
