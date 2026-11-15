using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using ModularCA.Journal;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace ModularCA.Keystore.Signing;

/// <summary>What the signer's journal is opened with, as the host resolved it.</summary>
/// <param name="Directory">The journal's home, absolute: the directory that holds <c>current/</c> and the set-aside journals.</param>
/// <param name="Enforce">Whether the two checks refuse what they find, or sign and log.</param>
/// <param name="Version">The product version, written into records.</param>
/// <param name="Incarnation">SHA-256 of the incarnation value; all zero when none is set.</param>
/// <param name="LowSpaceBytes">Free space on the journal's volume below which it is reported as low; 0 for never.</param>
/// <param name="CriticalSpaceBytes">Free space below which it is reported as nearly full; 0 for never. Neither stops the signer: only a write that fails does.</param>
public sealed record SignerJournalSettings(string Directory, bool Enforce, string Version, byte[] Incarnation,
    long LowSpaceBytes = 1L << 30, long CriticalSpaceBytes = 128L << 20);

/// <summary>A CRL as the journal's checks and records see it.</summary>
/// <param name="Number">The CRL number.</param>
/// <param name="Delta">Whether it carries a delta CRL indicator.</param>
/// <param name="ThisUpdate">Its thisUpdate.</param>
/// <param name="NextUpdate">Its nextUpdate, when it has one.</param>
/// <param name="Entries">The serials it lists (hex, no leading zeros, lower case) with their reason codes.</param>
/// <param name="SetHash">SHA-256 over its entries' encodings in sorted order: equal for two CRLs that list the same revoked set.</param>
/// <param name="RevocationDates">The revocation date of each serial in <paramref name="Entries"/>.</param>
public sealed record JournaledCrl(long Number, bool Delta, DateTime ThisUpdate, DateTime? NextUpdate, IReadOnlyDictionary<string, int> Entries, byte[] SetHash,
    IReadOnlyDictionary<string, DateTime> RevocationDates);

/// <summary>What the journal says of a CRL before it is signed.</summary>
/// <param name="Crl">The CRL as parsed, or null when it could not be.</param>
/// <param name="Refusal">Why it does not continue the journaled one, or null.</param>
/// <param name="Dropped">
/// Serials the newest journaled full CRL of this CA key lists, that were not on hold there, and
/// that this CRL leaves out. Each has to be shown to be expired before the CRL is signed.
/// </param>
public sealed record CrlJudgement(JournaledCrl? Crl, string? Refusal, IReadOnlyList<string> Dropped);

/// <summary>A CRL offered for a record does not continue the journaled one; raised where the record is placed, after any other CRL of that key.</summary>
public sealed class JournalCheckException(string message) : Exception(message);

/// <summary>
/// The signer's side of its issuance journal: it opens the writer, turns what the signer signed
/// into records, keeps in memory the newest CRL journaled for each CA key, and makes the two
/// checks only the signer can make. See <c>docs/architecture/signer-journal.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The CRL check.</b> A CRL for a CA key must carry a CRL number above every number the
/// journal holds for that key, full and delta sharing one sequence as the node numbers them.
/// A full CRL must list every serial the newest journaled full CRL listed, except a serial that
/// was on hold there (releasing a hold takes it off the list) and a serial the caller shows to
/// be expired. A delta CRL is held to the number only. A CA key with no journaled CRL has no
/// predecessor, so its first CRL is not checked.
/// </para>
/// <para>
/// <b>The OCSP check.</b> A response that says "good" for a serial is refused when the newest
/// journaled full CRL of that CA key, or a delta CRL journaled after it, lists the serial with a
/// reason other than certificateHold or removeFromCRL, and when the last revocation fact the
/// node recorded for the serial after that CRL says it is revoked and no release followed.
/// </para>
/// <para>
/// The newest CRL of each key is found by reading the journal's CRL records once after it
/// opens, in the background; both checks wait for that reading.
/// </para>
/// </remarks>
public sealed class SignerJournal : IAsyncDisposable
{
    private const int ReasonCertificateHold = 6;
    private const int ReasonRemoveFromCrl = 8;
    private static readonly DerObjectIdentifier CrlNumberOid = X509Extensions.CrlNumber;

    private readonly Func<JournalWriterOptions> _options;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, CrlStream> _crls = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CrlRefusal> _refusals = new(StringComparer.Ordinal);
    private (long At, int Count, long Bytes) _setAside = (-1, 0, 0);
    private volatile JournalTrust _trust = JournalTrust.Pending;
    private JournalWriter? _writer;
    private Task _index = Task.CompletedTask;
    private Task _verification = Task.CompletedTask;
    private long _verifiedBytes = -1;
    private long _verifyTotalBytes = -1;
    private string? _fault;
    private long _lastAttempt = -1;

    /// <summary>
    /// Creates the journal and opens it. A journal that cannot be opened is logged as an error
    /// and tried again when a record is next offered; until then every record is refused.
    /// </summary>
    /// <param name="options">Builds the writer's options: the instance, the keys and the directory. Called at each attempt to open.</param>
    /// <param name="settings">The directory, the product version and whether the checks refuse.</param>
    /// <param name="logger">Logger.</param>
    public SignerJournal(Func<JournalWriterOptions> options, SignerJournalSettings settings, ILogger logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        Settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        try
        {
            Writer();
        }
        catch (JournalUnavailableException ex)
        {
            _logger.LogError("Signer journal: {Message} Certificates and CRLs are refused until the journal can be written.", ex.Message);
        }
    }

    /// <summary>The directory, the version and the checks' mode.</summary>
    public SignerJournalSettings Settings { get; }

    /// <summary>The writer, opened if it is not; a failed attempt is not repeated within five seconds.</summary>
    /// <exception cref="JournalUnavailableException">The journal cannot be opened.</exception>
    private JournalWriter Writer()
    {
        var writer = _writer;
        if (writer != null)
            return writer;
        lock (_gate)
        {
            if (_writer != null)
                return _writer;
            if (_lastAttempt >= 0 && Stopwatch.GetElapsedTime(_lastAttempt) < TimeSpan.FromSeconds(5))
                throw new JournalUnavailableException(_fault ?? "The journal is not open.");
            try
            {
                JournalWriter opened;
                var options = _options();
                try
                {
                    opened = JournalWriter.Open(options);
                }
                catch (JournalUnavailableException other) when (other.OtherInstanceId != null)
                {
                    SetAsideJournalOfAnotherInstance(other.OtherInstanceId);
                    options = _options();
                    opened = JournalWriter.Open(options);
                }
                var heldSystemKey = options.SystemKey.PublicKey;
                var instanceId = options.InstanceId;
                _trust = JournalTrust.Pending;
                Interlocked.Exchange(ref _verifiedBytes, -1);
                Interlocked.Exchange(ref _verifyTotalBytes, -1);
                // The index first, which is quick and is what the CRL and OCSP checks wait for;
                // then the verification of the whole journal, which only the merge waits for.
                var index = Task.Run(() => BuildIndex(opened.Directory));
                _index = index;
                _verification = index.ContinueWith(_ => VerifyAndVouch(opened.Directory, heldSystemKey, instanceId),
                    CancellationToken.None, TaskContinuationOptions.RunContinuationsAsynchronously, TaskScheduler.Default);
                _writer = opened;
                _fault = null;
                _logger.LogInformation("Signer journal open in {Directory} at sequence {Seq}.", opened.Directory, opened.Status.Seq);
                return opened;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _lastAttempt = Stopwatch.GetTimestamp();
                _fault = ex is JournalUnavailableException ? ex.Message : $"The journal could not be opened: {ex.GetType().Name}: {ex.Message}";
                throw ex as JournalUnavailableException ?? new JournalUnavailableException(_fault, ex);
            }
        }
    }

    /// <summary>
    /// Sets aside the journal of another instance found in <c>current/</c>, so that this
    /// instance begins its own. That is what a host is left with when an archive of one instance
    /// is restored onto a host that ran another, and after a factory reset of a journal the
    /// reset did not know: the keystores and the database are new, and the journal is still the
    /// other instance's. Nothing is deleted or changed in it: <c>&lt;home&gt;/current</c> is
    /// renamed, whole, to <c>&lt;home&gt;/set-aside-instance-&lt;tag&gt;-&lt;time&gt;</c>
    /// (<see cref="JournalLayout.SetAsideInstanceName"/>), and opening the journal again makes a
    /// new <c>current</c>. The home itself is not renamed, so it may be a mount point.
    /// </summary>
    /// <exception cref="JournalUnavailableException">The rename failed.</exception>
    private void SetAsideJournalOfAnotherInstance(string otherInstanceId)
    {
        var home = Settings.Directory;
        var name = JournalLayout.SetAsideInstanceName(otherInstanceId, DateTime.UtcNow);
        string? aside;
        try
        {
            aside = JournalLayout.SetAsideCurrent(home, name);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new JournalUnavailableException(
                $"The journal in '{JournalLayout.Current(home)}' belongs to instance {otherInstanceId}, not to this one, and could not be set aside as '{name}' in '{home}' ({ex.Message}). "
                + $"The signer must be able to rename directories inside '{home}'. Until it can, or until '{JournalLayout.CurrentName}' is renamed there by hand, the signer issues nothing.", ex);
        }
        _setAside = (-1, 0, 0);
        _logger.LogWarning(
            "Signer journal: '{Home}' held the journal of another instance ({Other}), which is what a restore of this instance's archive onto a host that ran that one leaves. "
            + "It was kept and set aside as '{Aside}', and this instance begins its own journal.", home, otherInstanceId, aside);
    }

    /// <summary>Whether a record can be taken now; a certificate or CRL is not signed when it cannot.</summary>
    /// <exception cref="JournalUnavailableException">The journal cannot take a record, with the reason.</exception>
    public void EnsureAvailable() => Writer();

    /// <summary>The journal as the signer reports it to the node.</summary>
    public SignerJournalInfo Info()
    {
        JournalStatus? status = null;
        string? fault = _fault;
        try
        {
            status = Writer().Status;
            fault = status.Fault;
        }
        catch (JournalUnavailableException ex)
        {
            fault = ex.Message;
        }

        long? free = null;
        long size = status?.DirectoryBytes ?? 0;
        var setAside = _setAside;
        try
        {
            // The set-aside journals change only when one is set aside; they are listed again once a minute.
            if (setAside.At < 0 || Stopwatch.GetElapsedTime(setAside.At) > TimeSpan.FromMinutes(1))
            {
                var (count, bytes) = JournalLayout.SetAside(Settings.Directory);
                _setAside = setAside = (Stopwatch.GetTimestamp(), count, bytes);
            }
            var directory = Settings.Directory;
            var probe = Directory.Exists(directory) ? directory : Path.GetDirectoryName(directory) ?? directory;
            free = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(Path.GetFullPath(probe))! : probe).AvailableFreeSpace;
            if (status == null && Directory.Exists(directory))
                size = JournalReader.ListSegments(directory).Sum(s => new FileInfo(s.Path).Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _logger.LogDebug(ex, "Signer journal: the free space of the journal's volume could not be read.");
        }

        return new SignerJournalInfo(
            Available: status?.Available ?? false,
            Fault: fault,
            Seq: status?.Seq ?? 0,
            Hash: Convert.ToHexStringLower(status?.Hash ?? new byte[JournalFormat.HashLength]),
            LastCheckpointAtUtc: status?.LastCheckpointAt?.UtcDateTime,
            UncheckpointedRecords: status?.Uncheckpointed ?? 0,
            SizeBytes: size,
            FreeBytes: free,
            AwaitingRestoreMarkerUntilUtc: status?.AwaitingRestoreMarkerUntil is { } until && until > DateTimeOffset.UtcNow ? until.UtcDateTime : null,
            LowSpaceBytes: Settings.LowSpaceBytes,
            CriticalSpaceBytes: Settings.CriticalSpaceBytes,
            SetAsideJournals: setAside.Count,
            SetAsideBytes: setAside.Bytes,
            RefusedCrls: _refusals
                .Select(r => new SignerJournalRefusedCrl(r.Value.CaId, r.Key, r.Value.Missing.Count, r.Value.At, r.Value.JournaledNumber))
                .OrderBy(r => r.CaKey, StringComparer.Ordinal)
                .ToList(),
            Verified: _trust.Ok,
            VerificationFault: _trust.Why,
            VerifiedBytes: Interlocked.Read(ref _verifiedBytes) is var done and >= 0 ? done : null,
            VerifyTotalBytes: Interlocked.Read(ref _verifyTotalBytes) is var total and >= 0 ? total : null);
    }

    /// <summary>
    /// Keeps the fact that a full CRL for a CA key was refused because it left out
    /// <paramref name="missing"/>, with every serial, so that the health answer can say so and
    /// the whole list can be read. It stands until a full CRL for the key is recorded.
    /// </summary>
    /// <param name="caPublicKey">The CA key's SubjectPublicKeyInfo.</param>
    /// <param name="caId">The CA's identifier, when there is one.</param>
    /// <param name="missing">The serials (hex, lower case) the CRL left out and nothing excuses.</param>
    public void NoteCrlRefused(byte[] caPublicKey, Guid? caId, IReadOnlyList<string> missing)
    {
        var key = Key(caPublicKey);
        var listed = new List<SignerJournalMissingSerial>(missing.Count);
        long number = -1;
        if (_crls.TryGetValue(key, out var stream))
        {
            lock (stream)
            {
                number = stream.Full?.Number ?? -1;
                foreach (var serial in missing)
                {
                    var reason = stream.Full != null && stream.Full.Entries.TryGetValue(serial, out var r) ? r : 0;
                    var at = stream.Full != null && stream.Full.RevocationDates.TryGetValue(serial, out var d) ? d : DateTime.UnixEpoch;
                    listed.Add(new SignerJournalMissingSerial(serial.ToUpperInvariant(), reason, at));
                }
            }
        }
        listed.Sort((a, b) => a.Serial.Length != b.Serial.Length ? a.Serial.Length.CompareTo(b.Serial.Length) : string.CompareOrdinal(a.Serial, b.Serial));
        _refusals[key] = new CrlRefusal(caId, DateTime.UtcNow, number, listed);
    }

    /// <summary>
    /// Every serial the last refused full CRL of <paramref name="caId"/> left out; null when no
    /// refusal stands for that CA.
    /// </summary>
    public SignerJournalMissingRevocations? MissingRevocations(Guid caId)
    {
        var found = _refusals.Values.Where(r => r.CaId == caId).OrderByDescending(r => r.At).FirstOrDefault();
        return found == null ? null : new SignerJournalMissingRevocations(caId, found.At, found.JournaledNumber, found.Missing);
    }

    /// <summary>
    /// Records a certificate the signer signed: the whole to-be-signed certificate and the
    /// signature, the index, and what the node passed with the request. Returns after the flush
    /// that covers the record.
    /// </summary>
    /// <param name="caId">The CA's identifier, when the signing key belongs to a registered CA.</param>
    /// <param name="signerPublicKey">The signing key's SubjectPublicKeyInfo.</param>
    /// <param name="caCertificate">The CA certificate current when this was signed, when there is one.</param>
    /// <param name="tbs">The to-be-signed certificate, parsed.</param>
    /// <param name="tbsBytes">Its bytes as signed.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="context">The signing context.</param>
    public Task<JournalAppended> RecordCertificateAsync(Guid? caId, byte[] signerPublicKey, byte[]? caCertificate,
        TbsCertificateStructure tbs, byte[] tbsBytes, byte[] signature, SigningContext context)
    {
        var shape = SignedDataTypes.Shape(tbs);
        var origin = context.Issuance;
        var payload = new CertificatePayload(
            Ca: caId?.ToString("D"),
            CaKey: SHA256.HashData(signerPublicKey),
            CaCert: caCertificate == null ? null : SHA256.HashData(caCertificate),
            Context: ContextOf(context),
            Version: Settings.Version,
            Tbs: tbsBytes,
            Signature: signature,
            Serial: tbs.SerialNumber.PositiveValue.ToByteArrayUnsigned(),
            NotBefore: JournalFormat.ToMicros(tbs.StartDate.ToDateTime().ToUniversalTime()),
            NotAfter: JournalFormat.ToMicros(tbs.EndDate.ToDateTime().ToUniversalTime()),
            SubjectKey: SHA256.HashData(shape.SubjectPublicKeyInfo),
            IsCa: shape.IsCa,
            Spent: Spent(origin),
            Answers: origin?.Answers is { } answers ? new Answers(answers.Kind, answers.Id) : null,
            Replaces: origin?.Replaces is { } replaces ? new Replaces(replaces.Serial, replaces.CaKey) : null,
            Belongs: Belongs(origin)).Encode();
        return Writer().AppendAsync(RecordType.Certificate, 0, payload);
    }

    /// <summary>Records an SSH certificate the signer signed: the whole certificate and what the node passed with the request.</summary>
    /// <param name="caId">The SSH CA's identifier.</param>
    /// <param name="caPublicKeyBlob">The SSH CA key's public key blob; its SHA-256 is the record's <c>caKey</c>.</param>
    /// <param name="certificate">The certificate blob as signed.</param>
    /// <param name="context">The signing context.</param>
    public Task<JournalAppended> RecordSshCertificateAsync(Guid? caId, byte[] caPublicKeyBlob, byte[] certificate, SigningContext context)
    {
        var origin = context.Issuance;
        var payload = new SshCertificatePayload(
            Ca: caId?.ToString("D"),
            CaKey: SHA256.HashData(caPublicKeyBlob),
            Context: ContextOf(context),
            Version: Settings.Version,
            Certificate: certificate,
            Spent: Spent(origin),
            Answers: origin?.Answers is { } answers ? new Answers(answers.Kind, answers.Id) : null,
            Replaces: origin?.Replaces is { } replaces ? new Replaces(replaces.Serial, replaces.CaKey) : null,
            Belongs: Belongs(origin)).Encode();
        return Writer().AppendAsync(RecordType.SshCertificate, 0, payload);
    }

    /// <summary>
    /// Records a fact the node asserts, with flag bit 0. The payload is checked against its type
    /// and re-encoded first.
    /// </summary>
    /// <exception cref="FormatException">The type is not a node fact, or the payload is not that fact's.</exception>
    public async Task<JournalAppended> RecordFactAsync(ushort type, byte[] payload)
    {
        var normalized = NodeFacts.Normalize(type, payload);
        var appended = await Writer().AppendAsync(type, JournalFormat.FlagNodeAsserted, normalized).ConfigureAwait(false);
        // A revocation or a released hold the signer has just recorded is part of what it can
        // give back to a node whose database has gone back in time.
        if (FactOf(type, appended.Seq, normalized, vouched: true) is { } fact)
        {
            var stream = _crls.GetOrAdd(fact.CaKey, _ => new CrlStream());
            lock (stream)
            {
                if (fact.Entry.Seq > (stream.Full?.RecordSeq ?? 0))
                    stream.Facts.Add(fact.Entry);
            }
        }
        return appended;
    }

    /// <summary>A <c>Revocation</c> or <c>Unrevocation</c> record as the revocation list of its CA key needs it; null for any other record.</summary>
    private static (string CaKey, RevocationFact Entry)? FactOf(ushort type, ulong seq, byte[] payload, bool vouched)
    {
        try
        {
            if (type == RecordType.Revocation)
            {
                var r = RevocationPayload.Decode(payload);
                return (Convert.ToHexStringLower(r.CaKey), new RevocationFact(seq, new BigInteger(1, r.Serial).ToString(16), Released: false,
                    (int)r.Reason, JournalFormat.FromMicros(r.Time).UtcDateTime, r.Form, vouched));
            }
            if (type == RecordType.Unrevocation)
            {
                var u = UnrevocationPayload.Decode(payload);
                return (Convert.ToHexStringLower(u.CaKey), new RevocationFact(seq, new BigInteger(1, u.Serial).ToString(16), Released: true,
                    0, JournalFormat.FromMicros(u.Time).UtcDateTime, 0, vouched));
            }
        }
        catch (FormatException)
        {
            // Not a payload this build reads: it says nothing here.
        }
        return null;
    }

    private static IReadOnlyList<SpentToken>? Spent(IssuanceOrigin? origin)
        => origin?.Spent is { Count: > 0 } spent ? spent.Select(s => new SpentToken(s.Kind, s.Id, s.Use)).ToList() : null;

    private static Belongs? Belongs(IssuanceOrigin? origin)
        => origin?.Belongs is { IsEmpty: false } b ? new Belongs(b.Profile, b.Space, b.OwnerKind, b.Owner, b.Template) : null;

    private static SigningContextInfo ContextOf(SigningContext context)
        => new(context.Purpose.ToString(), context.Issuance?.Protocol, context.Issuance?.Requester);

    /// <summary>
    /// Reads a to-be-signed CRL as the checks and the record need it, or says why it cannot be
    /// journaled: no CRL number, or one that is not a non-negative 63-bit integer.
    /// </summary>
    public static (JournaledCrl? Crl, string? Problem) Read(TbsCertificateList tbs)
    {
        ArgumentNullException.ThrowIfNull(tbs);
        var extensions = tbs.Extensions;
        var numberExtension = extensions?.GetExtension(CrlNumberOid);
        if (numberExtension == null)
            return (null, "The CRL carries no CRL number.");
        BigInteger number;
        try
        {
            number = DerInteger.GetInstance(numberExtension.GetParsedValue()).PositiveValue;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidCastException)
        {
            return (null, "The CRL's number is not a non-negative integer.");
        }
        if (number.BitLength > 63)
            return (null, "The CRL's number is larger than the journal records.");

        var entries = new Dictionary<string, int>(StringComparer.Ordinal);
        var dates = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        var encodings = new List<byte[]>();
        foreach (var entry in tbs.GetRevokedCertificates() ?? Array.Empty<CrlEntry>())
        {
            var reason = 0;
            var reasonExtension = entry.Extensions?.GetExtension(X509Extensions.ReasonCode);
            if (reasonExtension != null)
                reason = DerEnumerated.GetInstance(reasonExtension.GetParsedValue()).IntValueExact;
            var serial = entry.UserCertificate.PositiveValue.ToString(16);
            entries[serial] = reason;
            dates[serial] = entry.RevocationDate.ToDateTime().ToUniversalTime();
            encodings.Add(entry.GetEncoded(Asn1Encodable.Der));
        }
        encodings.Sort((a, b) => a.AsSpan().SequenceCompareTo(b));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var encoding in encodings)
            hash.AppendData(encoding);

        return (new JournaledCrl(
            number.LongValueExact,
            extensions!.GetExtension(X509Extensions.DeltaCrlIndicator) != null,
            tbs.ThisUpdate.ToDateTime().ToUniversalTime(),
            tbs.NextUpdate?.ToDateTime().ToUniversalTime(),
            entries,
            hash.GetHashAndReset(),
            dates), null);
    }

    /// <summary>
    /// Judges a CRL before it is signed against the newest one journaled for the same CA key.
    /// The serials in <see cref="CrlJudgement.Dropped"/> are for the caller to show expired.
    /// </summary>
    /// <param name="caPublicKey">The CA key's SubjectPublicKeyInfo.</param>
    /// <param name="tbs">The to-be-signed CRL.</param>
    public async Task<CrlJudgement> JudgeCrlAsync(byte[] caPublicKey, TbsCertificateList tbs)
    {
        var (crl, problem) = Read(tbs);
        if (crl == null)
            return new CrlJudgement(null, problem, Array.Empty<string>());
        Writer();
        await _index.ConfigureAwait(false);
        if (!_crls.TryGetValue(Key(caPublicKey), out var stream))
            return new CrlJudgement(crl, null, Array.Empty<string>());

        lock (stream)
        {
            if (crl.Number <= stream.LastNumber)
                return new CrlJudgement(crl,
                    $"The CRL carries number {crl.Number}, and the signer has already journaled number {stream.LastNumber} for this CA key; a CRL must raise the number.",
                    Array.Empty<string>());
            if (crl.Delta || stream.Full == null)
                return new CrlJudgement(crl, null, Array.Empty<string>());
            var dropped = stream.Full.Entries
                .Where(e => e.Value != ReasonCertificateHold && !crl.Entries.ContainsKey(e.Key))
                .Select(e => e.Key)
                .ToList();
            return new CrlJudgement(crl, null, dropped);
        }
    }

    /// <summary>
    /// Records a CRL the signer signed. It carries the whole to-be-signed CRL when its revoked
    /// set differs from the previous CRL of the same kind (full or delta) for that CA key, and
    /// at the first such CRL of the key in a segment; otherwise it points at the record in the
    /// same segment that holds the same set. Returns after the flush that covers the record.
    /// </summary>
    /// <exception cref="JournalCheckException">Another CRL of the same key was recorded in between with this number or a higher one.</exception>
    public Task<JournalAppended> RecordCrlAsync(Guid? caId, byte[] caPublicKey, byte[]? caCertificate, JournaledCrl crl,
        byte[] tbsBytes, byte[] signature, SigningContext context)
    {
        var caKey = SHA256.HashData(caPublicKey);
        var stream = _crls.GetOrAdd(Convert.ToHexStringLower(caKey), _ => new CrlStream());
        var caCert = caCertificate == null ? null : SHA256.HashData(caCertificate);
        return Writer().AppendAsync(RecordType.Crl, 0, place =>
        {
            lock (stream)
            {
                if (crl.Number <= stream.LastNumber)
                {
                    var message = $"The CRL carries number {crl.Number}, and number {stream.LastNumber} was journaled for this CA key while it was being signed; it is not recorded.";
                    if (Settings.Enforce)
                        throw new JournalCheckException(message);
                    _logger.LogWarning("Signer journal (checks: warn): {Message}", message);
                }

                var list = crl.Delta ? stream.Delta : stream.Full;
                var whole = list == null || list.HolderSegment != place.SegmentFirstSeq || !list.SetHash.AsSpan().SequenceEqual(crl.SetHash);
                var payload = new CrlPayload(
                    Ca: caId?.ToString("D"), CaKey: caKey, CaCert: caCert, Context: ContextOf(context), Version: Settings.Version,
                    CrlNumber: (ulong)crl.Number,
                    ThisUpdate: JournalFormat.ToMicros(crl.ThisUpdate),
                    NextUpdate: crl.NextUpdate is DateTime next ? JournalFormat.ToMicros(next) : null,
                    Signature: signature,
                    Tbs: whole ? tbsBytes : null,
                    SameSetAs: whole ? null : list!.HolderSeq,
                    TbsHash: whole ? null : SHA256.HashData(tbsBytes),
                    Delta: crl.Delta).Encode();

                // What the signer signs in this run it knows to be its own: vouched for, and signed by the CA key.
                var updated = new CrlList(whole ? place.Seq : list!.HolderSeq, place.SegmentFirstSeq, crl.SetHash, crl.Number,
                    crl.Entries, crl.RevocationDates, place.Seq) { Vouched = true, SignatureOk = true };
                if (crl.Delta) stream.Delta = updated; else stream.Full = updated;
                if (!crl.Delta)
                {
                    // A full CRL the signer signs ends a refusal that stood for the key, and is
                    // the list every later revocation fact is counted from.
                    _refusals.TryRemove(Convert.ToHexStringLower(caKey), out _);
                    stream.Facts.RemoveAll(f => f.Seq < place.Seq);
                }
                stream.LastNumber = Math.Max(stream.LastNumber, crl.Number);
                return payload;
            }
        });
    }

    /// <summary>
    /// Judges an OCSP response before it is signed: null when it may be, otherwise why not. A
    /// response is refused when it says "good" for a serial the newest journaled CRL of the CA
    /// key lists as revoked.
    /// </summary>
    /// <param name="caPublicKey">The SubjectPublicKeyInfo of the CA the responder answers for.</param>
    /// <param name="response">The response data to be signed.</param>
    public async ValueTask<string?> JudgeOcspAsync(byte[] caPublicKey, ResponseData response)
    {
        if (!_index.IsCompletedSuccessfully)
        {
            try { await _index.ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
        }
        if (_crls.IsEmpty || !_crls.TryGetValue(Key(caPublicKey), out var stream))
            return null;

        foreach (var element in response.Responses)
        {
            var single = SingleResponse.GetInstance(element);
            if (single.CertStatus.TagNo != 0)
                continue;
            var serial = single.CertId.SerialNumber.PositiveValue.ToString(16);
            lock (stream)
            {
                if (Revoked(stream.Full, serial) || (stream.Delta != null && stream.Full != null && stream.Delta.Number > stream.Full.Number && Revoked(stream.Delta, serial))
                    || (stream.Full == null && Revoked(stream.Delta, serial)))
                    return $"The response says 'good' for serial {serial}, which the newest CRL the signer journaled for this CA key lists as revoked.";
                // A revocation the node recorded after that CRL, and has not released since: the newest revocations of all.
                if (stream.Facts.LastOrDefault(f => f.Serial == serial) is { Released: false } fact && fact.Form == RevocationForm.Revoked)
                    return $"The response says 'good' for serial {serial}, which the node recorded as revoked with the signer (journal sequence {fact.Seq}) after the newest journaled CRL.";
            }
        }
        return null;

        static bool Revoked(CrlList? list, string serial)
            => list != null && list.Entries.TryGetValue(serial, out var reason) && reason != ReasonCertificateHold && reason != ReasonRemoveFromCrl;
    }

    private static string Key(byte[] caPublicKey) => Convert.ToHexStringLower(SHA256.HashData(caPublicKey));

    /// <summary>
    /// Reads the journal once by its record lengths, oldest segment first, and keeps for each CA
    /// key: the newest full and the newest delta CRL, the highest CRL number, and the revocation
    /// facts recorded after the newest full CRL. It checks no hash and no signature and is
    /// quick; the CRL check and the OCSP check wait for it and for nothing else. What it reads is
    /// not believed for the merge until <see cref="VerifyAndVouch"/> has vouched for it.
    /// </summary>
    private void BuildIndex(string directory)
    {
        try
        {
            var started = Stopwatch.GetTimestamp();
            var segments = JournalReader.ListSegments(directory);
            var candidates = new Dictionary<string, Candidate>(StringComparer.Ordinal);
            var numbers = new Dictionary<string, long>(StringComparer.Ordinal);
            var facts = new Dictionary<string, List<RevocationFact>>(StringComparer.Ordinal);
            foreach (var segment in segments)
            {
                var holders = new Dictionary<ulong, CrlPayload>();
                JournalReader.Skim(segment, (type, seq, load) =>
                {
                    if (type is RecordType.Revocation or RecordType.Unrevocation)
                    {
                        if (FactOf(type, seq, load(), vouched: false) is not { } fact)
                            return;
                        if (!facts.TryGetValue(fact.CaKey, out var ofKey))
                            facts[fact.CaKey] = ofKey = new List<RevocationFact>();
                        ofKey.Add(fact.Entry with { FromDisk = true });
                        return;
                    }
                    if (type != RecordType.Crl)
                        return;
                    CrlPayload record;
                    try { record = CrlPayload.Decode(load()); }
                    catch (FormatException) { return; }
                    CrlPayload holder;
                    ulong holderSeq;
                    if (record.Tbs != null)
                    {
                        holders[seq] = record;
                        holder = record;
                        holderSeq = seq;
                    }
                    else if (record.SameSetAs is ulong pointed && holders.TryGetValue(pointed, out var held))
                    {
                        holder = held;
                        holderSeq = pointed;
                    }
                    else
                    {
                        // A pointer whose record is not in this segment: not this layout's; the key keeps what it had.
                        return;
                    }
                    var key = Convert.ToHexStringLower(record.CaKey);
                    numbers[key] = Math.Max(numbers.GetValueOrDefault(key, -1), (long)record.CrlNumber);
                    candidates[key + (record.Delta ? "/d" : "/f")] = new Candidate(record, holder, holderSeq, seq, segment.FirstSeq);
                    // The facts before a full CRL are in it or were released before it.
                    if (!record.Delta && facts.TryGetValue(key, out var earlier))
                        earlier.Clear();
                });
            }

            foreach (var (key, found) in candidates)
            {
                var tbs = SignedDataTypes.TbsCertList(found.Holder.Tbs!);
                if (tbs == null)
                    continue;
                var (crl, _) = Read(tbs);
                if (crl == null)
                    continue;
                var stream = _crls.GetOrAdd(key[..^2], _ => new CrlStream());
                lock (stream)
                {
                    var list = new CrlList(found.HolderSeq, found.Segment, crl.SetHash, (long)found.Record.CrlNumber, crl.Entries, crl.RevocationDates, found.Seq) { FromDisk = true };
                    // A CRL the signer signed while this reading ran is newer than anything on disk at start.
                    if (found.Record.Delta) stream.Delta ??= list; else stream.Full ??= list;
                }
            }
            foreach (var (key, number) in numbers)
            {
                var stream = _crls.GetOrAdd(key, _ => new CrlStream());
                lock (stream)
                    stream.LastNumber = Math.Max(stream.LastNumber, number);
            }
            foreach (var (key, ofKey) in facts)
            {
                if (ofKey.Count == 0)
                    continue;
                var stream = _crls.GetOrAdd(key, _ => new CrlStream());
                lock (stream)
                {
                    var after = stream.Full?.RecordSeq ?? 0;
                    stream.Facts.InsertRange(0, ofKey.Where(f => f.Seq > after));
                    stream.Facts.Sort((x, y) => x.Seq.CompareTo(y.Seq));
                }
            }
            _logger.LogInformation("Signer journal: the newest CRL and the later revocations of {Keys} CA key(s) read from {Segments} segment(s) in {Elapsed} ms.",
                _crls.Count, segments.Count, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JournalFormatException)
        {
            _logger.LogError(ex, "Signer journal: the journaled CRLs could not be read; the CRL and OCSP checks know only the CRLs signed since this start.");
        }
    }

    /// <summary>
    /// Verifies the whole journal as it lay on disk when the signer started, in the background,
    /// and marks what the index holds as vouched for or not. The merge waits for it; signing
    /// does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What is verified</b> (<see cref="JournalVerifier"/>): every record's hash, the sequence
    /// and the chain from the first record, what each <c>SegmentStart</c> says of the segment
    /// before it, every checkpoint's signature under the checkpoint key in force, and every key
    /// block's signature by the system key it names. <see cref="SignerJournalInfo.Verified"/> is
    /// what <c>--journal-verify</c> would say of it.
    /// </para>
    /// <para>
    /// <b>What is believed for the merge</b>, record by record: a record is vouched for when a
    /// <c>Checkpoint</c> follows it <i>in its own segment</i> that is signed by a checkpoint key
    /// whose key block carries a signature by the system key <i>this signer holds now</i>.
    /// Nothing else about the journal decides it: not whether a change of system key in it was
    /// explained or signed for, and not which system key the journal was last written under.
    /// </para>
    /// <para>
    /// Why that is enough. A checkpoint signs its own sequence and the hash of the record before
    /// it, and every record carries the hash of the one before, so a checkpoint's signature
    /// fixes the whole chain before it: a genuine checkpoint replayed after other records does
    /// not verify, because the hash it signed is not theirs. Whoever holds only the files can
    /// append records, key changes to keys of their own and a replayed genuine key block, but
    /// cannot sign a checkpoint with a key the held system key signed for, so nothing they wrote
    /// is followed by one. The checkpoint must be in the record's own segment because the
    /// signer's next start writes a genuine checkpoint over whatever the files then hold: that
    /// one is in a new segment, the signer never appends to a segment it did not begin in the
    /// same run, and so records someone appended (or the tail a signer that stopped without
    /// warning left) are never in a segment with a genuine checkpoint after them.
    /// </para>
    /// <para>
    /// The CRL check and the OCSP check use every record, vouched for or not: they can only
    /// refuse.
    /// </para>
    /// </remarks>
    private void VerifyAndVouch(string directory, byte[] heldSystemPublicKey, string instanceId)
    {
        var started = Stopwatch.GetTimestamp();
        var heldHash = JournalSignatures.KeyHash(heldSystemPublicKey);
        var believedKeys = new HashSet<string>(StringComparer.Ordinal);
        var vouched = new HashSet<ulong>();
        var waiting = new List<ulong>();
        SegmentFile? current = null;

        void Consider(KeyBlock block)
        {
            // A key block the system key this signer holds signed for this instance.
            if (block.SystemKey.AsSpan().SequenceEqual(heldHash) && JournalSignatures.VerifyKeyBlock(block, instanceId, heldSystemPublicKey))
                believedKeys.Add(Convert.ToHexStringLower(JournalSignatures.KeyHash(block.Key)));
        }

        void OnRecord(SegmentFile file, JournalRecord record)
        {
            if (!ReferenceEquals(file, current))
            {
                // What a segment left after its last believed checkpoint stays unvouched.
                waiting.Clear();
                current = file;
            }
            try
            {
                switch (record.Type)
                {
                    case RecordType.SegmentStart:
                        Consider(SegmentStartPayload.Decode(record.Payload).CheckpointKey);
                        break;
                    case RecordType.Genesis:
                        Consider(GenesisPayload.Decode(record.Payload).CheckpointKey);
                        break;
                    case RecordType.CheckpointKeyChanged:
                        Consider(CheckpointKeyChangedPayload.Decode(record.Payload).NewKey);
                        break;
                    case RecordType.Checkpoint:
                        // The verifier has checked its signature under the key in force, whose hash this is.
                        if (believedKeys.Contains(Convert.ToHexStringLower(CheckpointPayload.Decode(record.Payload).KeyHash)))
                        {
                            foreach (var seq in waiting)
                                vouched.Add(seq);
                            waiting.Clear();
                        }
                        break;
                    case RecordType.Crl:
                    case RecordType.Revocation:
                    case RecordType.Unrevocation:
                        waiting.Add(record.Seq);
                        break;
                }
            }
            catch (FormatException)
            {
                // The verifier reports a payload it cannot read where it matters; here it vouches for nothing.
            }
        }

        JournalTrust trust;
        try
        {
            JournalVerification? result = null;
            for (var attempt = 0; attempt < 3 && result == null; attempt++)
            {
                believedKeys.Clear();
                vouched.Clear();
                waiting.Clear();
                current = null;
                var verification = JournalVerifier.Verify(JournalReader.ListSegments(directory), new JournalVerifyOptions
                {
                    EveryCheckpoint = true,
                    TolerateUnexplainedKeyChange = true,
                    OnRecord = OnRecord,
                    Progress = (done, total) =>
                    {
                        Interlocked.Exchange(ref _verifyTotalBytes, total);
                        Interlocked.Exchange(ref _verifiedBytes, done);
                    },
                });
                // A segment renamed while it was read (the writer sealed it): read again.
                if (verification.Fault is { Reason: var reason } && reason.StartsWith("the segment could not be read", StringComparison.Ordinal) && attempt < 2)
                {
                    Thread.Sleep(200);
                    continue;
                }
                result = verification;
            }
            if (result!.Fault is { } fault)
                trust = new JournalTrust(false, $"The journal does not verify: {fault}.");
            else if (result.Unexplained.Count > 0)
                trust = new JournalTrust(false, $"The journal does not verify: {result.Unexplained[0]}.");
            else
            {
                trust = new JournalTrust(true, null);
                // Read to the end: the two figures meet.
                Interlocked.Exchange(ref _verifiedBytes, Interlocked.Read(ref _verifyTotalBytes));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JournalFormatException)
        {
            trust = new JournalTrust(false, $"The journal could not be read to verify it ({ex.GetType().Name}: {ex.Message}).");
        }

        foreach (var stream in _crls.Values)
        {
            lock (stream)
            {
                foreach (var list in new[] { stream.Full, stream.Delta })
                    if (list is { FromDisk: true })
                        list.Vouched = vouched.Contains(list.RecordSeq) && vouched.Contains(list.HolderSeq);
                for (var i = 0; i < stream.Facts.Count; i++)
                    if (stream.Facts[i].FromDisk)
                        stream.Facts[i] = stream.Facts[i] with { Vouched = vouched.Contains(stream.Facts[i].Seq) };
            }
        }
        _trust = trust;
        var elapsed = (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        if (trust.Ok == true)
            _logger.LogInformation("Signer journal: verified in {Elapsed} ms ({Bytes} bytes).", elapsed, Interlocked.Read(ref _verifyTotalBytes));
        else
            _logger.LogError("Signer journal: {Why} The signer goes on recording and checking. Revocations are given back to a database that has lost them "
                + "only from records a checkpoint of a key this signer's system key signed for covers.", trust.Why);
    }

    /// <summary>
    /// The revocations the journal holds for a CA key, as a database that has gone back in time
    /// needs them: the entries of the newest full CRL journaled for the key, changed by a delta
    /// CRL journaled after it, then by every <c>Revocation</c> and <c>Unrevocation</c> fact
    /// recorded after that full CRL, in order. A released hold is not in it; a hold that stands
    /// is, as a hold. Null when the journal holds nothing for the key.
    /// </summary>
    /// <remarks>
    /// The answer is a refusal (<see cref="SignerJournaledRevocations.Trusted"/> false, no
    /// entry) when the key's newest full CRL is not vouched for (<see cref="VerifyAndVouch"/>),
    /// or when the signature in its record does not verify under
    /// <paramref name="caPublicKey"/> over its to-be-signed bytes. A delta CRL or a fact that is
    /// not vouched for, and a delta whose signature does not verify, contribute nothing. It
    /// waits for the verification of the journal to end.
    /// </remarks>
    /// <param name="caId">The CA asked about, for the answer.</param>
    /// <param name="caSpki">The CA key's SubjectPublicKeyInfo.</param>
    /// <param name="caPublicKey">The same key, to verify the journaled CRLs' signatures with.</param>
    /// <param name="skip">How many entries of the list to pass over.</param>
    /// <param name="take">The most entries to return.</param>
    public async Task<SignerJournaledRevocations?> JournaledRevocationsAsync(Guid caId, byte[] caSpki,
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter caPublicKey, int skip, int take)
    {
        Writer();
        await _index.ConfigureAwait(false);
        await _verification.ConfigureAwait(false);
        var trust = _trust;
        if (!_crls.TryGetValue(Key(caSpki), out var stream))
            return null;

        CrlList? full;
        CrlList? delta;
        List<RevocationFact> facts;
        int factCount;
        ulong lastFact;
        lock (stream)
        {
            full = stream.Full;
            delta = stream.Delta;
            factCount = stream.Facts.Count;
            lastFact = factCount == 0 ? 0 : stream.Facts[^1].Seq;
            // The list is worked out once and kept while nothing it was made from has changed: a
            // node asks for it a part at a time, and a list of a hundred thousand entries is not
            // built and sorted again for each part.
            if (stream.Answer is { } kept && ReferenceEquals(kept.Full, full) && ReferenceEquals(kept.Delta, delta) && kept.Facts == factCount && kept.LastFact == lastFact)
                return new SignerJournaledRevocations(caId, true, null, full?.Number, full?.RecordSeq, kept.Ordered.Count, Part(kept.Ordered));
            facts = stream.Facts.Where(f => f.Vouched).ToList();
        }
        if (full == null && facts.Count == 0)
            return null;

        var entries = new Dictionary<string, SignerJournaledRevocation>(StringComparer.Ordinal);
        if (full != null)
        {
            if (!full.Vouched)
                return new SignerJournaledRevocations(caId, false,
                    $"The newest CRL in the journal for this CA (number {full.Number}, sequence {full.RecordSeq}) is not followed, in its segment, by a checkpoint of a key "
                    + "that the system key this signer holds signed for, so nothing vouches for it."
                    + (trust.Ok == false ? " " + trust.Why : string.Empty),
                    full.Number, full.RecordSeq, 0, []);
            if (!SignatureHolds(full, caPublicKey))
                return new SignerJournaledRevocations(caId, false,
                    $"The signature of the newest CRL in the journal for this CA (number {full.Number}, sequence {full.HolderSeq}) does not verify under the CA's key.",
                    full.Number, full.RecordSeq, 0, []);
            foreach (var (serial, reason) in full.Entries)
                entries[serial] = Entry(serial, reason, full.RevocationDates.GetValueOrDefault(serial, DateTime.UnixEpoch), "crl", full.Number, full.RecordSeq);
            if (delta != null && delta.Number > full.Number && delta.Vouched && SignatureHolds(delta, caPublicKey))
            {
                foreach (var (serial, reason) in delta.Entries)
                {
                    if (reason == ReasonRemoveFromCrl)
                        entries.Remove(serial);
                    else
                        entries[serial] = Entry(serial, reason, delta.RevocationDates.GetValueOrDefault(serial, DateTime.UnixEpoch), "delta", delta.Number, delta.RecordSeq);
                }
            }
        }
        foreach (var fact in facts.Where(f => f.Seq > (full?.RecordSeq ?? 0)).OrderBy(f => f.Seq))
        {
            if (fact.Released)
                entries.Remove(fact.Serial);
            else if (fact.Form == RevocationForm.Retired)
                continue;   // A retirement is not a revocation: it is on no CRL and is not given back.
            else
                entries[fact.Serial] = Entry(fact.Serial, fact.Form == RevocationForm.Hold ? ReasonCertificateHold : fact.Reason, fact.At, "fact", 0, fact.Seq);
        }

        var ordered = entries.Values
            .OrderBy(e => e.Serial.Length).ThenBy(e => e.Serial, StringComparer.Ordinal)
            .ToList();
        lock (stream)
            stream.Answer = new KeptAnswer(full, delta, factCount, lastFact, ordered);
        return new SignerJournaledRevocations(caId, true, null, full?.Number, full?.RecordSeq, ordered.Count, Part(ordered));

        List<SignerJournaledRevocation> Part(List<SignerJournaledRevocation> all)
        {
            var from = Math.Clamp(skip, 0, all.Count);
            return all.GetRange(from, Math.Min(Math.Clamp(take, 1, MaxRevocationsPerAnswer), all.Count - from));
        }

        static SignerJournaledRevocation Entry(string serial, int reason, DateTime at, string source, long number, ulong seq)
            => new(serial.ToUpperInvariant(), reason, DateTime.SpecifyKind(at, DateTimeKind.Utc), reason == ReasonCertificateHold, source, number, seq);
    }

    /// <summary>The most entries one answer of <see cref="JournaledRevocationsAsync"/> carries.</summary>
    public const int MaxRevocationsPerAnswer = 5000;

    /// <summary>
    /// Whether the signature in the journal record that holds <paramref name="list"/>'s
    /// to-be-signed CRL verifies under the CA's key. The record is read from its segment once;
    /// a CRL the signer signed in this run is its own.
    /// </summary>
    private bool SignatureHolds(CrlList list, Org.BouncyCastle.Crypto.AsymmetricKeyParameter caPublicKey)
    {
        if (list.SignatureOk is bool known)
            return known;
        var ok = false;
        try
        {
            var directory = Writer().Directory;
            var segment = JournalReader.ListSegments(directory).FirstOrDefault(f => f.FirstSeq == list.HolderSegment);
            CrlPayload? holder = null;
            if (segment != null)
                JournalReader.Skim(segment, (type, seq, load) =>
                {
                    if (type == RecordType.Crl && seq == list.HolderSeq)
                        holder = CrlPayload.Decode(load());
                });
            if (holder?.Tbs != null)
            {
                var tbs = TbsCertificateList.GetInstance(Asn1Object.FromByteArray(holder.Tbs));
                var crl = new Org.BouncyCastle.X509.X509Crl(CertificateList.GetInstance(new DerSequence(tbs, tbs.Signature, new DerBitString(holder.Signature))));
                crl.Verify(caPublicKey);
                ok = true;
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning("Signer journal: the CRL record at sequence {Seq} does not carry a signature that verifies under the CA's key ({Kind}).", list.HolderSeq, ex.GetType().Name);
        }
        list.SignatureOk = ok;
        return ok;
    }

    /// <summary>Stops the writer in order: what was offered is written, then a checkpoint and a Seal.</summary>
    public async ValueTask DisposeAsync()
    {
        JournalWriter? writer;
        lock (_gate)
        {
            writer = _writer;
            _writer = null;
            _lastAttempt = Stopwatch.GetTimestamp();
            _fault = "The journal is closed.";
        }
        if (writer != null)
            await writer.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>The list last worked out for a CA key, and what it was worked out from.</summary>
    private sealed record KeptAnswer(CrlList? Full, CrlList? Delta, int Facts, ulong LastFact, List<SignerJournaledRevocation> Ordered);

    private sealed class CrlStream
    {
        public long LastNumber = -1;
        public CrlList? Full;
        public CrlList? Delta;

        /// <summary>The answer to the merge's question, kept while <see cref="Full"/>, <see cref="Delta"/> and <see cref="Facts"/> are what it was made from.</summary>
        public KeptAnswer? Answer;

        /// <summary>The revocation facts recorded after <see cref="Full"/>, in the order of their records.</summary>
        public readonly List<RevocationFact> Facts = new();
    }

    /// <summary>Whether the journal on disk may be a source of revocations: null while it is being verified.</summary>
    private sealed record JournalTrust(bool? Ok, string? Why)
    {
        public static readonly JournalTrust Pending = new(null, null);
    }

    /// <summary>A CRL record found while the journal is read at start, with the record that holds its list.</summary>
    private sealed class Candidate(CrlPayload record, CrlPayload holder, ulong holderSeq, ulong seq, ulong segment)
    {
        public CrlPayload Record { get; } = record;
        public CrlPayload Holder { get; } = holder;
        public ulong HolderSeq { get; } = holderSeq;
        public ulong Seq { get; } = seq;
        public ulong Segment { get; } = segment;
    }

    /// <summary>A <c>Revocation</c> or <c>Unrevocation</c> fact of one CA key.</summary>
    /// <param name="Seq">The record's sequence.</param>
    /// <param name="Serial">The serial, hex, lower case, no leading zeros.</param>
    /// <param name="Released">True for an <c>Unrevocation</c>: a hold released.</param>
    /// <param name="Reason">The reason code the fact gives.</param>
    /// <param name="At">The time the fact gives.</param>
    /// <param name="Form">Revoked, hold or retired.</param>
    /// <param name="Vouched">Whether the record is believed for the merge: the signer recorded it in this run, or the verification vouched for it.</param>
    /// <param name="FromDisk">Whether it was read from the journal at start, and so waits for the verification.</param>
    private sealed record RevocationFact(ulong Seq, string Serial, bool Released, int Reason, DateTime At, ulong Form, bool Vouched, bool FromDisk = false);

    /// <summary>The newest CRL of one kind for one CA key: where the record holding its whole list is, and what it lists.</summary>
    private sealed record CrlList(ulong HolderSeq, ulong HolderSegment, byte[] SetHash, long Number, IReadOnlyDictionary<string, int> Entries,
        IReadOnlyDictionary<string, DateTime> RevocationDates, ulong RecordSeq)
    {
        /// <summary>Whether the list is believed for the merge: the signer signed it in this run, or the verification vouched for its records.</summary>
        public bool Vouched { get; set; }

        /// <summary>Whether it was read from the journal at start, and so waits for the verification.</summary>
        public bool FromDisk { get; init; }

        /// <summary>Whether the signature in the holding record verifies under the CA key; null until it was checked.</summary>
        public bool? SignatureOk { get; set; }
    }

    /// <summary>A refused full CRL of one CA key: when, against which journaled CRL, and every serial it left out.</summary>
    private sealed record CrlRefusal(Guid? CaId, DateTime At, long JournaledNumber, IReadOnlyList<SignerJournalMissingSerial> Missing);
}
