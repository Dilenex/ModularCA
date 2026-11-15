namespace ModularCA.Journal;

/// <summary>
/// The fixed numbers of the journal's layout: the framing, the record types and the flag bits.
/// A number here never changes meaning. <c>docs/architecture/signer-journal.md</c> states the
/// same layout in prose.
/// </summary>
public static class JournalFormat
{
    /// <summary>The value of the <c>format</c> byte this build writes and reads.</summary>
    public const byte Format = 1;

    /// <summary>The four bytes every record body begins with: ASCII <c>MCAJ</c>.</summary>
    public static ReadOnlySpan<byte> Magic => "MCAJ"u8;

    /// <summary>The bytes of a record body before its payload.</summary>
    public const int FixedPartLength = 96;

    /// <summary>The bytes of the length prefix.</summary>
    public const int LengthPrefixLength = 4;

    /// <summary>The bytes of a hash: SHA-256.</summary>
    public const int HashLength = 32;

    /// <summary>What a record costs before its payload: the length, the fixed part and the hash.</summary>
    public const int RecordOverhead = LengthPrefixLength + FixedPartLength + HashLength;

    /// <summary>The most bytes a whole record may take, its length prefix and hash included: 256 MiB.</summary>
    public const long MaxRecordLength = 256L * 1024 * 1024;

    /// <summary>The size at which a segment is sealed: 64 MiB. A segment may pass it by the one record that crosses it.</summary>
    public const long SegmentSealBytes = 64L * 1024 * 1024;

    /// <summary>The age at which a segment is sealed.</summary>
    public static readonly TimeSpan SegmentSealAge = TimeSpan.FromHours(24);

    /// <summary>The longest a record waits for the checkpoint that covers it, while there is activity.</summary>
    public static readonly TimeSpan CheckpointInterval = TimeSpan.FromSeconds(1);

    /// <summary>The most records written between two checkpoints.</summary>
    public const int CheckpointRecords = 1000;

    /// <summary>Flag bit 0: the record states a fact the node asserted; the signer did not see it happen.</summary>
    public const byte FlagNodeAsserted = 0x01;

    /// <summary>The suffix of an open segment's file name, after the 20-digit first sequence.</summary>
    public const string OpenSuffix = ".open.mcaj";

    /// <summary>The suffix of a sealed segment's file name, after the 20-digit first sequence.</summary>
    public const string SealedSuffix = ".mcaj";

    /// <summary>The name of the open segment whose first record has sequence <paramref name="firstSeq"/>.</summary>
    public static string OpenName(ulong firstSeq) => firstSeq.ToString("D20", System.Globalization.CultureInfo.InvariantCulture) + OpenSuffix;

    /// <summary>The name of the sealed segment whose first record has sequence <paramref name="firstSeq"/>.</summary>
    public static string SealedName(ulong firstSeq) => firstSeq.ToString("D20", System.Globalization.CultureInfo.InvariantCulture) + SealedSuffix;

    /// <summary>
    /// Reads a segment file name: its first sequence and whether it is the open form. False for
    /// any name that is not exactly 20 digits followed by one of the two suffixes.
    /// </summary>
    public static bool TryParseName(string fileName, out ulong firstSeq, out bool open)
    {
        firstSeq = 0;
        open = false;
        if (fileName.Length < 20)
            return false;
        for (var i = 0; i < 20; i++)
            if (fileName[i] is < '0' or > '9')
                return false;
        var rest = fileName.AsSpan(20);
        if (rest.SequenceEqual(OpenSuffix))
            open = true;
        else if (!rest.SequenceEqual(SealedSuffix))
            return false;
        return ulong.TryParse(fileName.AsSpan(0, 20), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out firstSeq);
    }

    /// <summary>Microseconds since 1970-01-01 UTC, the unit of <c>at</c> and of every time in a payload.</summary>
    public static long ToMicros(DateTimeOffset time) => (time.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    /// <summary>The instant <paramref name="micros"/> microseconds after 1970-01-01 UTC.</summary>
    public static DateTimeOffset FromMicros(long micros) => new(DateTimeOffset.UnixEpoch.UtcTicks + micros * 10, TimeSpan.Zero);
}

/// <summary>
/// The record types. The numbers are the layout's and never change meaning; numbers not listed
/// are free, and a reader checks and skips a type it does not know.
/// </summary>
public static class RecordType
{
    /// <summary>The beginning of a journal.</summary>
    public const ushort Genesis = 1;
    /// <summary>The first record of every segment.</summary>
    public const ushort SegmentStart = 2;
    /// <summary>A signature by the checkpoint key over the chain so far.</summary>
    public const ushort Checkpoint = 3;
    /// <summary>The last record of a segment closed in order.</summary>
    public const ushort Seal = 4;
    /// <summary>Records were removed before this point. Not written by this version.</summary>
    public const ushort Pruned = 5;
    /// <summary>A start of the signer.</summary>
    public const ushort Start = 6;
    /// <summary>The checkpoint key, or the system key that signs for it, changed.</summary>
    public const ushort CheckpointKeyChanged = 7;

    /// <summary>A certificate the signer signed.</summary>
    public const ushort Certificate = 16;
    /// <summary>A CRL the signer signed.</summary>
    public const ushort Crl = 17;
    /// <summary>OCSP signatures, summarized. Not written by this version.</summary>
    public const ushort OcspSummary = 18;
    /// <summary>SCEP, CMP and timestamp signatures. Not written by this version.</summary>
    public const ushort OtherSignature = 19;
    /// <summary>An SSH certificate the signer signed.</summary>
    public const ushort SshCertificate = 20;
    /// <summary>An SSH revocation list.</summary>
    public const ushort SshRevocationList = 21;

    /// <summary>The node revoked a certificate, put it on hold or retired it.</summary>
    public const ushort Revocation = 32;
    /// <summary>The node released a hold.</summary>
    public const ushort Unrevocation = 33;
    /// <summary>A one-time token was used without a certificate being issued.</summary>
    public const ushort SpentWithoutCertificate = 34;
    /// <summary>A restore ran.</summary>
    public const ushort RestoreMarker = 35;
    /// <summary>The node saw a changed incarnation.</summary>
    public const ushort ContinuityEvent = 36;
    /// <summary>Something was disabled.</summary>
    public const ushort Disabled = 37;

    /// <summary>Reserved: key operations.</summary>
    public const ushort ReservedKeyOperations = 48;
    /// <summary>Reserved: secret wrap and unwrap.</summary>
    public const ushort ReservedSecretWrap = 49;
    /// <summary>Reserved: ceremonies.</summary>
    public const ushort ReservedCeremonies = 50;
    /// <summary>Reserved: registry, lock, unlock, lease, term.</summary>
    public const ushort ReservedRegistry = 51;
    /// <summary>Reserved: refusals.</summary>
    public const ushort ReservedRefusals = 64;
    /// <summary>Reserved: <c>RestoreRecovered</c>.</summary>
    public const ushort ReservedRestoreRecovered = 80;

    /// <summary>The types the node may assert through <c>RecordFact</c> in this version.</summary>
    public static readonly IReadOnlySet<ushort> NodeFacts = new HashSet<ushort>
    {
        Revocation, Unrevocation, SpentWithoutCertificate, RestoreMarker, ContinuityEvent, Disabled, SshRevocationList,
    };

    /// <summary>The layout's name for a type, or its number for one this build does not know.</summary>
    public static string Name(ushort type) => type switch
    {
        Genesis => nameof(Genesis),
        SegmentStart => nameof(SegmentStart),
        Checkpoint => nameof(Checkpoint),
        Seal => nameof(Seal),
        Pruned => nameof(Pruned),
        Start => nameof(Start),
        CheckpointKeyChanged => nameof(CheckpointKeyChanged),
        Certificate => nameof(Certificate),
        Crl => nameof(Crl),
        OcspSummary => nameof(OcspSummary),
        OtherSignature => nameof(OtherSignature),
        SshCertificate => nameof(SshCertificate),
        SshRevocationList => nameof(SshRevocationList),
        Revocation => nameof(Revocation),
        Unrevocation => nameof(Unrevocation),
        SpentWithoutCertificate => nameof(SpentWithoutCertificate),
        RestoreMarker => nameof(RestoreMarker),
        ContinuityEvent => nameof(ContinuityEvent),
        Disabled => nameof(Disabled),
        _ => type.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
}
