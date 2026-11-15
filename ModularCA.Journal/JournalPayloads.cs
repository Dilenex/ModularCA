namespace ModularCA.Journal;

/// <summary>
/// The integer keys of the journal's payload maps. <b>These numbers never change.</b> A key has
/// one meaning in every record type that carries it; a new member takes a new number, and a
/// number is never reused. Nested maps (the key block, the signing context, a spent token and so
/// on) have their own small numbering, stated on the nested classes below.
/// </summary>
public static class JournalKeys
{
    // Keys with one meaning in every type.
    /// <summary><c>ca</c>: the CA's identifier in the instance, text.</summary>
    public const ulong Ca = 1;
    /// <summary><c>caKey</c>: SHA-256 of the issuing CA's public key (SubjectPublicKeyInfo; for an SSH CA, of its public key blob), 32 bytes.</summary>
    public const ulong CaKey = 2;
    /// <summary><c>caCert</c>: SHA-256 of the CA certificate current when this was signed, 32 bytes.</summary>
    public const ulong CaCert = 3;
    /// <summary><c>context</c>: the signing context, a map (<see cref="SigningContextInfo"/>).</summary>
    public const ulong Context = 4;
    /// <summary><c>version</c>: the product version that wrote the record, text.</summary>
    public const ulong Version = 5;

    // Structure records.
    /// <summary>The instance identifier, text.</summary>
    public const ulong InstanceId = 10;
    /// <summary>The checkpoint key block, a map (<see cref="KeyBlock"/>).</summary>
    public const ulong CheckpointKey = 11;
    /// <summary>Why a journal begins (<see cref="GenesisReason"/>), unsigned.</summary>
    public const ulong GenesisReason = 12;
    /// <summary>The head of the journal this one continues, a map (<see cref="HeadRef"/>).</summary>
    public const ulong Continues = 13;
    /// <summary>The previous segment, a map (<see cref="PreviousSegment"/>).</summary>
    public const ulong Previous = 14;
    /// <summary>SHA-256 of the public key (SubjectPublicKeyInfo) that made <see cref="Signature"/>, 32 bytes.</summary>
    public const ulong KeyHash = 15;
    /// <summary>The algorithm of <see cref="Signature"/>, text.</summary>
    public const ulong Algorithm = 16;
    /// <summary>A signature, bytes: a checkpoint's, a certificate's or a CRL's.</summary>
    public const ulong Signature = 17;
    /// <summary>Whether the previous segment ended without a <c>Seal</c>, boolean.</summary>
    public const ulong PreviousUnsealed = 18;
    /// <summary>The old checkpoint key's signature over the new key, bytes.</summary>
    public const ulong OldKeySignature = 19;
    /// <summary>The algorithm of <see cref="OldKeySignature"/>, text.</summary>
    public const ulong OldKeyAlgorithm = 20;
    /// <summary>The old system key's signature over the new system key, bytes.</summary>
    public const ulong OldSystemKeySignature = 21;
    /// <summary>The algorithm of <see cref="OldSystemKeySignature"/>, text.</summary>
    public const ulong OldSystemKeyAlgorithm = 22;
    /// <summary>What explains a change the key before did not sign, a map (<see cref="ChangeExplanation"/>).</summary>
    public const ulong Explains = 23;
    /// <summary>Reserved for <c>Pruned</c>: the last record removed, a map (<see cref="HeadRef"/>).</summary>
    public const ulong LastRemoved = 24;
    /// <summary>
    /// The system key's public key (SubjectPublicKeyInfo, DER), beside a key block that names it
    /// by hash, so the block's signature can be checked from the files alone.
    /// </summary>
    public const ulong SystemPublicKey = 25;
    /// <summary>
    /// The hash of the journal's <c>Genesis</c> record, in every <c>SegmentStart</c> after the
    /// first segment's: what tells one journal of an instance from another, readable from the
    /// newest segment alone and still there when the first segment has been pruned.
    /// </summary>
    public const ulong GenesisHash = 26;

    // What the signer signed.
    /// <summary>The whole to-be-signed structure (a TBSCertificate or a TBSCertList), DER bytes.</summary>
    public const ulong Tbs = 30;
    /// <summary>A certificate serial number: unsigned, big-endian, no leading zero byte.</summary>
    public const ulong Serial = 32;
    /// <summary>notBefore, microseconds since 1970-01-01 UTC.</summary>
    public const ulong NotBefore = 33;
    /// <summary>notAfter, microseconds since 1970-01-01 UTC.</summary>
    public const ulong NotAfter = 34;
    /// <summary>SHA-256 of the subject's public key (SubjectPublicKeyInfo), 32 bytes.</summary>
    public const ulong SubjectKey = 35;
    /// <summary>Whether the certificate is a CA's, boolean.</summary>
    public const ulong IsCa = 36;
    /// <summary><c>spent</c>: the one-time tokens this issuance used, an array of maps (<see cref="SpentToken"/>).</summary>
    public const ulong Spent = 37;
    /// <summary><c>answers</c>: what was being answered, a map (<see cref="Answers"/>).</summary>
    public const ulong Answers = 38;
    /// <summary><c>replaces</c>: the certificate this one renews or reissues, a map (<see cref="Replaces"/>).</summary>
    public const ulong Replaces = 39;
    /// <summary><c>belongs</c>: what the certificate belongs to, a map (<see cref="Belongs"/>).</summary>
    public const ulong Belongs = 40;
    /// <summary>The CRL number, unsigned.</summary>
    public const ulong CrlNumber = 42;
    /// <summary>thisUpdate, microseconds since 1970-01-01 UTC.</summary>
    public const ulong ThisUpdate = 43;
    /// <summary>nextUpdate, microseconds since 1970-01-01 UTC.</summary>
    public const ulong NextUpdate = 44;
    /// <summary>The sequence of the record, in the same segment, that holds the same revoked set, unsigned.</summary>
    public const ulong SameSetAs = 45;
    /// <summary>SHA-256 of the to-be-signed structure, when the record does not carry it, 32 bytes.</summary>
    public const ulong TbsHash = 46;
    /// <summary>Whether a CRL is a delta CRL, boolean; absent means a full CRL.</summary>
    public const ulong Delta = 47;
    /// <summary>The whole SSH certificate as signed, bytes.</summary>
    public const ulong SshCertificate = 50;
    /// <summary>The whole SSH revocation list (an OpenSSH KRL), bytes.</summary>
    public const ulong SshRevocationList = 51;

    // Facts the node asserts.
    /// <summary>The revocation reason, the CRLReason code of RFC 5280, unsigned.</summary>
    public const ulong RevocationReason = 60;
    /// <summary>When the fact happened, microseconds since 1970-01-01 UTC.</summary>
    public const ulong Time = 61;
    /// <summary>Whether the CA has a record of the certificate, boolean.</summary>
    public const ulong Known = 62;
    /// <summary>Which it was: revoked, on hold or retired (<see cref="RevocationForm"/>), unsigned.</summary>
    public const ulong Form = 63;
    /// <summary>A kind, unsigned: <see cref="TokenKind"/> in <c>SpentWithoutCertificate</c>, <see cref="DisabledKind"/> in <c>Disabled</c>.</summary>
    public const ulong Kind = 64;
    /// <summary>An identifier, text.</summary>
    public const ulong Id = 65;
    /// <summary>A restore's archive file name, text.</summary>
    public const ulong Archive = 66;
    /// <summary>The instance identifier in the archive's manifest, text.</summary>
    public const ulong ArchiveInstanceId = 67;
    /// <summary>The creation time in the archive's manifest, microseconds since 1970-01-01 UTC.</summary>
    public const ulong ArchiveCreatedAt = 68;
    /// <summary>The journal head in the archive's manifest, a map (<see cref="HeadRef"/>).</summary>
    public const ulong ArchiveHead = 69;
    /// <summary>The incarnation hash before, 32 bytes.</summary>
    public const ulong OldIncarnation = 70;
    /// <summary>The incarnation hash after, 32 bytes.</summary>
    public const ulong NewIncarnation = 71;
}

/// <summary>Why a journal begins.</summary>
public static class GenesisReason
{
    /// <summary>The first start of a signer that keeps a journal.</summary>
    public const ulong FirstStart = 1;
    /// <summary>The journal continues another, whose head the record carries.</summary>
    public const ulong ContinuesAnother = 2;
}

/// <summary>The kinds of one-time token, in <c>spent</c> and in <c>SpentWithoutCertificate</c>.</summary>
public static class TokenKind
{
    /// <summary>An enrollment token.</summary>
    public const ulong EnrollmentToken = 1;
    /// <summary>A CMP shared secret.</summary>
    public const ulong CmpSharedSecret = 2;
    /// <summary>An ACME external account binding key.</summary>
    public const ulong AcmeExternalAccountBinding = 3;
    /// <summary>The first administrator's claim token.</summary>
    public const ulong FirstAdministratorClaim = 4;
}

/// <summary>The kinds of thing an issuance answers.</summary>
public static class AnswersKind
{
    /// <summary>Nothing: the certificate was issued on the instance's own initiative.</summary>
    public const ulong None = 0;
    /// <summary>A pending request: a row of the instance's certificate requests.</summary>
    public const ulong PendingRequest = 1;
    /// <summary>An ACME order.</summary>
    public const ulong AcmeOrder = 2;
    /// <summary>An enrollment transaction of a protocol that has one (SCEP, CMP).</summary>
    public const ulong EnrollmentTransaction = 3;
}

/// <summary>The kinds of owner in <c>belongs</c>.</summary>
public static class OwnerKind
{
    /// <summary>A user.</summary>
    public const ulong User = 1;
    /// <summary>A badge.</summary>
    public const ulong Badge = 2;
    /// <summary>An infrastructure registration.</summary>
    public const ulong InfrastructureRegistration = 3;
}

/// <summary>Which a <c>Revocation</c> fact was.</summary>
public static class RevocationForm
{
    /// <summary>The certificate was revoked.</summary>
    public const ulong Revoked = 1;
    /// <summary>The certificate was put on hold.</summary>
    public const ulong Hold = 2;
    /// <summary>The certificate was retired.</summary>
    public const ulong Retired = 3;
}

/// <summary>The kinds of thing a <c>Disabled</c> fact names.</summary>
public static class DisabledKind
{
    /// <summary>A certificate authority.</summary>
    public const ulong Ca = 1;
    /// <summary>An SSH CA key.</summary>
    public const ulong SshCaKey = 2;
    /// <summary>A space.</summary>
    public const ulong Space = 3;
    /// <summary>An account.</summary>
    public const ulong Account = 4;
    /// <summary>A sign-in credential.</summary>
    public const ulong SignInCredential = 5;

    /// <summary>Every kind, for the test that ties them to the mode gate.</summary>
    public static readonly IReadOnlyList<ulong> All = new[] { Ca, SshCaKey, Space, Account, SignInCredential };
}

/// <summary>What explains a key change the key before did not sign.</summary>
public static class ExplanationKind
{
    /// <summary>A restore: the <c>RestoreMarker</c> directly before the record.</summary>
    public const ulong Restore = 1;
    /// <summary>A changed incarnation: a roll-back of volumes.</summary>
    public const ulong ChangedIncarnation = 2;
}

/// <summary>A place in a journal: a sequence and the hash of its record. Keys: 1 seq, 2 hash.</summary>
public sealed record HeadRef(ulong Seq, byte[] Hash)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().UInt(1, Seq).Bytes(2, Hash);
    internal static HeadRef? From(CborMap? map) => map == null ? null : new HeadRef(map.RequireUInt(1), map.RequireBytes(2));
}

/// <summary>
/// The checkpoint key block. Keys: 1 <c>key</c>, the checkpoint public key (SubjectPublicKeyInfo,
/// DER); 2 <c>systemKey</c>, SHA-256 of the system key's SubjectPublicKeyInfo; 3
/// <c>systemSignature</c>, the system key's signature over
/// <c>"ModularCA.Journal.CheckpointKey.v1\0"</c>, the instance identifier and <c>key</c>; 4
/// <c>algorithm</c>, the algorithm of that signature.
/// </summary>
public sealed record KeyBlock(byte[] Key, byte[] SystemKey, byte[] SystemSignature, string Algorithm)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().Bytes(1, Key).Bytes(2, SystemKey).Bytes(3, SystemSignature).Text(4, Algorithm);
    internal static KeyBlock From(CborMap map) => new(map.RequireBytes(1), map.RequireBytes(2), map.RequireBytes(3), map.RequireText(4));

    /// <summary>Whether two blocks carry the same bytes in every member.</summary>
    public bool SameAs(KeyBlock other)
        => Key.AsSpan().SequenceEqual(other.Key) && SystemKey.AsSpan().SequenceEqual(other.SystemKey)
           && SystemSignature.AsSpan().SequenceEqual(other.SystemSignature) && Algorithm == other.Algorithm;
}

/// <summary>
/// The previous segment, as a <c>SegmentStart</c> states it. Keys: 1 name, 2 the bytes of whole
/// records in it, 3 its last sequence, 4 its last hash, 5 whether it ended with a <c>Seal</c>.
/// </summary>
public sealed record PreviousSegment(string Name, long WholeBytes, ulong LastSeq, byte[] LastHash, bool Sealed)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().Text(1, Name).UInt(2, (ulong)WholeBytes).UInt(3, LastSeq).Bytes(4, LastHash).Bool(5, Sealed);
    internal static PreviousSegment? From(CborMap? map) => map == null ? null
        : new PreviousSegment(map.RequireText(1), (long)map.RequireUInt(2), map.RequireUInt(3), map.RequireBytes(4), map.Bool(5) ?? false);
}

/// <summary>
/// What explains a key change. Keys: 1 kind (<see cref="ExplanationKind"/>); for a restore, 2
/// the archive's file name, 3 the instance identifier and 4 the creation time from its
/// manifest; for a changed incarnation, 5 the hash before and 6 the hash after.
/// </summary>
public sealed record ChangeExplanation(ulong Kind, string? Archive = null, string? ArchiveInstanceId = null, long? ArchiveCreatedAt = null,
    byte[]? OldIncarnation = null, byte[]? NewIncarnation = null)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().UInt(1, Kind).Text(2, Archive).Text(3, ArchiveInstanceId).Int(4, ArchiveCreatedAt)
        .Bytes(5, OldIncarnation).Bytes(6, NewIncarnation);
    internal static ChangeExplanation? From(CborMap? map) => map == null ? null
        : new ChangeExplanation(map.RequireUInt(1), map.Text(2), map.Text(3), map.Int(4), map.Bytes(5), map.Bytes(6));
}

/// <summary>The signing context of a record. Keys: 1 purpose, 2 protocol, 3 requester; each only when known.</summary>
public sealed record SigningContextInfo(string? Purpose, string? Protocol = null, string? Requester = null)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().Text(1, Purpose).Text(2, Protocol).Text(3, Requester);
    internal static SigningContextInfo? From(CborMap? map) => map == null ? null : new SigningContextInfo(map.Text(1), map.Text(2), map.Text(3));
}

/// <summary>
/// A one-time token an issuance used. Keys: 1 kind (<see cref="TokenKind"/>), 2 the token's
/// identifier, 3 which use it was, counted from 1. Never the token or a hash of it.
/// </summary>
public sealed record SpentToken(ulong Kind, string Id, ulong Use)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().UInt(1, Kind).Text(2, Id).UInt(3, Use);
    internal static SpentToken From(CborMap map) => new(map.RequireUInt(1), map.RequireText(2), map.UInt(3) ?? 1);
}

/// <summary>What an issuance answered. Keys: 1 kind (<see cref="AnswersKind"/>), 2 its identifier.</summary>
public sealed record Answers(ulong Kind, string? Id)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().UInt(1, Kind).Text(2, Id);
    internal static Answers? From(CborMap? map) => map == null ? null : new Answers(map.RequireUInt(1), map.Text(2));
}

/// <summary>The certificate an issuance renews or reissues. Keys: 1 its serial, 2 its <c>caKey</c>.</summary>
public sealed record Replaces(byte[] Serial, byte[] CaKey)
{
    internal CborMapBuilder ToMap() => new CborMapBuilder().Bytes(1, Serial).Bytes(2, CaKey);
    internal static Replaces? From(CborMap? map) => map == null ? null : new Replaces(map.RequireBytes(1), map.RequireBytes(2));
}

/// <summary>
/// What a certificate belongs to, by identifier, each only when it applies. Keys: 1 the
/// certificate profile, 2 the space, 3 the owner's kind (<see cref="OwnerKind"/>), 4 the owner,
/// 5 the template.
/// </summary>
public sealed record Belongs(string? Profile = null, string? Space = null, ulong? OwnerKind = null, string? Owner = null, string? Template = null)
{
    /// <summary>Whether no member is set, in which case the record carries no <c>belongs</c>.</summary>
    public bool IsEmpty => Profile == null && Space == null && OwnerKind == null && Owner == null && Template == null;
    internal CborMapBuilder ToMap() => new CborMapBuilder().Text(1, Profile).Text(2, Space).UInt(3, OwnerKind).Text(4, Owner).Text(5, Template);
    internal static Belongs? From(CborMap? map) => map == null ? null : new Belongs(map.Text(1), map.Text(2), map.UInt(3), map.Text(4), map.Text(5));
}

/// <summary><c>Genesis</c> (type 1): the instance identifier, the checkpoint key block and the reason.</summary>
public sealed record GenesisPayload(string InstanceId, KeyBlock CheckpointKey, ulong Reason, HeadRef? Continues = null, string? Version = null, byte[]? SystemPublicKey = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.InstanceId, InstanceId).Map(JournalKeys.CheckpointKey, CheckpointKey.ToMap())
        .UInt(JournalKeys.GenesisReason, Reason).Map(JournalKeys.Continues, Continues?.ToMap()).Text(JournalKeys.Version, Version)
        .Bytes(JournalKeys.SystemPublicKey, SystemPublicKey).Encode();

    /// <summary>Decodes a <c>Genesis</c> payload.</summary>
    public static GenesisPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireText(JournalKeys.InstanceId), KeyBlock.From(m.RequireMap(JournalKeys.CheckpointKey)),
            m.RequireUInt(JournalKeys.GenesisReason), HeadRef.From(m.Map(JournalKeys.Continues)), m.Text(JournalKeys.Version), m.Bytes(JournalKeys.SystemPublicKey));
    }
}

/// <summary>
/// <c>SegmentStart</c> (type 2): the instance identifier, the checkpoint key block in force, the
/// previous segment, and, in every segment but the journal's first, the hash of the journal's
/// <c>Genesis</c> record (the first segment's <c>SegmentStart</c> precedes the <c>Genesis</c>
/// and cannot carry it; that segment holds the record itself).
/// </summary>
public sealed record SegmentStartPayload(string InstanceId, KeyBlock CheckpointKey, PreviousSegment? Previous, byte[]? SystemPublicKey = null, byte[]? GenesisHash = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.InstanceId, InstanceId).Map(JournalKeys.CheckpointKey, CheckpointKey.ToMap())
        .Map(JournalKeys.Previous, Previous?.ToMap()).Bytes(JournalKeys.SystemPublicKey, SystemPublicKey).Bytes(JournalKeys.GenesisHash, GenesisHash).Encode();

    /// <summary>Decodes a <c>SegmentStart</c> payload.</summary>
    public static SegmentStartPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireText(JournalKeys.InstanceId), KeyBlock.From(m.RequireMap(JournalKeys.CheckpointKey)), PreviousSegment.From(m.Map(JournalKeys.Previous)),
            m.Bytes(JournalKeys.SystemPublicKey), m.Bytes(JournalKeys.GenesisHash));
    }
}

/// <summary>
/// <c>Checkpoint</c> (type 3): SHA-256 of the signing public key, the algorithm, and the
/// signature over <c>"ModularCA.Journal.Checkpoint.v1\0"</c>, the instance identifier, and the
/// record's own <c>seq</c> and <c>prev</c>.
/// </summary>
public sealed record CheckpointPayload(byte[] KeyHash, string Algorithm, byte[] Signature)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Bytes(JournalKeys.KeyHash, KeyHash).Text(JournalKeys.Algorithm, Algorithm).Bytes(JournalKeys.Signature, Signature).Encode();

    /// <summary>Decodes a <c>Checkpoint</c> payload.</summary>
    public static CheckpointPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireBytes(JournalKeys.KeyHash), m.RequireText(JournalKeys.Algorithm), m.RequireBytes(JournalKeys.Signature));
    }
}

/// <summary><c>Seal</c> (type 4): nothing; an empty map.</summary>
public static class SealPayload
{
    /// <summary>The payload's deterministic encoding: the empty map, one byte <c>0xA0</c>.</summary>
    public static byte[] Encode() => new CborMapBuilder().Encode();
}

/// <summary><c>Start</c> (type 6): the product version, and whether the previous segment ended without a <c>Seal</c>.</summary>
public sealed record StartPayload(string Version, bool PreviousUnsealed)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.Version, Version).Bool(JournalKeys.PreviousUnsealed, PreviousUnsealed).Encode();

    /// <summary>Decodes a <c>Start</c> payload.</summary>
    public static StartPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.Text(JournalKeys.Version) ?? string.Empty, m.Bool(JournalKeys.PreviousUnsealed) ?? false);
    }
}

/// <summary>
/// <c>CheckpointKeyChanged</c> (type 7): the new checkpoint key block; the old checkpoint key's
/// signature over the new key when the signer holds the old key; and, when the system key in
/// the block differs from the one before, the old system key's signature over the new one when
/// the signer holds it, otherwise what explains the change.
/// </summary>
public sealed record CheckpointKeyChangedPayload(KeyBlock NewKey, byte[]? OldKeySignature = null, string? OldKeyAlgorithm = null,
    byte[]? OldSystemKeySignature = null, string? OldSystemKeyAlgorithm = null, ChangeExplanation? Explains = null, byte[]? SystemPublicKey = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Map(JournalKeys.CheckpointKey, NewKey.ToMap())
        .Bytes(JournalKeys.OldKeySignature, OldKeySignature).Text(JournalKeys.OldKeyAlgorithm, OldKeyAlgorithm)
        .Bytes(JournalKeys.OldSystemKeySignature, OldSystemKeySignature).Text(JournalKeys.OldSystemKeyAlgorithm, OldSystemKeyAlgorithm)
        .Map(JournalKeys.Explains, Explains?.ToMap()).Bytes(JournalKeys.SystemPublicKey, SystemPublicKey).Encode();

    /// <summary>Decodes a <c>CheckpointKeyChanged</c> payload.</summary>
    public static CheckpointKeyChangedPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(KeyBlock.From(m.RequireMap(JournalKeys.CheckpointKey)), m.Bytes(JournalKeys.OldKeySignature), m.Text(JournalKeys.OldKeyAlgorithm),
            m.Bytes(JournalKeys.OldSystemKeySignature), m.Text(JournalKeys.OldSystemKeyAlgorithm), ChangeExplanation.From(m.Map(JournalKeys.Explains)),
            m.Bytes(JournalKeys.SystemPublicKey));
    }
}

/// <summary>
/// <c>Certificate</c> (type 16): the whole to-be-signed certificate and the signature, from
/// which the certificate is rebuilt byte for byte; the four keys the node supplied; and an
/// index of serial, validity, subject key and whether it is a CA's.
/// </summary>
public sealed record CertificatePayload(
    string? Ca, byte[] CaKey, byte[]? CaCert, SigningContextInfo? Context, string? Version,
    byte[] Tbs, byte[] Signature, byte[] Serial, long NotBefore, long NotAfter, byte[] SubjectKey, bool IsCa,
    IReadOnlyList<SpentToken>? Spent = null, Answers? Answers = null, Replaces? Replaces = null, Belongs? Belongs = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder()
        .Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Bytes(JournalKeys.CaCert, CaCert)
        .Map(JournalKeys.Context, Context?.ToMap()).Text(JournalKeys.Version, Version)
        .Bytes(JournalKeys.Tbs, Tbs).Bytes(JournalKeys.Signature, Signature).Bytes(JournalKeys.Serial, Serial)
        .Int(JournalKeys.NotBefore, NotBefore).Int(JournalKeys.NotAfter, NotAfter).Bytes(JournalKeys.SubjectKey, SubjectKey).Bool(JournalKeys.IsCa, IsCa)
        .MapArray(JournalKeys.Spent, Spent?.Select(s => s.ToMap()).ToList()).Map(JournalKeys.Answers, Answers?.ToMap())
        .Map(JournalKeys.Replaces, Replaces?.ToMap()).Map(JournalKeys.Belongs, Belongs is { IsEmpty: false } ? Belongs.ToMap() : null)
        .Encode();

    /// <summary>Decodes a <c>Certificate</c> payload.</summary>
    public static CertificatePayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        var spent = m.MapArray(JournalKeys.Spent).Select(SpentToken.From).ToList();
        return new(m.Text(JournalKeys.Ca), m.RequireBytes(JournalKeys.CaKey), m.Bytes(JournalKeys.CaCert),
            SigningContextInfo.From(m.Map(JournalKeys.Context)), m.Text(JournalKeys.Version),
            m.RequireBytes(JournalKeys.Tbs), m.RequireBytes(JournalKeys.Signature), m.RequireBytes(JournalKeys.Serial),
            m.RequireInt(JournalKeys.NotBefore), m.RequireInt(JournalKeys.NotAfter), m.RequireBytes(JournalKeys.SubjectKey), m.Bool(JournalKeys.IsCa) ?? false,
            spent.Count > 0 ? spent : null, Journal.Answers.From(m.Map(JournalKeys.Answers)), Journal.Replaces.From(m.Map(JournalKeys.Replaces)),
            Journal.Belongs.From(m.Map(JournalKeys.Belongs)));
    }
}

/// <summary>
/// <c>Crl</c> (type 17): the CRL number, <c>thisUpdate</c>, <c>nextUpdate</c> and the
/// signature; and either the whole to-be-signed CRL, or the sequence of the record in the same
/// segment that holds the same revoked set, with the SHA-256 of this CRL's to-be-signed bytes.
/// </summary>
public sealed record CrlPayload(
    string? Ca, byte[] CaKey, byte[]? CaCert, SigningContextInfo? Context, string? Version,
    ulong CrlNumber, long ThisUpdate, long? NextUpdate, byte[] Signature,
    byte[]? Tbs, ulong? SameSetAs, byte[]? TbsHash, bool Delta)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder()
        .Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Bytes(JournalKeys.CaCert, CaCert)
        .Map(JournalKeys.Context, Context?.ToMap()).Text(JournalKeys.Version, Version)
        .UInt(JournalKeys.CrlNumber, CrlNumber).Int(JournalKeys.ThisUpdate, ThisUpdate).Int(JournalKeys.NextUpdate, NextUpdate)
        .Bytes(JournalKeys.Signature, Signature).Bytes(JournalKeys.Tbs, Tbs).UInt(JournalKeys.SameSetAs, SameSetAs).Bytes(JournalKeys.TbsHash, TbsHash)
        .Bool(JournalKeys.Delta, Delta ? true : null)
        .Encode();

    /// <summary>Decodes a <c>Crl</c> payload.</summary>
    public static CrlPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.Text(JournalKeys.Ca), m.RequireBytes(JournalKeys.CaKey), m.Bytes(JournalKeys.CaCert),
            SigningContextInfo.From(m.Map(JournalKeys.Context)), m.Text(JournalKeys.Version),
            m.RequireUInt(JournalKeys.CrlNumber), m.RequireInt(JournalKeys.ThisUpdate), m.Int(JournalKeys.NextUpdate), m.RequireBytes(JournalKeys.Signature),
            m.Bytes(JournalKeys.Tbs), m.UInt(JournalKeys.SameSetAs), m.Bytes(JournalKeys.TbsHash), m.Bool(JournalKeys.Delta) ?? false);
    }
}

/// <summary><c>SshCertificate</c> (type 20): the whole SSH certificate as signed, and the four keys the node supplied.</summary>
public sealed record SshCertificatePayload(
    string? Ca, byte[] CaKey, SigningContextInfo? Context, string? Version, byte[] Certificate,
    IReadOnlyList<SpentToken>? Spent = null, Answers? Answers = null, Replaces? Replaces = null, Belongs? Belongs = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder()
        .Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Map(JournalKeys.Context, Context?.ToMap()).Text(JournalKeys.Version, Version)
        .Bytes(JournalKeys.SshCertificate, Certificate)
        .MapArray(JournalKeys.Spent, Spent?.Select(s => s.ToMap()).ToList()).Map(JournalKeys.Answers, Answers?.ToMap())
        .Map(JournalKeys.Replaces, Replaces?.ToMap()).Map(JournalKeys.Belongs, Belongs is { IsEmpty: false } ? Belongs.ToMap() : null)
        .Encode();

    /// <summary>Decodes an <c>SshCertificate</c> payload.</summary>
    public static SshCertificatePayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        var spent = m.MapArray(JournalKeys.Spent).Select(SpentToken.From).ToList();
        return new(m.Text(JournalKeys.Ca), m.RequireBytes(JournalKeys.CaKey), SigningContextInfo.From(m.Map(JournalKeys.Context)), m.Text(JournalKeys.Version),
            m.RequireBytes(JournalKeys.SshCertificate), spent.Count > 0 ? spent : null, Journal.Answers.From(m.Map(JournalKeys.Answers)),
            Journal.Replaces.From(m.Map(JournalKeys.Replaces)), Journal.Belongs.From(m.Map(JournalKeys.Belongs)));
    }
}

/// <summary><c>SshRevocationList</c> (type 21): the whole list for one SSH CA key, when it changed.</summary>
public sealed record SshRevocationListPayload(string? Ca, byte[] CaKey, byte[] List)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Bytes(JournalKeys.SshRevocationList, List).Encode();

    /// <summary>Decodes an <c>SshRevocationList</c> payload.</summary>
    public static SshRevocationListPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.Text(JournalKeys.Ca), m.RequireBytes(JournalKeys.CaKey), m.RequireBytes(JournalKeys.SshRevocationList));
    }
}

/// <summary>
/// <c>Revocation</c> (type 32): serial, <c>caKey</c>, reason, the time, whether the CA has a
/// record of the certificate, and which it was (revoked, hold, retired).
/// </summary>
public sealed record RevocationPayload(byte[] Serial, byte[] CaKey, string? Ca, ulong Reason, long Time, bool Known, ulong Form)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Bytes(JournalKeys.Serial, Serial)
        .UInt(JournalKeys.RevocationReason, Reason).Int(JournalKeys.Time, Time).Bool(JournalKeys.Known, Known).UInt(JournalKeys.Form, Form).Encode();

    /// <summary>Decodes a <c>Revocation</c> payload.</summary>
    public static RevocationPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireBytes(JournalKeys.Serial), m.RequireBytes(JournalKeys.CaKey), m.Text(JournalKeys.Ca), m.UInt(JournalKeys.RevocationReason) ?? 0,
            m.RequireInt(JournalKeys.Time), m.Bool(JournalKeys.Known) ?? true, m.UInt(JournalKeys.Form) ?? RevocationForm.Revoked);
    }
}

/// <summary><c>Unrevocation</c> (type 33): serial, <c>caKey</c> and the time; a hold released.</summary>
public sealed record UnrevocationPayload(byte[] Serial, byte[] CaKey, string? Ca, long Time)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.Ca, Ca).Bytes(JournalKeys.CaKey, CaKey).Bytes(JournalKeys.Serial, Serial)
        .Int(JournalKeys.Time, Time).Encode();

    /// <summary>Decodes an <c>Unrevocation</c> payload.</summary>
    public static UnrevocationPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireBytes(JournalKeys.Serial), m.RequireBytes(JournalKeys.CaKey), m.Text(JournalKeys.Ca), m.RequireInt(JournalKeys.Time));
    }
}

/// <summary><c>SpentWithoutCertificate</c> (type 34): a one-time token used with no certificate issued, by kind and identifier.</summary>
public sealed record SpentWithoutCertificatePayload(ulong Kind, string Id, long? Time = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().UInt(JournalKeys.Kind, Kind).Text(JournalKeys.Id, Id).Int(JournalKeys.Time, Time).Encode();

    /// <summary>Decodes a <c>SpentWithoutCertificate</c> payload.</summary>
    public static SpentWithoutCertificatePayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireUInt(JournalKeys.Kind), m.RequireText(JournalKeys.Id), m.Int(JournalKeys.Time));
    }
}

/// <summary>
/// <c>RestoreMarker</c> (type 35): a restore ran. The archive's file name and, from its
/// manifest, the instance identifier, the creation time and the journal head if it carries one.
/// </summary>
public sealed record RestoreMarkerPayload(string Archive, string? ArchiveInstanceId, long? ArchiveCreatedAt, HeadRef? ArchiveHead, long? Time = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Text(JournalKeys.Archive, Archive).Text(JournalKeys.ArchiveInstanceId, ArchiveInstanceId)
        .Int(JournalKeys.ArchiveCreatedAt, ArchiveCreatedAt).Map(JournalKeys.ArchiveHead, ArchiveHead?.ToMap()).Int(JournalKeys.Time, Time).Encode();

    /// <summary>Decodes a <c>RestoreMarker</c> payload.</summary>
    public static RestoreMarkerPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireText(JournalKeys.Archive), m.Text(JournalKeys.ArchiveInstanceId), m.Int(JournalKeys.ArchiveCreatedAt),
            HeadRef.From(m.Map(JournalKeys.ArchiveHead)), m.Int(JournalKeys.Time));
    }
}

/// <summary><c>ContinuityEvent</c> (type 36): the node saw a changed incarnation; the two hashes.</summary>
public sealed record ContinuityEventPayload(byte[] OldIncarnation, byte[] NewIncarnation, long? Time = null)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().Bytes(JournalKeys.OldIncarnation, OldIncarnation).Bytes(JournalKeys.NewIncarnation, NewIncarnation)
        .Int(JournalKeys.Time, Time).Encode();

    /// <summary>Decodes a <c>ContinuityEvent</c> payload.</summary>
    public static ContinuityEventPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireBytes(JournalKeys.OldIncarnation), m.RequireBytes(JournalKeys.NewIncarnation), m.Int(JournalKeys.Time));
    }
}

/// <summary><c>Disabled</c> (type 37): a kind (<see cref="DisabledKind"/>), the identifier and the time.</summary>
public sealed record DisabledPayload(ulong Kind, string Id, long Time)
{
    /// <summary>The payload's deterministic encoding.</summary>
    public byte[] Encode() => new CborMapBuilder().UInt(JournalKeys.Kind, Kind).Text(JournalKeys.Id, Id).Int(JournalKeys.Time, Time).Encode();

    /// <summary>Decodes a <c>Disabled</c> payload.</summary>
    public static DisabledPayload Decode(byte[] payload)
    {
        var m = CborMap.Decode(payload);
        return new(m.RequireUInt(JournalKeys.Kind), m.RequireText(JournalKeys.Id), m.RequireInt(JournalKeys.Time));
    }
}

/// <summary>
/// Checks a fact the node offers before the signer records it: the type must be one the node
/// may assert, and the payload must decode as that type. Returns the payload re-encoded
/// deterministically, so what is appended is this layout's encoding whatever the node sent, and
/// keys the type does not have are dropped.
/// </summary>
public static class NodeFacts
{
    /// <summary>Validates and re-encodes a fact payload.</summary>
    /// <exception cref="FormatException">The type is not a node fact, or the payload does not decode as it.</exception>
    public static byte[] Normalize(ushort type, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return type switch
        {
            RecordType.Revocation => Check(RevocationPayload.Decode(payload)).Encode(),
            RecordType.Unrevocation => Check(UnrevocationPayload.Decode(payload)).Encode(),
            RecordType.SpentWithoutCertificate => SpentWithoutCertificatePayload.Decode(payload).Encode(),
            RecordType.RestoreMarker => RestoreMarkerPayload.Decode(payload).Encode(),
            RecordType.ContinuityEvent => Check(ContinuityEventPayload.Decode(payload)).Encode(),
            RecordType.Disabled => DisabledPayload.Decode(payload).Encode(),
            RecordType.SshRevocationList => Check(SshRevocationListPayload.Decode(payload)).Encode(),
            _ => throw new FormatException($"Record type {RecordType.Name(type)} is not a fact the node asserts."),
        };
    }

    private static RevocationPayload Check(RevocationPayload p)
    {
        Hash(p.CaKey, "caKey");
        if (p.Serial.Length is 0 or > 64) throw new FormatException("A serial is 1 to 64 bytes.");
        return p;
    }

    private static UnrevocationPayload Check(UnrevocationPayload p)
    {
        Hash(p.CaKey, "caKey");
        if (p.Serial.Length is 0 or > 64) throw new FormatException("A serial is 1 to 64 bytes.");
        return p;
    }

    private static ContinuityEventPayload Check(ContinuityEventPayload p)
    {
        Hash(p.OldIncarnation, "the old incarnation");
        Hash(p.NewIncarnation, "the new incarnation");
        return p;
    }

    private static SshRevocationListPayload Check(SshRevocationListPayload p)
    {
        Hash(p.CaKey, "caKey");
        return p;
    }

    private static void Hash(byte[] value, string name)
    {
        if (value.Length != JournalFormat.HashLength)
            throw new FormatException($"{name} is a SHA-256: 32 bytes.");
    }
}
