using Google.Protobuf;
using Grpc.Core;
using ModularCA.Shared.Signing;

namespace ModularCA.Signer.Wire;

/// <summary>
/// The mapping between the contract types in <see cref="ModularCA.Shared.Signing"/> and their
/// wire messages, in both directions, and the refusal convention both ends share: a refusal is
/// a <see cref="StatusCode.PermissionDenied"/> status whose detail is the message and whose
/// <see cref="RefusalReasonTrailer"/> trailer carries the <see cref="SigningRefusalReason"/>
/// member name. Bad input from the wire is an <see cref="ArgumentException"/>, which the
/// server turns into <see cref="StatusCode.InvalidArgument"/>.
/// </summary>
public static class WireMapping
{
    /// <summary>The trailer that names the refusal reason on a refused call.</summary>
    public const string RefusalReasonTrailer = "modularca-refusal-reason";

    /// <summary>Renders a nullable GUID for the wire: its canonical form, or empty for none.</summary>
    public static string ToWire(Guid? id) => id?.ToString("D") ?? string.Empty;

    /// <summary>Reads a GUID the wire may leave empty.</summary>
    public static Guid? ToNullableGuid(string value, string field)
    {
        if (string.IsNullOrEmpty(value)) return null;
        return ToGuid(value, field);
    }

    /// <summary>Reads a GUID the wire must carry.</summary>
    public static Guid ToGuid(string value, string field)
        => Guid.TryParseExact(value, "D", out var id)
            ? id
            : throw new ArgumentException($"'{value}' is not a GUID.", field);

    /// <summary>Maps a key reference to the wire.</summary>
    public static KeyRef ToWire(Shared.Signing.KeyRef key) => new()
    {
        CertificateId = key.CertificateId.ToString("D"),
        Keystore = key.Keystore,
    };

    /// <summary>Reads a key reference from the wire; a missing message is an argument error.</summary>
    public static Shared.Signing.KeyRef FromWire(KeyRef? key)
    {
        if (key == null) throw new ArgumentException("The key reference is missing.", "key");
        return new Shared.Signing.KeyRef(
            ToGuid(key.CertificateId, "key.certificate_id"),
            string.IsNullOrEmpty(key.Keystore) ? Shared.Signing.KeyRef.DefaultKeystore : key.Keystore);
    }

    /// <summary>Maps a context to the wire.</summary>
    public static SigningContext ToWire(Shared.Signing.SigningContext context) => new()
    {
        Caller = context.Caller ?? string.Empty,
        Purpose = context.Purpose.ToString(),
        SpaceId = ToWire(context.SpaceId),
        CaId = ToWire(context.CaId),
        CeremonyId = ToWire(context.CeremonyId),
        InstanceScope = context.InstanceScope,
        Issuance = ToWire(context.Issuance),
    };

    /// <summary>What the node knows about an issuance, for the wire; null when it passed nothing.</summary>
    public static IssuanceOrigin? ToWire(Shared.Signing.IssuanceOrigin? origin)
    {
        if (origin == null) return null;
        var wire = new IssuanceOrigin { Protocol = origin.Protocol ?? string.Empty, Requester = origin.Requester ?? string.Empty };
        foreach (var token in origin.Spent ?? Array.Empty<IssuanceSpent>())
            wire.Spent.Add(new SpentToken { Kind = token.Kind, Id = token.Id, Use = token.Use });
        if (origin.Answers is { } answers)
            wire.Answers = new IssuanceAnswers { Kind = answers.Kind, Id = answers.Id ?? string.Empty };
        if (origin.Replaces is { } replaces)
            wire.Replaces = new IssuanceReplaces { Serial = ByteString.CopyFrom(replaces.Serial), CaKey = ByteString.CopyFrom(replaces.CaKey) };
        if (origin.Belongs is { IsEmpty: false } belongs)
            wire.Belongs = new IssuanceBelongs
            {
                Profile = belongs.Profile ?? string.Empty,
                Space = belongs.Space ?? string.Empty,
                OwnerKind = belongs.OwnerKind ?? 0,
                Owner = belongs.Owner ?? string.Empty,
                Template = belongs.Template ?? string.Empty,
            };
        return wire;
    }

    /// <summary>What the node passed with an issuance, off the wire; null when it passed nothing. An empty string is an absent member.</summary>
    public static Shared.Signing.IssuanceOrigin? FromWire(IssuanceOrigin? origin)
    {
        if (origin == null) return null;
        static string? Text(string value) => string.IsNullOrEmpty(value) ? null : value;
        var belongs = origin.Belongs == null ? null : new Shared.Signing.IssuanceBelongs(
            Text(origin.Belongs.Profile), Text(origin.Belongs.Space),
            origin.Belongs.OwnerKind == 0 ? null : origin.Belongs.OwnerKind, Text(origin.Belongs.Owner), Text(origin.Belongs.Template));
        return new Shared.Signing.IssuanceOrigin(
            origin.Spent.Count == 0 ? null : origin.Spent.Select(t => new IssuanceSpent(t.Kind, t.Id, t.Use == 0 ? 1 : t.Use)).ToList(),
            origin.Answers == null ? null : new Shared.Signing.IssuanceAnswers(origin.Answers.Kind, Text(origin.Answers.Id)),
            origin.Replaces == null ? null : new Shared.Signing.IssuanceReplaces(origin.Replaces.Serial.ToByteArray(), origin.Replaces.CaKey.ToByteArray()),
            belongs is { IsEmpty: false } ? belongs : null,
            Text(origin.Protocol),
            Text(origin.Requester));
    }

    /// <summary>The signer's journal report for the wire; <c>present</c> is false for a signer that keeps none.</summary>
    public static JournalInfoResponse ToWire(SignerJournalInfo? info)
    {
        if (info == null) return new JournalInfoResponse { Present = false };
        var response = new JournalInfoResponse
        {
            Present = true,
            Available = info.Available,
            Fault = info.Fault ?? string.Empty,
            Seq = info.Seq,
            Hash = info.Hash,
            LastCheckpointUnixMicros = info.LastCheckpointAtUtc is DateTime at ? (DateTime.SpecifyKind(at, DateTimeKind.Utc).Ticks - DateTime.UnixEpoch.Ticks) / 10 : 0,
            UncheckpointedRecords = info.UncheckpointedRecords,
            SizeBytes = info.SizeBytes,
            FreeBytes = info.FreeBytes ?? 0,
            FreeKnown = info.FreeBytes != null,
            AwaitingRestoreMarkerUntilUnixMicros = info.AwaitingRestoreMarkerUntilUtc is DateTime until ? Micros(until) : 0,
            LowSpaceBytes = info.LowSpaceBytes ?? 0,
            CriticalSpaceBytes = info.CriticalSpaceBytes ?? 0,
            SpaceLevelsKnown = info.LowSpaceBytes != null && info.CriticalSpaceBytes != null,
            SetAsideJournals = info.SetAsideJournals,
            SetAsideBytes = info.SetAsideBytes,
            Verified = info.Verified switch { true => 1, false => 2, null => 0 },
            VerificationFault = info.VerificationFault ?? string.Empty,
            VerifiedBytes = info.VerifiedBytes ?? 0,
            VerifyTotalBytes = info.VerifyTotalBytes ?? 0,
            VerificationProgressKnown = info.VerifiedBytes != null && info.VerifyTotalBytes != null,
        };
        foreach (var refused in info.RefusedCrls ?? [])
            response.RefusedCrls.Add(new RefusedCrl
            {
                CaId = refused.CaId?.ToString("D") ?? string.Empty,
                CaKey = refused.CaKey,
                MissingSerials = refused.MissingSerials,
                RefusedAtUnixMicros = Micros(refused.RefusedAtUtc),
                JournaledCrlNumber = refused.JournaledCrlNumber,
            });
        return response;
    }

    private static long Micros(DateTime utc) => (DateTime.SpecifyKind(utc, DateTimeKind.Utc).Ticks - DateTime.UnixEpoch.Ticks) / 10;

    private static DateTime FromMicros(long micros) => new(DateTime.UnixEpoch.Ticks + micros * 10, DateTimeKind.Utc);

    /// <summary>Writes the serials a refused CRL left out to the wire; <c>present</c> is false for none.</summary>
    public static JournalMissingRevocationsResponse ToWire(SignerJournalMissingRevocations? missing)
    {
        if (missing == null) return new JournalMissingRevocationsResponse { Present = false };
        var response = new JournalMissingRevocationsResponse
        {
            Present = true,
            RefusedAtUnixMicros = Micros(missing.RefusedAtUtc),
            JournaledCrlNumber = missing.JournaledCrlNumber,
        };
        foreach (var serial in missing.Serials)
            response.Serials.Add(new MissingSerial { Serial = serial.Serial, Reason = serial.Reason, RevokedAtUnixMicros = Micros(serial.RevokedAtUtc) });
        return response;
    }

    /// <summary>Reads the serials a refused CRL left out from the wire; null when no refusal stands.</summary>
    public static SignerJournalMissingRevocations? FromWire(Guid caId, JournalMissingRevocationsResponse response)
    {
        if (!response.Present) return null;
        return new SignerJournalMissingRevocations(caId, FromMicros(response.RefusedAtUnixMicros), response.JournaledCrlNumber,
            response.Serials.Select(s => new SignerJournalMissingSerial(s.Serial, s.Reason, FromMicros(s.RevokedAtUnixMicros))).ToList());
    }

    /// <summary>The signer's journal report off the wire; null when the signer keeps none.</summary>
    public static SignerJournalInfo? FromWire(JournalInfoResponse response)
    {
        if (!response.Present) return null;
        return new SignerJournalInfo(
            response.Available,
            string.IsNullOrEmpty(response.Fault) ? null : response.Fault,
            response.Seq,
            response.Hash,
            response.LastCheckpointUnixMicros == 0 ? null : new DateTime(DateTime.UnixEpoch.Ticks + response.LastCheckpointUnixMicros * 10, DateTimeKind.Utc),
            response.UncheckpointedRecords,
            response.SizeBytes,
            response.FreeKnown ? response.FreeBytes : null,
            response.AwaitingRestoreMarkerUntilUnixMicros == 0 ? null : FromMicros(response.AwaitingRestoreMarkerUntilUnixMicros),
            response.SpaceLevelsKnown ? response.LowSpaceBytes : null,
            response.SpaceLevelsKnown ? response.CriticalSpaceBytes : null,
            response.SetAsideJournals,
            response.SetAsideBytes,
            response.RefusedCrls.Select(r => new SignerJournalRefusedCrl(
                Guid.TryParse(r.CaId, out var id) ? id : null, r.CaKey, r.MissingSerials, FromMicros(r.RefusedAtUnixMicros), r.JournaledCrlNumber)).ToList(),
            response.Verified switch { 1 => true, 2 => false, _ => null },
            string.IsNullOrEmpty(response.VerificationFault) ? null : response.VerificationFault,
            response.VerificationProgressKnown ? response.VerifiedBytes : null,
            response.VerificationProgressKnown ? response.VerifyTotalBytes : null);
    }

    /// <summary>Writes a part of the journal's revocations to the wire; <c>present</c> is false for none.</summary>
    public static JournaledRevocationsResponse ToWire(SignerJournaledRevocations? list)
    {
        if (list == null) return new JournaledRevocationsResponse { Present = false };
        var response = new JournaledRevocationsResponse
        {
            Present = true,
            Trusted = list.Trusted,
            NotTrustedReason = list.NotTrustedReason ?? string.Empty,
            CrlKnown = list.CrlNumber != null,
            CrlNumber = list.CrlNumber ?? 0,
            CrlSeq = list.CrlSeq ?? 0,
            Total = list.Total,
        };
        foreach (var e in list.Entries)
            response.Entries.Add(new JournaledRevocation
            {
                Serial = e.Serial, Reason = e.Reason, RevokedAtUnixMicros = Micros(e.RevokedAtUtc), Hold = e.Hold,
                Source = e.Source, SourceNumber = e.SourceNumber, SourceSeq = e.SourceSeq,
            });
        return response;
    }

    /// <summary>Reads a part of the journal's revocations from the wire; null when the journal holds none for the CA.</summary>
    public static SignerJournaledRevocations? FromWire(Guid caId, JournaledRevocationsResponse response)
    {
        if (!response.Present) return null;
        return new SignerJournaledRevocations(caId, response.Trusted,
            string.IsNullOrEmpty(response.NotTrustedReason) ? null : response.NotTrustedReason,
            response.CrlKnown ? response.CrlNumber : null, response.CrlKnown ? response.CrlSeq : null, response.Total,
            response.Entries.Select(e => new SignerJournaledRevocation(e.Serial, e.Reason, FromMicros(e.RevokedAtUnixMicros), e.Hold, e.Source, e.SourceNumber, e.SourceSeq)).ToList());
    }

    /// <summary>
    /// Reads a context from the wire; an unknown purpose or a missing message is an argument
    /// error. The instance marker crosses only as sent: an omitted one is false, so an empty
    /// space id from an older client is an unstated scope, not the instance.
    /// </summary>
    public static Shared.Signing.SigningContext FromWire(SigningContext? context)
    {
        if (context == null) throw new ArgumentException("The signing context is missing.", "context");
        if (!Enum.TryParse<SigningPurpose>(context.Purpose, ignoreCase: false, out var purpose) || !Enum.IsDefined(purpose))
            throw new ArgumentException($"'{context.Purpose}' is not a signing purpose.", "context.purpose");
        return new Shared.Signing.SigningContext(
            context.Caller,
            purpose,
            ToNullableGuid(context.SpaceId, "context.space_id"),
            ToNullableGuid(context.CaId, "context.ca_id"),
            ToNullableGuid(context.CeremonyId, "context.ceremony_id"))
        {
            Issuance = FromWire(context.Issuance),
            InstanceScope = context.InstanceScope,
        };
    }

    /// <summary>Maps a key spec to the wire; the X.509 usage crosses as the empty default.</summary>
    public static KeySpec ToWire(Shared.Signing.KeySpec spec)
    {
        var wire = new KeySpec { Algorithm = spec.Algorithm, SizeOrCurve = spec.SizeOrCurve, Usage = spec.Usage ?? Shared.Signing.KeySpec.X509Usage };
        if (spec.Label != null) wire.Label = spec.Label;
        return wire;
    }

    /// <summary>
    /// Reads a key spec from the wire. A client older than the usage field omits it, which
    /// reads as the X.509 usage; the signer refuses any usage it does not know.
    /// </summary>
    public static Shared.Signing.KeySpec FromWire(KeySpec? spec)
    {
        if (spec == null) throw new ArgumentException("The key spec is missing.", "spec");
        return new Shared.Signing.KeySpec(spec.Algorithm, spec.SizeOrCurve, spec.HasLabel ? spec.Label : null, spec.Usage);
    }

    /// <summary>Maps key material to the wire.</summary>
    public static KeyMaterial ToWire(Shared.Signing.KeyMaterial material) => new()
    {
        Wrapped = ByteString.CopyFrom(material.Wrapped),
        Format = material.Format,
        CertificateId = material.CertificateId.ToString("D"),
        Keystore = material.Keystore,
    };

    /// <summary>Reads key material from the wire.</summary>
    public static Shared.Signing.KeyMaterial FromWire(KeyMaterial? material)
    {
        if (material == null) throw new ArgumentException("The key material is missing.", "material");
        return new Shared.Signing.KeyMaterial(
            material.Wrapped.ToByteArray(),
            material.Format,
            ToGuid(material.CertificateId, "material.certificate_id"),
            string.IsNullOrEmpty(material.Keystore) ? Shared.Signing.KeyRef.DefaultKeystore : material.Keystore);
    }

    /// <summary>Maps an export wrap to the wire.</summary>
    public static ExportWrap ToWire(Shared.Signing.ExportWrap wrap)
    {
        var wire = new ExportWrap { Format = wrap.Format, Password = wrap.Password ?? string.Empty };
        foreach (var der in wrap.Chain ?? Array.Empty<byte[]>())
            wire.Chain.Add(ByteString.CopyFrom(der));
        return wire;
    }

    /// <summary>Reads an export wrap from the wire.</summary>
    public static Shared.Signing.ExportWrap FromWire(ExportWrap? wrap)
    {
        if (wrap == null) throw new ArgumentException("The export wrap is missing.", "wrap");
        return new Shared.Signing.ExportWrap(
            wrap.Format,
            wrap.Password,
            wrap.Chain.Count == 0 ? null : wrap.Chain.Select(c => c.ToByteArray()).ToList());
    }

    /// <summary>Maps a listed key to the wire.</summary>
    public static KeyInfo ToWire(Shared.Signing.KeyInfo info) => new()
    {
        Key = ToWire(info.Key),
        PublicKeyDer = ByteString.CopyFrom(info.PublicKeyDer),
        Kind = info.Kind.ToString(),
        CaId = ToWire(info.CaId),
        SpaceId = ToWire(info.SpaceId),
        Backend = info.Backend,
    };

    /// <summary>Reads a listed key from the wire.</summary>
    public static Shared.Signing.KeyInfo FromWire(KeyInfo info)
    {
        if (!Enum.TryParse<KeyKind>(info.Kind, ignoreCase: false, out var kind) || !Enum.IsDefined(kind))
            throw new ArgumentException($"'{info.Kind}' is not a key kind.", "keys.kind");
        return new Shared.Signing.KeyInfo(
            FromWire(info.Key),
            info.PublicKeyDer.ToByteArray(),
            kind,
            ToNullableGuid(info.CaId, "keys.ca_id"),
            ToNullableGuid(info.SpaceId, "keys.space_id"),
            info.Backend);
    }

    /// <summary>
    /// Maps an SSH certificate request and its context to the wire. The wire has no null, so a
    /// member left null crosses as empty, which is also how the in-process signer reads it.
    /// </summary>
    public static SignSshCertificateRequest ToWire(Shared.Signing.SshCertificateRequest request, Shared.Signing.SigningContext context)
    {
        var wire = new SignSshCertificateRequest
        {
            Key = ToWire(request.Key),
            SubjectPublicKey = ByteString.CopyFrom(request.SubjectPublicKey ?? Array.Empty<byte>()),
            CertType = request.CertType ?? string.Empty,
            Serial = request.Serial,
            KeyId = request.KeyId ?? string.Empty,
            ValidAfter = request.ValidAfter,
            ValidBefore = request.ValidBefore,
            Context = ToWire(context),
        };
        foreach (var principal in request.Principals ?? Array.Empty<string>())
            wire.Principals.Add(principal ?? string.Empty);
        foreach (var option in request.CriticalOptions ?? Array.Empty<Shared.Signing.SshCertificateOption>())
            wire.CriticalOptions.Add(ToWire(option));
        foreach (var option in request.Extensions ?? Array.Empty<Shared.Signing.SshCertificateOption>())
            wire.Extensions.Add(ToWire(option));
        return wire;
    }

    /// <summary>
    /// Reads an SSH certificate request from the wire; its context is read apart, as for every
    /// call. A missing key reference, or one whose id is not a GUID, is an argument error. What
    /// the fields say is not judged here: a certificate type, a subject key or a time that makes
    /// no certificate reaches the signer, which refuses it and records that it did.
    /// </summary>
    public static Shared.Signing.SshCertificateRequest FromWire(SignSshCertificateRequest? request)
    {
        if (request == null) throw new ArgumentException("The SSH certificate request is missing.", "request");
        return new Shared.Signing.SshCertificateRequest(
            FromWire(request.Key),
            request.SubjectPublicKey.ToByteArray(),
            request.CertType,
            request.Serial,
            request.KeyId,
            request.Principals.ToList(),
            request.ValidAfter,
            request.ValidBefore,
            request.CriticalOptions.Select(FromWire).ToList(),
            request.Extensions.Select(FromWire).ToList());
    }

    /// <summary>Maps a critical option or extension to the wire; a missing one, name or value is empty.</summary>
    public static SshOption ToWire(Shared.Signing.SshCertificateOption? option) => new()
    {
        Name = option?.Name ?? string.Empty,
        Value = option?.Value ?? string.Empty,
    };

    /// <summary>Reads a critical option or extension from the wire.</summary>
    public static Shared.Signing.SshCertificateOption FromWire(SshOption option) => new(option.Name, option.Value);

    /// <summary>Renders a secret kind for the wire: the enum member's name, as purposes cross.</summary>
    public static string ToWire(SecretKind kind) => kind.ToString();

    /// <summary>Reads a secret kind from the wire; an unknown kind is an argument error rather than a guess.</summary>
    public static SecretKind ToSecretKind(string value)
        => Enum.TryParse<SecretKind>(value, ignoreCase: false, out var kind) && Enum.IsDefined(kind)
            ? kind
            : throw new ArgumentException($"'{value}' is not a secret kind.", "kind");

    /// <summary>
    /// Maps a health report to the wire, with the HSM settings when the report carries them:
    /// whether it is on, the module path, the slot and the key labels. The types have no field
    /// for the PIN or a key id.
    /// </summary>
    public static HealthResponse ToWire(SignerHealth health)
    {
        var wire = new HealthResponse
        {
            Unlocked = health.Unlocked,
            KeyCount = health.KeyCount,
            Backend = health.Backend,
        };
        if (health.Hsm is { } hsm)
        {
            wire.Hsm = new HsmStatus { Enabled = hsm.Enabled, ModulePath = hsm.ModulePath, SlotId = hsm.SlotId };
            foreach (var label in hsm.KeyLabels)
                wire.Hsm.KeyLabels.Add(new HsmKeyLabel { CaLabel = label.CaLabel, KeyLabel = label.KeyLabel });
        }
        return wire;
    }

    /// <summary>Reads a health report from the wire; the HSM settings are null from a signer that sent none.</summary>
    public static SignerHealth FromWire(HealthResponse health) => new(health.Unlocked, health.KeyCount, health.Backend)
    {
        Hsm = health.Hsm is { } hsm
            ? new SignerHsmStatus(hsm.Enabled, hsm.ModulePath, hsm.SlotId,
                hsm.KeyLabels.Select(l => new SignerHsmKeyLabel(l.CaLabel, l.KeyLabel)).ToList())
            : null,
    };

    /// <summary>
    /// The status a refusal crosses the wire as: PermissionDenied, the message as the detail,
    /// the reason's name in the trailer.
    /// </summary>
    public static RpcException ToRpcException(SigningRefusedException refusal)
    {
        var trailers = new Metadata { { RefusalReasonTrailer, refusal.Reason.ToString() } };
        return new RpcException(new Status(StatusCode.PermissionDenied, refusal.Message), trailers);
    }

    /// <summary>
    /// The refusal a status carries, when it carries one: the trailer names a
    /// <see cref="SigningRefusalReason"/>. Null for a status that is not a refusal.
    /// </summary>
    public static SigningRefusedException? ToRefusal(RpcException ex)
    {
        var reason = ex.Trailers.GetValue(RefusalReasonTrailer);
        if (reason == null) return null;
        if (!Enum.TryParse<SigningRefusalReason>(reason, ignoreCase: false, out var parsed) || !Enum.IsDefined(parsed))
            return null;
        return new SigningRefusedException(parsed, ex.Status.Detail);
    }
}
