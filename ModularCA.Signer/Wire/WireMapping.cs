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
        TenantId = ToWire(context.TenantId),
        CaId = ToWire(context.CaId),
        CeremonyId = ToWire(context.CeremonyId),
    };

    /// <summary>Reads a context from the wire; an unknown purpose or a missing message is an argument error.</summary>
    public static Shared.Signing.SigningContext FromWire(SigningContext? context)
    {
        if (context == null) throw new ArgumentException("The signing context is missing.", "context");
        if (!Enum.TryParse<SigningPurpose>(context.Purpose, ignoreCase: false, out var purpose) || !Enum.IsDefined(purpose))
            throw new ArgumentException($"'{context.Purpose}' is not a signing purpose.", "context.purpose");
        return new Shared.Signing.SigningContext(
            context.Caller,
            purpose,
            ToNullableGuid(context.TenantId, "context.tenant_id"),
            ToNullableGuid(context.CaId, "context.ca_id"),
            ToNullableGuid(context.CeremonyId, "context.ceremony_id"));
    }

    /// <summary>Maps a key spec to the wire.</summary>
    public static KeySpec ToWire(Shared.Signing.KeySpec spec)
    {
        var wire = new KeySpec { Algorithm = spec.Algorithm, SizeOrCurve = spec.SizeOrCurve };
        if (spec.Label != null) wire.Label = spec.Label;
        return wire;
    }

    /// <summary>Reads a key spec from the wire.</summary>
    public static Shared.Signing.KeySpec FromWire(KeySpec? spec)
    {
        if (spec == null) throw new ArgumentException("The key spec is missing.", "spec");
        return new Shared.Signing.KeySpec(spec.Algorithm, spec.SizeOrCurve, spec.HasLabel ? spec.Label : null);
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
        TenantId = ToWire(info.TenantId),
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
            ToNullableGuid(info.TenantId, "keys.tenant_id"),
            info.Backend);
    }

    /// <summary>Maps a health report to the wire.</summary>
    public static HealthResponse ToWire(SignerHealth health) => new()
    {
        Unlocked = health.Unlocked,
        KeyCount = health.KeyCount,
        Backend = health.Backend,
    };

    /// <summary>Reads a health report from the wire.</summary>
    public static SignerHealth FromWire(HealthResponse health) => new(health.Unlocked, health.KeyCount, health.Backend);

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
