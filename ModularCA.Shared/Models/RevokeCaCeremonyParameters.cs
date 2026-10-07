namespace ModularCA.Shared.Models;

/// <summary>
/// Parameters for the RevokeCa key ceremony (KC-06). Serialized into the ceremony's
/// ParametersJson column and deserialized at execution time.
/// </summary>
public class RevokeCaCeremonyParameters
{
    /// <summary>Primary key of the CA certificate to revoke.</summary>
    public Guid CertificateId { get; set; }

    /// <summary>Serial number of the CA certificate (for audit/display).</summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>Revocation reason as a string (maps to <see cref="ModularCA.Shared.Enums.RevocationReason"/>).</summary>
    public string Reason { get; set; } = "Unspecified";

    /// <summary>Space that owns the CA, or null for an instance CA. <see cref="Guid.Empty"/> reads as null.</summary>
    public Guid? SpaceId { get => _spaceId; set => _spaceId = value == Guid.Empty ? null : value; }
    private Guid? _spaceId;
}
