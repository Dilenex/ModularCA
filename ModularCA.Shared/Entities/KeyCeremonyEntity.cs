using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Represents a key ceremony workflow for catastrophic CA operations that require
/// multi-party approval (quorum). Ceremonies track the initiator, required approvals,
/// current approval state, and expiration. The audit trail is permanent and must never be deleted.
/// </summary>
[Table("KeyCeremonies")]
public class KeyCeremonyEntity
{
    /// <summary>Primary key.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// The type of catastrophic operation (e.g., CreateRootCA, CreateIntermediateCA, RevokeCA).
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string OperationType { get; set; } = string.Empty;

    /// <summary>
    /// Coarse category for this ceremony. Nullable so historical rows (written before this
    /// column existed) still deserialize; the migration backfills all existing rows to
    /// <see cref="CeremonyType.CaCreation"/>. Query-path filters should treat <c>null</c>
    /// as <c>CaCreation</c> for backwards compatibility.
    /// </summary>
    public CeremonyType? CeremonyType { get; set; }

    /// <summary>Human-readable description of the ceremony's purpose.</summary>
    [MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    /// <summary>The ID of the entity targeted by this operation (e.g., CA ID).</summary>
    public string TargetEntityId { get; set; } = string.Empty;

    /// <summary>The user ID of the administrator who initiated this ceremony.</summary>
    public Guid InitiatedByUserId { get; set; }

    /// <summary>The username of the administrator who initiated this ceremony.</summary>
    [MaxLength(255)]
    public string InitiatedByUsername { get; set; } = string.Empty;

    /// <summary>
    /// The number of distinct admin approvals required before the operation can execute.
    /// Derived from the CA admin group's RequiredQuorum at initiation time.
    /// </summary>
    public int RequiredApprovals { get; set; } = 1;

    /// <summary>The current number of approvals received.</summary>
    public int CurrentApprovals { get; set; } = 0;

    /// <summary>
    /// The ceremony lifecycle status: Pending, Approved, Rejected, Executed, Expired, or Cancelled.
    /// </summary>
    [MaxLength(20)]
    public string Status { get; set; } = "Pending";

    /// <summary>Timestamp when the ceremony was initiated.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Timestamp when the ceremony expires if not completed. Default 24 hours from creation.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Timestamp when the ceremony operation was executed, if applicable.</summary>
    public DateTime? ExecutedAt { get; set; }

    /// <summary>
    /// Serialized JSON of the operation parameters needed to execute the ceremony.
    /// </summary>
    public string ParametersJson { get; set; } = "{}";

    /// <summary>
    /// Serialized JSON array of approval records, each containing userId, username, timestamp, and decision.
    /// </summary>
    public string ApprovalsJson { get; set; } = "[]";

    /// <summary>
    /// The space this ceremony belongs to, or null for the instance. Used for scoping
    /// visibility to CA admins within the same space. Populated from the top-level
    /// <c>SpaceId</c> of ParametersJson at initiation time.
    /// </summary>
    public Guid? SpaceId { get; set; }
}
