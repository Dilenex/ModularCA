using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("AuditLogs")]
public class AuditLogEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Actor information
    public Guid? ActorUserId { get; set; }

    [MaxLength(255)]
    public string? ActorUsername { get; set; }

    // What happened
    // Widened from 50 → 80. Several new action-type constants
    // (KeystoreKeyReplaced, PolicySyncImported, CertManagerSignCompleted) live near
    // the old cap; the enum catalog should be string-named without truncation risk.
    [Required]
    [MaxLength(80)]
    public string ActionType { get; set; } = string.Empty;

    // What it happened to
    [MaxLength(50)]
    public string? TargetEntityType { get; set; }

    [MaxLength(255)]
    public string? TargetEntityId { get; set; }

    // Details as JSON blob
    public string? DetailsJson { get; set; }

    // Request context
    [MaxLength(45)]
    public string? SourceIp { get; set; }

    // Outcome
    public bool Success { get; set; } = true;

    [MaxLength(500)]
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// The CA this audit event applies to. Null for system-wide events (login, config changes).
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>Tenant ID for tenant-scoped audit filtering. Derived from the CA's tenant when available.</summary>
    public Guid? TenantId { get; set; }

    /// <summary>The access badge the actor wore, if any; the audit trail names the badge, not just the user.</summary>
    public Guid? AccessBadgeId { get; set; }

    /// <summary>The worn badge's name at the time, so the row reads without a lookup.</summary>
    [MaxLength(100)]
    public string? AccessBadgeName { get; set; }

    /// <summary>SHA-256 hex hash of the canonical form of this audit record.</summary>
    [MaxLength(64)]
    public string? RecordHash { get; set; }

    /// <summary>RecordHash of the preceding record in this tenant's chain. Null for the first record.</summary>
    [MaxLength(64)]
    public string? PreviousRecordHash { get; set; }
}
