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

    /// <summary>
    /// The hash chain the record belongs to: null for the instance chain, where every record goes
    /// from 0.4.0, or the id of the tenant whose retired per-tenant chain holds a record written before.
    /// </summary>
    public Guid? TenantId { get; set; }

    /// <summary>
    /// The space the event belongs to, or null for the instance or an event of no space. It does not
    /// select the chain (<see cref="TenantId"/> does), and it is hashed only when set, so records
    /// written before it existed verify unchanged.
    /// </summary>
    public Guid? SpaceId { get; set; }

    /// <summary>The access badge the actor wore, if any; the audit trail names the badge, not just the user.</summary>
    public Guid? AccessBadgeId { get; set; }

    /// <summary>The worn badge's name at the time, so the row reads without a lookup.</summary>
    [MaxLength(100)]
    public string? AccessBadgeName { get; set; }

    /// <summary>SHA-256 hex hash of the canonical form of this audit record.</summary>
    [MaxLength(64)]
    public string? RecordHash { get; set; }

    /// <summary>
    /// Which canonical form <see cref="RecordHash"/> was computed with, or null for a record
    /// written before the form was versioned.
    /// <para>
    /// A null here is not a defect in the row; it means the hash was computed over a rendering of
    /// the timestamp carrying more precision than the column could store, so the value it was
    /// taken from no longer exists and the hash can never be reproduced. Those records are
    /// reported as unverifiable rather than as tampered, which is the honest answer and the one
    /// that leaves a real tamper visible instead of buried.
    /// </para>
    /// </summary>
    public int? HashVersion { get; set; }

    /// <summary>RecordHash of the preceding record in this tenant's chain. Null for the first record.</summary>
    [MaxLength(64)]
    public string? PreviousRecordHash { get; set; }
}
