using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// The incarnation this database last saw (<c>docs/architecture/rollback-continuity.md</c>,
/// section 1). One row, kept in the database it would be rolled back with: a start compares it
/// with what the machine reports, and a difference means this database is running on another
/// machine or timeline than the one that last wrote it.
/// </summary>
[Table("InstanceIncarnation")]
public class InstanceIncarnationEntity
{
    /// <summary>The fixed id of the one row.</summary>
    public const int SingletonId = 1;

    /// <summary>The row id; always <see cref="SingletonId"/>.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.None)]
    public int Id { get; set; } = SingletonId;

    /// <summary>The source the value came from: <c>injected</c>, or <c>none</c> when the machine reported nothing.</summary>
    [Required]
    [MaxLength(32)]
    public string Source { get; set; } = string.Empty;

    /// <summary>SHA-256, in hex, of the value the source reported; null for <c>none</c>. The value itself is not kept.</summary>
    [MaxLength(64)]
    public string? ValueHash { get; set; }

    /// <summary>When this value was stored.</summary>
    public DateTime RecordedAt { get; set; } = DateTime.UtcNow;

    /// <summary>What stored it: a start, or the product's own restore.</summary>
    [MaxLength(64)]
    public string RecordedBy { get; set; } = string.Empty;
}

/// <summary>
/// One time the instance found itself running from an earlier or copied state, or lost its
/// incarnation source. An event nobody has acknowledged is the standing notice in the console
/// and in <c>/health/ready</c>.
/// </summary>
[Table("InstanceContinuityEvents")]
public class InstanceContinuityEventEntity
{
    /// <summary>The row id (UUID version 7).</summary>
    [Key]
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>What was found: see <c>ContinuityEventKind</c>.</summary>
    [Required]
    [MaxLength(32)]
    public string Kind { get; set; } = string.Empty;

    /// <summary>When the start that found it ran.</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>The short tag of the incarnation the database held; null when it held none or the event is not about one.</summary>
    [MaxLength(64)]
    public string? OldTag { get; set; }

    /// <summary>The short tag of the incarnation the machine reported; null when it reported none.</summary>
    [MaxLength(64)]
    public string? NewTag { get; set; }

    /// <summary>
    /// The time of the newest record the application database held when the event was found:
    /// everything after it on the earlier timeline is unknown here. Null for an empty database.
    /// </summary>
    public DateTime? EdgeOfMemoryUtc { get; set; }

    /// <summary>The time of the audit trail's newest row at that moment, when there is an audit database.</summary>
    public DateTime? AuditNewestUtc { get; set; }

    /// <summary>The floor the CRL number counters were raised to; null when they were not raised.</summary>
    public long? CrlNumberFloor { get; set; }

    /// <summary>How many CRL configurations' counters the floor changed.</summary>
    public int CrlCountersRaised { get; set; }

    /// <summary>What was found and done, as JSON, for a machine to read.</summary>
    public string? DetailsJson { get; set; }

    /// <summary>When an administrator acknowledged it; null while it is a standing notice.</summary>
    public DateTime? AcknowledgedAt { get; set; }

    /// <summary>Who acknowledged it.</summary>
    public Guid? AcknowledgedByUserId { get; set; }

    /// <summary>The acknowledging administrator's user name at the time.</summary>
    [MaxLength(255)]
    public string? AcknowledgedByUsername { get; set; }
}
