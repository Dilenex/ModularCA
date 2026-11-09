using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Proper de-dup log for notification jobs. Replaces the
/// <c>NotificationPreferenceEntity.Description</c> string-date hack used by
/// <c>CertExpiryNotificationJob</c> with a dedicated row-per-notification table.
/// <para>
/// Unique index on <c>(EventType, TargetEntityId, NotificationDate)</c> makes
/// duplicate sends atomically impossible — a second insert in the same window
/// fails on the index, which the notification job treats as "already sent".
/// </para>
/// </summary>
[Table("NotificationLogs")]
public class NotificationLogEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Event type (for example <c>"CertExpiryWarning"</c> or <c>"CertExpiryReminder_7d"</c>;
    /// <c>"CertExpiring_30d"</c> before 0.4.3). Matches the notification job's internal key. Case sensitive.
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string EventType { get; set; } = string.Empty;

    /// <summary>
    /// Target entity identifier (typically a certificate serial number). Empty string
    /// for job-scope (non-per-entity) notifications so the unique index still matches.
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string TargetEntityId { get; set; } = string.Empty;

    /// <summary>
    /// UTC date (time portion zeroed) the notification was emitted; for a certificate expiry step,
    /// the certificate's <c>NotAfter</c> date, so the step is logged once per certificate.
    /// </summary>
    public DateTime NotificationDate { get; set; }

    /// <summary>Insertion timestamp (UTC) for the log row itself.</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
