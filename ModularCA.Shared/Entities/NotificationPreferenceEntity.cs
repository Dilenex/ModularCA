using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Whether email is sent for one notification event type, and to whom. When <c>CertExpiring</c> is
/// sent follows each certificate's expiry warning and
/// <c>CertExpiryNotification.WarningDaysBeforeExpiry</c>; the unread <c>DaysBeforeExpiry</c> column
/// was dropped in 0.4.4 (the <c>DropUnreadSettingColumns</c> migration).
/// </summary>
[Table("NotificationPreferences")]
public class NotificationPreferenceEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(50)]
    public string EventType { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    [MaxLength(500)]
    public string? Recipients { get; set; }

    [MaxLength(255)]
    public string? Description { get; set; }
}
