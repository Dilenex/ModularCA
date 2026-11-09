using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One-time recovery codes generated at TOTP enrollment. A user who
/// loses access to their authenticator app can exchange a recovery code for a TOTP
/// reset at <c>/auth/totp/recovery</c>. Codes are hashed at rest (per-user salted PBKDF2;
/// older rows unsalted SHA-256) and consumed on first use via <see cref="UsedAt"/>.
/// </summary>
public class TotpRecoveryCodeEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Owning user.</summary>
    public Guid UserId { get; set; }

    [ForeignKey("UserId")]
    public virtual UserEntity? User { get; set; }

    /// <summary>
    /// Hash of the plaintext code: <c>pbkdf2:</c> plus 56 hex characters (per-user salted
    /// PBKDF2-HMAC-SHA256, from 0.4.3), or 64 uppercase hex characters of unsalted SHA-256 on rows
    /// written earlier. The plaintext is shown exactly once at enrollment time and cannot be
    /// recovered from the DB.
    /// </summary>
    [Required]
    [MaxLength(64)]
    public string CodeHash { get; set; } = string.Empty;

    /// <summary>When the code was generated (enrollment time).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When the code was consumed, if ever. Nullable until used.</summary>
    public DateTime? UsedAt { get; set; }
}
