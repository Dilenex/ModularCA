using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A one-time claim on an account: whoever presents the token whose SHA-256 is
/// <see cref="TokenHash"/> before <see cref="ExpiresAt"/> sets the account's password, once, through
/// <c>POST /api/v1/auth/claim</c>. It is how a headless bootstrap hands the first administrator
/// their access without the instance ever making a password that has to come back out of it: the
/// bootstrap.yaml carries only the hash, and the token stays with whoever generated it. A claim is
/// also issued on the host with <c>--issue-claim-token</c>. An account has at most one claim; a new
/// one replaces it, and redeeming it deletes the row, so a token works once.
/// </summary>
[Table("UserClaimTokens")]
public class UserClaimTokenEntity
{
    /// <summary>Primary key.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The account the claim sets the password of. Unique: one claim per account.</summary>
    public Guid UserId { get; set; }

    /// <summary>Navigation property to the account. The claim is deleted with it.</summary>
    [ForeignKey(nameof(UserId))]
    public virtual UserEntity? User { get; set; }

    /// <summary>
    /// SHA-256 of the token's UTF-8 text. The token is 256 random bits, so a plain hash is enough;
    /// the token itself is never stored.
    /// </summary>
    [MaxLength(32)]
    public byte[] TokenHash { get; set; } = [];

    /// <summary>When the claim was recorded (UTC).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When the claim stops working (UTC). An expired claim is refused like a wrong token.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>What recorded the claim: <c>bootstrap</c>, or <c>host:break-glass</c> for <c>--issue-claim-token</c>.</summary>
    [MaxLength(64)]
    public string IssuedBy { get; set; } = string.Empty;
}
