using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities;

[Table("AcmeAccounts")]
public class AcmeAccountEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string JwkJson { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string JwkThumbprint { get; set; } = string.Empty;

    public string ContactsJson { get; set; } = "[]";

    [Required]
    [MaxLength(20)]
    public string Status { get; set; } = nameof(AcmeAccountStatus.Valid);

    public bool TermsOfServiceAgreed { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// CA label this account was created under.
    /// Captured from the <c>/acme/{caLabel}/new-account</c> route so later requests
    /// routed to the plain <c>/api/v1/acme/account/{id}</c> endpoint can still
    /// resolve the right CA context for order finalization.
    /// </summary>
    [MaxLength(255)]
    public string? CaLabel { get; set; }

    /// <summary>
    /// The CA this account is bound to: the one its new-account request addressed, by label or
    /// as the default CA. Every request the account signs is refused at any other CA. Null only
    /// for an account the upgrade could not bind, which no CA accepts.
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }
}
