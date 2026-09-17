using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One decision the signer took about a private key: what was asked, by whom, under which
/// context, and whether policy allowed it. The signer writes a row for every decision, allowed
/// or refused, before it answers, so this table is the record of what was signed even when the
/// node's own audit is lost. It carries no foreign keys on purpose: a row must outlive the CA,
/// the certificate and the tenant it names.
/// </summary>
[Table("SignerAudit")]
public class SignerAuditEntity
{
    /// <summary>Row id.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>When the decision was taken, UTC.</summary>
    public DateTime At { get; set; }

    /// <summary>The contract operation: <c>Sign</c>, <c>Decrypt</c>, <c>Export</c>, <c>Generate</c> and so on.</summary>
    [MaxLength(32)]
    public string Operation { get; set; } = string.Empty;

    /// <summary>The caller's identity as the context named it.</summary>
    [MaxLength(128)]
    public string Caller { get; set; } = string.Empty;

    /// <summary>The purpose the context named, as the enum member's name.</summary>
    [MaxLength(32)]
    public string Purpose { get; set; } = string.Empty;

    /// <summary>The certificate id of the key the operation named, when it named one.</summary>
    public Guid? KeyCertificateId { get; set; }

    /// <summary>The keystore name of the key reference, when the operation named one.</summary>
    [MaxLength(64)]
    public string? Keystore { get; set; }

    /// <summary>The CA the context said the operation was for.</summary>
    public Guid? CaId { get; set; }

    /// <summary>The tenant the context said the operation was for.</summary>
    public Guid? TenantId { get; set; }

    /// <summary>The signature algorithm, for a signature.</summary>
    [MaxLength(64)]
    public string? Algorithm { get; set; }

    /// <summary><see cref="AllowedOutcome"/> or <see cref="RefusedOutcome"/>.</summary>
    [MaxLength(16)]
    public string Outcome { get; set; } = string.Empty;

    /// <summary>Why the operation was refused; null when it was allowed.</summary>
    [MaxLength(1024)]
    public string? Reason { get; set; }

    /// <summary>SHA-256 over the bytes that were signed, lower-case hex; null for an operation that signs nothing.</summary>
    [MaxLength(64)]
    public string? DataHash { get; set; }

    /// <summary>The policy allowed the operation.</summary>
    public const string AllowedOutcome = "allowed";

    /// <summary>The policy refused the operation.</summary>
    public const string RefusedOutcome = "refused";
}
