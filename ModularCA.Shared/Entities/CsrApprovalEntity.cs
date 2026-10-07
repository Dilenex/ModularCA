using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Tracks individual approval/rejection decisions for a certificate signing request.
/// Multiple approvals may be required before a CSR is fully approved for issuance.
/// </summary>
[Table("CsrApprovals")]
public class CsrApprovalEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid CertRequestId { get; set; }

    [ForeignKey("CertRequestId")]
    public virtual CertRequestEntity CertRequest { get; set; } = default!;

    [Required]
    public Guid ApproverId { get; set; }

    [ForeignKey("ApproverId")]
    public virtual UserEntity Approver { get; set; } = default!;

    [Required]
    [MaxLength(255)]
    public string ApproverUsername { get; set; } = string.Empty;

    /// <summary>Approved or Rejected</summary>
    [Required]
    [MaxLength(20)]
    public string Decision { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Comment { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
