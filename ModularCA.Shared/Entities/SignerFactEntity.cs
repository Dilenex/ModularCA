using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A fact that waits to be recorded in the signer's journal
/// (<c>docs/architecture/signer-journal.md</c>, "Facts the node asserts"): a revocation, a
/// released hold, a spent token, a restore, a changed incarnation, something disabled. The row
/// is written in the same save as the change it describes, so a change that is rolled back
/// leaves no fact, and it is removed once the signer has flushed the record. A row that stays
/// is a fact the signer could not take yet; it is offered again and never stops what it
/// describes.
/// </summary>
[Table("SignerFactQueue")]
public class SignerFactEntity
{
    /// <summary>The row's id; facts are offered to the signer in this order.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    /// <summary>The journal's record type number for the fact.</summary>
    public int Type { get; set; }

    /// <summary>The fact's payload, as the journal encodes it. Identifiers, serials and times; never a secret.</summary>
    [Required]
    public byte[] Payload { get; set; } = [];

    /// <summary>When the fact was queued.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>How many times the fact was offered to the signer and not taken.</summary>
    public int Attempts { get; set; }

    /// <summary>The earliest moment it is offered again; null for a fact not yet offered.</summary>
    public DateTime? NextAttemptAt { get; set; }

    /// <summary>Why the signer did not take it the last time it was offered.</summary>
    [MaxLength(1000)]
    public string? LastError { get; set; }
}
