using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Persistent IP allow-list rule scoped to a category of gated paths (see
/// <see cref="WhitelistScope"/>). A single rule holds a JSON array of CIDR
/// strings; at evaluation time the middleware matches the client IP against
/// those CIDRs. Rules flagged <see cref="IsSystemDefault"/> are seeded on
/// first bootstrap and cannot be deleted via the admin API (but their CIDRs
/// and enabled flag can be edited). All other rules are operator-authored
/// overrides. Uniqueness is enforced at the DB layer on the composite
/// <c>(Scope, CertificateAuthorityId, Protocol)</c> triple so at most one
/// rule exists per specific target.
/// </summary>
[Table("Whitelists")]
public class WhitelistEntity
{
    /// <summary>
    /// Primary key. Defaults to a new <see cref="Guid"/> so callers can
    /// create new entities without manually assigning an identifier.
    /// </summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Operator-facing label for this rule, shown in the admin UI. Required.
    /// Expected to be unique within a given scope triple but uniqueness is
    /// enforced at the service layer, not the DB.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional free-text description explaining the intent of the rule
    /// (e.g. "Corporate VPN range" or "Partner network for SCEP enrolment").
    /// </summary>
    [MaxLength(500)]
    public string? Description { get; set; }

    /// <summary>
    /// Which bucket of gated paths this rule applies to. See
    /// <see cref="WhitelistScope"/> for the full enumeration.
    /// </summary>
    [Required]
    public WhitelistScope Scope { get; set; }

    /// <summary>
    /// Target Certificate Authority for <see cref="WhitelistScope.Ca"/> and
    /// <see cref="WhitelistScope.Protocol"/> scoped rules. Null for
    /// system-level scopes (<see cref="WhitelistScope.System"/>,
    /// <see cref="WhitelistScope.Setup"/>, <see cref="WhitelistScope.Auth"/>,
    /// <see cref="WhitelistScope.Api"/>, <see cref="WhitelistScope.ShortUrl"/>).
    /// Wired to the CertificateAuthorities table at the DbContext layer with
    /// cascade delete.
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// Protocol identifier (e.g. "ACME", "EST", "SCEP", "CMP", "MSAE", "OCSP", "TSA")
    /// when <see cref="Scope"/> is <see cref="WhitelistScope.Protocol"/>.
    /// Null for all other scopes.
    /// </summary>
    [MaxLength(20)]
    public string? Protocol { get; set; }

    /// <summary>
    /// JSON-encoded <c>List&lt;string&gt;</c> of CIDR ranges
    /// (e.g. <c>["10.0.0.0/8","::1/128"]</c>). Stored as longtext so any
    /// reasonable number of entries fits; callers should use
    /// <see cref="CidrList"/> instead of touching this raw column. An empty
    /// JSON array (<c>"[]"</c>) means "block everything" by design.
    /// </summary>
    [Required]
    [Column(TypeName = "longtext")]
    public string Cidrs { get; set; } = "[]";

    /// <summary>
    /// Master toggle for this rule. When false, the middleware skips this
    /// row entirely during lookup (it behaves as if the row did not exist).
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// True for rows inserted by the bootstrap seeder. These rows may be
    /// edited (CIDRs changed, <see cref="IsEnabled"/> flipped) but the admin
    /// API refuses to delete them, ensuring a baseline rule always exists for
    /// the critical scopes.
    /// </summary>
    public bool IsSystemDefault { get; set; } = false;

    /// <summary>
    /// UTC timestamp of when the row was first inserted.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// UTC timestamp of the last mutation. Updated by the service on every
    /// <c>UpdateAsync</c> call.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Convenience accessor for <see cref="Cidrs"/> that hides the JSON
    /// serialization round-trip from callers. Getting returns an empty list
    /// on null or malformed JSON rather than throwing, so deserialization
    /// errors never brick the middleware. Setting re-serializes the list
    /// back into <see cref="Cidrs"/> immediately.
    /// </summary>
    [NotMapped]
    public List<string> CidrList
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Cidrs)) return new List<string>();
            try
            {
                return JsonSerializer.Deserialize<List<string>>(Cidrs) ?? new List<string>();
            }
            catch (JsonException)
            {
                return new List<string>();
            }
        }
        set => Cidrs = JsonSerializer.Serialize(value ?? new List<string>());
    }
}
