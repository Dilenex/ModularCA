using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Represents a logical tenant in the multi-tenancy model. Every CA and group must belong
/// to a tenant. The "System" tenant owns infrastructure CAs (system signing CA). Bootstrap
/// creates a second tenant from the config's Organization name for the root CA.
/// </summary>
public class TenantEntity
{
    /// <summary>Primary key.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Human-readable tenant name.</summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>URL-safe identifier used in route segments and API filters.</summary>
    [MaxLength(255)]
    public string Slug { get; set; } = string.Empty;

    /// <summary>Optional description of the tenant's purpose or organization.</summary>
    [MaxLength(500)]
    public string? Description { get; set; }

    /// <summary>Whether this tenant is active. Disabled tenants cannot issue certificates.</summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>Whether this is the internal system tenant. System tenants cannot be deleted or disabled.</summary>
    public bool IsSystemTenant { get; set; } = false;

    /// <summary>Whether this tenant can be deleted by administrators. Bootstrap tenants are protected.</summary>
    public bool CanBeDeleted { get; set; } = true;

    /// <summary>Timestamp when this tenant was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Maximum number of certificate authorities allowed for this tenant. 0 means unlimited.</summary>
    public int MaxCertificateAuthorities { get; set; } = 0;

    /// <summary>Maximum total certificates that can be issued across all CAs in this tenant. 0 means unlimited.</summary>
    public int MaxCertificatesTotal { get; set; } = 0;

    /// <summary>Maximum number of users that can be assigned to this tenant's groups. 0 means unlimited.</summary>
    public int MaxUsers { get; set; } = 0;

    /// <summary>
    /// Longest validity, in days, that a leaf certificate issued by one of this tenant's CAs may
    /// carry. 0 means unlimited, matching the quota fields above.
    /// </summary>
    /// <remarks>
    /// This replaced a single global <c>CertPolicy.MaxValidityDays</c> that defaulted to 825 — the
    /// CA/Browser Forum baseline for publicly trusted TLS, and the wrong shape of rule for a
    /// private CA. It governed every leaf in the installation regardless of tenant or profile, so
    /// an operator issuing a five-year device-identity certificate was refused by a number that
    /// only ever meant anything to public web PKI, and the only way to allow it was to relax the
    /// ceiling for everyone at once. Infrastructure certificates already carried an explicit
    /// exemption from it, which was the clearest sign that the rule belonged somewhere narrower.
    ///
    /// The ceiling is a ceiling, never a floor: a certificate profile may ask for less than the
    /// tenant allows and gets what it asks for, but a profile asking for more is shortened to this
    /// value. Being exceeded is not an error — issuance continues and the certificate carries a
    /// <c>MCA-ISS-004</c> diagnostic naming this tenant, the same way validity clamped by the
    /// issuing CA's own expiry reports <c>MCA-ISS-001</c>. Refusing instead would fail every ACME,
    /// EST and CMP enrollment whose profile happens to out-reach its tenant, for a condition the
    /// enrolling client can neither see nor do anything about.
    ///
    /// Publicly trusted TLS limits (398 days today, 825 historically) are compliance baselines
    /// rather than a property of this CA. The compliance scanner already reports them through
    /// <c>ComplianceConfig.WarnOverValidityDays</c> without blocking anything, which is where that
    /// knowledge belongs.
    /// </remarks>
    public int MaxValidityDays { get; set; } = 0;

    /// <summary>
    /// What happens when a request exceeds <see cref="MaxValidityDays"/>: shorten it (the
    /// default, and the behaviour the ceiling shipped with) or refuse it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Shortening is right for the enrollment protocols and wrong for an operator at a keyboard.
    /// An ACME client cannot see this tenant or change its own request, so refusing it would fail
    /// the enrollment over something nobody at the other end can act on. An admin issuing by hand
    /// is in the opposite position: they can see the ceiling, they can shorten the request, and a
    /// certificate that comes back quietly shorter than they asked for is a defect that surfaces
    /// years later as an unexpected expiry.
    /// </para>
    /// <para>
    /// So <see cref="ValidityCeilingBehavior.Refuse"/> binds interactive and admin issuance only.
    /// ACME, EST, SCEP, CMP, auto-renewal and Web TLS renewal always shorten regardless of what
    /// this says — enforced at the call site through
    /// <see cref="ValidityCeilingEnforcement"/>, whose default is the shortening one so a call
    /// site added later cannot start refusing by saying nothing. Infrastructure and CA
    /// certificates skip the ceiling entirely and are therefore never refused by it.
    /// </para>
    /// <para>
    /// Stored as an int rather than a string so that adding a third behaviour later does not
    /// require rewriting rows, and read back through the enum so an unrecognised value is a
    /// compile-time concern rather than a silent fall-through to "refuse everything".
    /// </para>
    /// </remarks>
    public ValidityCeilingBehavior ValidityCeilingBehavior { get; set; } = ValidityCeilingBehavior.Shorten;

    /// <summary>
    /// When true, CA creation for this tenant requires a key ceremony approval workflow.
    /// Direct creation endpoints auto-create a ceremony instead of creating the CA immediately.
    /// </summary>
    public bool RequireKeyCeremony { get; set; } = true;

    /// <summary>
    /// Number of approvals required for CA creation ceremonies in this tenant. Used when the
    /// target CA doesn't exist yet (CreateRootCA, CreateIntermediateCA). For operations on
    /// existing CAs (RevokeCA), the CA's admin group RequiredQuorum is used instead.
    /// </summary>
    public int CeremonyRequiredApprovals { get; set; } = 2;

    /// <summary>
    /// Per-tenant "user quorum" override for controlled-user ceremonies (promote/demote/delete
    /// of an admin/operator/CA-admin) scoped to this tenant's CAs. Null = fall back to the
    /// system-level <see cref="SecurityPolicyEntity.UserQuorum"/>. Distinct from
    /// <see cref="CeremonyRequiredApprovals"/> (the CA/key quorum).
    /// </summary>
    public int? UserCeremonyRequiredApprovals { get; set; }

    /// <summary>
    /// Soft-delete flag. When true, the row is hidden from every
    /// application query via the EF global query filter in
    /// <see cref="ModularCA.Database.ModularCADbContext"/>. Call
    /// <c>IgnoreQueryFilters()</c> (with an explicit system-admin gate) to resurrect.
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    /// <summary>Timestamp when <see cref="IsDeleted"/> was flipped to true. Null when active.</summary>
    public DateTime? DeletedAt { get; set; }
}
