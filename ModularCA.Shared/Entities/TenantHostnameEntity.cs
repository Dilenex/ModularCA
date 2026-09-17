using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One DNS name by which a tenant's enrollment and revocation endpoints are reached, served from
/// the same process as the console under its own TLS certificate. The name is chosen by the
/// tenant's operator, the certificate is issued by one of the tenant's own CAs, and Kestrel picks
/// it by SNI. The console's own name (<c>Https.PublicDomain</c>) is never stored here: sign-in
/// and security keys stay bound to that one name.
/// </summary>
[Table("TenantHostnames")]
public class TenantHostnameEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The tenant that owns the name. Its CAs are the only ones that may issue for it.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Lower-case DNS name without trailing dot, e.g. <c>ca.customer-a.example</c>. Unique across the system.</summary>
    [MaxLength(255)]
    public string Hostname { get; set; } = string.Empty;

    /// <summary>The tenant CA that issues (and renews) the endpoint TLS certificate for this name.</summary>
    public Guid IssuingCaId { get; set; }

    /// <summary>The current endpoint certificate, or null while none has been issued yet.</summary>
    public Guid? CertificateId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [MaxLength(1000)]
    public string? Notes { get; set; }

    [ForeignKey(nameof(TenantId))]
    public virtual TenantEntity? Tenant { get; set; }

    [ForeignKey(nameof(IssuingCaId))]
    public virtual CertificateAuthorityEntity? IssuingCa { get; set; }

    [ForeignKey(nameof(CertificateId))]
    public virtual CertificateEntity? Certificate { get; set; }
}
