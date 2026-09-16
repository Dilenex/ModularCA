using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One Active Directory forest bound to one tenant for Windows autoenrollment over Kerberos.
/// A ticket sealed by this realm is accepted only for CAs of <see cref="TenantId"/>, only when
/// it names <see cref="ServicePrincipal"/>, and only with one of the realm's live
/// <see cref="Keys"/>. The forest's principals act with the capabilities of
/// <see cref="EnrollmentUserId"/>, so every existing enrollment check applies unchanged.
/// </summary>
[Table("KerberosRealms")]
public class KerberosRealmEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The tenant this forest belongs to. The isolation boundary.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Upper-case Kerberos realm, e.g. <c>CORP.CUSTOMER-A.LOCAL</c>. Unique across tenants.</summary>
    [MaxLength(255)]
    public string Realm { get; set; } = string.Empty;

    /// <summary>Lower-case DNS domain used to build machine names and UPNs, e.g. <c>corp.customer-a.local</c>.</summary>
    [MaxLength(255)]
    public string DnsDomain { get; set; } = string.Empty;

    /// <summary>The SPN registered on the forest's service account, e.g. <c>HTTP/ca4.maroongang.net</c>.</summary>
    [MaxLength(255)]
    public string ServicePrincipal { get; set; } = string.Empty;

    /// <summary>The ModularCA user whose capabilities the forest's principals act with.</summary>
    public Guid EnrollmentUserId { get; set; }

    /// <summary>Whether computer accounts (<c>name$</c>) may enroll.</summary>
    public bool AllowMachines { get; set; } = true;

    /// <summary>Whether user accounts may enroll.</summary>
    public bool AllowUsers { get; set; } = true;

    /// <summary>A disabled realm is refused before any key is touched.</summary>
    public bool IsEnabled { get; set; } = true;

    [MaxLength(1000)]
    public string? Notes { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When a ticket from this realm was last accepted.</summary>
    public DateTime? LastUsedAt { get; set; }

    [ForeignKey(nameof(TenantId))]
    public virtual TenantEntity? Tenant { get; set; }

    [ForeignKey(nameof(EnrollmentUserId))]
    public virtual UserEntity? EnrollmentUser { get; set; }

    public virtual ICollection<KerberosRealmKeyEntity> Keys { get; set; } = new List<KerberosRealmKeyEntity>();
}

/// <summary>
/// One version of a realm's service key. Tickets name the version they were sealed under, so
/// several versions are live during a rotation; a superseded one stays usable until
/// <see cref="RetireAfter"/>. The key bytes are stored under Data Protection and are never
/// returned by any endpoint.
/// </summary>
[Table("KerberosRealmKeys")]
public class KerberosRealmKeyEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid RealmId { get; set; }

    /// <summary>Key version number as Active Directory reports it.</summary>
    public int Kvno { get; set; }

    /// <summary>Encryption type name, e.g. <c>AES256_CTS_HMAC_SHA1_96</c>. Only AES types are stored.</summary>
    [MaxLength(64)]
    public string EncryptionType { get; set; } = string.Empty;

    /// <summary>The raw key under Data Protection, base64.</summary>
    [MaxLength(1024)]
    public string ProtectedKey { get; set; } = string.Empty;

    /// <summary>How the key arrived; for the audit trail only.</summary>
    public KerberosKeySource Source { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Set when a newer version arrives; the key is refused after this and swept by the cleanup job.</summary>
    public DateTime? RetireAfter { get; set; }

    [ForeignKey(nameof(RealmId))]
    public virtual KerberosRealmEntity? Realm { get; set; }
}
