using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models;

/// <summary>
/// Structured parameters for a key ceremony operation. Serialized into
/// <see cref="Entities.KeyCeremonyEntity.ParametersJson"/> at initiation time
/// and locked — approvers review exactly what will be created/executed.
/// </summary>
public class KeyCeremonyParameters
{
    // Subject DN components
    [Required, MaxLength(256)]
    public string SubjectCN { get; set; } = string.Empty;

    [MaxLength(256)]
    public string? SubjectO { get; set; }

    [MaxLength(256)]
    public string? SubjectOU { get; set; }

    [MaxLength(256)]
    public string? SubjectL { get; set; }

    [MaxLength(256)]
    public string? SubjectST { get; set; }

    [MaxLength(256)]
    public string? SubjectC { get; set; }

    // Key algorithm & size
    [Required, MaxLength(50)]
    public string KeyAlgorithm { get; set; } = "ECDSA";

    public int KeySize { get; set; } = 384;

    // Validity & scope
    public int ValidityYears { get; set; } = 10;

    /// <summary>The space the CA belongs to, or null for an instance CA. <see cref="Guid.Empty"/> reads as null.</summary>
    public Guid? TenantId { get => _tenantId; set => _tenantId = value == Guid.Empty ? null : value; }
    private Guid? _tenantId;

    /// <summary>
    /// <see cref="InstanceScope"/> to create an instance CA; omitted with a <see cref="TenantId"/>.
    /// A request is refused unless it names exactly one (see <see cref="ScopeError"/>). Not read
    /// when a ceremony executes, so ceremonies opened before it existed still run.
    /// </summary>
    [MaxLength(20)]
    public string? Scope { get; set; }

    /// <summary>The <see cref="Scope"/> value that asks for an instance CA.</summary>
    public const string InstanceScope = "instance";

    /// <summary>
    /// Why a CA-creation request's scope is not explicit, or null when it is: a tenant id with no
    /// scope, or scope <see cref="InstanceScope"/> with no tenant id. A missing (or empty) tenant
    /// id alone never makes an instance CA.
    /// </summary>
    public static string? ScopeError(Guid? tenantId, string? scope)
    {
        var instance = string.Equals(scope?.Trim(), InstanceScope, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(scope) && !instance)
            return $"Unknown scope '{scope}'. Send scope \"{InstanceScope}\" for an instance CA, or a tenantId for a space's CA.";
        if (instance && tenantId != null)
            return $"The request names both scope \"{InstanceScope}\" and tenant {tenantId}; a CA belongs to one scope.";
        if (!instance && tenantId == null)
            return $"Name the CA's scope: a tenantId for a space's CA, or scope \"{InstanceScope}\" for an instance CA.";
        return null;
    }

    public Guid? ParentCaId { get; set; }

    [MaxLength(255)]
    public string? Label { get; set; }

    [MaxLength(2048)]
    public string? PublicBaseUrl { get; set; }

    // Certificate profile (IsCaProfile=true)
    public Guid? CertProfileId { get; set; }

    // Name constraints (RFC 5280 §4.2.1.10 subtrees)
    public List<string>? NameConstraintsPermitted { get; set; }
    public List<string>? NameConstraintsExcluded { get; set; }
}
