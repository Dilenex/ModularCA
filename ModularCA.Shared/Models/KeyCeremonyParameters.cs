using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ModularCA.Shared.Models;

/// <summary>
/// Structured parameters for a key ceremony operation. Serialized into
/// <see cref="Entities.KeyCeremonyEntity.ParametersJson"/> at initiation time
/// and locked — approvers review exactly what will be created/executed.
/// As a request body an unknown member (a pre-0.4.0 <c>tenantId</c>) is refused with 400, never
/// read as no space; stored rows are read by <see cref="CeremonyParametersJson"/>, which skips them.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
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
    public Guid? SpaceId { get => _spaceId; set => _spaceId = value == Guid.Empty ? null : value; }
    private Guid? _spaceId;

    /// <summary>
    /// <see cref="InstanceScope"/> to create an instance CA; omitted with a <see cref="SpaceId"/>.
    /// A request is refused unless it names exactly one (see <see cref="ScopeError"/>). Not read
    /// when a ceremony executes, so ceremonies opened before it existed still run.
    /// </summary>
    [MaxLength(20)]
    public string? Scope { get; set; }

    /// <summary>The <see cref="Scope"/> value that asks for an instance CA.</summary>
    public const string InstanceScope = "instance";

    /// <summary>
    /// Why a CA-creation request's scope is not explicit, or null when it is: a space id with no
    /// scope, or scope <see cref="InstanceScope"/> with no space id. A missing (or empty) space
    /// id alone never makes an instance CA.
    /// </summary>
    public static string? ScopeError(Guid? spaceId, string? scope)
    {
        var instance = string.Equals(scope?.Trim(), InstanceScope, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(scope) && !instance)
            return $"Unknown scope '{scope}'. Send scope \"{InstanceScope}\" for an instance CA, or a spaceId for a space's CA.";
        if (instance && spaceId != null)
            return $"The request names both scope \"{InstanceScope}\" and space {spaceId}; a CA belongs to one scope.";
        if (!instance && spaceId == null)
            return $"Name the CA's scope: a spaceId for a space's CA, or scope \"{InstanceScope}\" for an instance CA.";
        return null;
    }

    /// <summary>
    /// Why a text field holds a control character (U+0000 to U+001F, or U+007F), or null when
    /// none does. None belongs in a subject, label or URL, and PostgreSQL jsonb rejects a NUL.
    /// </summary>
    public string? ControlCharacterError()
    {
        IEnumerable<(string Name, string? Value)> fields = new (string, string?)[]
        {
            (nameof(SubjectCN), SubjectCN), (nameof(SubjectO), SubjectO), (nameof(SubjectOU), SubjectOU),
            (nameof(SubjectL), SubjectL), (nameof(SubjectST), SubjectST), (nameof(SubjectC), SubjectC),
            (nameof(KeyAlgorithm), KeyAlgorithm), (nameof(Scope), Scope), (nameof(Label), Label),
            (nameof(PublicBaseUrl), PublicBaseUrl),
        };
        fields = fields
            .Concat((NameConstraintsPermitted ?? []).Select(v => (nameof(NameConstraintsPermitted), (string?)v)))
            .Concat((NameConstraintsExcluded ?? []).Select(v => (nameof(NameConstraintsExcluded), (string?)v)));
        var bad = fields.FirstOrDefault(f => Utils.DnComponentSanitizer.HasControlCharacter(f.Value)).Name;
        return bad == null ? null : $"{bad} must not contain control characters.";
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
