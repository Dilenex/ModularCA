namespace ModularCA.Core.Models;

/// <summary>
/// Represents the effective (merged) request profile after resolving inheritance.
/// Each field value is either inherited from the parent or overridden by the child.
/// </summary>
public class EffectiveRequestProfile
{
    /// <summary>
    /// The ID of the child (source) profile that was resolved.
    /// </summary>
    public Guid SourceProfileId { get; set; }

    /// <summary>
    /// The ID of the parent profile, if inheritance is active. Null for standalone profiles.
    /// </summary>
    public Guid? ParentProfileId { get; set; }

    /// <summary>
    /// Profile display name. Always comes from the child profile (identity field).
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Profile description. Always comes from the child profile (identity field).
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// JSON array of subject DN field rules.
    /// </summary>
    public string SubjectDnRules { get; set; } = "[]";

    /// <summary>
    /// JSON object defining SAN type constraints.
    /// </summary>
    public string SanRules { get; set; } = "{}";

    /// <summary>
    /// JSON array of allowed CertProfile IDs the requester can choose from.
    /// </summary>
    public string AllowedCertProfileIds { get; set; } = "[]";

    /// <summary>
    /// Default cert profile used when the requester doesn't specify one.
    /// </summary>
    public Guid? DefaultCertProfileId { get; set; }

    /// <summary>
    /// When true, requests require manual admin approval before issuance.
    /// </summary>
    public bool RequireApproval { get; set; }

    /// <summary>
    /// Number of admin approvals required before a CSR can be issued.
    /// </summary>
    public int RequiredApprovalCount { get; set; } = 1;

    /// <summary>
    /// Maps field names to their source: "inherited" or "overridden".
    /// Used by the UI to visually distinguish inherited vs overridden values.
    /// </summary>
    public Dictionary<string, string> FieldSources { get; set; } = new();
}
