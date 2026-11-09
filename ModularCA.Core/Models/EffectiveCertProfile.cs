namespace ModularCA.Core.Models;

/// <summary>
/// Represents the effective (merged) certificate profile after resolving inheritance.
/// Each field value is either inherited from the parent or overridden by the child.
/// </summary>
public class EffectiveCertProfile
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
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether this profile is for CA certificates.
    /// </summary>
    public bool IsCaProfile { get; set; }

    /// <summary>
    /// Comma-separated key usage flags (e.g., "digitalSignature,keyCertSign").
    /// </summary>
    public string KeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Comma-separated OIDs for extended key usages.
    /// </summary>
    public string ExtendedKeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Minimum validity period in ISO 8601 duration format.
    /// </summary>
    public string? ValidityPeriodMin { get; set; }

    /// <summary>
    /// Maximum validity period in ISO 8601 duration format.
    /// </summary>
    public string? ValidityPeriodMax { get; set; }

    /// <summary>
    /// JSON array of allowed key algorithms (e.g., ["RSA", "ECDSA"]).
    /// </summary>
    public string AllowedKeyAlgorithms { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed key sizes (e.g., [2048, 4096]).
    /// </summary>
    public string AllowedKeySizes { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed signature algorithms.
    /// </summary>
    public string AllowedSignatureAlgorithms { get; set; } = "[]";

    /// <summary>
    /// Whether Certificate Transparency submission is enabled.
    /// </summary>
    public bool CtEnabled { get; set; }

    /// <summary>
    /// Whether wildcard SAN/CN entries are permitted by this profile. When false, any DNS
    /// SAN containing <c>*</c> is rejected at issuance time. Mirrored from
    /// <see cref="ModularCA.Shared.Entities.CertProfileEntity.AllowWildcard"/>.
    /// </summary>
    public bool AllowWildcard { get; set; }

    /// <summary>
    /// JSON array of CT log GUIDs to submit to. Null means use all enabled CT logs.
    /// </summary>
    public string? CtLogIds { get; set; }

    /// <summary>Effective soft expiry warning percent; null for the default.</summary>
    public int? ExpiryWarningPercent { get; set; }

    /// <summary>Effective longest soft warning window (ISO 8601); null for no cap.</summary>
    public string? ExpiryWarningMaxWindow { get; set; }

    /// <summary>Effective expiry alert percent; null for the default.</summary>
    public int? ExpiryAlertPercent { get; set; }

    /// <summary>Effective longest alert window (ISO 8601); null for no cap.</summary>
    public string? ExpiryAlertMaxWindow { get; set; }

    /// <summary>Whether the effective profile never warns of expiry.</summary>
    public bool ExpiryNeverWarn { get; set; }

    /// <summary>Whether the profile's expiry warning settings replace its parent's rather than being clamped to them.</summary>
    public bool ExpiryWarningOverridesParent { get; set; }

    /// <summary>The effective expiry warning settings, for <see cref="ModularCA.Shared.Utils.ExpiryWarningRule.Compute"/>.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public ModularCA.Shared.Utils.ExpiryWarningSettings ExpiryWarnings =>
        new(ExpiryWarningPercent, ExpiryWarningMaxWindow, ExpiryAlertPercent, ExpiryAlertMaxWindow, ExpiryNeverWarn);

    /// <summary>
    /// Maps field names to their source: "inherited", "overridden", or "clamped" (the child's
    /// value was less strict than the parent's and the parent's is used). Used by the UI to
    /// visually distinguish inherited, overridden and clamped values.
    /// </summary>
    public Dictionary<string, string> FieldSources { get; set; } = new();
}
