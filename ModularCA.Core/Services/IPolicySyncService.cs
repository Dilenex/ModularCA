namespace ModularCA.Core.Services;

/// <summary>
/// Service interface for GitOps-style policy synchronization that imports
/// profile definitions from YAML files into the database.
/// </summary>
public interface IPolicySyncService
{
    /// <summary>
    /// Synchronizes all profile YAML files found in the specified directory.
    /// Processes cert-profiles.yaml, signing-profiles.yaml, and request-profiles.yaml.
    /// </summary>
    /// <param name="directoryPath">Path to the directory containing YAML policy files.</param>
    /// <returns>A result summarizing created, updated, unchanged profiles and any errors.</returns>
    Task<PolicySyncResult> SyncFromDirectoryAsync(string directoryPath);

    /// <summary>
    /// Synchronizes profiles from raw YAML content for a specific profile type.
    /// </summary>
    /// <param name="yamlContent">The YAML content to parse.</param>
    /// <param name="profileType">The profile type: "cert", "signing", or "request".</param>
    /// <returns>A result summarizing created, updated, unchanged profiles and any errors.</returns>
    Task<PolicySyncResult> SyncFromYamlAsync(string yamlContent, string profileType);
}

/// <summary>
/// Result of a policy synchronization operation, tracking how many profiles
/// were created, updated, left unchanged, and any errors encountered.
/// </summary>
public class PolicySyncResult
{
    /// <summary>Number of new profiles created during sync.</summary>
    public int Created { get; set; }

    /// <summary>Number of existing profiles updated during sync.</summary>
    public int Updated { get; set; }

    /// <summary>Number of profiles that matched exactly and required no changes.</summary>
    public int Unchanged { get; set; }

    /// <summary>
    /// Number of live certificates whose expiry warning instants were re-computed because their
    /// certificate profile's expiry warning settings changed.
    /// </summary>
    public int ExpiryWarningsRecomputed { get; set; }

    /// <summary>List of error messages encountered during sync.</summary>
    public List<string> Errors { get; set; } = new();
}
