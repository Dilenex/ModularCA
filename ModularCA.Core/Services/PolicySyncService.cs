using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Core.Services;

/// <summary>
/// GitOps-style policy synchronization service that imports profile definitions
/// from YAML files into the database. Sync is additive: new profiles are created,
/// existing profiles are updated when changed, and profiles are never deleted.
/// </summary>
public class PolicySyncService : IPolicySyncService
{
    private readonly ModularCADbContext _db;
    private readonly ILogger<PolicySyncService> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="PolicySyncService"/>.
    /// </summary>
    /// <param name="db">The application database context.</param>
    /// <param name="logger">Logger for sync operation diagnostics.</param>
    public PolicySyncService(ModularCADbContext db, ILogger<PolicySyncService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<PolicySyncResult> SyncFromDirectoryAsync(string directoryPath)
    {
        var aggregate = new PolicySyncResult();

        if (!Directory.Exists(directoryPath))
        {
            aggregate.Errors.Add($"Policy directory not found: {directoryPath}");
            return aggregate;
        }

        var fileMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "cert-profiles.yaml", "cert" },
            { "signing-profiles.yaml", "signing" },
            { "request-profiles.yaml", "request" }
        };

        foreach (var (fileName, profileType) in fileMap)
        {
            var filePath = Path.Combine(directoryPath, fileName);
            if (!File.Exists(filePath))
            {
                _logger.LogDebug("Skipping {FileName} — file not found in {Directory}", fileName, directoryPath);
                continue;
            }

            try
            {
                var yamlContent = await File.ReadAllTextAsync(filePath);
                var result = await SyncFromYamlAsync(yamlContent, profileType);
                aggregate.Created += result.Created;
                aggregate.Updated += result.Updated;
                aggregate.Unchanged += result.Unchanged;
                aggregate.Errors.AddRange(result.Errors);
            }
            catch (Exception ex)
            {
                var error = $"Error processing {fileName}: {ex.Message}";
                _logger.LogError(ex, "Error processing {FileName}", fileName);
                aggregate.Errors.Add(error);
            }
        }

        return aggregate;
    }

    /// <inheritdoc />
    public async Task<PolicySyncResult> SyncFromYamlAsync(string yamlContent, string profileType)
    {
        return profileType.ToLowerInvariant() switch
        {
            "cert" => await SyncCertProfilesAsync(yamlContent),
            "signing" => await SyncSigningProfilesAsync(yamlContent),
            "request" => await SyncRequestProfilesAsync(yamlContent),
            _ => new PolicySyncResult { Errors = { $"Unknown profile type: {profileType}. Expected: cert, signing, or request." } }
        };
    }

    /// <summary>
    /// Parses and synchronizes certificate profile definitions from YAML content.
    /// </summary>
    private async Task<PolicySyncResult> SyncCertProfilesAsync(string yamlContent)
    {
        var result = new PolicySyncResult();
        var deserializer = BuildDeserializer();

        CertProfileYamlRoot root;
        try
        {
            root = deserializer.Deserialize<CertProfileYamlRoot>(yamlContent);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"YAML parse error for cert profiles: {ex.Message}");
            return result;
        }

        if (root?.Profiles == null || root.Profiles.Count == 0)
        {
            _logger.LogDebug("No cert profiles found in YAML content");
            return result;
        }

        var existingProfiles = await _db.CertProfiles
            .Where(p => p.CertificateAuthorityId == null)
            .ToListAsync();

        foreach (var yamlProfile in root.Profiles)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(yamlProfile.Name))
                {
                    result.Errors.Add("Cert profile entry missing required 'name' field");
                    continue;
                }

                var existing = existingProfiles.FirstOrDefault(p =>
                    string.Equals(p.Name, yamlProfile.Name, StringComparison.OrdinalIgnoreCase));

                if (existing == null)
                {
                    var entity = new CertProfileEntity
                    {
                        Name = yamlProfile.Name,
                        Description = yamlProfile.Description ?? string.Empty,
                        IsCaProfile = yamlProfile.IsCaProfile,
                        KeyUsages = yamlProfile.KeyUsages ?? string.Empty,
                        ExtendedKeyUsages = yamlProfile.ExtendedKeyUsages ?? "[]",
                        AllowedKeyAlgorithms = yamlProfile.AllowedKeyAlgorithms ?? "[]",
                        AllowedKeySizes = yamlProfile.AllowedKeySizes ?? "[]",
                        AllowedSignatureAlgorithms = yamlProfile.AllowedSignatureAlgorithms ?? "[]",
                        ValidityPeriodMin = yamlProfile.ValidityPeriodMin,
                        ValidityPeriodMax = yamlProfile.ValidityPeriodMax,
                        CtEnabled = yamlProfile.CtEnabled
                    };
                    _db.CertProfiles.Add(entity);
                    result.Created++;
                    _logger.LogInformation("Creating cert profile: {Name}", yamlProfile.Name);
                }
                else if (HasCertProfileChanged(existing, yamlProfile))
                {
                    existing.Description = yamlProfile.Description ?? string.Empty;
                    existing.IsCaProfile = yamlProfile.IsCaProfile;
                    existing.KeyUsages = yamlProfile.KeyUsages ?? string.Empty;
                    existing.ExtendedKeyUsages = yamlProfile.ExtendedKeyUsages ?? "[]";
                    existing.AllowedKeyAlgorithms = yamlProfile.AllowedKeyAlgorithms ?? "[]";
                    existing.AllowedKeySizes = yamlProfile.AllowedKeySizes ?? "[]";
                    existing.AllowedSignatureAlgorithms = yamlProfile.AllowedSignatureAlgorithms ?? "[]";
                    existing.ValidityPeriodMin = yamlProfile.ValidityPeriodMin;
                    existing.ValidityPeriodMax = yamlProfile.ValidityPeriodMax;
                    existing.CtEnabled = yamlProfile.CtEnabled;
                    existing.UpdatedAt = DateTime.UtcNow;
                    existing.Revision++;
                    result.Updated++;
                    _logger.LogInformation("Updating cert profile: {Name}", yamlProfile.Name);
                }
                else
                {
                    result.Unchanged++;
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Error syncing cert profile '{yamlProfile.Name}': {ex.Message}");
            }
        }

        await _db.SaveChangesAsync();
        return result;
    }

    /// <summary>
    /// Parses and synchronizes signing profile definitions from YAML content.
    /// </summary>
    private async Task<PolicySyncResult> SyncSigningProfilesAsync(string yamlContent)
    {
        var result = new PolicySyncResult();
        var deserializer = BuildDeserializer();

        SigningProfileYamlRoot root;
        try
        {
            root = deserializer.Deserialize<SigningProfileYamlRoot>(yamlContent);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"YAML parse error for signing profiles: {ex.Message}");
            return result;
        }

        if (root?.Profiles == null || root.Profiles.Count == 0)
        {
            _logger.LogDebug("No signing profiles found in YAML content");
            return result;
        }

        var existingProfiles = await _db.SigningProfiles.ToListAsync();

        foreach (var yamlProfile in root.Profiles)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(yamlProfile.Name))
                {
                    result.Errors.Add("Signing profile entry missing required 'name' field");
                    continue;
                }

                var existing = existingProfiles.FirstOrDefault(p =>
                    string.Equals(p.Name, yamlProfile.Name, StringComparison.OrdinalIgnoreCase));

                if (existing == null)
                {
                    var entity = new SigningProfileEntity
                    {
                        Name = yamlProfile.Name,
                        Description = yamlProfile.Description ?? string.Empty,
                        AllowedAlgorithms = yamlProfile.AllowedAlgorithms ?? "[]",
                        AllowedEKUs = yamlProfile.AllowedEKUs ?? "[]",
                        IsDefault = yamlProfile.IsDefault,
                        MaxPathLength = yamlProfile.MaxPathLength,
                        NameConstraintsPermitted = yamlProfile.NameConstraintsPermitted,
                        NameConstraintsExcluded = yamlProfile.NameConstraintsExcluded,
                        PolicyOids = yamlProfile.PolicyOids,
                        InhibitAnyPolicy = yamlProfile.InhibitAnyPolicy
                    };
                    _db.SigningProfiles.Add(entity);
                    result.Created++;
                    _logger.LogInformation("Creating signing profile: {Name}", yamlProfile.Name);
                }
                else if (HasSigningProfileChanged(existing, yamlProfile))
                {
                    existing.Description = yamlProfile.Description ?? string.Empty;
                    existing.AllowedAlgorithms = yamlProfile.AllowedAlgorithms ?? "[]";
                    existing.AllowedEKUs = yamlProfile.AllowedEKUs ?? "[]";
                    existing.IsDefault = yamlProfile.IsDefault;
                    existing.MaxPathLength = yamlProfile.MaxPathLength;
                    existing.NameConstraintsPermitted = yamlProfile.NameConstraintsPermitted;
                    existing.NameConstraintsExcluded = yamlProfile.NameConstraintsExcluded;
                    existing.PolicyOids = yamlProfile.PolicyOids;
                    existing.InhibitAnyPolicy = yamlProfile.InhibitAnyPolicy;
                    existing.UpdatedAt = DateTime.UtcNow;
                    existing.Revision++;
                    result.Updated++;
                    _logger.LogInformation("Updating signing profile: {Name}", yamlProfile.Name);
                }
                else
                {
                    result.Unchanged++;
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Error syncing signing profile '{yamlProfile.Name}': {ex.Message}");
            }
        }

        await _db.SaveChangesAsync();
        return result;
    }

    /// <summary>
    /// Parses and synchronizes request profile definitions from YAML content.
    /// </summary>
    private async Task<PolicySyncResult> SyncRequestProfilesAsync(string yamlContent)
    {
        var result = new PolicySyncResult();
        var deserializer = BuildDeserializer();

        RequestProfileYamlRoot root;
        try
        {
            root = deserializer.Deserialize<RequestProfileYamlRoot>(yamlContent);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"YAML parse error for request profiles: {ex.Message}");
            return result;
        }

        if (root?.Profiles == null || root.Profiles.Count == 0)
        {
            _logger.LogDebug("No request profiles found in YAML content");
            return result;
        }

        var existingProfiles = await _db.RequestProfiles
            .Where(p => p.CertificateAuthorityId == null)
            .ToListAsync();

        foreach (var yamlProfile in root.Profiles)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(yamlProfile.Name))
                {
                    result.Errors.Add("Request profile entry missing required 'name' field");
                    continue;
                }

                var existing = existingProfiles.FirstOrDefault(p =>
                    string.Equals(p.Name, yamlProfile.Name, StringComparison.OrdinalIgnoreCase));

                if (existing == null)
                {
                    var entity = new RequestProfileEntity
                    {
                        Name = yamlProfile.Name,
                        Description = yamlProfile.Description,
                        RequireApproval = yamlProfile.RequireApproval,
                        RequiredApprovalCount = yamlProfile.RequiredApprovalCount,
                        SubjectDnRules = yamlProfile.SubjectDnRules ?? "[]",
                        SanRules = yamlProfile.SanRules ?? "{}",
                        AllowedCertProfileIds = yamlProfile.AllowedCertProfileIds ?? "[]"
                    };
                    _db.RequestProfiles.Add(entity);
                    result.Created++;
                    _logger.LogInformation("Creating request profile: {Name}", yamlProfile.Name);
                }
                else if (HasRequestProfileChanged(existing, yamlProfile))
                {
                    existing.Description = yamlProfile.Description;
                    existing.RequireApproval = yamlProfile.RequireApproval;
                    existing.RequiredApprovalCount = yamlProfile.RequiredApprovalCount;
                    existing.SubjectDnRules = yamlProfile.SubjectDnRules ?? "[]";
                    existing.SanRules = yamlProfile.SanRules ?? "{}";
                    existing.AllowedCertProfileIds = yamlProfile.AllowedCertProfileIds ?? "[]";
                    existing.UpdatedAt = DateTime.UtcNow;
                    result.Updated++;
                    _logger.LogInformation("Updating request profile: {Name}", yamlProfile.Name);
                }
                else
                {
                    result.Unchanged++;
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Error syncing request profile '{yamlProfile.Name}': {ex.Message}");
            }
        }

        await _db.SaveChangesAsync();
        return result;
    }

    /// <summary>
    /// Compares an existing cert profile entity to a YAML definition to detect changes.
    /// </summary>
    private static bool HasCertProfileChanged(CertProfileEntity existing, CertProfileYamlEntry yaml)
    {
        return existing.Description != (yaml.Description ?? string.Empty)
            || existing.IsCaProfile != yaml.IsCaProfile
            || existing.KeyUsages != (yaml.KeyUsages ?? string.Empty)
            || existing.ExtendedKeyUsages != (yaml.ExtendedKeyUsages ?? "[]")
            || existing.AllowedKeyAlgorithms != (yaml.AllowedKeyAlgorithms ?? "[]")
            || existing.AllowedKeySizes != (yaml.AllowedKeySizes ?? "[]")
            || existing.AllowedSignatureAlgorithms != (yaml.AllowedSignatureAlgorithms ?? "[]")
            || existing.ValidityPeriodMin != yaml.ValidityPeriodMin
            || existing.ValidityPeriodMax != yaml.ValidityPeriodMax
            || existing.CtEnabled != yaml.CtEnabled;
    }

    /// <summary>
    /// Compares an existing signing profile entity to a YAML definition to detect changes.
    /// </summary>
    private static bool HasSigningProfileChanged(SigningProfileEntity existing, SigningProfileYamlEntry yaml)
    {
        return existing.Description != (yaml.Description ?? string.Empty)
            || existing.AllowedAlgorithms != (yaml.AllowedAlgorithms ?? "[]")
            || existing.AllowedEKUs != (yaml.AllowedEKUs ?? "[]")
            || existing.IsDefault != yaml.IsDefault
            || existing.MaxPathLength != yaml.MaxPathLength
            || existing.NameConstraintsPermitted != yaml.NameConstraintsPermitted
            || existing.NameConstraintsExcluded != yaml.NameConstraintsExcluded
            || existing.PolicyOids != yaml.PolicyOids
            || existing.InhibitAnyPolicy != yaml.InhibitAnyPolicy;
    }

    /// <summary>
    /// Compares an existing request profile entity to a YAML definition to detect changes.
    /// </summary>
    private static bool HasRequestProfileChanged(RequestProfileEntity existing, RequestProfileYamlEntry yaml)
    {
        return existing.Description != yaml.Description
            || existing.RequireApproval != yaml.RequireApproval
            || existing.RequiredApprovalCount != yaml.RequiredApprovalCount
            || existing.SubjectDnRules != (yaml.SubjectDnRules ?? "[]")
            || existing.SanRules != (yaml.SanRules ?? "{}")
            || existing.AllowedCertProfileIds != (yaml.AllowedCertProfileIds ?? "[]");
    }

    /// <summary>
    /// Builds a YamlDotNet deserializer configured for camelCase property naming.
    /// </summary>
    private static IDeserializer BuildDeserializer()
    {
        return new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
    }

    #region YAML deserialization models

    /// <summary>Root object for cert-profiles.yaml.</summary>
    private class CertProfileYamlRoot
    {
        public List<CertProfileYamlEntry> Profiles { get; set; } = new();
    }

    /// <summary>A single certificate profile entry in YAML.</summary>
    private class CertProfileYamlEntry
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool IsCaProfile { get; set; }
        public string? KeyUsages { get; set; }
        public string? ExtendedKeyUsages { get; set; }
        public string? AllowedKeyAlgorithms { get; set; }
        public string? AllowedKeySizes { get; set; }
        public string? AllowedSignatureAlgorithms { get; set; }
        public string? ValidityPeriodMin { get; set; }
        public string? ValidityPeriodMax { get; set; }
        public bool CtEnabled { get; set; }
    }

    /// <summary>Root object for signing-profiles.yaml.</summary>
    private class SigningProfileYamlRoot
    {
        public List<SigningProfileYamlEntry> Profiles { get; set; } = new();
    }

    /// <summary>A single signing profile entry in YAML.</summary>
    private class SigningProfileYamlEntry
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string? AllowedAlgorithms { get; set; }
        public string? AllowedEKUs { get; set; }
        public bool IsDefault { get; set; }
        public int? MaxPathLength { get; set; }
        public string? NameConstraintsPermitted { get; set; }
        public string? NameConstraintsExcluded { get; set; }
        public string? PolicyOids { get; set; }
        public bool InhibitAnyPolicy { get; set; }
    }

    /// <summary>Root object for request-profiles.yaml.</summary>
    private class RequestProfileYamlRoot
    {
        public List<RequestProfileYamlEntry> Profiles { get; set; } = new();
    }

    /// <summary>A single request profile entry in YAML.</summary>
    private class RequestProfileYamlEntry
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool RequireApproval { get; set; }
        public int RequiredApprovalCount { get; set; } = 1;
        public string? SubjectDnRules { get; set; }
        public string? SanRules { get; set; }
        public string? AllowedCertProfileIds { get; set; }
    }

    #endregion
}
