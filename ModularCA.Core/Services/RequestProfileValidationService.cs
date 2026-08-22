using ModularCA.Database;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using System.Text.Json;

using ModularCA.Core.Models;
namespace ModularCA.Core.Services
{
    /// <summary>
    /// Validates certificate requests against a Request Profile's subject DN rules,
    /// SAN constraints, and allowed cert profiles.
    /// </summary>
    public class RequestProfileValidationService
    {
        private readonly ModularCADbContext _db;

        private readonly IProfileResolutionService _profileResolution;

        public RequestProfileValidationService(ModularCADbContext db, IProfileResolutionService profileResolution)
        {
            _db = db;
            _profileResolution = profileResolution;
        }

        /// <summary>
        /// Loads the request profile with inheritance applied.
        /// <para>
        /// Both entry points here used to read the raw <c>RequestProfileEntity</c> straight from
        /// the database, which skipped the CLM-002 clamping in
        /// <c>ProfileResolutionService.ResolveRequestProfileAsync</c> entirely. That method had
        /// exactly one caller in the whole repository — an admin preview endpoint — so
        /// <c>MergeRequestProfiles</c> was effectively dead code at runtime and the "stricter
        /// only" guarantee did not hold on any enrollment path. A CA-scoped request profile whose
        /// parent set <c>RequireApproval = true</c> could set it to false, and every EST, SCEP,
        /// CMP and ACME enrollment under it issued without approval.
        /// </para>
        /// <para>
        /// Returns null when the profile does not exist, matching the previous FindAsync
        /// behaviour so callers keep their "no profile = no validation" semantics.
        /// </para>
        /// </summary>
        private async Task<EffectiveRequestProfile?> LoadEffectiveAsync(Guid requestProfileId)
        {
            try
            {
                return await _profileResolution.ResolveRequestProfileAsync(requestProfileId);
            }
            catch (InvalidOperationException)
            {
                return null; // profile not found
            }
        }

        /// <summary>
        /// Resolves the effective cert profile ID using the fallback chain:
        /// 1. Requester's explicit choice (validated against request profile's AllowedCertProfileIds)
        /// 2. Protocol config default (CaProtocolConfig.CertProfileId — per CA + protocol)
        /// 3. Request profile default (RequestProfile.DefaultCertProfileId — catch-all)
        /// Returns the resolved cert profile ID, or null if nothing resolved.
        /// </summary>
        public async Task<(Guid? CertProfileId, string? Error)> ResolveCertProfileIdAsync(
            Guid? requesterChoice,
            Guid protocolDefaultId,
            Guid? requestProfileId)
        {
            // Load request profile if specified
            List<Guid>? allowedIds = null;
            Guid? requestProfileDefault = null;
            if (requestProfileId != null)
            {
                var profile = await LoadEffectiveAsync(requestProfileId.Value);
                if (profile != null)
                {
                    var parsed = JsonSerializer.Deserialize<List<Guid>>(profile.AllowedCertProfileIds ?? "[]");
                    if (parsed != null && parsed.Count > 0)
                        allowedIds = parsed;
                    requestProfileDefault = profile.DefaultCertProfileId;
                }
            }

            // 1. Requester's choice — validate against allowed list
            if (requesterChoice != null)
            {
                if (allowedIds != null && !allowedIds.Contains(requesterChoice.Value))
                    return (null, $"Certificate profile {requesterChoice} is not allowed by the request profile");
                return (requesterChoice, null);
            }

            // 2. Protocol config default
            if (protocolDefaultId != Guid.Empty)
            {
                if (allowedIds != null && !allowedIds.Contains(protocolDefaultId))
                {
                    // Protocol default not in allowed list — fall through to #3
                }
                else
                {
                    return (protocolDefaultId, null);
                }
            }

            // 3. Request profile default
            if (requestProfileDefault != null)
                return (requestProfileDefault, null);

            // Fallback to protocol default even if not in allowed list (better than nothing)
            if (protocolDefaultId != Guid.Empty)
                return (protocolDefaultId, null);

            return (null, "No certificate profile could be resolved");
        }

        /// <summary>
        /// Validates a certificate request against the specified request profile.
        /// Returns (isValid, errorMessage, modifiedSubject) where modifiedSubject has
        /// fixed values applied and defaults filled in.
        /// Profile-supplied regexes are evaluated through <see cref="ProfileRegex"/> rather than
        /// the static <c>Regex.IsMatch</c>: this method is on the hot path for every enrollment
        /// protocol (ACME/EST/SCEP/CMP/public enrollment), so an untimed match against an
        /// operator-authored pattern with nested quantifiers would let an unauthenticated
        /// requester burn a CPU core per request. The helper bounds the match and fails closed.
        /// </summary>
        public async Task<(bool IsValid, string? Error, string? ModifiedSubject)> ValidateAsync(
            Guid requestProfileId,
            string subjectDn,
            string? sansJson)
        {
            var profile = await LoadEffectiveAsync(requestProfileId);
            if (profile == null)
                return (true, null, subjectDn); // No profile = no validation

            // Parse the subject DN into components
            var dnComponents = ParseSubjectDn(subjectDn);
            var rules = JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(profile.SubjectDnRules) ?? new();

            // Validate each rule
            foreach (var rule in rules)
            {
                var value = dnComponents.GetValueOrDefault(rule.Field.ToUpperInvariant());

                switch (rule.Requirement)
                {
                    case "Required":
                        if (string.IsNullOrEmpty(value) && string.IsNullOrEmpty(rule.FixedValue) && string.IsNullOrEmpty(rule.DefaultValue))
                            return (false, $"Subject field '{rule.Field}' is required", null);
                        break;
                    case "Forbidden":
                        if (!string.IsNullOrEmpty(value))
                            return (false, $"Subject field '{rule.Field}' is not allowed", null);
                        break;
                }

                // Apply fixed value
                if (!string.IsNullOrEmpty(rule.FixedValue))
                    dnComponents[rule.Field.ToUpperInvariant()] = rule.FixedValue;
                // Apply default if missing
                else if (string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(rule.DefaultValue))
                    dnComponents[rule.Field.ToUpperInvariant()] = rule.DefaultValue;

                // Get the effective value after fixed/default
                var effectiveValue = dnComponents.GetValueOrDefault(rule.Field.ToUpperInvariant());

                // Regex check
                if (!string.IsNullOrEmpty(rule.Regex) && !string.IsNullOrEmpty(effectiveValue))
                {
                    // ProfileRegex applies a bounded match timeout and fails closed: a hostile or
                    // uncompilable profile pattern reads as "no match" and rejects the request
                    // rather than pinning a core (ReDoS) or waving the value through.
                    if (!ProfileRegex.IsMatch(effectiveValue, rule.Regex))
                        return (false, $"Subject field '{rule.Field}' value '{effectiveValue}' does not match pattern '{rule.Regex}'", null);
                }

                // Max length check
                if (rule.MaxLength.HasValue && !string.IsNullOrEmpty(effectiveValue) && effectiveValue.Length > rule.MaxLength.Value)
                    return (false, $"Subject field '{rule.Field}' exceeds max length {rule.MaxLength}", null);
            }

            // Validate SANs
            var sanRules = JsonSerializer.Deserialize<SanRules>(profile.SanRules);
            if (sanRules != null && !string.IsNullOrEmpty(sansJson))
            {
                var sans = JsonSerializer.Deserialize<List<string>>(sansJson) ?? new();
                var sanError = ValidateSans(sans, sanRules);
                if (sanError != null)
                    return (false, sanError, null);
            }
            else if (sanRules?.Required == true)
            {
                var sans = !string.IsNullOrEmpty(sansJson) ? JsonSerializer.Deserialize<List<string>>(sansJson) : null;
                if (sans == null || sans.Count == 0)
                    return (false, "At least one Subject Alternative Name is required", null);
            }

            // Rebuild the modified subject DN
            var modifiedSubject = RebuildSubjectDn(dnComponents);
            return (true, null, modifiedSubject);
        }

        /// <summary>
        /// Parses a subject DN string like "CN=foo,O=bar,C=US" into a dictionary.
        /// Handles commas inside quoted values (e.g., O="Acme, Inc.").
        /// </summary>
        internal static Dictionary<string, string> ParseSubjectDn(string dn)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(dn))
                return result;

            // Split on commas that are not inside quotes
            var components = new List<string>();
            var current = new System.Text.StringBuilder();
            bool inQuotes = false;

            for (int i = 0; i < dn.Length; i++)
            {
                char c = dn[i];

                if (c == '"')
                {
                    inQuotes = !inQuotes;
                    current.Append(c);
                }
                else if (c == ',' && !inQuotes)
                {
                    var part = current.ToString().Trim();
                    if (!string.IsNullOrEmpty(part))
                        components.Add(part);
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }

            // Add the last component
            var lastPart = current.ToString().Trim();
            if (!string.IsNullOrEmpty(lastPart))
                components.Add(lastPart);

            // Parse each component into key=value
            foreach (var component in components)
            {
                var eqIndex = component.IndexOf('=');
                if (eqIndex <= 0)
                    continue;

                var key = component.Substring(0, eqIndex).Trim().ToUpperInvariant();
                var value = component.Substring(eqIndex + 1).Trim();

                // Remove surrounding quotes if present
                if (value.Length >= 2 && value.StartsWith('"') && value.EndsWith('"'))
                    value = value.Substring(1, value.Length - 2);

                result[key] = value;
            }

            return result;
        }

        /// <summary>
        /// Rebuilds a subject DN string from a dictionary of components.
        /// Uses a standard ordering: CN, OU, O, L, ST, C, then any remaining.
        /// </summary>
        internal static string RebuildSubjectDn(Dictionary<string, string> components)
        {
            // Standard DN field ordering
            var orderedFields = new[] { "CN", "OU", "O", "L", "ST", "C", "DC", "E", "SERIALNUMBER" };

            var parts = new List<string>();

            // Add fields in standard order
            foreach (var field in orderedFields)
            {
                if (components.TryGetValue(field, out var value) && !string.IsNullOrEmpty(value))
                {
                    // Quote values that contain commas
                    var formattedValue = value.Contains(',') ? $"\"{value}\"" : value;
                    parts.Add($"{field}={formattedValue}");
                }
            }

            // Add any remaining fields not in the standard order
            foreach (var kvp in components)
            {
                if (!string.IsNullOrEmpty(kvp.Value) &&
                    !orderedFields.Contains(kvp.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var formattedValue = kvp.Value.Contains(',') ? $"\"{kvp.Value}\"" : kvp.Value;
                    parts.Add($"{kvp.Key}={formattedValue}");
                }
            }

            return string.Join(",", parts);
        }

        /// <summary>
        /// Validates a list of SANs against the SAN rules.
        /// SANs are stored as "TYPE:value" (e.g., "DNS:example.com", "IP:1.2.3.4").
        /// Returns an error string if validation fails, null if valid.
        /// Per-type patterns run through <see cref="ProfileRegex"/> so a pathological profile
        /// pattern cannot be turned into a denial of service by a crafted SAN value, and so a
        /// pattern that times out or fails to compile rejects the SAN instead of accepting it.
        /// </summary>
        internal static string? ValidateSans(List<string> sans, SanRules rules)
        {
            // Count SANs per type for maxCount validation
            var typeCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var san in sans)
            {
                var colonIndex = san.IndexOf(':');
                if (colonIndex <= 0)
                    return $"Invalid SAN format: '{san}' (expected TYPE:value)";

                var sanType = san.Substring(0, colonIndex).Trim().ToUpperInvariant();
                var sanValue = san.Substring(colonIndex + 1).Trim();

                // Check if the SAN type is allowed
                if (rules.AllowedTypes != null && rules.AllowedTypes.Count > 0)
                {
                    var allowed = rules.AllowedTypes.Any(t =>
                        string.Equals(t, sanType, StringComparison.OrdinalIgnoreCase));
                    if (!allowed)
                        return $"SAN type '{sanType}' is not allowed. Allowed types: {string.Join(", ", rules.AllowedTypes)}";
                }

                // Track count per type
                typeCounts.TryGetValue(sanType, out var count);
                typeCounts[sanType] = count + 1;

                // Apply per-type rules
                if (rules.Rules != null && rules.Rules.TryGetValue(sanType, out var typeRule))
                {
                    // Regex validation
                    // Bounded, fail-closed match — see the subject-DN rule check in ValidateAsync.
                    if (!string.IsNullOrEmpty(typeRule.Regex) && !ProfileRegex.IsMatch(sanValue, typeRule.Regex))
                        return $"SAN value '{sanValue}' (type {sanType}) does not match pattern '{typeRule.Regex}'";
                }
            }

            // Check max count per type
            if (rules.Rules != null)
            {
                foreach (var kvp in typeCounts)
                {
                    if (rules.Rules.TryGetValue(kvp.Key, out var typeRule) && kvp.Value > typeRule.MaxCount)
                        return $"Too many SANs of type '{kvp.Key}': {kvp.Value} (max {typeRule.MaxCount})";
                }
            }

            return null;
        }
    }
}
