using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using System.Text.Json;
using System.Xml;

namespace ModularCA.Core.Services;

/// <summary>
/// Resolves effective profile values by merging CA-scoped profiles with their
/// inherited parent profiles. Validates that child overrides are equal or
/// stricter than parent constraints to maintain policy hierarchies.
/// </summary>
public class ProfileResolutionService : IProfileResolutionService
{
    private readonly ModularCADbContext _db;
    private readonly ILogger<ProfileResolutionService> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="ProfileResolutionService"/>.
    /// </summary>
    /// <param name="db">Database context for profile lookups.</param>
    /// <param name="logger">Logger instance.</param>
    public ProfileResolutionService(ModularCADbContext db, ILogger<ProfileResolutionService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<EffectiveCertProfile> ResolveCertProfileAsync(Guid certProfileId)
    {
        var child = await _db.CertProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == certProfileId);

        if (child == null)
            throw new InvalidOperationException($"Cert profile '{certProfileId}' not found.");

        // If inheritance is not active, return standalone
        if (!child.InheritanceEnabled || child.InheritsFromId == null)
            return MapCertProfileStandalone(child);

        var parent = await _db.CertProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == child.InheritsFromId);

        // Defensive: if parent doesn't exist, treat as standalone
        if (parent == null)
        {
            _logger.LogWarning(
                "Cert profile '{ChildId}' references non-existent parent '{ParentId}'. Treating as standalone.",
                certProfileId, child.InheritsFromId);
            return MapCertProfileStandalone(child);
        }

        return MergeCertProfiles(child, parent);
    }

    /// <inheritdoc />
    public async Task<EffectiveRequestProfile> ResolveRequestProfileAsync(Guid requestProfileId)
    {
        var child = await _db.RequestProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == requestProfileId);

        if (child == null)
            throw new InvalidOperationException($"Request profile '{requestProfileId}' not found.");

        if (!child.InheritanceEnabled || child.InheritsFromId == null)
            return MapRequestProfileStandalone(child);

        var parent = await _db.RequestProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == child.InheritsFromId);

        if (parent == null)
        {
            _logger.LogWarning(
                "Request profile '{ChildId}' references non-existent parent '{ParentId}'. Treating as standalone.",
                requestProfileId, child.InheritsFromId);
            return MapRequestProfileStandalone(child);
        }

        return MergeRequestProfiles(child, parent);
    }

    /// <inheritdoc />
    public async Task<List<string>> ValidateCertProfileInheritanceAsync(Guid childProfileId)
    {
        var errors = new List<string>();

        var child = await _db.CertProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == childProfileId);

        if (child == null)
        {
            errors.Add($"Cert profile '{childProfileId}' not found.");
            return errors;
        }

        if (!child.InheritanceEnabled || child.InheritsFromId == null)
            return errors; // No inheritance, nothing to validate

        var parent = await _db.CertProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == child.InheritsFromId);

        if (parent == null)
        {
            errors.Add($"Parent cert profile '{child.InheritsFromId}' not found.");
            return errors;
        }

        // ValidityPeriodMax: child must be <= parent
        ValidateMaxDuration(child.ValidityPeriodMax, parent.ValidityPeriodMax,
            "ValidityPeriodMax", errors);

        // ValidityPeriodMin: child must be >= parent (stricter minimum)
        ValidateMinDuration(child.ValidityPeriodMin, parent.ValidityPeriodMin,
            "ValidityPeriodMin", errors);

        // JSON array subset checks
        ValidateJsonArraySubset(child.KeyUsages, parent.KeyUsages,
            "KeyUsages", errors);
        ValidateJsonArraySubset(child.ExtendedKeyUsages, parent.ExtendedKeyUsages,
            "ExtendedKeyUsages", errors);
        ValidateJsonArraySubset(child.AllowedKeyAlgorithms, parent.AllowedKeyAlgorithms,
            "AllowedKeyAlgorithms", errors);
        ValidateJsonArraySubset(child.AllowedKeySizes, parent.AllowedKeySizes,
            "AllowedKeySizes", errors);
        ValidateJsonArraySubset(child.AllowedSignatureAlgorithms, parent.AllowedSignatureAlgorithms,
            "AllowedSignatureAlgorithms", errors);

        return errors;
    }

    /// <inheritdoc />
    public async Task<List<string>> ValidateRequestProfileInheritanceAsync(Guid childProfileId)
    {
        var errors = new List<string>();

        var child = await _db.RequestProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == childProfileId);

        if (child == null)
        {
            errors.Add($"Request profile '{childProfileId}' not found.");
            return errors;
        }

        if (!child.InheritanceEnabled || child.InheritsFromId == null)
            return errors;

        var parent = await _db.RequestProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == child.InheritsFromId);

        if (parent == null)
        {
            errors.Add($"Parent request profile '{child.InheritsFromId}' not found.");
            return errors;
        }

        // MaxValidityPeriod: child must be <= parent
        ValidateMaxDuration(child.MaxValidityPeriod, parent.MaxValidityPeriod,
            "MaxValidityPeriod", errors);

        // AllowedCertProfileIds: child must be subset of parent
        ValidateJsonArraySubset(child.AllowedCertProfileIds, parent.AllowedCertProfileIds,
            "AllowedCertProfileIds", errors);

        // RequiredApprovalCount: child must be >= parent (stricter)
        if (child.RequiredApprovalCount < parent.RequiredApprovalCount)
        {
            errors.Add(
                $"RequiredApprovalCount: child value ({child.RequiredApprovalCount}) " +
                $"is less strict than parent ({parent.RequiredApprovalCount}).");
        }

        return errors;
    }

    // ── Mapping helpers (standalone — no merge) ──────────────────────────

    /// <summary>
    /// Maps a standalone cert profile entity to an effective profile with all fields marked as "overridden".
    /// </summary>
    private static EffectiveCertProfile MapCertProfileStandalone(CertProfileEntity entity)
    {
        return new EffectiveCertProfile
        {
            SourceProfileId = entity.Id,
            ParentProfileId = null,
            Name = entity.Name,
            Description = entity.Description,
            IsCaProfile = entity.IsCaProfile,
            KeyUsages = entity.KeyUsages,
            ExtendedKeyUsages = entity.ExtendedKeyUsages,
            ValidityPeriodMin = entity.ValidityPeriodMin,
            ValidityPeriodMax = entity.ValidityPeriodMax,
            AllowedKeyAlgorithms = entity.AllowedKeyAlgorithms,
            AllowedKeySizes = entity.AllowedKeySizes,
            AllowedSignatureAlgorithms = entity.AllowedSignatureAlgorithms,
            CtEnabled = entity.CtEnabled,
            CtLogIds = entity.CtLogIds,
            AllowWildcard = entity.AllowWildcard,
            FieldSources = new Dictionary<string, string>() // Empty — all fields are "own"
        };
    }

    /// <summary>
    /// Maps a standalone request profile entity to an effective profile with no inheritance.
    /// </summary>
    private static EffectiveRequestProfile MapRequestProfileStandalone(RequestProfileEntity entity)
    {
        return new EffectiveRequestProfile
        {
            SourceProfileId = entity.Id,
            ParentProfileId = null,
            Name = entity.Name,
            Description = entity.Description,
            SubjectDnRules = entity.SubjectDnRules,
            SanRules = entity.SanRules,
            AllowedCertProfileIds = entity.AllowedCertProfileIds,
            DefaultCertProfileId = entity.DefaultCertProfileId,
            RequireApproval = entity.RequireApproval,
            MaxValidityPeriod = entity.MaxValidityPeriod,
            RequiredApprovalCount = entity.RequiredApprovalCount,
            FieldSources = new Dictionary<string, string>()
        };
    }

    // ── Merge helpers ────────────────────────────────────────────────────

    /// <summary>
    /// Merges a child cert profile with its parent, producing an effective profile
    /// where child overrides take precedence and unset child fields inherit from parent.
    /// CLM-002: Enforces that CA profile overrides are equal or stricter than the
    /// parent (system) profile. If a CA profile attempts to weaken a constraint,
    /// the stricter parent value is used and a warning is logged.
    /// </summary>
    private EffectiveCertProfile MergeCertProfiles(CertProfileEntity child, CertProfileEntity parent)
    {
        var sources = new Dictionary<string, string>();

        // CLM-002: Enforce boolean restrictions — CA cannot weaken parent constraints.
        // If parent says IsCaProfile=true, child cannot set it to false (weakening).
        // If parent says AllowWildcard=false, child cannot set it to true (weakening).
        var effectiveIsCaProfile = child.IsCaProfile;
        if (parent.IsCaProfile && !child.IsCaProfile)
        {
            _logger.LogWarning(
                "CLM-002: Cert profile '{ChildId}' attempts to weaken IsCaProfile from parent '{ParentId}'. Using parent value (true).",
                child.Id, parent.Id);
            effectiveIsCaProfile = true;
        }

        var effectiveAllowWildcard = child.AllowWildcard;
        if (!parent.AllowWildcard && child.AllowWildcard)
        {
            _logger.LogWarning(
                "CLM-002: Cert profile '{ChildId}' attempts to enable AllowWildcard which parent '{ParentId}' disables. Using parent value (false).",
                child.Id, parent.Id);
            effectiveAllowWildcard = false;
        }

        var effectiveCtEnabled = child.CtEnabled;
        if (parent.CtEnabled && !child.CtEnabled)
        {
            _logger.LogWarning(
                "CLM-002: Cert profile '{ChildId}' attempts to disable CtEnabled which parent '{ParentId}' requires. Using parent value (true).",
                child.Id, parent.Id);
            effectiveCtEnabled = true;
        }

        // CLM-002: Enforce ValidityPeriodMax — child must be <= parent (shorter or equal)
        var mergedValidityMax = MergeNullableString(child.ValidityPeriodMax, parent.ValidityPeriodMax, nameof(EffectiveCertProfile.ValidityPeriodMax), sources);
        mergedValidityMax = ClampMaxDuration(mergedValidityMax, parent.ValidityPeriodMax,
            nameof(EffectiveCertProfile.ValidityPeriodMax), child.Id, parent.Id);

        // CLM-002: Enforce ValidityPeriodMin — child must be >= parent (larger or equal)
        var mergedValidityMin = MergeNullableString(child.ValidityPeriodMin, parent.ValidityPeriodMin, nameof(EffectiveCertProfile.ValidityPeriodMin), sources);
        mergedValidityMin = ClampMinDuration(mergedValidityMin, parent.ValidityPeriodMin,
            nameof(EffectiveCertProfile.ValidityPeriodMin), child.Id, parent.Id);

        // CLM-002: Enforce JSON array subset — child must be a subset of parent
        var mergedKeyAlgorithms = ClampJsonArraySubset(
            MergeJsonArray(child.AllowedKeyAlgorithms, parent.AllowedKeyAlgorithms, nameof(EffectiveCertProfile.AllowedKeyAlgorithms), sources),
            parent.AllowedKeyAlgorithms, nameof(EffectiveCertProfile.AllowedKeyAlgorithms), child.Id, parent.Id);
        var mergedKeySizes = ClampJsonArraySubset(
            MergeJsonArray(child.AllowedKeySizes, parent.AllowedKeySizes, nameof(EffectiveCertProfile.AllowedKeySizes), sources),
            parent.AllowedKeySizes, nameof(EffectiveCertProfile.AllowedKeySizes), child.Id, parent.Id);
        var mergedSigAlgorithms = ClampJsonArraySubset(
            MergeJsonArray(child.AllowedSignatureAlgorithms, parent.AllowedSignatureAlgorithms, nameof(EffectiveCertProfile.AllowedSignatureAlgorithms), sources),
            parent.AllowedSignatureAlgorithms, nameof(EffectiveCertProfile.AllowedSignatureAlgorithms), child.Id, parent.Id);

        var result = new EffectiveCertProfile
        {
            SourceProfileId = child.Id,
            ParentProfileId = parent.Id,

            // Identity fields always come from the child
            Name = child.Name,
            Description = child.Description,

            // Boolean fields — clamped above
            IsCaProfile = effectiveIsCaProfile,
            CtEnabled = effectiveCtEnabled,
            AllowWildcard = effectiveAllowWildcard,

            // String fields: merge with fallback to parent
            KeyUsages = MergeJsonArray(child.KeyUsages, parent.KeyUsages, nameof(EffectiveCertProfile.KeyUsages), sources),
            ExtendedKeyUsages = MergeJsonArray(child.ExtendedKeyUsages, parent.ExtendedKeyUsages, nameof(EffectiveCertProfile.ExtendedKeyUsages), sources),
            ValidityPeriodMin = mergedValidityMin,
            ValidityPeriodMax = mergedValidityMax,
            CtLogIds = MergeNullableString(child.CtLogIds, parent.CtLogIds, nameof(EffectiveCertProfile.CtLogIds), sources),

            // JSON array fields — clamped above
            AllowedKeyAlgorithms = mergedKeyAlgorithms,
            AllowedKeySizes = mergedKeySizes,
            AllowedSignatureAlgorithms = mergedSigAlgorithms,

            FieldSources = sources
        };

        // Mark identity fields
        sources[nameof(EffectiveCertProfile.Name)] = "overridden";
        sources[nameof(EffectiveCertProfile.Description)] = "overridden";

        // Mark boolean fields
        sources[nameof(EffectiveCertProfile.IsCaProfile)] = "overridden";
        sources[nameof(EffectiveCertProfile.CtEnabled)] = "overridden";

        return result;
    }

    /// <summary>
    /// Merges a child request profile with its parent, producing an effective profile
    /// where child overrides take precedence and unset child fields inherit from parent.
    /// CLM-002: Enforces that CA request profile overrides are equal or stricter than
    /// the parent. If a CA profile attempts to weaken a constraint, the stricter parent
    /// value is used and a warning is logged.
    /// </summary>
    private EffectiveRequestProfile MergeRequestProfiles(RequestProfileEntity child, RequestProfileEntity parent)
    {
        var sources = new Dictionary<string, string>();

        // CLM-002: Enforce RequireApproval — if parent requires approval, child cannot disable it
        var effectiveRequireApproval = child.RequireApproval;
        if (parent.RequireApproval && !child.RequireApproval)
        {
            _logger.LogWarning(
                "CLM-002: Request profile '{ChildId}' attempts to disable RequireApproval which parent '{ParentId}' requires. Using parent value (true).",
                child.Id, parent.Id);
            effectiveRequireApproval = true;
        }

        // CLM-002: Enforce MaxValidityPeriod — child must be <= parent (shorter or equal)
        var mergedMaxValidity = MergeNullableString(child.MaxValidityPeriod, parent.MaxValidityPeriod, nameof(EffectiveRequestProfile.MaxValidityPeriod), sources);
        mergedMaxValidity = ClampMaxDuration(mergedMaxValidity, parent.MaxValidityPeriod,
            nameof(EffectiveRequestProfile.MaxValidityPeriod), child.Id, parent.Id);

        // CLM-002: Enforce RequiredApprovalCount — child must be >= parent (stricter)
        var effectiveApprovalCount = child.RequiredApprovalCount > 0 ? child.RequiredApprovalCount : parent.RequiredApprovalCount;
        if (child.RequiredApprovalCount > 0 && child.RequiredApprovalCount < parent.RequiredApprovalCount)
        {
            _logger.LogWarning(
                "CLM-002: Request profile '{ChildId}' RequiredApprovalCount ({ChildVal}) is less strict than parent '{ParentId}' ({ParentVal}). Using parent value.",
                child.Id, child.RequiredApprovalCount, parent.Id, parent.RequiredApprovalCount);
            effectiveApprovalCount = parent.RequiredApprovalCount;
        }

        // CLM-002: Enforce AllowedCertProfileIds — child must be a subset of parent
        var mergedCertProfileIds = ClampJsonArraySubset(
            MergeJsonArray(child.AllowedCertProfileIds, parent.AllowedCertProfileIds, nameof(EffectiveRequestProfile.AllowedCertProfileIds), sources),
            parent.AllowedCertProfileIds, nameof(EffectiveRequestProfile.AllowedCertProfileIds), child.Id, parent.Id);

        var result = new EffectiveRequestProfile
        {
            SourceProfileId = child.Id,
            ParentProfileId = parent.Id,

            // Identity fields always come from the child
            Name = child.Name,
            Description = child.Description,

            // Boolean fields — clamped above
            RequireApproval = effectiveRequireApproval,

            // Nullable string fields — clamped above
            MaxValidityPeriod = mergedMaxValidity,

            // JSON fields
            SubjectDnRules = MergeJsonArray(child.SubjectDnRules, parent.SubjectDnRules, nameof(EffectiveRequestProfile.SubjectDnRules), sources),
            SanRules = MergeJsonObject(child.SanRules, parent.SanRules, nameof(EffectiveRequestProfile.SanRules), sources),
            AllowedCertProfileIds = mergedCertProfileIds,

            // Guid? field: use child if set, else parent
            DefaultCertProfileId = child.DefaultCertProfileId ?? parent.DefaultCertProfileId,

            // Int field — clamped above
            RequiredApprovalCount = effectiveApprovalCount,

            FieldSources = sources
        };

        // Mark identity fields
        sources[nameof(EffectiveRequestProfile.Name)] = "overridden";
        sources[nameof(EffectiveRequestProfile.Description)] = "overridden";

        // Mark boolean fields
        sources[nameof(EffectiveRequestProfile.RequireApproval)] = "overridden";

        // Mark DefaultCertProfileId
        sources[nameof(EffectiveRequestProfile.DefaultCertProfileId)] =
            child.DefaultCertProfileId != null ? "overridden" : "inherited";

        // Mark RequiredApprovalCount
        sources[nameof(EffectiveRequestProfile.RequiredApprovalCount)] =
            child.RequiredApprovalCount > 0 ? "overridden" : "inherited";

        return result;
    }

    // ── Field merge primitives ───────────────────────────────────────────

    /// <summary>
    /// Merges a non-nullable string field. If the child value is non-empty, it overrides; otherwise inherits from parent.
    /// </summary>
    private static string MergeString(string? child, string? parent, string fieldName, Dictionary<string, string> sources)
    {
        if (!string.IsNullOrEmpty(child))
        {
            sources[fieldName] = "overridden";
            return child;
        }
        sources[fieldName] = "inherited";
        return parent ?? string.Empty;
    }


    /// <summary>
    /// Merges a nullable string field. If the child value is non-empty, it overrides; otherwise inherits from parent.
    /// </summary>
    private static string? MergeNullableString(string? child, string? parent, string fieldName, Dictionary<string, string> sources)
    {
        if (!string.IsNullOrEmpty(child))
        {
            sources[fieldName] = "overridden";
            return child;
        }
        sources[fieldName] = parent != null ? "inherited" : "inherited";
        return parent;
    }

    /// <summary>
    /// Merges a JSON array field. Treats an empty array or null/empty as "not set" (inherit from
    /// parent). Any non-empty array in the child is treated as an override.
    /// <para>
    /// KeyUsages and ExtendedKeyUsages used to route through <see cref="MergeString"/> instead,
    /// which tests only <c>string.IsNullOrEmpty</c> — and <c>"[]"</c> is a two-character string, so
    /// an empty child array counted as a deliberate override and the parent's list was discarded.
    /// Downstream, <c>IssuanceValidationService.SetupAllowedExtendedOids</c> short-circuits on an
    /// empty cert-profile list and emits no EKU extension at all, so an empty array anywhere in the
    /// chain silently stripped EKUs from every certificate issued under that profile — no error, no
    /// log. Emptiness is now decided by parsing rather than by an exact <c>"[]"</c> compare, so a
    /// whitespace variant such as <c>"[ ]"</c> cannot reintroduce it.
    /// </para>
    /// <para>
    /// TRADE-OFF, deliberate: a child cannot express "explicitly none" while its parent declares
    /// some. That is the safer reading — <c>ValidateJsonArraySubset</c> already treats an empty
    /// child as trivially valid, so the alternative lets a profile silently drop to no-usages while
    /// passing every check. An explicit clear should be a distinct marker, not an empty array that
    /// is indistinguishable from an unset field.
    /// </para>
    /// </summary>
    private static string MergeJsonArray(string child, string parent, string fieldName, Dictionary<string, string> sources)
    {
        // Empty child array means "inherit all from parent" (permissive inheritance).
        // Non-empty child array intersects with parent array (restrictive inheritance).
        if (!IsEmptyJsonArray(child))
        {
            sources[fieldName] = "overridden";
            return child;
        }
        sources[fieldName] = "inherited";
        return parent;
    }

    /// <summary>
    /// True when <paramref name="value"/> carries no entries: null, whitespace, or a JSON array with
    /// zero elements. Malformed JSON counts as NON-empty so a corrupt value surfaces downstream
    /// rather than being silently replaced by the parent's list.
    /// </summary>
    private static bool IsEmptyJsonArray(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        try
        {
            var parsed = JsonSerializer.Deserialize<List<string>>(value);
            return parsed is null || parsed.Count == 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Merges a JSON object field. Treats "{}" or null/empty as "not set" (inherit from parent).
    /// Any non-empty object in the child is treated as an override.
    /// </summary>
    private static string MergeJsonObject(string child, string parent, string fieldName, Dictionary<string, string> sources)
    {
        if (!string.IsNullOrEmpty(child) && child != "{}")
        {
            sources[fieldName] = "overridden";
            return child;
        }
        sources[fieldName] = "inherited";
        return parent;
    }

    // ── Validation helpers ───────────────────────────────────────────────

    /// <summary>
    /// Validates that the child's maximum duration does not exceed the parent's maximum duration.
    /// Uses <see cref="XmlConvert.ToTimeSpan"/> to parse ISO 8601 duration strings.
    /// </summary>
    private static void ValidateMaxDuration(string? childValue, string? parentValue, string fieldName, List<string> errors)
    {
        if (string.IsNullOrEmpty(childValue) || string.IsNullOrEmpty(parentValue))
            return; // No constraint to validate

        try
        {
            var childSpan = XmlConvert.ToTimeSpan(childValue);
            var parentSpan = XmlConvert.ToTimeSpan(parentValue);

            if (childSpan > parentSpan)
            {
                errors.Add(
                    $"{fieldName}: child value '{childValue}' ({childSpan.TotalDays:F0}d) " +
                    $"exceeds parent '{parentValue}' ({parentSpan.TotalDays:F0}d).");
            }
        }
        catch (FormatException)
        {
            errors.Add($"{fieldName}: unable to parse duration values (child='{childValue}', parent='{parentValue}').");
        }
    }

    /// <summary>
    /// Validates that the child's minimum duration is not shorter than the parent's minimum duration.
    /// A shorter minimum would weaken the parent's constraint, allowing certificates with
    /// validity periods below what the parent policy intended.
    /// Uses <see cref="XmlConvert.ToTimeSpan"/> to parse ISO 8601 duration strings.
    /// </summary>
    private static void ValidateMinDuration(string? childValue, string? parentValue, string fieldName, List<string> errors)
    {
        if (string.IsNullOrEmpty(childValue) || string.IsNullOrEmpty(parentValue))
            return; // No constraint to validate

        try
        {
            var childSpan = XmlConvert.ToTimeSpan(childValue);
            var parentSpan = XmlConvert.ToTimeSpan(parentValue);

            if (childSpan < parentSpan)
            {
                errors.Add(
                    $"{fieldName}: child value '{childValue}' ({childSpan.TotalDays:F0}d) " +
                    $"is shorter than parent '{parentValue}' ({parentSpan.TotalDays:F0}d).");
            }
        }
        catch (FormatException)
        {
            errors.Add($"{fieldName}: unable to parse duration values (child='{childValue}', parent='{parentValue}').");
        }
    }

    /// <summary>
    /// Validates that the child's JSON array values are a subset of the parent's values.
    /// Empty child arrays are treated as "inherit all" and pass validation.
    /// Empty parent arrays are treated as "no restriction" so any child value is allowed.
    /// </summary>
    private static void ValidateJsonArraySubset(string childJson, string parentJson, string fieldName, List<string> errors)
    {
        if (string.IsNullOrEmpty(childJson) || childJson == "[]")
            return; // Child inherits, no override to validate

        if (string.IsNullOrEmpty(parentJson) || parentJson == "[]")
            return; // Parent has no restriction, child can set anything

        try
        {
            var childItems = JsonSerializer.Deserialize<List<string>>(childJson) ?? new List<string>();
            var parentItems = JsonSerializer.Deserialize<List<string>>(parentJson) ?? new List<string>();

            var parentSet = new HashSet<string>(parentItems, StringComparer.OrdinalIgnoreCase);
            var violations = childItems.Where(item => !parentSet.Contains(item)).ToList();

            if (violations.Count > 0)
            {
                errors.Add(
                    $"{fieldName}: child contains values not in parent: [{string.Join(", ", violations)}]. " +
                    $"Parent allows: [{string.Join(", ", parentItems)}].");
            }
        }
        catch (JsonException)
        {
            errors.Add($"{fieldName}: unable to parse JSON array values for subset comparison.");
        }
    }

    // ── CLM-002: Merge-time clamping helpers ────────────────────────────────

    /// <summary>
    /// CLM-002: Clamps a maximum duration so that the merged value does not exceed
    /// the parent's maximum. If the merged value is longer than the parent allows,
    /// the parent value is used and a warning is logged.
    /// </summary>
    private string? ClampMaxDuration(string? mergedValue, string? parentValue, string fieldName, Guid childId, Guid parentId)
    {
        if (string.IsNullOrEmpty(mergedValue) || string.IsNullOrEmpty(parentValue))
            return mergedValue;

        try
        {
            var mergedSpan = XmlConvert.ToTimeSpan(mergedValue);
            var parentSpan = XmlConvert.ToTimeSpan(parentValue);

            if (mergedSpan > parentSpan)
            {
                _logger.LogWarning(
                    "CLM-002: Profile '{ChildId}' {Field} '{MergedVal}' exceeds parent '{ParentId}' limit '{ParentVal}'. Clamping to parent value.",
                    childId, fieldName, mergedValue, parentId, parentValue);
                return parentValue;
            }
        }
        catch (FormatException)
        {
            _logger.LogWarning(
                "CLM-002: Unable to parse {Field} durations for profile '{ChildId}' (merged='{MergedVal}', parent='{ParentVal}'). Keeping merged value.",
                fieldName, childId, mergedValue, parentValue);
        }

        return mergedValue;
    }

    /// <summary>
    /// CLM-002: Clamps a minimum duration so that the merged value is not shorter
    /// than the parent's minimum. If the merged value is shorter than the parent requires,
    /// the parent value is used and a warning is logged.
    /// </summary>
    private string? ClampMinDuration(string? mergedValue, string? parentValue, string fieldName, Guid childId, Guid parentId)
    {
        if (string.IsNullOrEmpty(mergedValue) || string.IsNullOrEmpty(parentValue))
            return mergedValue;

        try
        {
            var mergedSpan = XmlConvert.ToTimeSpan(mergedValue);
            var parentSpan = XmlConvert.ToTimeSpan(parentValue);

            if (mergedSpan < parentSpan)
            {
                _logger.LogWarning(
                    "CLM-002: Profile '{ChildId}' {Field} '{MergedVal}' is shorter than parent '{ParentId}' minimum '{ParentVal}'. Clamping to parent value.",
                    childId, fieldName, mergedValue, parentId, parentValue);
                return parentValue;
            }
        }
        catch (FormatException)
        {
            _logger.LogWarning(
                "CLM-002: Unable to parse {Field} durations for profile '{ChildId}' (merged='{MergedVal}', parent='{ParentVal}'). Keeping merged value.",
                fieldName, childId, mergedValue, parentValue);
        }

        return mergedValue;
    }

    /// <summary>
    /// CLM-002: Clamps a JSON array so that the merged value is a subset of the parent's
    /// allowed values. Any items in the merged set that are not in the parent set are
    /// removed and a warning is logged.
    /// </summary>
    private string ClampJsonArraySubset(string mergedJson, string parentJson, string fieldName, Guid childId, Guid parentId)
    {
        if (string.IsNullOrEmpty(mergedJson) || mergedJson == "[]")
            return mergedJson;

        if (string.IsNullOrEmpty(parentJson) || parentJson == "[]")
            return mergedJson; // Parent has no restriction

        try
        {
            var mergedItems = JsonSerializer.Deserialize<List<string>>(mergedJson) ?? new List<string>();
            var parentItems = JsonSerializer.Deserialize<List<string>>(parentJson) ?? new List<string>();

            var parentSet = new HashSet<string>(parentItems, StringComparer.OrdinalIgnoreCase);
            var violations = mergedItems.Where(item => !parentSet.Contains(item)).ToList();

            if (violations.Count > 0)
            {
                _logger.LogWarning(
                    "CLM-002: Profile '{ChildId}' {Field} contains values not allowed by parent '{ParentId}': [{Violations}]. Removing non-subset items.",
                    childId, fieldName, parentId, string.Join(", ", violations));

                var clamped = mergedItems.Where(item => parentSet.Contains(item)).ToList();
                return JsonSerializer.Serialize(clamped);
            }
        }
        catch (JsonException)
        {
            _logger.LogWarning(
                "CLM-002: Unable to parse {Field} JSON arrays for profile '{ChildId}'. Keeping merged value.",
                fieldName, childId);
        }

        return mergedJson;
    }
}
