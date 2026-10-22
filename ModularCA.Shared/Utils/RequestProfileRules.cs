using ModularCA.Shared.Models.RequestProfiles;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The vocabulary of a request profile's rules (<see cref="SubjectDnFieldRule"/> and
/// <see cref="SanRules"/>) and the one place it is checked: at save, by
/// <see cref="Normalize"/>, and at enforcement, by the comparisons here, which ignore case.
/// </summary>
/// <remarks>
/// Rules used to be stored as typed and compared with <c>==</c>, so a rule saved as
/// <c>"required"</c> enforced nothing, a per-type SAN rule keyed <c>"Email"</c> was never found for
/// an <c>EMAIL:</c> name, and a misspelled field or SAN type was kept without a word. The console
/// spells these as <c>modularca.adminui/src/components/requestProfileRules.ts</c> does.
/// </remarks>
public static class RequestProfileRules
{
    /// <summary>The field must be present (or supplied by a fixed or default value).</summary>
    public const string Required = "Required";

    /// <summary>The field may be present.</summary>
    public const string Optional = "Optional";

    /// <summary>The field must not be present.</summary>
    public const string Forbidden = "Forbidden";

    /// <summary>The requirement values, in their stored spelling.</summary>
    public static readonly IReadOnlyList<string> Requirements = [Required, Optional, Forbidden];

    /// <summary>
    /// The subject DN fields a rule may name, as the subject parser keys them (upper case): those
    /// issuance accepts in a subject (<c>E</c> is emailAddress).
    /// </summary>
    public static readonly IReadOnlyList<string> SubjectFields = ["CN", "O", "OU", "L", "ST", "C", "DC", "E", "SERIALNUMBER", "UID", "T", "STREET"];

    /// <summary>The SAN types a profile may allow or carry a rule for, in their stored spelling.</summary>
    public static readonly IReadOnlyList<string> SanTypes = ["DNS", "IP", "Email", "URI", "UPN"];

    /// <summary>Whether <paramref name="requirement"/> is Required, in any case.</summary>
    public static bool IsRequired(string? requirement) => string.Equals(requirement?.Trim(), Required, StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether <paramref name="requirement"/> is Forbidden, in any case.</summary>
    public static bool IsForbidden(string? requirement) => string.Equals(requirement?.Trim(), Forbidden, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The per-type rule <paramref name="rules"/> holds for SAN type <paramref name="sanType"/>,
    /// matching the type in any case and reading EMAIL and RFC822 as Email.
    /// </summary>
    public static bool TryGetSanRule(SanRules? rules, string sanType, out SanTypeRule rule)
    {
        rule = null!;
        if (rules?.Rules == null)
            return false;
        var wanted = CanonicalSanType(sanType) ?? sanType;
        foreach (var (type, candidate) in rules.Rules)
        {
            if (candidate != null && string.Equals(CanonicalSanType(type) ?? type, wanted, StringComparison.OrdinalIgnoreCase))
            {
                rule = candidate;
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Checks a profile's rules and rewrites them in their stored spelling: requirements as
    /// Required, Optional or Forbidden, fields upper case (emailAddress as E), SAN types as
    /// <see cref="SanTypes"/> spells them. Returns why the rules cannot be saved, naming the bad
    /// value and listing the allowed ones, or null when they can. Nothing is rewritten when an
    /// error is returned.
    /// </summary>
    public static string? Normalize(List<SubjectDnFieldRule>? subjectDnRules, SanRules? sanRules)
    {
        var requirements = new List<string>();
        var fields = new List<string>();
        foreach (var (rule, index) in (subjectDnRules ?? []).Select((r, i) => (r, i)))
        {
            if (rule == null)
                return $"subjectDnRules[{index}] is empty.";
            var requirement = Requirements.FirstOrDefault(r => string.Equals(r, rule.Requirement?.Trim(), StringComparison.OrdinalIgnoreCase));
            if (requirement == null)
                return $"subjectDnRules[{index}] ({rule.Field}): requirement '{rule.Requirement}' is not one of {string.Join(", ", Requirements)}.";
            var field = CanonicalField(rule.Field);
            if (field == null)
                return $"subjectDnRules[{index}]: field '{rule.Field}' is not one of {string.Join(", ", SubjectFields)}.";
            if (rule.MaxLength is < 0)
                return $"subjectDnRules[{index}] ({field}): maxLength must not be negative.";
            requirements.Add(requirement);
            fields.Add(field);
        }

        var allowedTypes = new List<string>();
        Dictionary<string, SanTypeRule>? typeRules = null;
        if (sanRules != null)
        {
            foreach (var type in sanRules.AllowedTypes ?? [])
            {
                var canonical = CanonicalSanType(type);
                if (canonical == null)
                    return $"sanRules.allowedTypes: '{type}' is not one of {string.Join(", ", SanTypes)}.";
                if (!allowedTypes.Contains(canonical))
                    allowedTypes.Add(canonical);
            }
            typeRules = new Dictionary<string, SanTypeRule>(StringComparer.Ordinal);
            foreach (var (type, rule) in sanRules.Rules ?? [])
            {
                var canonical = CanonicalSanType(type);
                if (canonical == null)
                    return $"sanRules.rules: '{type}' is not one of {string.Join(", ", SanTypes)}.";
                if (rule == null)
                    return $"sanRules.rules.{type} is empty.";
                if (rule.MaxCount < 0)
                    return $"sanRules.rules.{type}: maxCount must not be negative.";
                if (!typeRules.TryAdd(canonical, rule))
                    return $"sanRules.rules names {canonical} more than once.";
            }
        }

        foreach (var (rule, index) in (subjectDnRules ?? []).Select((r, i) => (r, i)))
        {
            rule.Requirement = requirements[index];
            rule.Field = fields[index];
        }
        if (sanRules != null)
        {
            sanRules.AllowedTypes = allowedTypes;
            sanRules.Rules = typeRules!;
        }
        return null;
    }

    /// <summary><paramref name="field"/> as the subject parser keys it, or null when it is not one of <see cref="SubjectFields"/>.</summary>
    private static string? CanonicalField(string? field)
    {
        var upper = field?.Trim().ToUpperInvariant();
        if (upper is "EMAILADDRESS")
            return "E";
        return upper != null && SubjectFields.Contains(upper) ? upper : null;
    }

    /// <summary><paramref name="type"/> in its stored spelling (RFC822 as Email), or null when it is not one of <see cref="SanTypes"/>.</summary>
    public static string? CanonicalSanType(string? type)
    {
        var trimmed = type?.Trim();
        if (string.Equals(trimmed, "RFC822", StringComparison.OrdinalIgnoreCase))
            return "Email";
        return SanTypes.FirstOrDefault(t => string.Equals(t, trimmed, StringComparison.OrdinalIgnoreCase));
    }
}
