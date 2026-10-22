using System.Text.Json;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// How a request profile that inherits combines its name rules with its parent's: never looser
/// than the parent. A child with no rules of a kind takes the parent's; one with rules is merged
/// with them, field by field and type by type, keeping the stricter of each.
/// </summary>
internal static class RequestProfileInheritance
{
    /// <summary>
    /// The subject DN rules of a child and its parent combined. For a field both name: the
    /// stricter requirement (Optional, then Required, then Forbidden), the parent's fixed value
    /// and pattern where it has one, the shorter maximum length, and the child's default where it
    /// has one. A field only one of them names keeps that rule.
    /// </summary>
    /// <param name="child">The child's rules, a JSON array.</param>
    /// <param name="parent">The parent's rules, a JSON array.</param>
    internal static string MergeSubjectRules(string? child, string? parent)
    {
        var childRules = ReadSubjectRules(child);
        var parentRules = ReadSubjectRules(parent);
        if (childRules.Count == 0)
            return string.IsNullOrWhiteSpace(parent) ? "[]" : parent;
        if (parentRules.Count == 0)
            return child!;

        var merged = new List<SubjectDnFieldRule>();
        foreach (var p in parentRules)
        {
            var c = childRules.FirstOrDefault(r => Field(r.Field) == Field(p.Field));
            if (c == null)
            {
                merged.Add(p);
                continue;
            }
            merged.Add(new SubjectDnFieldRule
            {
                Field = p.Field,
                Requirement = Rank(c.Requirement) > Rank(p.Requirement) ? c.Requirement : p.Requirement,
                FixedValue = string.IsNullOrEmpty(p.FixedValue) ? c.FixedValue : p.FixedValue,
                Regex = string.IsNullOrEmpty(p.Regex) ? c.Regex : p.Regex,
                MaxLength = p.MaxLength is int pl && c.MaxLength is int cl ? Math.Min(pl, cl) : p.MaxLength ?? c.MaxLength,
                DefaultValue = string.IsNullOrEmpty(c.DefaultValue) ? p.DefaultValue : c.DefaultValue,
            });
        }
        merged.AddRange(childRules.Where(c => !parentRules.Any(p => Field(p.Field) == Field(c.Field))));
        return JsonSerializer.Serialize(merged);
    }

    /// <summary>
    /// The SAN rules of a child and its parent combined: the types both allow, required when
    /// either requires a SAN, and for each type the parent's pattern where it has one and the
    /// lower maximum count. A child with no SAN rules takes the parent's.
    /// </summary>
    /// <param name="child">The child's rules, a JSON object.</param>
    /// <param name="parent">The parent's rules, a JSON object.</param>
    internal static string MergeSanRules(string? child, string? parent)
    {
        if (IsEmptyObject(child))
            return IsEmptyObject(parent) ? "{}" : parent!;
        if (IsEmptyObject(parent))
            return child!;
        var c = RequestProfileValidationService.ReadSanRules(child);
        var p = RequestProfileValidationService.ReadSanRules(parent);
        if (c == null)
            return parent!;
        if (p == null)
            return child!;

        var allowed = p.AllowedTypes
            .Where(t => c.AllowedTypes.Any(ct => SanType(ct) == SanType(t)))
            .ToList();
        var rules = new Dictionary<string, SanTypeRule>();
        foreach (var type in allowed)
        {
            var hasParent = RequestProfileRules.TryGetSanRule(p, type, out var pr);
            var hasChild = RequestProfileRules.TryGetSanRule(c, type, out var cr);
            if (hasParent && hasChild)
                rules[type] = new SanTypeRule { Regex = string.IsNullOrEmpty(pr.Regex) ? cr.Regex : pr.Regex, MaxCount = Math.Min(pr.MaxCount, cr.MaxCount) };
            else if (hasParent)
                rules[type] = pr;
            else if (hasChild)
                rules[type] = cr;
        }
        return JsonSerializer.Serialize(new SanRules { AllowedTypes = allowed, Required = p.Required || c.Required, Rules = rules });
    }

    private static List<SubjectDnFieldRule> ReadSubjectRules(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];
        try
        {
            return JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(json, SafeJsonOptions.Stored)?.Where(r => r != null).ToList() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static bool IsEmptyObject(string? json) => string.IsNullOrWhiteSpace(json) || json.Trim() == "{}";

    private static int Rank(string? requirement)
        => RequestProfileRules.IsForbidden(requirement) ? 2 : RequestProfileRules.IsRequired(requirement) ? 1 : 0;

    private static string Field(string? field)
    {
        var upper = (field ?? string.Empty).Trim().ToUpperInvariant();
        return upper is "EMAILADDRESS" or "EMAIL" ? "E" : upper;
    }

    private static string SanType(string? type) => RequestProfileRules.CanonicalSanType(type) ?? (type ?? string.Empty).Trim().ToUpperInvariant();
}
