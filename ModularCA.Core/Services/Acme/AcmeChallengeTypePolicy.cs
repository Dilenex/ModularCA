namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Reads the per-CA <c>AcmeAllowedChallengeTypes</c> setting into the challenge types an
/// authorization may offer.
/// </summary>
/// <remarks>
/// The setting was stored and shown in the admin UI and read by nothing, so an operator who
/// restricted a CA to <c>dns-01</c> still saw <c>http-01</c> offered. The column is free text
/// with a 255-character limit; both the JSON-array form the UI may send and a plain
/// comma-separated list are accepted, so a value typed by hand works the same as one saved by
/// the form.
/// </remarks>
public static class AcmeChallengeTypePolicy
{
    private static readonly HashSet<string> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        "http-01", "dns-01", "tls-alpn-01",
    };

    /// <summary>
    /// Parses the stored value.
    /// </summary>
    /// <returns>
    /// The allowed types in canonical lower-case form, or null when the setting is empty, which
    /// means no restriction. Unknown names are dropped rather than treated as a restriction to
    /// nothing, so a typo does not silently disable enrollment.
    /// </returns>
    public static IReadOnlyCollection<string>? Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var cleaned = raw.Trim().Trim('[', ']');
        var types = cleaned
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => s.Trim('"', '\'', ' ').ToLowerInvariant())
            .Where(Known.Contains)
            .Distinct()
            .ToList();

        return types.Count == 0 ? null : types;
    }

    /// <summary>
    /// Filters offered challenges to the allowed types. A null policy leaves the offer unchanged.
    /// </summary>
    public static IEnumerable<T> Filter<T>(IEnumerable<T> challenges, IReadOnlyCollection<string>? allowed, Func<T, string> typeOf)
    {
        if (allowed == null || allowed.Count == 0)
            return challenges;
        return challenges.Where(c => allowed.Contains(typeOf(c), StringComparer.OrdinalIgnoreCase));
    }
}
