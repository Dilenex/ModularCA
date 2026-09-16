namespace ModularCA.Core;

/// <summary>
/// The <c>sort</c> query parameter of the paged list endpoints: <c>field</c> ascending or
/// <c>-field</c> descending. Each endpoint names the fields it accepts; anything else falls
/// back to the endpoint's default order rather than erroring, so a stale link still lists.
/// </summary>
public static class ListSort
{
    /// <summary>Parses <c>-field</c> / <c>field</c>. Null when empty or the field is not one of <paramref name="allowed"/>.</summary>
    public static (string Field, bool Descending)? Parse(string? raw, params string[] allowed)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        var desc = s.StartsWith('-');
        var field = desc ? s[1..] : s;
        var match = allowed.FirstOrDefault(a => string.Equals(a, field, StringComparison.OrdinalIgnoreCase));
        return match == null ? null : (match, desc);
    }
}
