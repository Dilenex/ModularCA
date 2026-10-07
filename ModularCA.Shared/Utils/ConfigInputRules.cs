using System.Net.Mail;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Save-time checks for list-valued settings written through PUT /admin/config/*. Each method
/// returns null when the value is acceptable, otherwise a message for a 400 response.
/// </summary>
public static class ConfigInputRules
{
    /// <summary>Largest expiry warning mark accepted, in days (ten years).</summary>
    public const int MaxWarningDays = 3650;

    /// <summary>
    /// Validates the expiry-notification day marks: each from 1 to <see cref="MaxWarningDays"/>.
    /// Zero or a negative mark would match certificates that have already expired or never fire.
    /// Null means "not supplied".
    /// </summary>
    /// <param name="days">The marks from the request body.</param>
    public static string? WarningDaysError(IEnumerable<int>? days)
    {
        if (days == null) return null;
        var bad = days.Where(d => d < 1 || d > MaxWarningDays).ToList();
        return bad.Count == 0
            ? null
            : $"WarningDays must each be from 1 to {MaxWarningDays}; got {string.Join(", ", bad)}.";
    }

    /// <summary>
    /// Validates a comma-separated recipient list as the mail senders split it (comma, entries
    /// trimmed, blanks dropped): every entry must parse as a mail address. Null or empty means no
    /// recipients and is accepted.
    /// </summary>
    /// <param name="csv">The recipients string from the request body.</param>
    /// <param name="field">The field name used in the message.</param>
    public static string? EmailListError(string? csv, string field)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        var bad = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(e => !MailAddress.TryCreate(e, out _))
            .ToList();
        return bad.Count == 0 ? null : $"{field} contains invalid email addresses: {string.Join(", ", bad)}.";
    }

    /// <summary>
    /// Validates one CORS origin. Rejects the wildcard, anything that is not an absolute URL, and
    /// plain http except for localhost, 127.0.0.1 and ::1 — the rules startup enforces, where a
    /// violation stops the server from starting. With <paramref name="requireBareOrigin"/>, also
    /// rejects a path, query, fragment or trailing slash: origins are compared as strings and the
    /// browser's Origin header never carries one, so such an entry would never match.
    /// </summary>
    /// <param name="origin">One trimmed origin.</param>
    /// <param name="requireBareOrigin">True at save time; false at startup, so an existing config still loads.</param>
    public static string? CorsOriginError(string origin, bool requireBareOrigin)
    {
        if (origin == "*")
            return "Wildcard origin '*' is not allowed. Specify exact origins in Http.CorsOrigins.";
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            return $"Invalid origin '{origin}' in Http.CorsOrigins — must be an absolute URL.";
        var isLocal = string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                      || uri.Host == "127.0.0.1" || uri.Host == "::1" || uri.Host == "[::1]";
        if (!isLocal && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return $"Non-local origin '{origin}' must use https:// in Http.CorsOrigins.";
        if (requireBareOrigin)
        {
            if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                return $"Origin '{origin}' must use https://.";
            var schemeEnd = origin.IndexOf("://", StringComparison.Ordinal) + 3;
            if (origin.IndexOfAny(new[] { '/', '?', '#' }, schemeEnd) >= 0)
                return $"Origin '{origin}' must be scheme, host and optional port only, with no path or trailing '/'.";
            if (!string.IsNullOrEmpty(uri.UserInfo))
                return $"Origin '{origin}' must not carry a user name or password.";
        }
        return null;
    }

    private static readonly System.Text.RegularExpressions.Regex SunsetDate =
        new(@"^\d{4}-\d{2}-\d{2}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// Validates one algorithm sunset rule, <c>ALG:YYYY-MM-DD</c>, as the console writes it and
    /// CertPolicyService reads it (split at the last colon). ALG is what the rule is compared with,
    /// case-insensitively: the key algorithm and size joined by a hyphen (<c>RSA-2048</c>,
    /// <c>ECDSA-P-256</c>), the key algorithm alone (<c>RSA</c>, <c>Ed25519</c>,
    /// <c>ML-DSA-65</c>), or the signature algorithm (<c>SHA1withRSA</c>); it may not be blank or
    /// hold spaces or a colon. The date must be a real calendar date written YYYY-MM-DD.
    /// CertPolicyService skips a rule it cannot read with only a log line, so the check is made here.
    /// </summary>
    /// <param name="rule">One rule from <c>CertPolicy.AlgorithmSunsetRules</c>.</param>
    public static string? AlgorithmSunsetRuleError(string? rule)
    {
        if (string.IsNullOrWhiteSpace(rule)) return "An algorithm sunset rule is empty.";
        var colon = rule.LastIndexOf(':');
        if (colon <= 0 || colon >= rule.Length - 1)
            return $"Sunset rule '{rule}' must be ALGORITHM:YYYY-MM-DD, e.g. RSA-2048:2030-01-01.";
        var alg = rule[..colon].Trim();
        var date = rule[(colon + 1)..].Trim();
        if (alg.Length == 0 || alg.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c == ':'))
            return $"Sunset rule '{rule}': the algorithm must be one word such as RSA-2048, ECDSA-P-256 or SHA1withRSA, with no spaces or colons.";
        if (!SunsetDate.IsMatch(date)
            || !DateTime.TryParseExact(date, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out _))
            return $"Sunset rule '{rule}': '{date}' is not a date written YYYY-MM-DD.";
        return null;
    }

    /// <summary>
    /// Validates every algorithm sunset rule (<see cref="AlgorithmSunsetRuleError"/>). Returns the
    /// first problem, or null when all pass or the list is null (not supplied).
    /// </summary>
    /// <param name="rules">The rules from the request body.</param>
    public static string? AlgorithmSunsetRulesError(IEnumerable<string?>? rules)
    {
        if (rules == null) return null;
        foreach (var rule in rules)
        {
            if (AlgorithmSunsetRuleError(rule) is { } error)
                return error;
        }
        return null;
    }

    /// <summary>
    /// Validates a comma-separated CORS origin list, split as startup splits it. Returns the first
    /// problem, or null when every origin passes <see cref="CorsOriginError"/>.
    /// </summary>
    /// <param name="csv">The Http.CorsOrigins value.</param>
    /// <param name="requireBareOrigin">See <see cref="CorsOriginError"/>.</param>
    public static string? CorsOriginsError(string? csv, bool requireBareOrigin)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        foreach (var origin in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (CorsOriginError(origin, requireBareOrigin) is { } error)
                return error;
        }
        return null;
    }

    /// <summary>
    /// The origins a CORS origin list allows, split as startup splits it. None when the list is
    /// blank, or when any entry breaks the startup rules (<see cref="CorsOriginsError"/> without
    /// the bare-origin check): a list that would have stopped a start allows nothing.
    /// </summary>
    /// <param name="csv">The Http.CorsOrigins value.</param>
    public static string[] CorsOriginsAllowed(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv) || CorsOriginsError(csv, requireBareOrigin: false) != null)
            return [];
        return csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
