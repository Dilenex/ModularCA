using System.Text.RegularExpressions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Decides whether a CSR's subject and SANs satisfy an enrollment token's name restrictions.
/// <para>
/// These restrictions are the only thing binding a public enrollment token to a set of names.
/// The endpoint that consumes them (<c>PublicEnrollmentController.SubmitEnrollment</c>) is
/// anonymous — possession of the token is the entire authorization — so a restriction that does
/// not hold is the difference between "this token can enroll one host in example.com" and "this
/// token can enroll anything".
/// </para>
/// <para>
/// Before this type existed, <c>SANRestriction</c> was accepted by the admin API, persisted, and
/// echoed back on the public token-info endpoint, but no code path ever read it — a control that
/// looked configured and did nothing. <c>SubjectRestriction</c> was enforced, but with two holes:
/// it was skipped entirely when the CSR carried an empty subject (routine for a SAN-only TLS
/// certificate), and it was a raw substring test against the whole DN string, so a restriction of
/// <c>example.com</c> was satisfied by <c>CN=evil-example.com.attacker.net</c>.
/// </para>
/// <para><b>Semantics.</b> A restriction is a comma- or whitespace-separated list of patterns,
/// and a name need match only one of them:</para>
/// <list type="bullet">
/// <item>
/// A pattern containing <c>=</c> is a DN component, e.g. <c>O=Acme</c>. It matches when the
/// subject carries that exact attribute value, compared on RDN boundaries rather than as a
/// substring — so <c>O=Acme</c> does not match <c>O=Acme Evil Corp</c>.
/// </item>
/// <item>
/// Any other pattern is a DNS name, e.g. <c>example.com</c> (the form the admin UI's placeholder
/// suggests). It matches a name that equals it, or that is a subdomain of it. Suffix matching is
/// on label boundaries: <c>example.com</c> matches <c>a.example.com</c> and not
/// <c>notexample.com</c>.
/// </item>
/// </list>
/// <para><b>Fail-closed rules.</b> Every case where the answer is not clearly "permitted" is
/// treated as a violation: a restriction with nothing to evaluate it against, a DNS pattern with
/// no CN to test, and a SAN of a type a DNS pattern cannot speak about (IP, email, URI). A
/// name-binding control that abstains is a name-binding control that is off.</para>
/// </summary>
public static class EnrollmentNameRestriction
{
    private static readonly char[] PatternSeparators = [',', ';', ' ', '\t', '\r', '\n'];

    // CN=..., tolerating whitespace and quoted values, up to the next unescaped comma.
    private static readonly Regex CommonNamePattern = new(
        @"(?:^|,)\s*CN\s*=\s*(?<cn>(?:[^,\\]|\\.)*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    /// <summary>Splits a restriction string into its individual patterns. Empty when unset.</summary>
    public static IReadOnlyList<string> ParsePatterns(string? restriction)
    {
        if (string.IsNullOrWhiteSpace(restriction)) return [];
        return restriction
            .Split(PatternSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
    }

    /// <summary>
    /// True when <paramref name="subject"/> satisfies <paramref name="restriction"/>. An unset
    /// restriction permits everything; a set restriction against an empty subject does not.
    /// </summary>
    /// <param name="subject">Subject DN string as parsed from the CSR.</param>
    /// <param name="restriction">The token's <c>SubjectRestriction</c>, or null.</param>
    /// <param name="failure">Why the subject was rejected, for the operator-facing error.</param>
    public static bool SubjectSatisfies(string? subject, string? restriction, out string failure)
    {
        var patterns = ParsePatterns(restriction);
        if (patterns.Count == 0)
        {
            failure = string.Empty;
            return true;
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            // Previously this returned "permitted". A CSR with no subject is normal for a
            // SAN-only certificate, which made an empty subject the simplest way to ignore the
            // restriction entirely.
            failure = "the CSR has no subject to match against the token's subject restriction";
            return false;
        }

        // EVERY Common Name in the subject must be permitted, not just the first one.
        //
        // A DN may carry more than one CN RDN, and the issued certificate carries all of them:
        // CertificateBuilderService.ResolveSubjectDn returns the CSR's subject verbatim. This
        // used to test only the leftmost CN, so a CSR with
        // `CN=host.example.com,CN=evil.attacker.net` satisfied a restriction of `example.com`
        // and was issued with both names. Worse on the request-profile path, where the subject
        // is rebuilt from a dictionary and the LAST CN wins — so the name that actually reached
        // the certificate was the one never checked.
        var commonNames = ExtractCommonNames(subject);

        // DN-component patterns ("O=Acme") are asserted against the whole subject, unchanged.
        foreach (var pattern in patterns.Where(IsDnComponent))
        {
            if (SubjectHasDnComponent(subject, pattern))
            {
                failure = string.Empty;
                return true;
            }
        }

        var dnsPatterns = patterns.Where(p => !IsDnComponent(p)).ToList();
        if (dnsPatterns.Count > 0 && commonNames.Count > 0)
        {
            var unpermitted = commonNames
                .Where(cn => !dnsPatterns.Any(p => DnsNameMatches(cn, p)))
                .ToList();

            if (unpermitted.Count == 0)
            {
                failure = string.Empty;
                return true;
            }

            failure = $"the CSR subject Common Name(s) {string.Join(", ", unpermitted.Select(n => $"'{n}'"))} "
                    + $"do not match the token restriction '{restriction}'";
            return false;
        }

        failure = commonNames.Count == 0 && dnsPatterns.Count > 0
            ? "the CSR subject has no Common Name to match against the token's subject restriction"
            : $"the CSR subject does not match the token restriction '{restriction}'";
        return false;
    }

    /// <summary>
    /// True when EVERY entry in <paramref name="sans"/> satisfies <paramref name="restriction"/>.
    /// An unset restriction permits everything; an empty SAN list trivially satisfies any
    /// restriction, since a restriction bounds which names may appear rather than requiring any.
    /// </summary>
    /// <param name="sans">
    /// SAN entries in the <c>TYPE:value</c> form produced by <c>CertificateUtil.ParseCsr</c> —
    /// <c>DNS:</c>, <c>IP:</c>, <c>Email:</c>, or <c>Other:</c>.
    /// </param>
    /// <param name="restriction">The token's <c>SANRestriction</c>, or null.</param>
    /// <param name="failure">Which SAN was rejected and why.</param>
    public static bool SansSatisfy(IEnumerable<string>? sans, string? restriction, out string failure)
    {
        var patterns = ParsePatterns(restriction);
        if (patterns.Count == 0)
        {
            failure = string.Empty;
            return true;
        }

        // DN component patterns say nothing about a SAN. If the operator supplied only those,
        // there is no rule a SAN can satisfy — refuse rather than silently permit all of them.
        var dnsPatterns = patterns.Where(p => !IsDnComponent(p)).ToList();

        foreach (var entry in sans ?? [])
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;

            var separator = entry.IndexOf(':');
            var type = separator > 0 ? entry[..separator] : "DNS";
            var value = separator > 0 ? entry[(separator + 1)..] : entry;

            if (!type.Equals("DNS", StringComparison.OrdinalIgnoreCase))
            {
                // An IP, email or URI SAN cannot be evaluated against a DNS-name restriction.
                // Permitting it would let a token restricted to example.com issue for
                // IP:10.0.0.1 or an arbitrary email identity.
                failure = $"SAN '{entry}' is not a DNS name and cannot satisfy the token's SAN restriction '{restriction}'";
                return false;
            }

            if (!dnsPatterns.Any(p => DnsNameMatches(value, p)))
            {
                failure = $"SAN '{value}' does not match the token restriction '{restriction}'";
                return false;
            }
        }

        failure = string.Empty;
        return true;
    }

    /// <summary>A pattern is a DN component when it carries an <c>=</c>, as in <c>O=Acme</c>.</summary>
    private static bool IsDnComponent(string pattern) => pattern.Contains('=');

    /// <summary>
    /// Matches a DN component on RDN boundaries. Splitting on unescaped commas keeps
    /// <c>O=Acme</c> from matching <c>O=Acme Evil Corp</c>, which a substring test would accept.
    /// </summary>
    private static bool SubjectHasDnComponent(string subject, string pattern)
    {
        var wanted = pattern.Replace(" ", string.Empty);
        foreach (var rdn in SplitRdns(subject))
        {
            if (rdn.Replace(" ", string.Empty).Equals(wanted, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Splits a DN on commas that are not backslash-escaped.</summary>
    private static IEnumerable<string> SplitRdns(string subject)
    {
        var start = 0;
        for (var i = 0; i < subject.Length; i++)
        {
            if (subject[i] == '\\') { i++; continue; }
            if (subject[i] != ',') continue;
            yield return subject[start..i];
            start = i + 1;
        }
        if (start < subject.Length) yield return subject[start..];
    }

    /// <summary>
    /// Exact or subdomain match, case-insensitive, on label boundaries. A leading <c>*.</c> on
    /// the candidate is stripped first so a wildcard request is judged by the domain it covers.
    /// </summary>
    private static bool DnsNameMatches(string name, string pattern)
    {
        var candidate = name.Trim().TrimEnd('.');
        if (candidate.StartsWith("*.", StringComparison.Ordinal)) candidate = candidate[2..];
        var wanted = pattern.Trim().TrimEnd('.').TrimStart('.');

        if (candidate.Length == 0 || wanted.Length == 0) return false;
        if (candidate.Equals(wanted, StringComparison.OrdinalIgnoreCase)) return true;

        return candidate.Length > wanted.Length
            && candidate.EndsWith(wanted, StringComparison.OrdinalIgnoreCase)
            && candidate[candidate.Length - wanted.Length - 1] == '.';
    }

    /// <summary>
    /// Returns EVERY CN value in a DN, in the order they appear. Empty when there is none.
    /// </summary>
    /// <remarks>
    /// All of them, not the first: a subject may assert several Common Names and the issued
    /// certificate carries all of them, so a restriction that checked only one left the rest
    /// unconstrained. A regex timeout yields an empty list, which the caller treats as
    /// "no Common Name to match" and therefore refuses — failing closed.
    /// </remarks>
    private static List<string> ExtractCommonNames(string subject)
    {
        try
        {
            return CommonNamePattern.Matches(subject)
                .Select(m => m.Groups["cn"].Value.Trim().Trim('"'))
                .Where(cn => !string.IsNullOrWhiteSpace(cn))
                .ToList();
        }
        catch (RegexMatchTimeoutException)
        {
            return [];
        }
    }
}
