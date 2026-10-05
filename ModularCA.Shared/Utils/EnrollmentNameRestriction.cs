using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.X509;

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
/// <para><b>Semantics.</b> A restriction is a list of patterns (see <see cref="ParsePatterns"/>
/// for how the text is split), and a name need match only one of them:</para>
/// <list type="bullet">
/// <item>
/// A pattern containing <c>=</c> is a DN component, e.g. <c>O=Acme Corp</c>. It matches when the
/// subject carries that exact attribute value, compared on RDN boundaries rather than as a
/// substring — so <c>O=Acme</c> does not match <c>O=Acme Evil Corp</c>. Attribute names compare
/// by OID where the name is known (<c>E</c> and <c>emailAddress</c> are the same attribute);
/// values compare case-insensitively with runs of whitespace treated as one space.
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
    private static readonly char[] SegmentSeparators = [';', '\r', '\n'];

    // CN=..., tolerating whitespace and quoted values, up to the next unescaped comma.
    private static readonly Regex CommonNamePattern = new(
        @"(?:^|,)\s*CN\s*=\s*(?<cn>(?:[^,\\]|\\.)*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    // Whitespace that ends one DN pattern because the next word starts another: `O=Acme OU=Eng`.
    // Only attribute names the DN parser knows (or a dotted OID) count, so a value holding a
    // word and an `=` stays whole.
    private static readonly Regex NextDnPattern = new(
        @"\s+(?=(?:" + string.Join("|", X509Name.DefaultLookup.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape))
            + @"|(?:OID\.)?\d+(?:\.\d+)+)\s*=)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    private static readonly Regex DnsLabel = new("^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$", RegexOptions.CultureInvariant);
    private static readonly Regex AttributeName = new(@"^(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?\d+(?:\.\d+)+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// Splits a restriction string into its individual patterns. Empty when unset.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This used to split on every comma, semicolon and whitespace character, so the DN pattern
    /// <c>O=Acme Corp</c> became the two patterns <c>O=Acme</c> and <c>Corp</c>. Since a name need
    /// match only one pattern, that token accepted any subject with <c>O=Acme</c>, and any subject
    /// whose Common Names all ended in <c>.corp</c> (a bare word is a DNS suffix), while refusing
    /// the <c>O=Acme Corp</c> subject it was written for.
    /// </para>
    /// <para>
    /// The text is now read in three steps, which keeps every stored restriction that did not
    /// contain a DN value with a space meaning what it meant:
    /// </para>
    /// <list type="number">
    /// <item>Split on line breaks and <c>;</c> (the separators the console writes).</item>
    /// <item>Split each part on commas not escaped with a backslash, as before.</item>
    /// <item>A piece containing <c>=</c> is a DN pattern and keeps its spaces; it is split only
    /// where whitespace is followed by another known <c>attribute=</c> (so <c>O=Acme OU=Eng</c> is
    /// still two patterns). Anything else is DNS names, which cannot contain spaces, so it is split
    /// on whitespace as before (<c>a.com b.com</c>).</item>
    /// </list>
    /// <para>
    /// The one stored shape that reads differently is a DN value followed by a space and a DNS
    /// name, <c>O=Acme example.com</c>: it is now one DN pattern rather than two. That narrows the
    /// token rather than widening it. An unescaped comma inside a DN value still separates
    /// patterns, as it always did; the console escapes it.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ParsePatterns(string? restriction)
    {
        if (string.IsNullOrWhiteSpace(restriction)) return [];
        var patterns = new List<string>();
        foreach (var segment in restriction.Split(SegmentSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var piece in SplitUnescaped(segment, ','))
            {
                string[] parts;
                try { parts = NextDnPattern.Split(piece); }
                catch (RegexMatchTimeoutException) { parts = [piece]; }
                foreach (var part in parts)
                {
                    if (part.Contains('='))
                        patterns.Add(part.Trim());
                    else
                        patterns.AddRange(part.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                }
            }
        }
        return patterns.Where(p => p.Length > 0).ToList();
    }

    /// <summary>
    /// Why <paramref name="restriction"/> should not be saved, or null when it may be. A pattern
    /// must be a DNS name (no wildcard: a name already covers its subdomains) or, in a subject
    /// restriction, <c>attribute=value</c>. A SAN restriction takes DNS names only, since a DN
    /// pattern can never be satisfied by a SAN.
    /// </summary>
    /// <param name="restriction">The restriction text, or null.</param>
    /// <param name="forSans">True for <c>SANRestriction</c>, false for <c>SubjectRestriction</c>.</param>
    /// <param name="maxLength">The column length the text must fit.</param>
    public static string? RestrictionError(string? restriction, bool forSans, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(restriction)) return null;
        var field = forSans ? "SAN restriction" : "Subject restriction";
        if (restriction.Length > maxLength)
            return $"The {field} is {restriction.Length} characters; at most {maxLength} fit.";
        if (restriction.Any(c => (c < 0x20 && c != '\r' && c != '\n' && c != '\t') || c == 0x7F))
            return $"The {field} contains a control character.";

        foreach (var pattern in ParsePatterns(restriction))
        {
            if (IsDnComponent(pattern))
            {
                if (forSans)
                    return $"'{pattern}' is a DN component; a SAN restriction takes DNS names only, and no SAN can satisfy a DN pattern.";
                var eq = pattern.IndexOf('=');
                var name = pattern[..eq].Trim();
                if (!AttributeName.IsMatch(name))
                    return $"'{pattern}' does not start with an attribute name such as O, OU or C.";
                if (Normalise(pattern[(eq + 1)..]).Length == 0)
                    return $"'{pattern}' has no value after '='.";
                continue;
            }

            var host = pattern.TrimEnd('.');
            if (host.StartsWith('.')) host = host[1..];
            if (host.Contains('*'))
                return $"'{pattern}': a pattern already covers its subdomains, so write it without the wildcard.";
            if (host.Length == 0 || host.Length > 253 || host.Split('.').Any(l => l.Length == 0 || l.Length > 63 || !DnsLabel.IsMatch(l)))
                return $"'{pattern}' is not a DNS name.";
        }
        return null;
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
    /// Matches a DN component on RDN boundaries: the subject is split on unescaped commas (and
    /// a multi-valued RDN on unescaped <c>+</c>), so <c>O=Acme</c> does not match
    /// <c>O=Acme Evil Corp</c>, which a substring test would accept. The attribute compares by OID
    /// when the DN parser knows its name, and the value as <see cref="Normalise"/> leaves it.
    /// </summary>
    private static bool SubjectHasDnComponent(string subject, string pattern)
    {
        var wanted = SplitAttribute(pattern);
        if (wanted == null) return false;
        foreach (var rdn in SplitUnescaped(subject, ','))
        {
            foreach (var ava in SplitUnescaped(rdn, '+'))
            {
                var have = SplitAttribute(ava);
                if (have != null
                    && have.Value.Name.Equals(wanted.Value.Name, StringComparison.OrdinalIgnoreCase)
                    && have.Value.Value.Equals(wanted.Value.Value, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// An <c>attribute=value</c> pair in comparable form: the attribute as its OID when the DN
    /// parser knows the name (else upper-cased), the value normalised. Null without an <c>=</c>.
    /// </summary>
    private static (string Name, string Value)? SplitAttribute(string ava)
    {
        var eq = ava.IndexOf('=');
        if (eq <= 0) return null;
        var name = ava[..eq].Trim();
        if (name.StartsWith("OID.", StringComparison.OrdinalIgnoreCase)) name = name[4..];
        if (X509Name.DefaultLookup.TryGetValue(name.ToLowerInvariant(), out var oid)) name = oid.Id;
        return (name.ToUpperInvariant(), Normalise(ava[(eq + 1)..]));
    }

    /// <summary>
    /// A DN value for comparison: backslash escapes removed, surrounding quotes and whitespace
    /// trimmed, and each run of whitespace made one space (X.520 insignificant-space handling).
    /// </summary>
    private static string Normalise(string value)
    {
        var sb = new System.Text.StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length) { sb.Append(value[++i]); continue; }
            sb.Append(value[i]);
        }
        var trimmed = sb.ToString().Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"') trimmed = trimmed[1..^1].Trim();
        return string.Join(' ', trimmed.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>Splits text on <paramref name="separator"/> where it is not backslash-escaped; pieces trimmed, empty ones dropped.</summary>
    private static IEnumerable<string> SplitUnescaped(string text, char separator)
    {
        var start = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\') { i++; continue; }
            if (text[i] != separator) continue;
            var piece = text[start..i].Trim();
            if (piece.Length > 0) yield return piece;
            start = i + 1;
        }
        if (start < text.Length && text[start..].Trim() is { Length: > 0 } last) yield return last;
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
