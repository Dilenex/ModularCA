using System.Text.RegularExpressions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Outcome of evaluating an operator-authored profile pattern against a requester-supplied value.
/// Deliberately four-valued rather than a <see langword="bool"/>: enforcement sites only care about
/// <see cref="Match"/> versus "anything else" (fail closed), but the preview/validate endpoints need
/// to tell a caller "your value is wrong" (<see cref="NoMatch"/>) apart from "the profile itself is
/// broken" (<see cref="InvalidPattern"/> / <see cref="Timeout"/>) so a bad profile surfaces as a
/// profile problem instead of silently passing or blaming the requester.
/// </summary>
public enum ProfileRegexOutcome
{
    /// <summary>The pattern compiled and matched the input within the time budget.</summary>
    Match,

    /// <summary>The pattern compiled and ran to completion, but the input did not match.</summary>
    NoMatch,

    /// <summary>
    /// The pattern is not a syntactically valid .NET regular expression (bad escape, unterminated
    /// group, etc.), or the input/pattern arguments were unusable. The profile author must fix it.
    /// </summary>
    InvalidPattern,

    /// <summary>
    /// The match exceeded <see cref="ProfileRegex.MatchTimeout"/>. Almost always means the pattern
    /// has nested/ambiguous quantifiers and the input triggered catastrophic backtracking — i.e. a
    /// ReDoS attempt or a pathological profile. Never treat this as a pass.
    /// </summary>
    Timeout
}

/// <summary>
/// Single entry point for matching requester-controlled input against regular-expression patterns
/// that come out of the database (request-profile subject-DN rules, SAN type rules, SSH allowed-
/// principal patterns).
///
/// WHY THIS EXISTS: those call sites used the static <c>Regex.IsMatch(input, pattern)</c> overload,
/// which applies <see cref="Regex.InfiniteMatchTimeout"/>. A profile pattern containing nested
/// quantifiers (the classic <c>(a+)+$</c> shape) plus a crafted enrollment value makes the
/// backtracking engine run effectively forever, pinning a CPU core for every request that reaches
/// it. Because the enrollment protocols (ACME, EST, SCEP, CMP and the public enrollment endpoint)
/// all funnel through <c>RequestProfileValidationService</c>, that is a pre-authentication
/// denial-of-service on the whole issuance pipeline. Every match against a stored pattern must
/// therefore run under a bounded budget.
///
/// DESIGN DECISIONS (deliberate, please do not "simplify" them away):
/// <list type="bullet">
///   <item><description>
///   <b>Fail closed.</b> A timeout or an uncompilable pattern is never folded into "valid". At an
///   enforcement site the answer is "does not match", so a hostile input cannot buy itself an
///   issuance by making the validator give up. This is the opposite of the previous
///   <c>catch { status = "valid"; }</c> behaviour, which let a broken profile authorise everything.
///   </description></item>
///   <item><description>
///   <b>Timeout, not <see cref="RegexOptions.NonBacktracking"/>.</b> NonBacktracking would remove
///   the backtracking blowup outright, but it rejects backreferences, lookarounds and atomic groups
///   with a <see cref="NotSupportedException"/>. Operators have already authored profiles using
///   lookaheads, and under the fail-closed rule above those would start denying every request. A
///   timeout preserves existing pattern semantics while still bounding the damage.
///   </description></item>
///   <item><description>
///   <b>No cache.</b> Patterns are attacker-adjacent keys (an operator with profile-edit rights can
///   mint unlimited distinct patterns), so a <c>ConcurrentDictionary&lt;string, Regex&gt;</c> keyed
///   by pattern is an unbounded-growth footgun. We also avoid the static <c>Regex</c> overloads
///   entirely: their internal cache is keyed on pattern/options/culture and reusing an entry that
///   was created with a different match timeout is exactly the subtlety this class exists to rule
///   out. Constructing the <see cref="Regex"/> per call costs microseconds against a 100 ms budget,
///   and correctness is worth more than that here.
///   </description></item>
/// </list>
/// </summary>
public static class ProfileRegex
{
    /// <summary>
    /// Per-match CPU budget for an operator-supplied pattern. Generous for any sane pattern against
    /// a subject-DN value, SAN or SSH principal (those complete in microseconds), but short enough
    /// that a deliberately catastrophic pattern costs an attacker's request far more than it costs
    /// the server.
    /// </summary>
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Evaluates <paramref name="input"/> against the operator-supplied <paramref name="pattern"/>
    /// under <see cref="MatchTimeout"/> and reports which of the four outcomes occurred. Use this
    /// overload where the caller needs to distinguish "the value is wrong" from "the profile is
    /// broken" (for example the validate/preview endpoints, which report a per-field status to the
    /// UI). Enforcement paths should prefer <see cref="IsMatch"/>.
    /// A null/empty pattern is <see cref="ProfileRegexOutcome.InvalidPattern"/>: callers are
    /// expected to skip the rule entirely when no pattern is configured, so reaching here with an
    /// empty one is a caller bug rather than an implicit "allow everything".
    /// </summary>
    /// <param name="input">The requester-controlled value being validated. Null is treated as empty.</param>
    /// <param name="pattern">The pattern loaded from the profile.</param>
    public static ProfileRegexOutcome Evaluate(string? input, string? pattern)
    {
        if (string.IsNullOrEmpty(pattern))
            return ProfileRegexOutcome.InvalidPattern;

        try
        {
            var regex = new Regex(pattern, RegexOptions.None, MatchTimeout);
            return regex.IsMatch(input ?? string.Empty)
                ? ProfileRegexOutcome.Match
                : ProfileRegexOutcome.NoMatch;
        }
        catch (RegexMatchTimeoutException)
        {
            // Catastrophic backtracking (or simply a pattern too expensive for this input).
            // Reported separately from InvalidPattern so operators can tell a typo in a profile
            // apart from a pattern that is being weaponised against them.
            return ProfileRegexOutcome.Timeout;
        }
        catch (ArgumentException)
        {
            // Regex ctor rejected the pattern: it never compiled, so nothing was matched.
            return ProfileRegexOutcome.InvalidPattern;
        }
    }

    /// <summary>
    /// Fail-closed convenience wrapper over <see cref="Evaluate"/> for enforcement sites that gate
    /// real issuance: returns <see langword="true"/> only for <see cref="ProfileRegexOutcome.Match"/>.
    /// A timed-out or uncompilable pattern therefore reads as "does not match" and the request is
    /// rejected — the safe direction for a CA, since the alternative is issuing a certificate whose
    /// constraints were never actually checked.
    /// </summary>
    /// <param name="input">The requester-controlled value being validated. Null is treated as empty.</param>
    /// <param name="pattern">The pattern loaded from the profile.</param>
    public static bool IsMatch(string? input, string? pattern)
        => Evaluate(input, pattern) == ProfileRegexOutcome.Match;
}
