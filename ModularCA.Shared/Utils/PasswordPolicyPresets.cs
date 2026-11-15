using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Named password policies an administrator can apply in one action. One today: NIST SP 800-63B
/// (revision 4), which is also what a new install starts with. Every setting a preset writes stays
/// editable afterwards.
/// </summary>
public static class PasswordPolicyPresets
{
    /// <summary>The identifier of the NIST SP 800-63B preset in the admin API.</summary>
    public const string Nist80063B = "nist-sp-800-63b";

    /// <summary>The preset's name as the console shows it.</summary>
    public const string Nist80063BName = "NIST SP 800-63B";

    /// <summary>
    /// The preset's minimum length: 15 characters, what SP 800-63B asks for where the password is
    /// the only factor. (It allows 8 where a second factor is always used; the preset takes the
    /// stricter figure because an account may sign in before it has enrolled one.)
    /// </summary>
    public const int Nist80063BMinLength = 15;

    /// <summary>The shortest maximum length SP 800-63B allows a verifier to impose: 64 characters.</summary>
    public const int Nist80063BMaxLengthFloor = 64;

    /// <summary>The maximum length the preset sets when the stored one is under <see cref="Nist80063BMaxLengthFloor"/>.</summary>
    public const int Nist80063BMaxLength = 128;

    /// <summary>
    /// Sets on <paramref name="policy"/> exactly what the NIST SP 800-63B preset means: a minimum
    /// length of <see cref="Nist80063BMinLength"/>; no required character class and no
    /// character-class count; no expiry (<c>MaxAgeDays</c> 0); the bundled blocklist on. A maximum
    /// length under 64 (0, no maximum, aside) becomes 128; a larger one is kept. The password
    /// history and the administrator's own blocklist are not touched: the standard asks for
    /// neither and forbids neither.
    /// </summary>
    public static void ApplyNist80063B(PasswordPolicyEntity policy)
    {
        policy.MinLength = Nist80063BMinLength;
        if (policy.MaxLength > 0 && policy.MaxLength < Nist80063BMaxLengthFloor)
            policy.MaxLength = Nist80063BMaxLength;
        policy.RequireUppercase = false;
        policy.RequireLowercase = false;
        policy.RequireDigit = false;
        policy.RequireSymbol = false;
        policy.MinUppercase = 0;
        policy.MinLowercase = 0;
        policy.MinDigits = 0;
        policy.MinSpecial = 0;
        policy.MaxAgeDays = 0;
        policy.UseBundledBlocklist = true;
    }

    /// <summary>
    /// How <paramref name="policy"/> differs from what SP 800-63B asks for, one sentence each;
    /// empty when it meets the standard. A policy stricter in length than the preset still meets
    /// it; one with composition rules or expiry does not, because the standard says not to impose
    /// them.
    /// </summary>
    public static IReadOnlyList<string> DifferencesFromNist80063B(PasswordPolicyEntity policy)
    {
        var found = new List<string>();
        if (policy.MinLength < Nist80063BMinLength)
            found.Add($"The minimum length is {policy.MinLength}; the standard asks for {Nist80063BMinLength} where a password can be the only factor.");
        if (policy.MaxLength > 0 && policy.MaxLength < Nist80063BMaxLengthFloor)
            found.Add($"The maximum length is {policy.MaxLength}; the standard asks that at least {Nist80063BMaxLengthFloor} characters be allowed.");
        if (policy.RequireUppercase || policy.RequireLowercase || policy.RequireDigit || policy.RequireSymbol
            || policy.MinUppercase > 0 || policy.MinLowercase > 0 || policy.MinDigits > 0 || policy.MinSpecial > 0)
            found.Add("Character classes are required; the standard says not to impose composition rules.");
        if (policy.MaxAgeDays > 0)
            found.Add($"Passwords expire after {policy.MaxAgeDays} days; the standard says to require a change only on evidence of compromise.");
        if (!policy.UseBundledBlocklist && string.IsNullOrWhiteSpace(policy.DictionaryPath))
            found.Add("New passwords are not checked against a blocklist of common and compromised passwords.");
        return found;
    }
}
