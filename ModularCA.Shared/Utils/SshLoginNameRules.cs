namespace ModularCA.Shared.Utils;

/// <summary>
/// What an SSH login name may be: the account a certificate lets its holder log in as, written
/// into the certificate as a principal. One rule for the names an administrator grants and for
/// the username a user holds as a login name of their own.
/// </summary>
/// <remarks>
/// 1 to <see cref="MaxLength"/> characters. The first is an ASCII letter, a digit or an
/// underscore; the rest are ASCII letters, digits and <c>. _ @ + -</c>. Names are compared byte
/// for byte, as <c>sshd</c> compares a principal: <c>Deploy</c> and <c>deploy</c> are two names.
/// <see cref="Pattern"/> is the same grammar as a regular expression, for a certificate
/// profile's principal patterns.
/// </remarks>
public static class SshLoginNameRules
{
    /// <summary>The longest login name, in characters.</summary>
    public const int MaxLength = 128;

    /// <summary>
    /// The grammar <see cref="IsValid"/> checks, as the regular expression a certificate profile
    /// lists among its allowed principal patterns, so that a profile seeded with it refuses no
    /// name a grant allows. It reads the same in .NET and in a browser. In .NET alone its
    /// <c>$</c> also matches before one final line feed, which <see cref="IsValid"/> refuses and
    /// the signer refuses as a control character in a principal.
    /// </summary>
    public static readonly string Pattern = $"^[A-Za-z0-9_][A-Za-z0-9._@+-]{{0,{MaxLength - 1}}}$";

    /// <summary>Whether <paramref name="name"/> fits the grammar.</summary>
    public static bool IsValid(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxLength)
            return false;
        if (!IsLetterOrDigit(name[0]) && name[0] != '_')
            return false;
        for (var i = 1; i < name.Length; i++)
        {
            var c = name[i];
            if (!IsLetterOrDigit(c) && c is not ('.' or '_' or '@' or '+' or '-'))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Whether <paramref name="username"/> is a login name its user holds as their own on a key
    /// that allows own usernames: it fits the grammar and is not <c>root</c>, in any case.
    /// Whoever may create or rename a user decides that user's username, so <c>root</c> is never
    /// held this way; it is held only through a grant (owner, 2026-10-07).
    /// </summary>
    public static bool CanBeOwn(string? username)
        => IsValid(username) && !string.Equals(username, "root", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Null when <paramref name="name"/> fits the grammar, otherwise a sentence for a 400 answer.
    /// The sentence repeats the name only when it is short and printable.
    /// </summary>
    public static string? Error(string? name)
    {
        if (IsValid(name))
            return null;
        if (string.IsNullOrEmpty(name))
            return "A login name is empty.";
        var shown = name.Length <= MaxLength && !name.Any(char.IsControl) ? $"'{name}'" : "A login name";
        return $"{shown} is not a login name: use 1 to {MaxLength} characters, starting with a letter, a digit or an underscore, "
            + "then letters, digits and . _ @ + -";
    }

    private static bool IsLetterOrDigit(char c) => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9');
}
