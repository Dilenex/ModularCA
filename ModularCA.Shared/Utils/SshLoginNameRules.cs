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
/// </remarks>
public static class SshLoginNameRules
{
    /// <summary>The longest login name, in characters.</summary>
    public const int MaxLength = 128;

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
