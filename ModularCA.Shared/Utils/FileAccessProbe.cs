namespace ModularCA.Shared.Utils;

/// <summary>
/// Tells a file that is there and may not be read from one that is absent.
/// <see cref="File.Exists(string)"/> answers false for both: for a file whose directory this
/// account may not enter, or that a mandatory access policy (SELinux) denies, as for one that does
/// not exist. A message that says "not found" then sends an operator to look for a file that is
/// in its place.
/// </summary>
public static class FileAccessProbe
{
    /// <summary>
    /// True when opening <paramref name="path"/> is refused for lack of permission, on the file or
    /// on a directory above it. False when it can be opened, when it is absent, and for any other
    /// fault.
    /// </summary>
    /// <param name="path">The file.</param>
    public static bool IsUnreadable(string path)
    {
        try
        {
            using var _ = File.OpenRead(path);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
        catch (Exception e) when (e is IOException or NotSupportedException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// What to say of a file that <see cref="File.Exists(string)"/> does not see: that this account
    /// may not read it, naming the account, or that it was not found.
    /// </summary>
    /// <param name="what">What the file is, to start the sentence: "Backup archive", for example.</param>
    /// <param name="path">The file.</param>
    public static string Describe(string what, string path)
        => IsUnreadable(path)
            ? $"{what} cannot be read by '{Environment.UserName}' (permission denied): {path}. It is there; check its owner and mode, the directories above it, and the mount's SELinux label."
            : $"{what} not found: {path}";
}
