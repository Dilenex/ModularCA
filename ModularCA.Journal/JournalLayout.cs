using System.Globalization;

namespace ModularCA.Journal;

/// <summary>
/// How the journal lies in the directory the signer is given, its <b>home</b>. The home may be
/// the root of a volume mounted for the journal alone, so nothing here renames or replaces the
/// home itself: everything is inside it.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><c>&lt;home&gt;/current/</c> holds the live segments: the directory the writer creates,
/// appends and renames in, and the one a reader reads.</item>
/// <item><c>&lt;home&gt;/set-aside-instance-&lt;tag&gt;-&lt;time&gt;/</c> is the journal of another
/// instance that the signer found in <c>current/</c> and set aside: <c>current</c> renamed, whole.
/// The tag is the first 16 letters and digits of that instance's identifier.</item>
/// <item><c>&lt;home&gt;/set-aside-reset-&lt;time&gt;/</c> is the journal a factory reset set aside.</item>
/// </list>
/// The time is <c>yyyyMMdd-HHmmss-fff</c>, UTC. The home holds <c>current/</c> and set-aside
/// directories and nothing else. Nothing prunes a set-aside directory.
/// </remarks>
public static class JournalLayout
{
    /// <summary>The name of the directory of live segments inside the home.</summary>
    public const string CurrentName = "current";

    /// <summary>What the name of every set-aside directory begins with.</summary>
    public const string SetAsidePrefix = "set-aside-";

    /// <summary>What the name of another instance's journal, set aside by the signer, begins with.</summary>
    public const string SetAsideInstancePrefix = SetAsidePrefix + "instance-";

    /// <summary>What the name of a journal set aside by a factory reset begins with.</summary>
    public const string SetAsideResetPrefix = SetAsidePrefix + "reset-";

    /// <summary>The directory of live segments of the journal whose home is <paramref name="home"/>.</summary>
    public static string Current(string home) => Path.Combine(home, CurrentName);

    /// <summary>The part of a set-aside name that says whose journal it is: the first 16 letters and digits of the instance identifier.</summary>
    public static string InstanceTag(string instanceId) => new(instanceId.Where(char.IsAsciiLetterOrDigit).Take(16).ToArray());

    /// <summary>The name of the directory another instance's journal is set aside under.</summary>
    public static string SetAsideInstanceName(string instanceId, DateTime utc) => SetAsideInstancePrefix + InstanceTag(instanceId) + "-" + Stamp(utc);

    /// <summary>The name of the directory a factory reset sets the journal aside under.</summary>
    public static string SetAsideResetName(DateTime utc) => SetAsideResetPrefix + Stamp(utc);

    private static string Stamp(DateTime utc) => utc.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);

    /// <summary>
    /// Sets the live journal aside: renames <c>&lt;home&gt;/current</c> to
    /// <c>&lt;home&gt;/&lt;name&gt;</c>, whole and unchanged. The home itself is not renamed, so it may
    /// be a mount point. Returns the new path, or null when there is no <c>current</c> to set
    /// aside. The caller creates a new <c>current</c> by opening the journal.
    /// </summary>
    /// <exception cref="IOException">The rename failed.</exception>
    /// <exception cref="UnauthorizedAccessException">The rename is not this account's to make.</exception>
    public static string? SetAsideCurrent(string home, string name)
    {
        var current = Current(home);
        if (!Directory.Exists(current))
            return null;
        var aside = Path.Combine(home, name);
        Directory.Move(current, aside);
        return aside;
    }

    /// <summary>
    /// The set-aside journals in <paramref name="home"/>: how many there are, and the bytes their
    /// files take. It only lists.
    /// </summary>
    public static (int Count, long Bytes) SetAside(string home)
    {
        if (!Directory.Exists(home))
            return (0, 0);
        var count = 0;
        long bytes = 0;
        foreach (var directory in new DirectoryInfo(home).EnumerateDirectories(SetAsidePrefix + "*"))
        {
            count++;
            bytes += directory.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
        }
        return (count, bytes);
    }

    /// <summary>
    /// The directory a reader reads when it is given <paramref name="path"/>, which may be a
    /// home or a directory that holds segments itself (a set-aside journal, a bare copy of the
    /// segments). The rule: a directory that holds at least one segment file is read as it is;
    /// otherwise, when it has a <c>current</c> directory, that is read; otherwise the path is
    /// read as it is and holds no journal.
    /// </summary>
    public static string ReadDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        try
        {
            if (JournalReader.ListSegments(path).Count > 0)
                return path;
            var current = Current(path);
            return Directory.Exists(current) ? current : path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return path;
        }
    }
}
