using System.Text;

namespace ModularCA.Auth.Services;

/// <summary>
/// The password blocklist shipped with the product: <c>password-blocklist/bundled-blocklist.txt</c>
/// beside the binaries (the build output, and <c>/opt/modularca</c> from the Linux tarball or
/// package). It is checked when the password policy's <c>UseBundledBlocklist</c> is on, in
/// addition to the administrator's own list when one is set.
/// <para>
/// The file is read once per process, on first use, into a set held in memory; a check is one or a
/// few set lookups and reads nothing from disk. Everything happens in this process: no password,
/// and no hash of one, leaves the host.
/// </para>
/// <para>
/// Matching ignores case and Unicode compatibility forms (both sides are normalized to NFKC and
/// lower-cased). A password is on the list when it equals an entry, or when it is one unit
/// repeated end to end and that unit is an entry or is one or two characters long
/// (<c>passwordpassword</c>, <c>aaaaaaaaaaaaaaaa</c>, <c>abababababababab</c>).
/// </para>
/// </summary>
public static class BundledPasswordBlocklist
{
    /// <summary>The directory, beside the binaries, the list is shipped in.</summary>
    public const string DirectoryName = "password-blocklist";

    /// <summary>The list's file name.</summary>
    public const string FileName = "bundled-blocklist.txt";

    private static readonly Lazy<BundledPasswordBlocklistContent> Shipped = new(() => Load(FilePath));

    /// <summary>The full path the list is read from: <see cref="DirectoryName"/>/<see cref="FileName"/> under the application directory.</summary>
    public static string FilePath => Path.Combine(AppContext.BaseDirectory, DirectoryName, FileName);

    /// <summary>The shipped list, read on first use and kept for the life of the process.</summary>
    public static BundledPasswordBlocklistContent Current => Shipped.Value;

    /// <summary>Whether <paramref name="password"/> is on the shipped list (see the class remarks for what matches).</summary>
    public static bool Contains(string password) => Current.Contains(password);

    /// <summary>
    /// Reads a list file: UTF-8, one password per line; blank lines and lines starting with
    /// <c>#</c> are ignored. A file that is missing or cannot be read gives an empty list whose
    /// <see cref="BundledPasswordBlocklistContent.Available"/> is false and whose
    /// <see cref="BundledPasswordBlocklistContent.Problem"/> says why; it never throws, so a
    /// damaged install still lets passwords be set, and the console reports the list as missing.
    /// </summary>
    public static BundledPasswordBlocklistContent Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new BundledPasswordBlocklistContent(path, false, new HashSet<string>(StringComparer.Ordinal), $"The file {path} does not exist.");
            var entries = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#') continue;
                entries.Add(Normalize(trimmed));
            }
            return new BundledPasswordBlocklistContent(path, true, entries, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new BundledPasswordBlocklistContent(path, false, new HashSet<string>(StringComparer.Ordinal), ex.Message);
        }
    }

    /// <summary>
    /// The form entries and passwords are compared in: Unicode NFKC, lower case (invariant).
    /// Text that cannot be normalized (an unpaired surrogate) is lower-cased only.
    /// </summary>
    public static string Normalize(string text)
    {
        try
        {
            return text.Normalize(NormalizationForm.FormKC).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return text.ToLowerInvariant();
        }
    }
}

/// <summary>A blocklist read into memory, with where it came from and whether it could be read.</summary>
/// <param name="Path">The file the list was read from.</param>
/// <param name="Available">False when the file was missing or unreadable; the list is then empty.</param>
/// <param name="Entries">The entries, normalized by <see cref="BundledPasswordBlocklist.Normalize"/>.</param>
/// <param name="Problem">Why the file could not be read, or null.</param>
public sealed record BundledPasswordBlocklistContent(string Path, bool Available, IReadOnlySet<string> Entries, string? Problem)
{
    /// <summary>The number of entries.</summary>
    public int Count => Entries.Count;

    /// <summary>
    /// Whether <paramref name="password"/> is on this list: it equals an entry, or it is one unit
    /// repeated end to end where the unit is an entry or at most two characters long. Case and
    /// Unicode compatibility forms are ignored. An empty password is never on the list.
    /// </summary>
    public bool Contains(string password)
    {
        if (string.IsNullOrEmpty(password)) return false;
        var normalized = BundledPasswordBlocklist.Normalize(password);
        if (Entries.Contains(normalized)) return true;

        // One unit repeated: every unit length that divides the whole, up to half of it.
        for (var unit = 1; unit <= normalized.Length / 2; unit++)
        {
            if (normalized.Length % unit != 0 || !IsRepetitionOf(normalized, unit)) continue;
            if (unit <= 2 || Entries.Contains(normalized[..unit])) return true;
        }
        return false;
    }

    private static bool IsRepetitionOf(string text, int unit)
    {
        for (var i = unit; i < text.Length; i++)
        {
            if (text[i] != text[i - unit]) return false;
        }
        return true;
    }
}
