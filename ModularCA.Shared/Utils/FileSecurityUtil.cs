using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Sets restrictive file permissions on sensitive config files. Provides cross-platform
/// best-effort hardening: chmod 600 on POSIX, NTFS DACL replacement on Windows.
/// </summary>
public static class FileSecurityUtil
{
    private static int _windowsAclWarningLogged;

    /// <summary>
    /// Sets file permissions to owner-only read/write. On POSIX systems this maps to
    /// <c>chmod 600</c> via <see cref="File.SetUnixFileMode"/>. On Windows, the file's
    /// DACL is replaced with explicit ACEs granting <see cref="FileSystemRights.FullControl"/>
    /// only to the current user and the local Administrators group, and inheritance is
    /// disabled so parent-folder ACEs do not leak access. A failure is written to standard error
    /// as a warning rather than thrown, so a permission-tightening failure does not crash callers
    /// writing secrets to disk. To create a secret file, prefer
    /// <see cref="WriteOwnerOnly(string, byte[])"/>, which on POSIX never leaves it readable in
    /// between.
    /// </summary>
    /// <param name="filePath">Absolute path to the file whose ACL should be tightened.</param>
    public static void SetOwnerOnly(string filePath)
    {
        if (!File.Exists(filePath))
            return;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                ApplyWindowsOwnerOnlyAcl(filePath);
            }
            catch (Exception ex)
            {
                if (System.Threading.Interlocked.Exchange(ref _windowsAclWarningLogged, 1) == 0)
                {
                    Console.Error.WriteLine(
                        $"[WARNING] FileSecurityUtil.SetOwnerOnly: failed to harden ACL on '{filePath}': {ex.Message}. " +
                        "Sensitive files may inherit parent-folder permissions until this is resolved.");
                }
            }
            return;
        }

        try
        {
            File.SetUnixFileMode(filePath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[WARNING] FileSecurityUtil.SetOwnerOnly: failed to restrict '{filePath}' to mode 0600: {ex.Message}. " +
                "Other local users may be able to read it; fix its owner and mode by hand.");
        }
    }

    /// <summary>
    /// Writes a secret file restricted to its owner. On Linux and other POSIX systems it is never
    /// readable by anyone else, not even for the moment between creating it and tightening it: a
    /// new file is created with mode 0600 through <see cref="FileStreamOptions.UnixCreateMode"/>.
    /// On Windows there is no create-time equivalent here: a new file starts with the ACL it
    /// inherits from its folder, is written while no other handle may open it
    /// (<see cref="FileShare.None"/>), and gets the owner-only DACL of <see cref="SetOwnerOnly"/>
    /// only after the write, so for that moment the folder's permissions apply. On every platform
    /// an existing file is tightened before the new contents go in and then truncated and
    /// rewritten. Tightening an existing file never grants: on POSIX it only takes the group's and
    /// others' bits away, so a file its owner made read-only stays read-only and the write is
    /// refused, as it is on Windows, where the read-only attribute survives the DACL. Failures to
    /// restrict permissions are reported as warnings, as in <see cref="SetOwnerOnly"/>; failures
    /// to write throw.
    /// </summary>
    /// <param name="filePath">The file to create or replace.</param>
    /// <param name="contents">The bytes to write.</param>
    public static void WriteOwnerOnly(string filePath, byte[] contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        if (File.Exists(filePath))
            RestrictExistingToOwner(filePath);

        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(filePath, options))
            stream.Write(contents);
        SetOwnerOnly(filePath);
    }

    /// <summary>
    /// Takes every right but the owner's away from an existing file without giving the owner any:
    /// on POSIX the group and other bits are cleared and the owner's left as they were (so 0444
    /// becomes 0400, not 0600); on Windows the owner-only DACL of <see cref="SetOwnerOnly"/>,
    /// which leaves the read-only attribute alone. Failures are warnings, as there.
    /// </summary>
    private static void RestrictExistingToOwner(string filePath)
    {
        if (OperatingSystem.IsWindows())
        {
            SetOwnerOnly(filePath);
            return;
        }

        try
        {
            const UnixFileMode ownerBits = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(filePath, File.GetUnixFileMode(filePath) & ownerBits);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[WARNING] FileSecurityUtil.WriteOwnerOnly: failed to restrict '{filePath}' to its owner before writing: {ex.Message}. " +
                "Other local users may be able to read it; fix its owner and mode by hand.");
        }
    }

    /// <summary>
    /// Writes key material to a NEW file restricted to its owner, never into an existing one. On
    /// POSIX the file is created with mode 0600 (<see cref="FileStreamOptions.UnixCreateMode"/>)
    /// and <see cref="FileMode.CreateNew"/>, so it is never readable by anyone else and a file
    /// someone else created at that path first is refused rather than written into. With
    /// <paramref name="replaceExisting"/>, an existing file is deleted first, so a descriptor some
    /// other user already holds on it points at the old file, not the new contents.
    /// </summary>
    /// <remarks>
    /// <see cref="WriteOwnerOnly(string, byte[])"/> truncates and rewrites an existing file, which
    /// suits configuration; for decrypted keys and archives the inode must be new. Writing an
    /// empty file, restricting it and then writing into it (as the unlocker did) leaves the empty
    /// file at default permissions for a moment, and a descriptor opened then survives the chmod.
    /// </remarks>
    /// <param name="filePath">The file to create.</param>
    /// <param name="contents">The bytes to write.</param>
    /// <param name="replaceExisting">Delete a file already at <paramref name="filePath"/> first.</param>
    /// <exception cref="IOException">The file exists (and is not to be replaced), or was recreated by someone else after the delete.</exception>
    public static void CreateOwnerOnly(string filePath, byte[] contents, bool replaceExisting = false)
    {
        ArgumentNullException.ThrowIfNull(contents);
        CreateOwnerOnly(filePath, stream => stream.Write(contents), replaceExisting);
    }

    /// <summary>
    /// <see cref="CreateOwnerOnly(string, byte[], bool)"/> for contents that are written to a
    /// stream rather than held as one array: a PKCS#12 store, a keystore file, a ZIP archive. The
    /// new file is opened as there (a new file, mode 0600 from creation on POSIX, no other handle
    /// allowed while it is written) and handed to <paramref name="write"/>; once that returns the
    /// file is closed and given the owner-only DACL on Windows. This replaces opening the file at
    /// default permissions, writing it and restricting it afterwards, which left it readable by
    /// whoever the directory and umask allowed until the chmod, and for as long as they kept the
    /// descriptor they opened then. When <paramref name="write"/> throws, the partly written file
    /// is deleted (best effort) and the exception propagates.
    /// </summary>
    /// <param name="filePath">The file to create.</param>
    /// <param name="write">Writes the contents. It may flush the stream to disk; it need not close it.</param>
    /// <param name="replaceExisting">Delete a file already at <paramref name="filePath"/> first.</param>
    /// <exception cref="IOException">The file exists (and is not to be replaced), or was recreated by someone else after the delete.</exception>
    public static void CreateOwnerOnly(string filePath, Action<FileStream> write, bool replaceExisting = false)
    {
        ArgumentNullException.ThrowIfNull(write);
        if (replaceExisting && File.Exists(filePath))
            File.Delete(filePath);

        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var stream = new FileStream(filePath, options);
        try
        {
            using (stream)
                write(stream);
        }
        catch
        {
            // The file is this call's own (CreateNew succeeded), so removing it takes nobody else's.
            try { File.Delete(filePath); } catch { /* the caller gets the write's exception, not the cleanup's */ }
            throw;
        }
        SetOwnerOnly(filePath);
    }

    /// <summary>
    /// Text counterpart of <see cref="WriteOwnerOnly(string, byte[])"/>; writes
    /// <paramref name="contents"/> as UTF-8 without a byte-order mark.
    /// </summary>
    /// <param name="filePath">The file to create or replace.</param>
    /// <param name="contents">The text to write.</param>
    public static void WriteOwnerOnly(string filePath, string contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        WriteOwnerOnly(filePath, new System.Text.UTF8Encoding(false).GetBytes(contents));
    }

    /// <summary>
    /// Sets directory permissions to owner-only (<c>chmod 700</c> on POSIX, an equivalent DACL
    /// on Windows).
    /// <para>
    /// Needed because <see cref="SetOwnerOnly"/> operates on files, and the backup and restore
    /// paths stage decrypted CA private keys inside directories under
    /// <see cref="Path.GetTempPath"/>. On Linux that is <c>/tmp</c>, which is world-readable —
    /// so every local user could read the keystores for the duration of a backup or a restore.
    /// Hardening the finished archive, which the code already did, does nothing for the
    /// plaintext staged next to it.
    /// </para>
    /// <para>
    /// Call this immediately after creating the directory and before writing anything into it.
    /// There is a brief window between creation and the mode change, but the directory is empty
    /// throughout it, so nothing sensitive is exposed.
    /// </para>
    /// </summary>
    /// <param name="directoryPath">Absolute path to the directory to tighten.</param>
    public static void SetDirectoryOwnerOnly(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
            return;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                ApplyWindowsDirectoryOwnerOnlyAcl(directoryPath);
            }
            catch (Exception ex)
            {
                if (System.Threading.Interlocked.Exchange(ref _windowsAclWarningLogged, 1) == 0)
                {
                    Console.Error.WriteLine(
                        $"[WARNING] FileSecurityUtil.SetDirectoryOwnerOnly: failed to harden ACL on " +
                        $"'{directoryPath}': {ex.Message}. Staged secrets may be readable by other users.");
                }
            }
            return;
        }

        try
        {
            // 0700 — the execute bit is required to traverse into a directory at all.
            File.SetUnixFileMode(directoryPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[WARNING] FileSecurityUtil.SetDirectoryOwnerOnly: failed to restrict '{directoryPath}' to mode 0700: " +
                $"{ex.Message}. Staged secrets may be readable by other users.");
        }
    }

    /// <summary>
    /// Creates a new, empty directory under <see cref="Path.GetTempPath"/> for staging secrets,
    /// with an unpredictable name (<paramref name="prefix"/> plus a random suffix) and restricted
    /// to its owner from the start, and returns its full path. Unlike
    /// <see cref="SetDirectoryOwnerOnly"/>, a directory that cannot be restricted is an error, not
    /// a warning: it is deleted and the call throws, so the caller stages nothing.
    /// <para>
    /// On POSIX the directory comes from <see cref="Directory.CreateTempSubdirectory"/>, which
    /// creates it atomically with a fresh random name and mode 0700 (<c>mkdtemp</c>), so no other
    /// user can have created it first or open it in between. A predictable name under
    /// <c>/tmp</c> is not safe even when chmodded: another local user can create it before the
    /// backup does, <see cref="Directory.CreateDirectory(string)"/> then reuses it silently, and
    /// the chmod fails on a directory that user owns. On Windows the owner-only DACL of
    /// <see cref="SetDirectoryOwnerOnly"/> is applied before the path is returned. On every
    /// platform the result is checked with <see cref="EnsureDirectoryOwnerOnly"/>.
    /// </para>
    /// </summary>
    /// <param name="prefix">The start of the directory name, e.g. <c>modularca-backup-</c>.</param>
    /// <returns>The full path of the new directory.</returns>
    /// <exception cref="IOException">The directory could not be created, or could not be restricted to its owner.</exception>
    /// <exception cref="UnauthorizedAccessException">The directory's permissions could not be read or set.</exception>
    public static string CreateOwnerOnlyTempDirectory(string prefix)
    {
        var directory = Directory.CreateTempSubdirectory(prefix).FullName;
        try
        {
            if (OperatingSystem.IsWindows())
                ApplyWindowsDirectoryOwnerOnlyAcl(directory);
            EnsureDirectoryOwnerOnly(directory);
            return directory;
        }
        catch
        {
            try { Directory.Delete(directory, recursive: true); } catch { /* best effort; the original error matters */ }
            throw;
        }
    }

    /// <summary>
    /// Makes sure <paramref name="directoryPath"/> exists and is reachable by its owner alone, or
    /// throws; unlike <see cref="SetDirectoryOwnerOnly"/>, nothing here is only a warning. For a
    /// directory that is kept and written into over time, such as the backup directory; a
    /// throwaway staging directory comes from <see cref="CreateOwnerOnlyTempDirectory"/>.
    /// <para>
    /// A missing directory (and any missing parent) is created owner-only: with mode 0700 from
    /// the start on POSIX, with the owner-only DACL of <see cref="SetDirectoryOwnerOnly"/> right
    /// after on Windows. An existing directory that others can reach is restricted to its owner
    /// when <paramref name="tightenExisting"/> is set, which works when this process owns it (on
    /// POSIX only the group and other bits are cleared, the owner keeps access); otherwise, or
    /// when restricting it fails, the call throws with what to do. Either way the result is
    /// checked with <see cref="EnsureDirectoryOwnerOnly"/>.
    /// </para>
    /// </summary>
    /// <param name="directoryPath">The directory to create or check.</param>
    /// <param name="tightenExisting">
    /// Restrict an existing directory others can reach instead of refusing it. Pass it only for a
    /// directory that is this application's alone: restricting a shared one (the application
    /// directory, or one another account reads through its group) locks that account out.
    /// </param>
    /// <returns>True when an existing directory's permissions were tightened, so the caller can say so.</returns>
    /// <exception cref="IOException">
    /// The directory could not be created, others can reach it and it was not to be tightened,
    /// or it could not be tightened.
    /// </exception>
    public static bool EnsureOwnerOnlyDirectory(string directoryPath, bool tightenExisting)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        if (!Directory.Exists(directoryPath))
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directoryPath);
                ApplyWindowsDirectoryOwnerOnlyAcl(directoryPath);
            }
            else
            {
                Directory.CreateDirectory(directoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            EnsureDirectoryOwnerOnly(directoryPath);
            return false;
        }

        try
        {
            EnsureDirectoryOwnerOnly(directoryPath);
            return false;
        }
        catch (IOException loose)
        {
            if (!tightenExisting)
                throw new IOException($"{loose.Message} Other local users can reach it. {OwnerOnlyInstructions(directoryPath)}", loose);
        }

        try
        {
            if (OperatingSystem.IsWindows())
            {
                ApplyWindowsDirectoryOwnerOnlyAcl(directoryPath);
            }
            else
            {
                const UnixFileMode ownerBits = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
                File.SetUnixFileMode(directoryPath, ownerBits);
            }
            EnsureDirectoryOwnerOnly(directoryPath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or PrivilegeNotHeldException)
        {
            throw new IOException(
                $"'{directoryPath}' can be reached by other local users and could not be restricted to its owner: {ex.Message} "
                + OwnerOnlyInstructions(directoryPath), ex);
        }
    }

    /// <summary>What an operator does about a directory others can reach, for the messages of <see cref="EnsureOwnerOnlyDirectory"/>.</summary>
    private static string OwnerOnlyInstructions(string directoryPath) => OperatingSystem.IsWindows()
        ? $"Restrict '{directoryPath}' to the service account and Administrators, with inheritance from its parent turned off."
        : $"Make the service account its owner and restrict it to that account, for example 'chown <service user> \"{directoryPath}\" && chmod 700 \"{directoryPath}\"' as root.";

    /// <summary>
    /// Throws unless <paramref name="directoryPath"/> is reachable by its owner alone. On POSIX
    /// no group or other permission bit may be set. On Windows the DACL must not inherit from the
    /// parent folder and may allow access only to the current user and the local Administrators
    /// group, as <see cref="SetDirectoryOwnerOnly"/> leaves it.
    /// </summary>
    /// <param name="directoryPath">The directory to check.</param>
    /// <exception cref="IOException">Someone other than the owner can reach the directory.</exception>
    public static void EnsureDirectoryOwnerOnly(string directoryPath)
    {
        if (OperatingSystem.IsWindows())
        {
            EnsureWindowsDirectoryOwnerOnly(directoryPath);
            return;
        }

        const UnixFileMode othersBits = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        var mode = File.GetUnixFileMode(directoryPath);
        if ((mode & othersBits) != 0)
            throw new IOException($"'{directoryPath}' is not restricted to its owner (mode {Convert.ToString((int)mode, 8)}).");
    }

    /// <summary>
    /// Windows half of <see cref="EnsureDirectoryOwnerOnly"/>: the DACL is protected from
    /// inheritance and every Allow rule names the current user or the local Administrators group.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void EnsureWindowsDirectoryOwnerOnly(string directoryPath)
    {
        var security = new DirectoryInfo(directoryPath).GetAccessControl();
        if (!security.AreAccessRulesProtected)
            throw new IOException($"'{directoryPath}' inherits permissions from its parent folder.");

        var currentUserSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot resolve current Windows user SID.");
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            currentUserSid.Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value))
                throw new IOException($"'{directoryPath}' grants access to {rule.IdentityReference.Value}.");
        }
    }

    /// <summary>
    /// Directory counterpart of <see cref="ApplyWindowsOwnerOnlyAcl"/>: replaces the DACL with
    /// explicit Allow ACEs for the current user and local Administrators, disables inheritance,
    /// and marks the entries inheritable so files created inside are covered too.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsDirectoryOwnerOnlyAcl(string directoryPath)
    {
        var dirInfo = new DirectoryInfo(directoryPath);
        var security = dirInfo.GetAccessControl();

        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var existing = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in existing)
            security.RemoveAccessRule(rule);

        var currentUserSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot resolve current Windows user SID.");
        var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        // ContainerInherit | ObjectInherit so everything staged inside inherits the restriction.
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        foreach (var sid in new[] { currentUserSid, administratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        dirInfo.SetAccessControl(security);
    }

    /// <summary>
    /// Replaces the file's DACL with explicit Allow ACEs for the current user and
    /// the local Administrators group, removing inheritance and any pre-existing ACEs.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsOwnerOnlyAcl(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        var security = fileInfo.GetAccessControl();

        // Disable inheritance and clear any inherited ACEs (do not preserve).
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        // Strip any explicit ACEs that were left behind.
        var existing = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in existing)
            security.RemoveAccessRule(rule);

        var currentUserSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Cannot resolve current Windows user SID.");
        var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        security.AddAccessRule(new FileSystemAccessRule(
            currentUserSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            administratorsSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        fileInfo.SetAccessControl(security);
    }
}
