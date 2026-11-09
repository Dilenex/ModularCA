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
    /// <see cref="WriteOwnerOnly(string, byte[])"/>, which never leaves it readable in between.
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
    /// Writes a secret file so that it is never readable by anyone but its owner, not even for the
    /// moment between creating it and tightening it. A new file is created with mode 0600 through
    /// <see cref="FileStreamOptions.UnixCreateMode"/>; an existing file is tightened before the new
    /// contents go in and then truncated and rewritten. On Windows the owner-only DACL of
    /// <see cref="SetOwnerOnly"/> is applied as well. Failures to restrict permissions are
    /// reported as warnings, as in <see cref="SetOwnerOnly"/>; failures to write throw.
    /// </summary>
    /// <param name="filePath">The file to create or replace.</param>
    /// <param name="contents">The bytes to write.</param>
    public static void WriteOwnerOnly(string filePath, byte[] contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        if (File.Exists(filePath))
            SetOwnerOnly(filePath);

        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(filePath, options))
            stream.Write(contents);
        SetOwnerOnly(filePath);
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
        if (replaceExisting && File.Exists(filePath))
            File.Delete(filePath);

        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(filePath, options))
            stream.Write(contents);
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
