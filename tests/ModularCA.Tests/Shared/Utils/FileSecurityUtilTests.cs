using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="FileSecurityUtil.SetDirectoryOwnerOnly"/>, added because the backup and
/// restore paths stage decrypted CA private keys in directories under
/// <see cref="Path.GetTempPath"/>. On Linux that is <c>/tmp</c>, world-readable by default, so
/// every local user could read the keystores for the duration of a backup or restore. The
/// finished archive was already hardened; the plaintext staged beside it was not.
/// <para>
/// Each test asserts on BOTH platforms rather than returning early on one. An early return in a
/// <c>[Fact]</c> is an invisible pass, and a security test that quietly does nothing on the
/// machine you happen to run it on is worse than no test — it reports green either way. POSIX
/// checks the file mode; Windows checks the DACL is protected and grants only the expected two
/// identities.
/// </para>
/// </summary>
public class FileSecurityUtilTests : IDisposable
{
    private readonly string _root;

    public FileSecurityUtilTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "modularca-filesec-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Missing_directory_is_a_no_op_rather_than_a_throw()
    {
        // Callers harden staging directories on paths that also handle failure; a throw here
        // would turn a permissions problem into a failed backup.
        var missing = Path.Combine(_root, "does-not-exist");

        FileSecurityUtil.SetDirectoryOwnerOnly(missing);   // must not throw
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public void A_file_path_is_not_treated_as_a_directory()
    {
        var file = Path.Combine(_root, "a-file.txt");
        File.WriteAllText(file, "x");

        FileSecurityUtil.SetDirectoryOwnerOnly(file);      // must not throw
        Assert.True(File.Exists(file));
    }

    [Fact]
    public void Directory_is_readable_only_by_its_owner()
    {
        var dir = Path.Combine(_root, "staging");
        Directory.CreateDirectory(dir);

        FileSecurityUtil.SetDirectoryOwnerOnly(dir);

        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(dir);
            return;
        }

        var mode = File.GetUnixFileMode(dir);

        // 0700: owner may read, write and traverse.
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            mode);

        // The point of the change. Asserted bit by bit so a future edit that adds one fails
        // here with an obvious message rather than through an opaque equality mismatch.
        foreach (var forbidden in new[]
                 {
                     UnixFileMode.GroupRead, UnixFileMode.GroupWrite, UnixFileMode.GroupExecute,
                     UnixFileMode.OtherRead, UnixFileMode.OtherWrite, UnixFileMode.OtherExecute,
                 })
        {
            Assert.False(mode.HasFlag(forbidden), $"{forbidden} must not be set on a secrets staging directory");
        }
    }

    [Fact]
    public void Directory_remains_usable_after_hardening()
    {
        // 0600 on a directory would make it unusable — the owner could not enter it, and the
        // backup would fail after hardening rather than before. That is the mistake reusing the
        // file-oriented SetOwnerOnly for directories would have made, so it is worth pinning.
        var dir = Path.Combine(_root, "traversable");
        Directory.CreateDirectory(dir);
        FileSecurityUtil.SetDirectoryOwnerOnly(dir);

        var probe = Path.Combine(dir, "inner.txt");
        File.WriteAllText(probe, "still writable");

        Assert.Equal("still writable", File.ReadAllText(probe));
        Assert.Single(Directory.GetFiles(dir));
    }

    [Fact]
    public void File_hardening_still_works_for_the_decrypted_archive()
    {
        var file = Path.Combine(_root, "decrypted.zip");
        File.WriteAllText(file, "pretend archive");

        FileSecurityUtil.SetOwnerOnly(file);

        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(file, isDirectory: false);
            return;
        }

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
    }

    /// <summary>
    /// Windows equivalent of the mode assertions: inheritance is off (so parent-folder ACEs
    /// cannot leak access into a directory holding CA private keys) and the only explicit
    /// grants are the current user and local Administrators.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void AssertWindowsOwnerOnly(string path, bool isDirectory = true)
    {
        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();

        Assert.True(security.AreAccessRulesProtected,
            "inheritance must be disabled so parent-folder ACEs cannot grant access");

        var rules = security
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();

        Assert.NotEmpty(rules);

        var allowed = new[]
        {
            WindowsIdentity.GetCurrent().User!.Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };

        foreach (var rule in rules)
        {
            Assert.Contains(rule.IdentityReference.Value, allowed);
        }
    }
}
