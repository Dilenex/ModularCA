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

    [Fact]
    public void WriteOwnerOnly_creates_a_secret_file_owner_only_with_its_contents()
    {
        var file = Path.Combine(_root, "backup.key");
        var key = new byte[] { 1, 2, 3, 4 };

        FileSecurityUtil.WriteOwnerOnly(file, key);

        Assert.Equal(key, File.ReadAllBytes(file));
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(file, isDirectory: false);
            return;
        }
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
    }

    [Fact]
    public void WriteOwnerOnly_replaces_an_existing_file_and_tightens_it()
    {
        var file = Path.Combine(_root, "keystore.yaml");
        File.WriteAllText(file, "old contents that are longer than the new ones");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        FileSecurityUtil.WriteOwnerOnly(file, "ks: secret\n");

        Assert.Equal("ks: secret\n", File.ReadAllText(file));
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(file, isDirectory: false);
            return;
        }
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
    }

    /// <summary>
    /// Tightening never grants: a file its owner made read-only is refused, not rewritten. Until
    /// 0.4.3's release run, WriteOwnerOnly set an existing file to 0600 before writing, which on
    /// POSIX gave a read-only file its write bit back and overwrote it (the migrate tool's
    /// ConfigUpdateTests caught it on Linux).
    /// </summary>
    [Fact]
    public void WriteOwnerOnly_refuses_a_file_its_owner_made_read_only()
    {
        var file = Path.Combine(_root, "db.yaml");
        File.WriteAllText(file, "kept");
        if (OperatingSystem.IsWindows())
            File.SetAttributes(file, FileAttributes.ReadOnly);
        else
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => FileSecurityUtil.WriteOwnerOnly(file, "replaced"));
            Assert.Equal("kept", File.ReadAllText(file));
            if (!OperatingSystem.IsWindows())
                Assert.Equal(UnixFileMode.UserRead, File.GetUnixFileMode(file)); // still restricted to its owner
        }
        finally
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
    }

    /// <summary>
    /// Bug hunt 2026-11, X2: decrypted keys and archives go into a NEW owner-only file. The
    /// unlocker wrote an empty file, restricted it, then wrote into it, and restore wrote the
    /// archive and restricted it afterwards; either way a descriptor opened in that window kept
    /// reading after the chmod.
    /// </summary>
    [Fact]
    public void CreateOwnerOnly_creates_a_new_owner_only_file()
    {
        var file = Path.Combine(_root, "entry.p8");
        var key = new byte[] { 9, 8, 7 };

        FileSecurityUtil.CreateOwnerOnly(file, key);

        Assert.Equal(key, File.ReadAllBytes(file));
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(file, isDirectory: false);
            return;
        }
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
    }

    /// <summary>A file someone else put at the path first is refused, not written into.</summary>
    [Fact]
    public void CreateOwnerOnly_refuses_a_file_that_is_already_there()
    {
        var file = Path.Combine(_root, "modularca-restore.zip");
        File.WriteAllText(file, "planted");

        Assert.Throws<IOException>(() => FileSecurityUtil.CreateOwnerOnly(file, [1, 2, 3]));
        Assert.Equal("planted", File.ReadAllText(file));
    }

    /// <summary>
    /// Asked to replace, it writes a new file: a reader that held the old one open sees the old
    /// contents, never the key.
    /// </summary>
    [Fact]
    public void CreateOwnerOnly_replaces_with_a_new_file_that_an_open_reader_does_not_see()
    {
        if (OperatingSystem.IsWindows()) return; // an open file cannot be deleted on Windows
        var file = Path.Combine(_root, "unlocked.p8");
        File.WriteAllText(file, "old");
        using var reader = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        FileSecurityUtil.CreateOwnerOnly(file, [1, 2, 3], replaceExisting: true);

        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(file));
        using var old = new StreamReader(reader);
        Assert.Equal("old", old.ReadToEnd());
    }

    [Fact]
    public void Bootstrap_writes_keystore_yaml_owner_only_with_one_line_per_keystore()
    {
        ModularCA.Bootstrap.BootstrapKeystoreWriter.WriteKeystorePasswordsToFile(
            _root,
            new Dictionary<string, string> { ["ca"] = "p1", ["sys"] = "p2" },
            new Dictionary<string, string> { ["ca"] = "s1" });

        var file = Path.Combine(_root, "keystore.yaml");
        Assert.Equal(new[] { "ca: s1", "sys: " }, File.ReadAllLines(file));
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
