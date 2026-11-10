using System.Text.Json;
using ModularCA.Bootstrap;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The directory a backup archive or pre-restore snapshot is written to, and the directory a
/// wrapped key ring is unpacked into, must be reachable by this account alone. Both only warned
/// when they could not be restricted, and an existing backup directory was left exactly as it was,
/// so archives could be written where other local users could list, replace or delete them, and
/// the unwrapped key ring where they could read it.
/// </summary>
public sealed class BackupDirectoryOwnerOnlyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"mca-owner-only-{Guid.NewGuid():N}");

    /// <summary>Creates the test's root directory.</summary>
    public BackupDirectoryOwnerOnlyTests() => Directory.CreateDirectory(_root);

    /// <summary>Removes the test's root directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    /// <summary>
    /// Creates <paramref name="path"/> so that others can reach it: on POSIX mode 0755, on Windows
    /// the permissions it inherits from the temporary directory.
    /// </summary>
    private static string Loose(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        Assert.Throws<IOException>(() => FileSecurityUtil.EnsureDirectoryOwnerOnly(path));
        return path;
    }

    private static bool IsOwnerOnly(string path)
    {
        try
        {
            FileSecurityUtil.EnsureDirectoryOwnerOnly(path);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    // ── FileSecurityUtil.EnsureOwnerOnlyDirectory ───────────────────────

    /// <summary>A missing directory, and its missing parent, are created owner-only.</summary>
    [Fact]
    public void A_missing_directory_is_created_owner_only()
    {
        var dir = Path.Combine(_root, "parent", "backups");

        Assert.False(FileSecurityUtil.EnsureOwnerOnlyDirectory(dir, tightenExisting: false));

        Assert.True(Directory.Exists(dir));
        Assert.True(IsOwnerOnly(dir));
    }

    /// <summary>An existing directory others can reach is refused, with instructions, and left as it is, unless it may be tightened.</summary>
    [Fact]
    public void An_existing_directory_others_can_reach_is_refused_unless_it_may_be_tightened()
    {
        var dir = Loose(Path.Combine(_root, "shared"));

        var refusal = Assert.Throws<IOException>(() => FileSecurityUtil.EnsureOwnerOnlyDirectory(dir, tightenExisting: false));

        Assert.Contains(dir, refusal.Message);
        Assert.Contains(OperatingSystem.IsWindows() ? "inheritance" : "chmod 700", refusal.Message);
        Assert.False(IsOwnerOnly(dir));
    }

    /// <summary>An existing directory others can reach is restricted to its owner when it may be, and the caller is told.</summary>
    [Fact]
    public void An_existing_directory_others_can_reach_is_tightened_when_it_may_be()
    {
        var dir = Loose(Path.Combine(_root, "backups"));
        File.WriteAllText(Path.Combine(dir, "old.zip"), "x");

        Assert.True(FileSecurityUtil.EnsureOwnerOnlyDirectory(dir, tightenExisting: true));

        Assert.True(IsOwnerOnly(dir));
        Assert.Equal("x", File.ReadAllText(Path.Combine(dir, "old.zip")));
        // Already owner-only: nothing to tighten the second time.
        Assert.False(FileSecurityUtil.EnsureOwnerOnlyDirectory(dir, tightenExisting: true));
    }

    // ── The backup directory ─────────────────────────────────────────────

    /// <summary>
    /// The backup directory others can reach, an upgraded install's <c>backups/</c> say, is
    /// tightened rather than refused, so its backups keep running.
    /// </summary>
    [Fact]
    public void The_backups_own_directory_is_tightened()
    {
        var backups = Loose(Path.Combine(_root, "backups"));

        Assert.True(BackupRestore.EnsureArchiveDirectory(backups, _root, backups));

        Assert.True(IsOwnerOnly(backups));
    }

    /// <summary>A directory an explicit output path names, other than the backup directory, is refused when others can reach it.</summary>
    [Fact]
    public void Another_directory_others_can_reach_is_refused()
    {
        var exports = Loose(Path.Combine(_root, "exports"));

        Assert.Throws<IOException>(() => BackupRestore.EnsureArchiveDirectory(exports, _root, Path.Combine(_root, "backups")));

        Assert.False(IsOwnerOnly(exports));
    }

    /// <summary>
    /// A backup directory that is the application directory (<c>Backup.OutputPath: .</c>) or one
    /// above it, so that it holds <c>config/</c> and the rest, is refused rather than tightened:
    /// restricting it would lock out the accounts and groups that read what is in it.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_backup_directory_shared_with_the_application_is_refused_not_tightened(bool aboveTheApplication)
    {
        var backups = Loose(Path.Combine(_root, "srv"));
        var app = aboveTheApplication ? Loose(Path.Combine(backups, "modularca")) : backups;

        Assert.Throws<IOException>(() => BackupRestore.EnsureArchiveDirectory(backups, app, backups));

        Assert.False(IsOwnerOnly(backups));
    }

    /// <summary>
    /// A backup directory inside <c>config/</c> is the backups' own and is tightened; only the
    /// shared directories themselves, and those above them, are left alone.
    /// </summary>
    [Fact]
    public void A_backup_directory_below_config_is_tightened()
    {
        var backups = Loose(Path.Combine(_root, "config", "backups"));

        Assert.True(BackupRestore.EnsureArchiveDirectory(backups, _root, backups));
        Assert.True(IsOwnerOnly(backups));
    }

    // ── Unpacking a wrapped directory ────────────────────────────────────

    private static byte[] Bundle(string target) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        Version = 1,
        Target = target,
        Files = new Dictionary<string, string> { ["key-1.xml"] = Convert.ToBase64String("<key/>"u8.ToArray()) },
    });

    /// <summary>A missing target is created owner-only and the files written into it.</summary>
    [Fact]
    public void Unpack_creates_its_target_owner_only()
    {
        var config = Path.Combine(_root, "config");
        Directory.CreateDirectory(config);

        BackupWrappedSecrets.Unpack(Bundle("dp-keys"), config);

        Assert.True(IsOwnerOnly(Path.Combine(config, "dp-keys")));
        Assert.Equal("<key/>", File.ReadAllText(Path.Combine(config, "dp-keys", "key-1.xml")));
    }

    /// <summary>
    /// An existing target others can reach, an upgraded install's <c>dp-keys</c> created with the
    /// default mode, is restricted to its owner before the key ring goes in.
    /// </summary>
    [Fact]
    public void Unpack_tightens_an_existing_target_others_can_reach()
    {
        var config = Path.Combine(_root, "config");
        var dpKeys = Loose(Path.Combine(config, "dp-keys"));

        BackupWrappedSecrets.Unpack(Bundle("dp-keys"), config);

        Assert.True(IsOwnerOnly(dpKeys));
        Assert.True(File.Exists(Path.Combine(dpKeys, "key-1.xml")));
    }
}
