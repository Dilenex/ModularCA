using System.Security.AccessControl;
using ModularCA.Bootstrap;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// A backup stages its plaintext dumps, keystores and configuration in a directory with an
/// unpredictable name that is owner-only from the moment it exists. It used to stage in
/// <c>/tmp/modularca-backup-&lt;timestamp&gt;</c>: another local user could create that directory
/// first, the backup reused it silently, and failing to restrict it was only a warning.
/// </summary>
public sealed class BackupStagingDirectoryTests
{
    [Fact]
    public void The_backup_stages_in_a_fresh_owner_only_directory_with_an_unpredictable_name()
    {
        var predictable = $"modularca-backup-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        var first = BackupRestore.CreateBackupStagingDirectory();
        var second = BackupRestore.CreateBackupStagingDirectory();
        try
        {
            Assert.NotEqual(first, second);
            foreach (var dir in new[] { first, second })
            {
                var name = Path.GetFileName(dir);
                Assert.StartsWith("modularca-backup-", name);
                Assert.NotEqual(predictable, name);
                Assert.Empty(Directory.EnumerateFileSystemEntries(dir));

                if (OperatingSystem.IsWindows())
                    Assert.True(new DirectoryInfo(dir).GetAccessControl().AreAccessRulesProtected,
                        "the staging directory must not inherit its parent folder's permissions");
                else
                    Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
            }
        }
        finally
        {
            foreach (var dir in new[] { first, second })
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// The restore's extraction directory and the pre-restore snapshot's staging directory follow
    /// the same rule. They were created at a name and then restricted, and a failure to restrict
    /// was only a warning, so the archive's plaintext keys could be expanded where other local
    /// users could read them; a directory that cannot be restricted now throws, which stops the
    /// restore before anything is extracted.
    /// </summary>
    [Theory]
    [InlineData("restore", "modularca-restore-")]
    [InlineData("pre-restore", "modularca-pre-restore-")]
    public void The_restore_stages_in_a_fresh_owner_only_directory(string which, string prefix)
    {
        Func<string> create = which == "restore"
            ? BackupRestore.CreateRestoreStagingDirectory
            : BackupRestore.CreatePreRestoreStagingDirectory;
        var first = create();
        var second = create();
        try
        {
            Assert.NotEqual(first, second);
            foreach (var dir in new[] { first, second })
            {
                Assert.StartsWith(prefix, Path.GetFileName(dir));
                Assert.Empty(Directory.EnumerateFileSystemEntries(dir));
                // The same check the factory makes before it returns, and throws on.
                ModularCA.Shared.Utils.FileSecurityUtil.EnsureDirectoryOwnerOnly(dir);

                if (OperatingSystem.IsWindows())
                    Assert.True(new DirectoryInfo(dir).GetAccessControl().AreAccessRulesProtected,
                        "the staging directory must not inherit its parent folder's permissions");
                else
                    Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
            }
        }
        finally
        {
            foreach (var dir in new[] { first, second })
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// The owner-only check the staging factories rely on refuses a directory others can reach,
    /// rather than warning: one that inherits its parent's permissions on Windows, one with group
    /// or other bits on POSIX.
    /// </summary>
    [Fact]
    public void A_directory_others_can_reach_fails_the_owner_only_check()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"modularca-staging-check-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

            Assert.Throws<IOException>(() => ModularCA.Shared.Utils.FileSecurityUtil.EnsureDirectoryOwnerOnly(dir));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
