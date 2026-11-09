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
}
