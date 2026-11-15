using ModularCA.Core.Services;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The one rule backup archives are pruned by (<see cref="BackupRetention"/>), over real files.
/// The files are created one after another, so their creation times are in that order, and the
/// tests move the clock the rule measures from instead of rewriting a file's creation time,
/// which a Linux file system does not allow.
/// </summary>
public sealed class BackupRetentionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mca-retention-" + Guid.NewGuid().ToString("N")[..12]);

    /// <summary>Creates the backup directory.</summary>
    public BackupRetentionTests() => Directory.CreateDirectory(_dir);

    /// <summary>Removes it.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Creates archives oldest first and returns their names in that order.</summary>
    private List<string> Create(int count, string extension = ".enc", int from = 1)
    {
        var names = new List<string>();
        for (var i = from; i < from + count; i++)
        {
            var name = $"modularca-backup-2026010{i}-020000-{Guid.NewGuid():N}{extension}";
            File.WriteAllText(Path.Combine(_dir, name), new string('x', i));
            names.Add(name);
            Thread.Sleep(40);
        }
        return names;
    }

    private List<string> OnDisk() => Directory.GetFiles(_dir).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList()!;

    [Fact]
    public void The_newest_archives_are_kept_and_the_rest_deleted_oldest_last_in_the_answer()
    {
        var names = Create(5);

        var pruned = BackupRetention.Apply(_dir, keepCount: 2, maxAge: null, minimumRetentionDays: 0, DateTime.UtcNow);

        Assert.Equal([names[2], names[1], names[0]], pruned.Deleted.Select(a => a.FileName));
        Assert.Equal([names[4], names[3]], pruned.Remaining.Select(a => a.FileName));
        Assert.Empty(pruned.KeptByMinimumRetention);
        Assert.Empty(pruned.Failed);
        Assert.Equal(new[] { names[3], names[4] }.Order(StringComparer.Ordinal), OnDisk());
        Assert.Equal(5, pruned.Remaining[0].SizeBytes);
    }

    [Fact]
    public void The_newest_archive_is_never_deleted_however_old_it_is()
    {
        var names = Create(3);

        var pruned = BackupRetention.Apply(_dir, keepCount: null, maxAge: TimeSpan.FromDays(1), minimumRetentionDays: 0, DateTime.UtcNow.AddDays(400));

        Assert.Equal([names[2]], pruned.Remaining.Select(a => a.FileName));
        Assert.Equal(2, pruned.Deleted.Count);
        Assert.Equal([names[2]], OnDisk());
    }

    [Fact]
    public void An_archive_older_than_the_age_is_deleted_and_a_younger_one_is_not()
    {
        var old = Create(2);
        Thread.Sleep(400);
        var between = DateTime.UtcNow;
        Thread.Sleep(400);
        var recent = Create(2, from: 3);

        var now = DateTime.UtcNow;
        var pruned = BackupRetention.Apply(_dir, keepCount: null, maxAge: now - between, minimumRetentionDays: 0, now);

        Assert.Equal(old.Order(StringComparer.Ordinal), pruned.Deleted.Select(a => a.FileName).Order(StringComparer.Ordinal));
        Assert.Equal(recent.Order(StringComparer.Ordinal), OnDisk());
    }

    [Fact]
    public void With_a_count_and_an_age_an_archive_goes_when_either_selects_it()
    {
        var names = Create(4);

        // By count alone the three newest stay; by age all but the newest go.
        var pruned = BackupRetention.Apply(_dir, keepCount: 3, maxAge: TimeSpan.FromDays(1), minimumRetentionDays: 0, DateTime.UtcNow.AddDays(30));

        Assert.Equal([names[3]], pruned.Remaining.Select(a => a.FileName));
        Assert.Equal(3, pruned.Deleted.Count);
    }

    [Fact]
    public void An_archive_younger_than_the_minimum_retention_is_kept_and_said_to_be()
    {
        var names = Create(4);

        var young = BackupRetention.Apply(_dir, keepCount: 1, maxAge: null, minimumRetentionDays: 3, DateTime.UtcNow);

        Assert.Empty(young.Deleted);
        Assert.Equal(4, young.Remaining.Count);
        Assert.Equal([names[2], names[1], names[0]], young.KeptByMinimumRetention.Select(a => a.FileName));
        Assert.Equal(4, OnDisk().Count);

        // The same request once they are older than the floor.
        var aged = BackupRetention.Apply(_dir, keepCount: 1, maxAge: null, minimumRetentionDays: 3, DateTime.UtcNow.AddDays(4));

        Assert.Equal(3, aged.Deleted.Count);
        Assert.Empty(aged.KeptByMinimumRetention);
        Assert.Equal([names[3]], OnDisk());
    }

    [Fact]
    public void Only_backup_archives_are_touched()
    {
        Create(2, ".enc");
        Create(2, ".zip", from: 3);
        var others = new[] { "pre-restore-20260101-000000.zip", "notes.txt", "modularca-backup-20260101.tar", "other-backup.enc" };
        foreach (var other in others)
            File.WriteAllText(Path.Combine(_dir, other), "kept");
        Directory.CreateDirectory(Path.Combine(_dir, "modularca-backup-directory.enc"));

        var pruned = BackupRetention.Apply(_dir, keepCount: 1, maxAge: null, minimumRetentionDays: 0, DateTime.UtcNow);

        Assert.Equal(3, pruned.Deleted.Count);
        Assert.Single(pruned.Remaining);
        Assert.All(others, other => Assert.True(File.Exists(Path.Combine(_dir, other))));
        Assert.True(Directory.Exists(Path.Combine(_dir, "modularca-backup-directory.enc")));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-3)]
    public void A_count_of_zero_or_less_prunes_nothing_as_the_retention_setting_has_always_been_read(int keepCount)
    {
        Create(3);

        var pruned = BackupRetention.Apply(_dir, keepCount, maxAge: null, minimumRetentionDays: 0, DateTime.UtcNow);

        Assert.Empty(pruned.Deleted);
        Assert.Equal(3, OnDisk().Count);
    }

    [Fact]
    public void Selecting_deletes_nothing_and_a_directory_that_is_not_there_holds_no_archives()
    {
        Create(3);

        var selection = BackupRetention.Select(_dir, keepCount: 1, maxAge: null, minimumRetentionDays: 0, DateTime.UtcNow);

        Assert.Equal(2, selection.ToDelete.Count);
        Assert.Equal(3, OnDisk().Count);
        Assert.Empty(BackupRetention.Archives(Path.Combine(_dir, "absent")));
        Assert.Empty(BackupRetention.Apply(Path.Combine(_dir, "absent"), 1, null, 0, DateTime.UtcNow).Remaining);
    }
}
