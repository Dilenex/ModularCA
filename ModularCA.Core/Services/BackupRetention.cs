namespace ModularCA.Core.Services;

/// <summary>
/// The one rule by which backup archives are pruned from the backup directory. The scheduled
/// backup, the console's "Create backup" and the hub's <c>backup.prune</c> all call it, so an
/// archive is kept or deleted for the same reasons whoever asks.
/// </summary>
/// <remarks>
/// <para>
/// The archives are the files named <c>modularca-backup-*.zip</c> and
/// <c>modularca-backup-*.enc</c> directly in the directory, ordered by creation time, newest
/// first. Nothing else in the directory is touched; a pre-restore snapshot is not a backup
/// archive.
/// </para>
/// <para>
/// An archive is deleted when it lies beyond the newest <c>keepCount</c>, or is older than
/// <c>maxAge</c>, with two exceptions that always win: the newest archive is never deleted, and
/// an archive younger than <c>minimumRetentionDays</c> is never deleted
/// (<see cref="ModularCA.Shared.Models.Config.BackupConfig.MinimumRetentionDays"/>, the floor that
/// stops a flood of backup requests from purging weeks of archives in seconds).
/// </para>
/// </remarks>
public static class BackupRetention
{
    /// <summary>One archive in the backup directory.</summary>
    /// <param name="FileName">The file's name.</param>
    /// <param name="SizeBytes">Its size.</param>
    /// <param name="CreatedAtUtc">When the file was created.</param>
    public sealed record Archive(string FileName, long SizeBytes, DateTime CreatedAtUtc);

    /// <summary>What one pruning did.</summary>
    /// <param name="Deleted">The archives deleted, newest first.</param>
    /// <param name="Remaining">The archives still in the directory afterwards, newest first.</param>
    /// <param name="KeptByMinimumRetention">Archives the rule would have deleted that the minimum retention floor kept; they are among <paramref name="Remaining"/>.</param>
    /// <param name="Failed">Archives the rule selected that could not be deleted, with the reason; they are among <paramref name="Remaining"/>.</param>
    public sealed record Result(
        IReadOnlyList<Archive> Deleted,
        IReadOnlyList<Archive> Remaining,
        IReadOnlyList<Archive> KeptByMinimumRetention,
        IReadOnlyList<(Archive Archive, string Error)> Failed);

    /// <summary>The backup archives in <paramref name="backupDirectory"/>, newest first; none when the directory does not exist.</summary>
    /// <param name="backupDirectory">The backup directory.</param>
    public static IReadOnlyList<FileInfo> Archives(string backupDirectory)
    {
        var directory = new DirectoryInfo(backupDirectory);
        if (!directory.Exists)
            return [];
        return directory.GetFiles("modularca-backup-*.zip")
            .Concat(directory.GetFiles("modularca-backup-*.enc"))
            .OrderByDescending(f => f.CreationTimeUtc)
            .ThenByDescending(f => f.Name, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>What the rule selects, before anything is deleted.</summary>
    /// <param name="ToDelete">The archives the rule deletes, newest first.</param>
    /// <param name="ToKeep">The archives it keeps, newest first.</param>
    /// <param name="KeptByMinimumRetention">Archives it would have deleted that the minimum retention floor keeps; they are among <paramref name="ToKeep"/>.</param>
    public sealed record Selection(
        IReadOnlyList<FileInfo> ToDelete,
        IReadOnlyList<FileInfo> ToKeep,
        IReadOnlyList<FileInfo> KeptByMinimumRetention);

    /// <summary>
    /// Applies the rule of this class to the backup directory without deleting anything: which
    /// archives go and which stay. <see cref="Delete"/> carries a selection out.
    /// </summary>
    /// <param name="backupDirectory">The backup directory.</param>
    /// <param name="keepCount">
    /// How many of the newest archives to keep; null sets no limit by count. Zero or less prunes
    /// nothing by count, as <c>Backup.RetentionCount</c> has always been read.
    /// </param>
    /// <param name="maxAge">Archives created longer ago than this are deleted; null sets no limit by age.</param>
    /// <param name="minimumRetentionDays">The floor in days; zero or less turns it off.</param>
    /// <param name="nowUtc">The time ages are measured from.</param>
    public static Selection Select(string backupDirectory, int? keepCount, TimeSpan? maxAge, int minimumRetentionDays, DateTime nowUtc)
    {
        var files = Archives(backupDirectory);
        var minDays = Math.Max(0, minimumRetentionDays);
        var floor = nowUtc.AddDays(-minDays);
        DateTime? oldest = maxAge is { } age ? nowUtc - age : null;

        var toDelete = new List<FileInfo>();
        var toKeep = new List<FileInfo>();
        var keptByFloor = new List<FileInfo>();
        for (var i = 0; i < files.Count; i++)
        {
            var file = files[i];
            // The newest archive is never selected, whatever was asked.
            var selected = i > 0
                && ((keepCount is > 0 && i >= keepCount)
                    || (oldest is { } cutoff && file.CreationTimeUtc < cutoff));
            if (selected && minDays > 0 && file.CreationTimeUtc > floor)
            {
                keptByFloor.Add(file);
                selected = false;
            }
            (selected ? toDelete : toKeep).Add(file);
        }
        return new Selection(toDelete, toKeep, keptByFloor);
    }

    /// <summary>
    /// Deletes what <paramref name="selection"/> selected and returns what was deleted and what
    /// remains. A file that cannot be deleted is reported and does not stop the rest.
    /// </summary>
    /// <param name="selection">The selection, from <see cref="Select"/>.</param>
    public static Result Delete(Selection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        static Archive Describe(FileInfo file) => new(file.Name, file.Length, file.CreationTimeUtc);

        var deleted = new List<Archive>();
        var remaining = selection.ToKeep.Select(Describe).ToList();
        var failed = new List<(Archive, string)>();
        foreach (var file in selection.ToDelete)
        {
            var archive = Describe(file);
            try
            {
                file.Delete();
                deleted.Add(archive);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                failed.Add((archive, ex.Message));
                remaining.Add(archive);
            }
        }
        remaining.Sort((a, b) => b.CreatedAtUtc.CompareTo(a.CreatedAtUtc));
        return new Result(deleted, remaining, selection.KeptByMinimumRetention.Select(Describe).ToList(), failed);
    }

    /// <summary>
    /// Prunes the backup directory by the rule of this class and returns what was deleted and
    /// what remains: <see cref="Select"/>, then <see cref="Delete"/>.
    /// </summary>
    /// <param name="backupDirectory">The backup directory.</param>
    /// <param name="keepCount">How many of the newest archives to keep; null sets no limit by count, and zero or less prunes nothing by count.</param>
    /// <param name="maxAge">Archives created longer ago than this are deleted; null sets no limit by age.</param>
    /// <param name="minimumRetentionDays">The floor in days; zero or less turns it off.</param>
    /// <param name="nowUtc">The time ages are measured from.</param>
    public static Result Apply(string backupDirectory, int? keepCount, TimeSpan? maxAge, int minimumRetentionDays, DateTime nowUtc)
        => Delete(Select(backupDirectory, keepCount, maxAge, minimumRetentionDays, nowUtc));
}
