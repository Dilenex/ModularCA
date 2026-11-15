using System.Text.Json;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// What the last run of <see cref="BackupVerificationJob"/> found, kept as the small file
/// <see cref="FileName"/> in the backup directory so that it outlives the process and is the same
/// for every process that shares the directory. Readers that must not verify anything themselves
/// (the hub's inventory) read it. It names archives and says whether each passed; it holds nothing
/// from inside an archive.
/// </summary>
/// <param name="VerifiedAtUtc">When the run checked the archives.</param>
/// <param name="Archives">Each archive the run checked, newest first.</param>
public sealed record BackupVerificationRecord(DateTime VerifiedAtUtc, IReadOnlyList<BackupVerificationRecord.Archive> Archives)
{
    /// <summary>
    /// The record's file name. It does not match <c>modularca-backup-*</c>, so nothing that lists,
    /// prunes or restores archives takes it for one.
    /// </summary>
    public const string FileName = "backup-verification.json";

    /// <summary>One archive and what the run found.</summary>
    /// <param name="FileName">The archive's file name.</param>
    /// <param name="Valid">Whether it passed the integrity checks.</param>
    public sealed record Archive(string FileName, bool Valid);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Writes the record into <paramref name="backupDirectory"/>, replacing the one before: to a
    /// temporary name first and then moved into place, so a reader never sees half a file.
    /// Throws what the file system throws; the caller decides whether that matters.
    /// </summary>
    /// <param name="backupDirectory">The backup directory.</param>
    /// <param name="record">What the run found.</param>
    public static void Write(string backupDirectory, BackupVerificationRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var path = Path.Combine(backupDirectory, FileName);
        var temporary = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(record, Json));
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Reads the record from <paramref name="backupDirectory"/>. Null when there is none (the job
    /// has not run since this build, or the directory is missing) or it cannot be read or parsed:
    /// "not verified" is the only honest reading of a record that is not there.
    /// </summary>
    /// <param name="backupDirectory">The backup directory.</param>
    public static BackupVerificationRecord? TryRead(string backupDirectory)
    {
        try
        {
            var path = Path.Combine(backupDirectory, FileName);
            if (!File.Exists(path)) return null;
            var record = JsonSerializer.Deserialize<BackupVerificationRecord>(File.ReadAllText(path), Json);
            return record?.Archives == null ? null : record;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }
}
