using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Keystore.Services;

/// <summary>
/// The record the signer's command-line tools leave. <c>--backup</c> and <c>--restore</c> run
/// with <c>--role signer --signer-dir &lt;dir&gt;</c> are a process of their own, beside the
/// signer and with the signer's files; they cannot reach the audit database any more than the
/// signer can. They append to the keystore audit journal in the signer's directory
/// (<see cref="KeystoreAuditJournal"/>), which the node reads over the signer channel at its next
/// pass and writes into the audit trail: one <c>BackupCreated</c> or <c>BackupRestored</c> event
/// with the outcome, and, because the journal is opened first, the keystore events the tool
/// itself raises (the keystores loaded for a backup, an unlock that failed).
/// </summary>
/// <remarks>
/// Without <c>--signer-dir</c> there is no journal and nothing here writes: the tool's keystore
/// events go to <c>logs/</c> as before. An event holds the archive's file name and the exit
/// code, never the backup password or a passphrase.
/// </remarks>
public static class SignerToolJournal
{
    private const int MaxNameLength = 200;

    /// <summary>
    /// Opens the journal of the signer directory <paramref name="paths"/> names and points the
    /// keystore service's events of this process at it; null in the shared layout, which has
    /// none. Never throws: what could not be prepared goes to <paramref name="warn"/>.
    /// </summary>
    public static KeystoreAuditJournal? Open(SignerPaths paths, Action<string>? warn = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return paths.AuditJournalDirectory is { } directory
            ? KeystoreAuditJournal.Open(directory, paths.LogsDirectory, warn)
            : null;
    }

    /// <summary>
    /// Runs a command-line backup and appends its outcome to <paramref name="journal"/> as
    /// <see cref="AuditActionType.BackupCreated"/>; with no journal it only runs the backup.
    /// </summary>
    /// <param name="journal">The signer's journal, or null in the shared layout.</param>
    /// <param name="outputPath">The archive path the operator gave, or null for the configured one.</param>
    /// <param name="backup">The backup; returns its exit code.</param>
    /// <returns>The backup's exit code.</returns>
    public static Task<int> BackupAsync(KeystoreAuditJournal? journal, string? outputPath, Func<Task<int>> backup)
        => RunAsync(journal, AuditActionType.BackupCreated, backup, outcome =>
            "Command-line backup run on the signer: " + outcome
            + (string.IsNullOrWhiteSpace(outputPath) ? "; archive in the configured backup directory" : $"; archive {FileName(outputPath)}"));

    /// <summary>
    /// Runs a command-line restore and appends its outcome to <paramref name="journal"/> as
    /// <see cref="AuditActionType.BackupRestored"/>; with no journal it only runs the restore.
    /// </summary>
    /// <param name="journal">The signer's journal, or null in the shared layout.</param>
    /// <param name="archivePath">The archive restored from.</param>
    /// <param name="restoreAudit">Whether the archive's audit database was asked to replace this host's.</param>
    /// <param name="restore">The restore; returns its exit code.</param>
    /// <returns>The restore's exit code.</returns>
    public static Task<int> RestoreAsync(KeystoreAuditJournal? journal, string archivePath, bool restoreAudit, Func<Task<int>> restore)
        => RunAsync(journal, AuditActionType.BackupRestored, restore, outcome =>
            $"Command-line restore run on the signer from {FileName(archivePath)}: {outcome}; "
            + (restoreAudit ? "asked to replace the audit history with the archive copy" : "asked to keep the audit history"));

    /// <summary>
    /// Runs <paramref name="operation"/> and appends one event saying how it ended: the exit
    /// code, or the type of the exception it threw, which is then rethrown. Only the type is
    /// recorded; an exception's message is not, since it is not written with the journal in mind.
    /// </summary>
    private static async Task<int> RunAsync(KeystoreAuditJournal? journal, string action, Func<Task<int>> operation, Func<string, string> detail)
    {
        ArgumentNullException.ThrowIfNull(operation);
        int exitCode;
        try
        {
            exitCode = await operation();
        }
        catch (Exception ex)
        {
            journal?.Append(action, keystoreName: null, success: false, detail($"stopped by {ex.GetType().Name}"));
            throw;
        }
        journal?.Append(action, keystoreName: null, success: exitCode == 0, detail($"exit code {exitCode}"));
        return exitCode;
    }

    /// <summary>The file name of a path the operator typed, held to a length; never the directory.</summary>
    private static string FileName(string? path)
    {
        var name = Path.GetFileName(path ?? string.Empty);
        if (string.IsNullOrWhiteSpace(name))
            return "(unnamed)";
        return name.Length <= MaxNameLength ? name : name[..MaxNameLength];
    }
}
