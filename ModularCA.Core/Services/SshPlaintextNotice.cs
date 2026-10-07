using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>One SSH CA key that was a plaintext file on the node and has been imported into the signer.</summary>
/// <param name="Id">The <c>SshCaKeys</c> row.</param>
/// <param name="Name">The key's name when it was imported.</param>
/// <param name="Fingerprint">The SHA-256 fingerprint of its public key.</param>
/// <param name="ImportedAt">When it was imported.</param>
/// <param name="File">The file it was read from, on the host that imported it.</param>
/// <param name="FileRemoved">Whether that file has been overwritten and deleted.</param>
public sealed record SshPlaintextNoticeEntry(Guid Id, string Name, string Fingerprint, DateTime ImportedAt, string File, bool FileRemoved);

/// <summary>A backup archive or pre-restore snapshot written before the last import.</summary>
/// <param name="Name">The file's name in the backup directory.</param>
/// <param name="WrittenAt">When it was last written.</param>
public sealed record SshPlaintextNoticeArchive(string Name, DateTime WrittenAt);

/// <summary>
/// The notice that this install kept SSH CA keys in plaintext before the signer held them
/// (<c>docs/architecture/ssh-keystore.md</c>, "Deleting the files").
/// </summary>
/// <param name="Applies">Whether any key was, or still is, a plaintext file on the node.</param>
/// <param name="Imported">The keys that were imported, oldest import first.</param>
/// <param name="AwaitingImport">How many keys are still files on the node.</param>
/// <param name="FirstImportedAt">When the first key was imported; null when none has been.</param>
/// <param name="LastImportedAt">When the last key was imported; null when none has been.</param>
/// <param name="EarlierArchives">The files in the backup directory written before the last import, which may still hold the keys.</param>
/// <param name="Message">The notice, for the operator.</param>
public sealed record SshPlaintextNotice(bool Applies, IReadOnlyList<SshPlaintextNoticeEntry> Imported, int AwaitingImport,
    DateTime? FirstImportedAt, DateTime? LastImportedAt, IReadOnlyList<SshPlaintextNoticeArchive> EarlierArchives, string Message);

/// <summary>
/// Reads the plaintext notice from the import records, which the import writes in the
/// transaction that switches a key's row to the signer. They are in the application database,
/// so the notice outlives the key files, audit retention and a wiped audit database, and
/// travels with a backup.
/// </summary>
public static class SshPlaintextNotices
{
    /// <summary>What the operator is told. This release informs only; it does not rotate.</summary>
    public const string Text =
        "These SSH CA keys were stored on the node in plaintext before the signer held them. Backup archives and pre-restore "
        + "snapshots made before they were imported still contain them, and overwriting a file does not guarantee it is erased on "
        + "solid-state drives, copy-on-write filesystems, virtual machine snapshots or filesystem backups. Rotating an SSH CA, "
        + "which is a new SSH CA and new trust lines on the servers, is the only remedy. It is recommended, and it is your decision.";

    /// <summary>The most archive names a notice lists.</summary>
    private const int MaxArchives = 200;

    /// <summary>
    /// Reads the notice. With <paramref name="backupDirectory"/>, also names the archives
    /// (<c>*.enc</c>, <c>*.zip</c>) in it that were written before the last import; a directory
    /// that cannot be listed yields none.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="backupDirectory">The backup directory, or null to name no archive.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<SshPlaintextNotice> ReadAsync(ModularCADbContext db, string? backupDirectory, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var imported = (await db.SshKeyImports.AsNoTracking().OrderBy(i => i.ImportedAt).ThenBy(i => i.Name).ToListAsync(cancellationToken))
            .Select(i => new SshPlaintextNoticeEntry(i.SshCaKeyId, i.Name, i.Fingerprint, i.ImportedAt, i.FilePath, i.FileRemovedAt != null))
            .ToList();
        var awaiting = await db.SshCaKeys.AsNoTracking().CountAsync(k => k.KeyStorage == SshCaKeyStorage.LegacyFile, cancellationToken);

        DateTime? first = imported.Count > 0 ? imported[0].ImportedAt : null;
        DateTime? last = imported.Count > 0 ? imported[^1].ImportedAt : null;
        var archives = last is { } before && backupDirectory != null ? ArchivesBefore(backupDirectory, before) : [];
        return new SshPlaintextNotice(imported.Count > 0 || awaiting > 0, imported, awaiting, first, last, archives, Text);
    }

    /// <summary>
    /// The archives and snapshots in <paramref name="directory"/> last written before
    /// <paramref name="before"/>, newest first, at most <see cref="MaxArchives"/>.
    /// </summary>
    internal static IReadOnlyList<SshPlaintextNoticeArchive> ArchivesBefore(string directory, DateTime before)
    {
        try
        {
            var info = new DirectoryInfo(directory);
            if (!info.Exists)
                return [];
            return info.EnumerateFiles("*", SearchOption.TopDirectoryOnly)
                .Where(f => f.Extension.Equals(".enc", StringComparison.OrdinalIgnoreCase) || f.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                .Where(f => f.LastWriteTimeUtc < before)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Take(MaxArchives)
                .Select(f => new SshPlaintextNoticeArchive(f.Name, f.LastWriteTimeUtc))
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return [];
        }
    }
}
