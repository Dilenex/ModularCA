using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The signer's command-line backup and restore (<c>--role signer --signer-dir</c>) are a
/// process beside the signer and used to leave no record: the keystore events they raised went
/// to a <c>logs/</c> nothing read, and the operation itself was written nowhere. They now append
/// to the keystore audit journal in the signer's directory. These tests run the tool's wrapper
/// over a real journal, then the real signer host and the node's delivery over the same
/// directory, and read the audit rows: the outcome of each run and the keystore events it
/// raised arrive, by <c>system-signer</c>, with a file name and an exit code and nothing else.
/// </summary>
[Collection(KeystoreAuditLogCollection.Name)]
public sealed class SignerToolJournalTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signer-tool-" + Guid.NewGuid().ToString("N"));
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";
    private readonly SignerPaths _paths;

    /// <summary>Creates a signer directory of this test's own.</summary>
    public SignerToolJournalTests()
    {
        var signerDir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(signerDir);
        _paths = SignerPaths.Dedicated(Path.Combine(_root, "app"), signerDir);
    }

    /// <summary>Gives the keystore service its default file back and removes the directories.</summary>
    public void Dispose()
    {
        KeystoreService.AuditLogDirectory = null;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private AuditDbContext AuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);

    /// <summary>One pass of the node's delivery, and the audit rows in the order they were written.</summary>
    private async Task<List<AuditLogEntity>> DeliverAsync(ISignerEventJournal journal)
    {
        await using (var auditDb = AuditDb())
        {
            var audit = new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
            var replay = new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance, auditDb);
            var result = await new SignerKeystoreEventDelivery(
                journal, replay, new SignerJournalCursorFile(Path.Combine(_root, SignerJournalCursorFile.FileName)),
                NullLogger<SignerKeystoreEventDelivery>.Instance).DeliverAsync();
            Assert.Null(result.Failure);
        }
        await using var read = AuditDb();
        return (await read.AuditLogs.AsNoTracking().ToListAsync())
            .OrderBy(r => JsonDocument.Parse(r.DetailsJson!).RootElement.GetProperty("JournalFile").GetString(), StringComparer.Ordinal)
            .ThenBy(r => JsonDocument.Parse(r.DetailsJson!).RootElement.GetProperty("JournalLine").GetInt32())
            .ToList();
    }

    [Fact]
    public async Task A_backup_and_a_restore_run_from_the_signers_directory_reach_the_audit_trail_through_the_journal()
    {
        // The tool starts: the journal is opened, so the keystore events of this process go to it.
        var journal = SignerToolJournal.Open(_paths);
        Assert.NotNull(journal);
        Assert.Equal(_paths.AuditJournalDirectory, journal!.Directory);
        Assert.Equal(_paths.AuditJournalDirectory, KeystoreService.AuditLogDirectory);

        // A backup, which unlocks the keystores as the real one does; then a restore that fails,
        // and a backup stopped by an exception whose message is not for the journal.
        SignerTestWorld? world = null;
        var backupExit = await SignerToolJournal.BackupAsync(journal, null, () =>
        {
            world = SignerTestWorld.CreateWithKeystoreFiles();
            return Task.FromResult(0);
        });
        var restoreExit = await SignerToolJournal.RestoreAsync(
            journal, Path.Combine(_root, "private-directory", "modularca-backup-20261110-080000.enc"), restoreAudit: false, () => Task.FromResult(1));
        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => SignerToolJournal.BackupAsync(
            journal, Path.Combine(_root, "private-directory", "named.enc"), () => throw new InvalidOperationException("the backup password was hunter2-backup-password")));
        Assert.Equal((0, 1), (backupExit, restoreExit));
        Assert.Contains("hunter2-backup-password", thrown.Message);

        // The signer, a process of its own, serves the same directory; the node reads and records.
        await using var host = await HostedSigner.StartAsync(world!, journal: new KeystoreAuditJournal(_paths.AuditJournalDirectory!));
        using var node = host.Connect();
        var rows = await DeliverAsync(node);

        Assert.Equal(
            [
                (AuditActionType.KeystoreLoaded, "Keystore", true),
                (AuditActionType.KeystoreLoaded, "Keystore", true),
                (AuditActionType.BackupCreated, "Backup", true),
                (AuditActionType.BackupRestored, "Backup", false),
                (AuditActionType.BackupCreated, "Backup", false),
            ],
            rows.Select(r => (r.ActionType, r.TargetEntityType!, r.Success)));
        Assert.All(rows, row =>
        {
            Assert.Equal(BootstrapAuditReplayService.SignerActor, row.ActorUsername);
            Assert.Contains("\"DeliveredBySigner\":true", row.DetailsJson);
            Assert.DoesNotContain("hunter2-backup-password", JsonSerializer.Serialize(row));
            Assert.DoesNotContain("private-directory", JsonSerializer.Serialize(row));
        });
        Assert.Contains("exit code 0", rows[2].DetailsJson);
        Assert.Contains("exit code 1", rows[3].ErrorMessage);
        Assert.Contains("modularca-backup-20261110-080000.enc", rows[3].ErrorMessage);
        Assert.Contains("asked to keep the audit history", rows[3].ErrorMessage);
        Assert.Contains("stopped by InvalidOperationException", rows[4].ErrorMessage);
        Assert.Contains("named.enc", rows[4].ErrorMessage);

        // The journal's own files hold what the rows hold and no more.
        var written = string.Concat(Directory.GetFiles(journal.Directory).Select(File.ReadAllText));
        Assert.DoesNotContain("hunter2-backup-password", written);
        Assert.DoesNotContain("private-directory", written);

        // A second pass adds nothing.
        Assert.Equal(5, (await DeliverAsync(node)).Count);
    }

    /// <summary>
    /// Without <c>--signer-dir</c> there is no journal: the tool runs as it did and writes
    /// nothing of its own, and the keystore service's events stay where they went.
    /// </summary>
    [Fact]
    public async Task In_the_shared_layout_the_tools_run_and_write_no_journal()
    {
        var shared = SignerPaths.Shared(Path.Combine(_root, "app"));
        var before = (KeystoreService.AuditLogDirectory, KeystoreService.AuditLogFilePrefix);

        var journal = SignerToolJournal.Open(shared);

        Assert.Null(journal);
        Assert.Equal(before, (KeystoreService.AuditLogDirectory, KeystoreService.AuditLogFilePrefix));
        Assert.Equal(3, await SignerToolJournal.BackupAsync(journal, null, () => Task.FromResult(3)));
        Assert.Equal(2, await SignerToolJournal.RestoreAsync(journal, "archive.enc", true, () => Task.FromResult(2)));
        Assert.False(Directory.Exists(Path.Combine(_root, "app")));
    }

    /// <summary>The host's <c>--backup</c> and <c>--restore</c> run through the wrapper, with the signer's paths.</summary>
    [Fact]
    public void The_command_line_backup_and_restore_run_through_the_journal_wrapper()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var startup = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs")).ReplaceLineEndings("\n");

        Assert.Contains(
            "var backupJournal = ModularCA.Keystore.Services.SignerToolJournal.Open(signerPaths,", startup);
        Assert.Contains(
            "SignerToolJournal.BackupAsync(\n        backupJournal, outputPath, () => BackupRestore.Backup(outputPath, BackupSignerFor));", startup);
        Assert.Contains(
            "var restoreJournal = ModularCA.Keystore.Services.SignerToolJournal.Open(signerPaths,", startup);
        Assert.Contains(
            "SignerToolJournal.RestoreAsync(\n        restoreJournal, archivePath, restoreAudit,\n        () => BackupRestore.Restore(archivePath, MaintenanceSignerFor,", startup);
        // Neither is called anywhere else in the host's startup, so no path skips the record.
        Assert.Equal(1, startup.Split("BackupRestore.Backup(").Length - 1);
        Assert.Equal(1, startup.Split("BackupRestore.Restore(").Length - 1);
    }
}
