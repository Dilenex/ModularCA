using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Core.Services;

/// <summary>
/// What one pass over a directory of <c>bootstrap-audit-*.jsonl</c> files did.
/// </summary>
/// <param name="FilesReplayed">Files whose every line is in the audit trail and that were renamed <c>.replayed</c>.</param>
/// <param name="Recorded">Lines written to the audit trail by this pass.</param>
/// <param name="AlreadyRecorded">Lines skipped because an earlier pass had already written them.</param>
/// <param name="Failures">One message per file left in place for a later pass, or for the scan itself.</param>
public sealed record BootstrapAuditReplayResult(
    int FilesReplayed, int Recorded, int AlreadyRecorded, IReadOnlyList<string> Failures)
{
    /// <summary>A pass that found nothing to do.</summary>
    public static BootstrapAuditReplayResult Nothing { get; } = new(0, 0, 0, []);
}

/// <summary>
/// What recording one batch of a remote signer's keystore events did.
/// </summary>
/// <param name="Written">Events written to the audit trail.</param>
/// <param name="Skipped">Events the trail already held.</param>
/// <param name="Last">The last event that is in the trail or needs no row; null when the first one failed or the batch was empty.</param>
/// <param name="Failure">Why the batch stopped early; null when every event was dealt with.</param>
public sealed record SignerEventBatchResult(
    int Written, int Skipped, ModularCA.Shared.Signing.SignerJournalEntry? Last, string? Failure);

/// <summary>
/// What one pass over the <c>bootstrap-audit-*.jsonl</c> files of a running node did, the files
/// left where they are (<see cref="BootstrapAuditReplayService.RecordNewLinesAsync"/>).
/// </summary>
/// <param name="Recorded">Lines written to the audit trail by this pass.</param>
/// <param name="AlreadyRecorded">Lines the trail already held.</param>
/// <param name="Failure">Why the pass stopped early; null when every line is in the trail.</param>
public sealed record NewLinesRecordResult(int Recorded, int AlreadyRecorded, string? Failure);

/// <summary>
/// Drains the <c>logs/bootstrap-audit-*.jsonl</c> files into the audit trail, each line as a real
/// <see cref="IAuditService.LogAsync"/> call. The files are written where no audit service is at
/// hand: by the bootstrap's setup steps (<c>BootstrapAuditLog</c>) and by the keystore service's
/// static paths. Two callers drain them: the bootstrap itself, as its last step, since the audit
/// schema exists by then and its <c>logs/</c> may not outlive it (an init container); and the
/// node at every start, from <c>StartModularCA.cs</c>, for what the bootstrap could not write
/// (which the bootstrap moves into <c>config/audit-pending</c>, since <c>config/</c> is kept on
/// every install type) and for the keystore events of the node's own previous run. A node that
/// holds the signer in process also records its keystore events while it runs, as they are
/// written (<see cref="RecordNewLinesAsync"/>), so they do not wait for the next start.
/// </summary>
/// <remarks>
/// <para>
/// Replaying is idempotent in two ways. A drained file is renamed <c>{file}.replayed</c>, so it
/// is not read again. And every line has an id derived from its file name, position and text,
/// recorded in the row as <c>BootstrapEntryId</c>: given the audit database, a pass skips the
/// lines whose id the trail already holds, so a file that one pass wrote in part (or wrote and
/// could not rename) gains no duplicate rows from the next, whichever process runs it.
/// </para>
/// <para>
/// Given the audit database, a file is renamed only once every one of its ids is in the trail;
/// an audit service that swallows a failed write therefore leaves the file for the next pass.
/// A failure is reported in the result and logged, never thrown: neither the bootstrap nor the
/// node's start stops for it.
/// </para>
/// </remarks>
/// <param name="auditService">Writes each row.</param>
/// <param name="logger">Receives what was replayed and what was left.</param>
/// <param name="auditDb">
/// The audit database the rows land in, to find the ids already recorded; null (no audit
/// database configured, or a test double) replays every line and relies on the rename alone.
/// </param>
public sealed class BootstrapAuditReplayService(
    IAuditService auditService,
    ILogger<BootstrapAuditReplayService> logger,
    AuditDbContext? auditDb = null)
{
    /// <summary>The actor every row replayed from a <c>bootstrap-audit-*.jsonl</c> file carries.</summary>
    public const string Actor = "system-bootstrap";

    /// <summary>
    /// The actor of a row written from a remote signer's journal
    /// (<see cref="RecordSignerEventsAsync"/>). Builds before this one wrote those rows as
    /// <see cref="Actor"/>; the ids already in the trail are read under both names, so an event
    /// an earlier build delivered is not recorded again under this one.
    /// </summary>
    public const string SignerActor = "system-signer";

    /// <summary>The details property that holds a replayed line's id.</summary>
    public const string EntryIdProperty = "BootstrapEntryId";

    /// <summary>The directory under <c>config/</c> where the bootstrap keeps the files the audit database refused.</summary>
    public const string PendingDirectoryName = "audit-pending";

    /// <summary>
    /// Where the bootstrap leaves the files it could not drain, for the node:
    /// <c>config/audit-pending</c> under <paramref name="baseDirectory"/>. It is in <c>config/</c>
    /// because every install type keeps that directory and shares it between the bootstrap and
    /// the node; the pod's bootstrap container has no <c>logs/</c> that outlives it.
    /// </summary>
    public static string PendingDirectory(string baseDirectory)
        => Path.Combine(baseDirectory, "config", PendingDirectoryName);

    /// <summary>
    /// Replays everything that waits under the application directory: what the bootstrap left in
    /// <c>config/audit-pending</c>, then <c>logs/</c>.
    /// </summary>
    public Task<BootstrapAuditReplayResult> ReplayPendingAsync(CancellationToken cancellationToken = default)
        => ReplayAllAsync(AppContext.BaseDirectory, cancellationToken);

    /// <summary>
    /// Replays, under <paramref name="baseDirectory"/>, the files the bootstrap kept in
    /// <c>config/audit-pending</c> (and the numbered directories under it, which hold a second
    /// file of the same name), oldest first, and then those in <c>logs/</c>: the bootstrap's
    /// records come before the keystore events of the node's own runs.
    /// </summary>
    public async Task<BootstrapAuditReplayResult> ReplayAllAsync(string baseDirectory, CancellationToken cancellationToken = default)
    {
        var directories = new List<string>();
        var pending = PendingDirectory(baseDirectory);
        try
        {
            if (Directory.Exists(pending))
            {
                directories.Add(pending);
                directories.AddRange(Directory.GetDirectories(pending)
                    .OrderBy(d => int.TryParse(Path.GetFileName(d), out var n) ? n : int.MaxValue)
                    .ThenBy(d => d, StringComparer.Ordinal));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "Could not list {Directory}; the audit records the bootstrap kept there wait for the next start", pending);
        }
        directories.Add(Path.Combine(baseDirectory, "logs"));

        var total = BootstrapAuditReplayResult.Nothing;
        foreach (var directory in directories)
        {
            var result = await ReplayPendingAsync(directory, cancellationToken);
            total = new BootstrapAuditReplayResult(
                total.FilesReplayed + result.FilesReplayed,
                total.Recorded + result.Recorded,
                total.AlreadyRecorded + result.AlreadyRecorded,
                [.. total.Failures, .. result.Failures]);
        }
        return total;
    }

    /// <summary>
    /// Scans <paramref name="logsDir"/> for <c>bootstrap-audit-*.jsonl</c> files, replays every
    /// line the trail does not already hold as an audit row, then renames each drained file with a
    /// <c>.replayed</c> suffix. A file that could not be drained stays for the next pass and is
    /// named in the result; nothing is thrown.
    /// </summary>
    public async Task<BootstrapAuditReplayResult> ReplayPendingAsync(string logsDir, CancellationToken cancellationToken = default)
    {
        var failures = new List<string>();
        int filesReplayed = 0, recorded = 0, alreadyRecorded = 0;
        try
        {
            if (!Directory.Exists(logsDir))
            {
                return BootstrapAuditReplayResult.Nothing;
            }

            var files = Directory.GetFiles(logsDir, "bootstrap-audit-*.jsonl");
            Array.Sort(files, StringComparer.Ordinal);
            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    var (written, skipped) = await ReplayFileAsync(file, cancellationToken);
                    recorded += written;
                    alreadyRecorded += skipped;
                    var replayedPath = file + ".replayed";
                    // If a prior half-finished replay exists, overwrite it.
                    if (File.Exists(replayedPath))
                    {
                        File.Delete(replayedPath);
                    }
                    File.Move(file, replayedPath);
                    filesReplayed++;
                    logger.LogInformation(
                        "Replayed bootstrap audit file {File} into audit DB ({Replayed}): {Written} written, {Skipped} already recorded",
                        Path.GetFileName(file), Path.GetFileName(replayedPath), written, skipped);
                }
                catch (Exception ex)
                {
                    failures.Add($"{Path.GetFileName(file)}: {ex.GetType().Name}: {ex.Message}");
                    logger.LogWarning(ex,
                        "Failed to replay bootstrap audit file {File}; leaving in place for retry on next startup",
                        file);
                }
            }
        }
        catch (Exception ex)
        {
            // Never escalate: a broken replay must not stop the CA from starting.
            failures.Add($"{ex.GetType().Name}: {ex.Message}");
            logger.LogWarning(ex, "BootstrapAuditReplayService encountered an error during scan");
        }
        return new BootstrapAuditReplayResult(filesReplayed, recorded, alreadyRecorded, failures);
    }

    /// <summary>
    /// Records the lines of the <c>bootstrap-audit-*.jsonl</c> files in <paramref name="logsDir"/>
    /// that the audit trail does not hold yet, and leaves the files where they are. This is how
    /// a running node that holds the signer in process gets its keystore events (a key appended,
    /// a keystore created, a verification or unlock failure) into the trail when they happen: the
    /// keystore service appends the line, and this is run over the file.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each row is the one the replay of the whole file writes, with the same
    /// <c>BootstrapEntryId</c> (file name, line position, text). So the drain at the next start,
    /// or the bootstrap's, finds every line of the file already recorded, writes nothing and
    /// renames it; and a pass here over a file an interrupted drain wrote in part adds only the
    /// rest. The file is not renamed here because the keystore service may be appending to it:
    /// a line written between the read and the rename would never be read.
    /// </para>
    /// <para>
    /// Only lines that end in a line end are read, so one still being written waits for the next
    /// pass. Each line is looked for in the audit database after it is logged, and the first
    /// that is missing ends the pass: the audit service may log a failed write and carry on, and
    /// the caller tries again later. Nothing is thrown for a file that cannot be read or an
    /// audit write that fails; the result says so.
    /// </para>
    /// </remarks>
    /// <param name="logsDir">The directory the keystore service writes its events to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">No audit database was given: without it a line cannot be told from one already recorded.</exception>
    public async Task<NewLinesRecordResult> RecordNewLinesAsync(string logsDir, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logsDir);
        if (auditDb == null)
            throw new InvalidOperationException("Recording keystore events as they happen needs the audit database, to tell a line from one already recorded.");

        int written = 0, skipped = 0;
        try
        {
            if (!Directory.Exists(logsDir))
                return new NewLinesRecordResult(0, 0, null);

            var files = Directory.GetFiles(logsDir, "bootstrap-audit-*.jsonl");
            Array.Sort(files, StringComparer.Ordinal);
            HashSet<string>? known = null;
            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file);
                var lines = await CompleteLinesAsync(file, cancellationToken);
                for (var lineNumber = 0; lineNumber < lines.Count; lineNumber++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var line = lines[lineNumber];
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    BootstrapAuditEntry? entry;
                    try
                    {
                        entry = JsonSerializer.Deserialize<BootstrapAuditEntry>(line, LineOptions);
                    }
                    catch (JsonException)
                    {
                        // The drain at the next start names a malformed line; it is passed over here.
                        continue;
                    }
                    if (entry is null || string.IsNullOrWhiteSpace(entry.Action))
                        continue;

                    var entryId = EntryId(fileName, lineNumber, line);
                    known ??= await RecordedEntryIdsAsync(cancellationToken);
                    if (known.Contains(entryId))
                    {
                        skipped++;
                        continue;
                    }

                    await LogReplayedLineAsync(entry.Action, entry, entryId);
                    var recorded = await auditDb.AuditLogs.AsNoTracking()
                        .AnyAsync(a => a.ActorUsername == Actor && a.DetailsJson != null && a.DetailsJson.Contains(entryId), cancellationToken);
                    if (!recorded)
                        return new NewLinesRecordResult(written, skipped,
                            $"The audit record at {fileName} line {lineNumber} did not reach the audit database.");
                    known.Add(entryId);
                    written++;
                }
            }
            return new NewLinesRecordResult(written, skipped, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new NewLinesRecordResult(written, skipped, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// The lines of a file that end in a line end, read while the keystore service may be
    /// appending to it. A line has the position <see cref="File.ReadAllLinesAsync(string, CancellationToken)"/>
    /// gives it, which is the position its id is derived from.
    /// </summary>
    private static async Task<List<string>> CompleteLinesAsync(string path, CancellationToken cancellationToken)
    {
        string text;
        await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
            text = await reader.ReadToEndAsync(cancellationToken);

        var lines = new List<string>();
        var start = 0;
        while (start < text.Length)
        {
            var end = text.IndexOf('\n', start);
            if (end < 0)
                break;
            lines.Add(text[start..end].TrimEnd('\r'));
            start = end + 1;
        }
        return lines;
    }

    /// <summary>
    /// Writes keystore events read from a remote signer's journal into the audit trail, in the
    /// order given, each as the row a replayed keystore line gets, by <see cref="SignerActor"/>,
    /// marked <c>DeliveredBySigner</c> and carrying where it stood in the journal. The record of
    /// a backup or a restore run on the signer from the command line is a <c>Backup</c> row; every
    /// other event is a <c>Keystore</c> row. An event's id
    /// is derived from its journal file, line and text, as for a replayed line, so an event the
    /// trail already holds is passed over and a second delivery adds nothing. That holds for the
    /// rows an earlier build wrote as <see cref="Actor"/> too: an upgraded node records none of
    /// them again.
    /// </summary>
    /// <remarks>
    /// Each event is looked for in the audit database after it is logged, and the first one that
    /// is not there ends the batch: the audit service may log a failed write and carry on, and
    /// events are recorded in order or not at all. The caller moves its note of how far it has
    /// read only as far as <see cref="SignerEventBatchResult.Last"/>.
    /// </remarks>
    /// <param name="entries">The events, oldest first.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">No audit database was given: there is nowhere to record to, or to check.</exception>
    public async Task<SignerEventBatchResult> RecordSignerEventsAsync(
        IReadOnlyList<ModularCA.Shared.Signing.SignerJournalEntry> entries, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (auditDb == null)
            throw new InvalidOperationException("Signer keystore events need the audit database to be recorded in.");

        var known = await RecordedEntryIdsAsync(cancellationToken);
        int written = 0, skipped = 0;
        ModularCA.Shared.Signing.SignerJournalEntry? last = null;
        foreach (var item in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entryId = EntryId(item.File, item.Line, item.Json);
            if (known.Contains(entryId))
            {
                skipped++;
                last = item;
                continue;
            }

            BootstrapAuditEntry? entry = null;
            try
            {
                entry = JsonSerializer.Deserialize<BootstrapAuditEntry>(item.Json, LineOptions);
            }
            catch (JsonException ex)
            {
                logger.LogWarning(ex, "Skipping a malformed keystore event from the signer's journal ({File} line {Line})", item.File, item.Line);
            }
            if (entry is null || string.IsNullOrWhiteSpace(entry.Action))
            {
                last = item;
                continue;
            }

            await auditService.LogAsync(
                actionType: entry.Action,
                actorUserId: null,
                actorUsername: SignerActor,
                targetEntityType: SignerEventTargetType(entry.Action),
                targetEntityId: entry.KeystoreName,
                details: new
                {
                    DeliveredBySigner = true,
                    BootstrapTimestamp = entry.Timestamp,
                    entry.InstanceId,
                    BootstrapEntryId = entryId,
                    JournalFile = item.File,
                    JournalLine = item.Line,
                    entry.Detail,
                },
                sourceIp: "local",
                success: entry.Success ?? true,
                errorMessage: entry.Success == false ? entry.Detail : null);

            var recorded = await auditDb.AuditLogs.AsNoTracking()
                .AnyAsync(a => a.ActorUsername == SignerActor && a.DetailsJson != null && a.DetailsJson.Contains(entryId), cancellationToken);
            if (!recorded)
            {
                return new SignerEventBatchResult(written, skipped, last,
                    $"The keystore event at {item.File} line {item.Line} did not reach the audit database.");
            }
            known.Add(entryId);
            written++;
            last = item;
        }
        return new SignerEventBatchResult(written, skipped, last, null);
    }

    /// <summary>
    /// What an event from the signer's journal is about. A backup or a restore run on the signer
    /// from the command line is a <c>Backup</c> event, as one run from the console is; every
    /// other event is about a keystore.
    /// </summary>
    private static string SignerEventTargetType(string action)
        => action is ModularCA.Shared.Enums.AuditActionType.BackupCreated or ModularCA.Shared.Enums.AuditActionType.BackupRestored
            ? "Backup"
            : "Keystore";

    // The writers emit camelCase keys; read without regard to case, or every line binds to nothing
    // and is skipped.
    private static readonly JsonSerializerOptions LineOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// The id of one line: the first 128 bits of the SHA-256 of the file's name, the line's
    /// position and its text, in hex. The same line of the same file gives the same id in any
    /// process, which is what lets a second pass recognise what a first one wrote.
    /// </summary>
    internal static string EntryId(string fileName, int lineNumber, string line)
        => Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(fileName + "\n" + lineNumber + "\n" + line)), 0, 16).ToLowerInvariant();

    /// <summary>
    /// The ids of the replayed lines and delivered signer events the audit trail holds; empty
    /// without an audit database. Rows by <see cref="Actor"/> and by <see cref="SignerActor"/>
    /// are both read: a signer event delivered before <see cref="SignerActor"/> existed is in the
    /// trail under <see cref="Actor"/>, and must still count as recorded.
    /// </summary>
    private async Task<HashSet<string>> RecordedEntryIdsAsync(CancellationToken cancellationToken)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (auditDb == null)
        {
            return ids;
        }

        var rows = await auditDb.AuditLogs.AsNoTracking()
            .Where(a => (a.ActorUsername == Actor || a.ActorUsername == SignerActor)
                && a.DetailsJson != null && a.DetailsJson.Contains(EntryIdProperty))
            .Select(a => a.DetailsJson!)
            .ToListAsync(cancellationToken);
        foreach (var json in rows)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Object
                    && doc.RootElement.TryGetProperty(EntryIdProperty, out var id)
                    && id.ValueKind == JsonValueKind.String)
                {
                    ids.Add(id.GetString()!);
                }
            }
            catch (JsonException)
            {
                // Not a row this service wrote.
            }
        }
        return ids;
    }

    /// <summary>
    /// Replays one file and returns how many lines were written and how many the trail already
    /// held. A keystore line is logged against its keystore, as a failure with its detail when the
    /// writer recorded one; a setup decision against the target it names, with its own details.
    /// Throws when, given the audit database, a line this pass logged is not in the trail
    /// afterwards, so the caller leaves the file in place.
    /// </summary>
    private async Task<(int Written, int Skipped)> ReplayFileAsync(string filePath, CancellationToken cancellationToken)
    {
        var fileName = Path.GetFileName(filePath);
        var lines = await File.ReadAllLinesAsync(filePath, cancellationToken);
        var known = await RecordedEntryIdsAsync(cancellationToken);
        var logged = new List<string>();
        var skipped = 0;
        for (var lineNumber = 0; lineNumber < lines.Length; lineNumber++)
        {
            var line = lines[lineNumber];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            BootstrapAuditEntry? entry = null;
            try
            {
                entry = JsonSerializer.Deserialize<BootstrapAuditEntry>(line, LineOptions);
            }
            catch (JsonException ex)
            {
                logger.LogWarning(ex,
                    "Skipping malformed bootstrap audit line in {File}: {Line}",
                    fileName, line);
                continue;
            }

            if (entry is null || string.IsNullOrWhiteSpace(entry.Action))
            {
                continue;
            }

            var entryId = EntryId(fileName, lineNumber, line);
            if (known.Contains(entryId))
            {
                skipped++;
                continue;
            }

            await LogReplayedLineAsync(entry.Action, entry, entryId);
            logged.Add(entryId);
        }

        // An audit service may log a failed write and carry on. The file is done only when the
        // trail holds every line of it.
        if (auditDb != null && logged.Count > 0)
        {
            var now = await RecordedEntryIdsAsync(cancellationToken);
            var missing = logged.Count(id => !now.Contains(id));
            if (missing > 0)
            {
                throw new IOException(
                    $"{missing} of {logged.Count} audit record(s) from {fileName} did not reach the audit database.");
            }
        }
        return (logged.Count, skipped);
    }

    /// <summary>
    /// Writes one line of a <c>bootstrap-audit-*.jsonl</c> file as its audit row, by
    /// <see cref="Actor"/> and carrying <paramref name="entryId"/>: a setup decision against the
    /// target it names, with its own details; a keystore line against its keystore, as a failure
    /// with its detail when the writer recorded one. The replay of a whole file and the recording
    /// of a running node's keystore events write the same row, which is what lets either
    /// recognise what the other wrote.
    /// </summary>
    /// <param name="action">The action the line names; the callers pass over a line that names none.</param>
    /// <param name="entry">The line.</param>
    /// <param name="entryId">The line's id.</param>
    private async Task LogReplayedLineAsync(string action, BootstrapAuditEntry entry, string entryId)
    {
        // A setup decision names its own target and carries its own details.
        if (!string.IsNullOrWhiteSpace(entry.TargetEntityType))
        {
            await auditService.LogAsync(
                actionType: action,
                actorUserId: null,
                actorUsername: Actor,
                targetEntityType: entry.TargetEntityType,
                targetEntityId: entry.TargetEntityId,
                details: new
                {
                    ReplayedFromBootstrap = true,
                    BootstrapTimestamp = entry.Timestamp,
                    entry.InstanceId,
                    BootstrapEntryId = entryId,
                    Decision = entry.Details,
                },
                sourceIp: "local",
                success: true);
            return;
        }

        await auditService.LogAsync(
            actionType: action,
            actorUserId: null,
            actorUsername: Actor,
            targetEntityType: "Keystore",
            targetEntityId: entry.KeystoreName,
            details: new
            {
                ReplayedFromBootstrap = true,
                BootstrapTimestamp = entry.Timestamp,
                entry.InstanceId,
                BootstrapEntryId = entryId,
                entry.SubjectDn,
                entry.Thumbprint,
                entry.Detail,
            },
            sourceIp: "local",
            success: entry.Success ?? true,
            errorMessage: entry.Success == false ? entry.Detail : null);
    }

    private sealed class BootstrapAuditEntry
    {
        public string? Timestamp { get; set; }
        public string? Action { get; set; }
        public string? KeystoreName { get; set; }
        public string? SubjectDn { get; set; }
        public string? Thumbprint { get; set; }
        public string? InstanceId { get; set; }
        public bool? Success { get; set; }
        public string? Detail { get; set; }
        public string? TargetEntityType { get; set; }
        public string? TargetEntityId { get; set; }
        public JsonElement? Details { get; set; }
    }
}
