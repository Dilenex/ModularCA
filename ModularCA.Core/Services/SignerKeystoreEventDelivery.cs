using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// How far the node has read a remote signer's journal of keystore events: the last event it
/// recorded, by journal file and line, and that event's id.
/// </summary>
/// <param name="File">The journal file's name.</param>
/// <param name="Line">The event's line in it, from 0.</param>
/// <param name="EntryId">The event's id, as the audit row carries it.</param>
public sealed record SignerJournalCursor(string File, int Line, string EntryId);

/// <summary>
/// Keeps <see cref="SignerJournalCursor"/> in a small file in the node's configuration directory
/// (<c>config/signer-audit-cursor.json</c>), which every install type keeps. It is the node's
/// note to itself and nothing the signer reads: losing or changing it makes the node read the
/// journal again from the beginning, where the ids of the events already in the audit trail keep
/// them from being recorded twice.
/// </summary>
public sealed class SignerJournalCursorFile
{
    /// <summary>The file's name under the node's configuration directory.</summary>
    public const string FileName = "signer-audit-cursor.json";

    private readonly string _path;

    /// <summary>Creates the store over <paramref name="path"/>, which need not exist.</summary>
    public SignerJournalCursorFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    /// <summary>The position last saved; null when there is none or the file cannot be read as one.</summary>
    public SignerJournalCursor? Load()
    {
        try
        {
            if (!File.Exists(_path))
                return null;
            var cursor = JsonSerializer.Deserialize<SignerJournalCursor>(File.ReadAllText(_path));
            return cursor is { File.Length: > 0, Line: >= 0, EntryId.Length: > 0 } ? cursor : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Saves the position, or removes the file for null. The file is written beside its place and
    /// moved over it, readable by its owner alone.
    /// </summary>
    public void Save(SignerJournalCursor? cursor)
    {
        if (cursor == null)
        {
            if (File.Exists(_path))
                File.Delete(_path);
            return;
        }
        var directory = Path.GetDirectoryName(Path.GetFullPath(_path))!;
        Directory.CreateDirectory(directory);
        var staged = _path + ".tmp";
        FileSecurityUtil.WriteOwnerOnly(staged, JsonSerializer.Serialize(cursor));
        File.Move(staged, _path, overwrite: true);
    }
}

/// <summary>
/// What one delivery pass did.
/// </summary>
/// <param name="Recorded">Events written to the audit trail.</param>
/// <param name="AlreadyRecorded">Events read again that the trail already held.</param>
/// <param name="StartedOver">Whether the journal was not the one read before, so it was read from the beginning.</param>
/// <param name="SignerUnreachable">Whether the pass ended because the signer did not answer.</param>
/// <param name="Failure">Why the pass ended early; null when the journal was read to its end.</param>
public sealed record SignerEventDeliveryResult(
    int Recorded, int AlreadyRecorded, bool StartedOver, bool SignerUnreachable, string? Failure);

/// <summary>
/// Brings a remote signer's keystore events into the audit trail. A signer that runs apart from
/// the node cannot reach the audit database: it records keystore loaded, created and appended,
/// and signatures and pins that did not verify, in a journal on its own disk. This reads the
/// journal over the signer channel (<see cref="ISignerEventJournal"/>, one read-only call) from
/// where the last pass stopped and writes each event through the audit service, on the hash
/// chain, with the id that keeps a second delivery from adding a second row
/// (<see cref="BootstrapAuditReplayService.RecordSignerEventsAsync"/>).
/// </summary>
/// <remarks>
/// <para>
/// Events are recorded in the journal's order, and the position moves only past events that are
/// in the audit database. A signer that does not answer, or an audit database that refuses, ends
/// the pass; the events stay in the journal and the next pass takes them. The node being away
/// loses nothing for the same reason.
/// </para>
/// <para>
/// Nothing here writes to the signer. The position is the node's own
/// (<see cref="SignerJournalCursorFile"/>); with each read the signer also returns the event at
/// that position, and when it is not the one this node recorded there (the signer's directory
/// was restored from a copy, or replaced), the journal is read from the beginning.
/// </para>
/// </remarks>
public sealed class SignerKeystoreEventDelivery
{
    /// <summary>How many events one read asks for.</summary>
    public const int PageSize = 200;

    private const int MaxPagesPerPass = 500;

    private readonly ISignerEventJournal _journal;
    private readonly BootstrapAuditReplayService _replay;
    private readonly SignerJournalCursorFile _cursor;
    private readonly ILogger<SignerKeystoreEventDelivery> _logger;

    /// <summary>Creates the delivery over the signer's journal, the audit trail's writer and the node's position file.</summary>
    public SignerKeystoreEventDelivery(
        ISignerEventJournal journal,
        BootstrapAuditReplayService replay,
        SignerJournalCursorFile cursor,
        ILogger<SignerKeystoreEventDelivery> logger)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _replay = replay ?? throw new ArgumentNullException(nameof(replay));
        _cursor = cursor ?? throw new ArgumentNullException(nameof(cursor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Reads the journal from the saved position to its end and records what it holds. Never
    /// throws for a signer that is away or an audit write that fails: the result says so.
    /// </summary>
    public async Task<SignerEventDeliveryResult> DeliverAsync(CancellationToken cancellationToken = default)
    {
        int recorded = 0, already = 0;
        var startedOver = false;
        try
        {
            var cursor = _cursor.Load();
            var checkAnchor = cursor != null;
            for (var pass = 0; pass < MaxPagesPerPass; pass++)
            {
                var page = await _journal.ReadAfterAsync(cursor?.File, cursor?.Line ?? 0, PageSize, cancellationToken);
                if (checkAnchor && cursor != null)
                {
                    checkAnchor = false;
                    var anchorId = page.Anchor == null ? null : BootstrapAuditReplayService.EntryId(cursor.File, cursor.Line, page.Anchor);
                    if (!string.Equals(anchorId, cursor.EntryId, StringComparison.Ordinal))
                    {
                        _logger.LogWarning(
                            "The signer's keystore audit journal does not hold the event this node last recorded ({File} line {Line}): "
                            + "the journal was restored or replaced. Reading it from the beginning; events already in the audit trail are not recorded again.",
                            cursor.File, cursor.Line);
                        cursor = null;
                        startedOver = true;
                        SaveCursor(null);
                        continue;
                    }
                }

                if (page.Entries.Count == 0)
                    break;

                var batch = await _replay.RecordSignerEventsAsync(page.Entries, cancellationToken);
                recorded += batch.Written;
                already += batch.Skipped;
                if (batch.Last is { } last)
                {
                    cursor = new SignerJournalCursor(last.File, last.Line, BootstrapAuditReplayService.EntryId(last.File, last.Line, last.Json));
                    SaveCursor(cursor);
                }
                if (batch.Failure != null)
                    return new SignerEventDeliveryResult(recorded, already, startedOver, false, batch.Failure);
                if (!page.More)
                    break;
            }
            return new SignerEventDeliveryResult(recorded, already, startedOver, false, null);
        }
        catch (SigningRefusedException ex) when (ex.Reason == SigningRefusalReason.SignerUnavailable)
        {
            return new SignerEventDeliveryResult(recorded, already, startedOver, true, ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new SignerEventDeliveryResult(recorded, already, startedOver, false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Saves the position. A position that cannot be saved is not a failed delivery: the events
    /// are in the trail, and the next pass reads them again and passes over them by their ids.
    /// </summary>
    private void SaveCursor(SignerJournalCursor? cursor)
    {
        try
        {
            _cursor.Save(cursor);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not save how far the signer's keystore audit journal has been read: {Message}", ex.Message);
        }
    }
}
