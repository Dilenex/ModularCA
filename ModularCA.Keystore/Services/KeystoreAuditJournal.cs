using System.Text;
using System.Text.Json;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;

namespace ModularCA.Keystore.Services;

/// <summary>
/// The journal a signer that runs apart from the node keeps of its keystore events, and the
/// reader the node is served from. <see cref="KeystoreService"/> appends one JSON line per event
/// (keystore loaded, created, a key appended, a signature or pin that did not verify, an unlock
/// that failed to decrypt), and the signer's command-line backup and restore one each
/// (<see cref="Append"/>), to
/// <c>keystore-audit-yyyyMMdd.jsonl</c> in the journal directory, which is in the signer's own
/// directory and not in its <c>logs/</c>: the pod's signer keeps its logs in a volume that does
/// not outlive the pod, and the journal has to wait there for as long as the node is away.
/// </summary>
/// <remarks>
/// <para>
/// The reader only reads. Nothing here removes, renames or rewrites a journal file, and no call
/// the node can make reaches a method that does, or reaches <see cref="Append"/>, which is not
/// on <see cref="ISignerEventJournal"/>: the node keeps its own note of how far it has read. Files are append-only and are read in the order of their names, which is the order of
/// their dates, so events leave in the order they were written.
/// </para>
/// <para>
/// A line is not handed over as it stands. It is parsed and rebuilt from the fields a keystore
/// event has (<c>timestamp</c>, <c>action</c>, <c>keystoreName</c>, <c>success</c>,
/// <c>detail</c>, <c>instanceId</c>), each held to a length, so whatever else a line might hold
/// never crosses the wire. None of those fields is given a secret by the code that writes them:
/// the detail is a count of entries, the message of a verification failure, the kind of an
/// unlock failure, or the outcome of a command-line backup or restore.
/// </para>
/// </remarks>
public sealed class KeystoreAuditJournal : ISignerEventJournal
{
    /// <summary>What a journal file's name starts with; the date and <c>.jsonl</c> follow.</summary>
    public const string FilePrefix = "keystore-audit";

    /// <summary>What the keystore events' file starts with where there is no journal: the file the node replays itself.</summary>
    public const string SharedFilePrefix = "bootstrap-audit";

    private const int MaxNameLength = 128;
    private const int MaxDetailLength = 2048;

    private readonly string _directory;

    /// <summary>Creates a reader over the journal in <paramref name="directory"/>, which need not exist yet.</summary>
    public KeystoreAuditJournal(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = directory;
    }

    /// <summary>The journal directory.</summary>
    public string Directory => _directory;

    /// <summary>
    /// Points the keystore service's events at the journal in <paramref name="directory"/>,
    /// creating it for its owner alone, and brings in what an earlier build left in
    /// <paramref name="legacyLogsDirectory"/> (<c>bootstrap-audit-*.jsonl</c> in the signer's
    /// <c>logs/</c>, which nothing ever read) so that those events are handed over too, before
    /// the ones this run adds. A legacy file whose day already has a journal file is left where
    /// it is. Never throws: a journal that cannot be prepared is reported through
    /// <paramref name="warn"/> and the signer starts all the same.
    /// </summary>
    /// <param name="directory">The journal directory.</param>
    /// <param name="legacyLogsDirectory">The signer's log directory, or null to bring nothing in.</param>
    /// <param name="warn">Receives what could not be done.</param>
    /// <returns>A reader over the journal.</returns>
    public static KeystoreAuditJournal Open(string directory, string? legacyLogsDirectory, Action<string>? warn = null)
    {
        var journal = new KeystoreAuditJournal(directory);
        try
        {
            FileSecurityUtil.EnsureOwnerOnlyDirectory(directory, tightenExisting: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warn?.Invoke($"The keystore audit journal directory {directory} could not be prepared for its owner alone: {ex.Message}");
        }

        if (legacyLogsDirectory != null && System.IO.Directory.Exists(legacyLogsDirectory))
        {
            try
            {
                var legacy = System.IO.Directory.GetFiles(legacyLogsDirectory, SharedFilePrefix + "-*.jsonl");
                Array.Sort(legacy, StringComparer.Ordinal);
                foreach (var file in legacy)
                {
                    var target = Path.Combine(directory, FilePrefix + Path.GetFileName(file)[SharedFilePrefix.Length..]);
                    if (File.Exists(target))
                        continue;
                    File.Move(file, target);
                    try { FileSecurityUtil.SetOwnerOnly(target); } catch { /* best-effort, as for a new file */ }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                warn?.Invoke($"Keystore events an earlier build left in {legacyLogsDirectory} could not be moved into the journal: {ex.Message}");
            }
        }

        KeystoreService.AuditLogDirectory = directory;
        KeystoreService.AuditLogFilePrefix = FilePrefix;
        return journal;
    }

    /// <summary>
    /// Appends one event to this journal, as the keystore service appends its own: the day's
    /// file, owner-only, one JSON line. For the signer's command-line tools (a backup, a
    /// restore), which run as a process of their own beside the signer and have no other way to
    /// leave a record the node will read. The caller passes names and outcomes, never a
    /// passphrase, a password or key material. Never throws.
    /// </summary>
    /// <param name="action">The audit action.</param>
    /// <param name="keystoreName">The keystore the event is about, or null when it is about none.</param>
    /// <param name="success">Whether what the event records succeeded.</param>
    /// <param name="detail">What happened, in a line.</param>
    /// <returns>Whether the line was written.</returns>
    public bool Append(string action, string? keystoreName, bool success, string? detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        return KeystoreService.AppendAuditLine(_directory, FilePrefix, action, keystoreName, success, detail);
    }

    /// <inheritdoc />
    public Task<SignerJournalPage> ReadAfterAsync(string? afterFile, int afterLine, int max, CancellationToken cancellationToken = default)
        => Task.FromResult(ReadAfter(afterFile, afterLine, max, cancellationToken));

    /// <summary>
    /// Reads the journal after a position. <paramref name="afterFile"/> is only ever compared
    /// with the names of the journal's own files, never opened, so it cannot name a file outside
    /// the journal. A line that is not a keystore event is passed over; a last line still being
    /// written (no line end yet) is left for the next read.
    /// </summary>
    private SignerJournalPage ReadAfter(string? afterFile, int afterLine, int max, CancellationToken cancellationToken)
    {
        max = Math.Clamp(max, 1, ISignerEventJournal.MaxPageSize);
        if (!System.IO.Directory.Exists(_directory))
            return SignerJournalPage.Empty;

        var files = System.IO.Directory.GetFiles(_directory, FilePrefix + "-*.jsonl");
        Array.Sort(files, StringComparer.Ordinal);
        var from = string.IsNullOrEmpty(afterFile) ? null : afterFile;

        var entries = new List<SignerJournalEntry>();
        string? anchor = null;
        foreach (var path in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            var order = from == null ? 1 : string.CompareOrdinal(name, from);
            if (order < 0)
                continue;

            var lines = CompleteLines(path);
            for (var number = 0; number < lines.Count; number++)
            {
                if (order == 0 && number < afterLine)
                    continue;
                var json = Rebuild(lines[number]);
                if (order == 0 && number == afterLine)
                {
                    anchor = json;
                    continue;
                }
                if (json == null)
                    continue;
                if (entries.Count == max)
                    return new SignerJournalPage(entries, true, anchor);
                entries.Add(new SignerJournalEntry(name, number, json));
            }
        }
        return new SignerJournalPage(entries, false, anchor);
    }

    /// <summary>
    /// The lines of a journal file that end in a line end, read while the keystore service may
    /// be appending to it.
    /// </summary>
    private static List<string> CompleteLines(string path)
    {
        string text;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
            text = reader.ReadToEnd();

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
    /// One journal line as the JSON that is handed over: the six fields of a keystore event and
    /// nothing else, in a fixed order, each string held to a length. Null for a line that is not
    /// a JSON object naming an action.
    /// </summary>
    internal static string? Rebuild(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            var action = Text(root, "action", MaxNameLength);
            if (string.IsNullOrWhiteSpace(action))
                return null;

            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                if (Text(root, "timestamp", MaxNameLength) is { } timestamp)
                    writer.WriteString("timestamp", timestamp);
                writer.WriteString("action", action);
                if (Text(root, "keystoreName", MaxNameLength) is { } keystore)
                    writer.WriteString("keystoreName", keystore);
                if (root.TryGetProperty("success", out var success) && success.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    writer.WriteBoolean("success", success.GetBoolean());
                if (Text(root, "detail", MaxDetailLength) is { } detail)
                    writer.WriteString("detail", detail);
                if (Text(root, "instanceId", MaxNameLength) is { } instance)
                    writer.WriteString("instanceId", instance);
                writer.WriteEndObject();
            }
            return Encoding.UTF8.GetString(buffer.ToArray());
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement root, string name, int maxLength)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            return null;
        var text = value.GetString()!;
        return text.Length <= maxLength ? text : text[..maxLength];
    }
}
