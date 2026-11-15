using System.Text.Json;

namespace ModularCA.HubConnection.Server;

/// <summary>
/// The request identifiers the listener has already carried out, with the answer each got, so
/// that a request sent again after a reconnect is done once. Kept in memory and, when a path is
/// given, in a small file beside the socket, so the memory survives a restart of the node. The
/// newest <see cref="Capacity"/> are kept.
/// </summary>
/// <remarks>
/// Not thread-safe by itself: the listener carries out one changing request at a time and calls
/// this under that lock. A file that cannot be read starts an empty ledger; a file that cannot be
/// written leaves the ledger in memory only. Neither stops a request.
/// </remarks>
public sealed class HubRequestLedger
{
    /// <summary>How many identifiers are remembered.</summary>
    public const int Capacity = 256;

    /// <summary>The file's name, beside the socket.</summary>
    public const string FileName = "hub-requests.json";

    private readonly string? _path;
    private readonly List<Entry> _entries = [];

    /// <summary>Opens the ledger, reading <paramref name="path"/> when it exists.</summary>
    /// <param name="path">The file to keep the ledger in, or null to keep it in memory only.</param>
    public HubRequestLedger(string? path)
    {
        _path = path;
        if (path == null || !File.Exists(path)) return;
        try
        {
            if (JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(path)) is { } saved)
                _entries.AddRange(saved.Where(e => !string.IsNullOrEmpty(e.Id)).TakeLast(Capacity));
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // An unreadable ledger is an empty one.
        }
    }

    /// <summary>The answer already given for <paramref name="id"/>, or null when it is new.</summary>
    /// <param name="id">The request identifier.</param>
    public Entry? Find(string id) => _entries.LastOrDefault(e => string.Equals(e.Id, id, StringComparison.Ordinal));

    /// <summary>Remembers the answer given for a request.</summary>
    /// <param name="entry">The request and its answer.</param>
    public void Remember(Entry entry)
    {
        _entries.Add(entry);
        if (_entries.Count > Capacity)
            _entries.RemoveRange(0, _entries.Count - Capacity);
        if (_path == null) return;
        try
        {
            var temporary = _path + ".tmp";
            var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
                JsonSerializer.Serialize(stream, _entries);
            File.Move(temporary, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Kept in memory; the next request tries the file again.
        }
    }

    /// <summary>One carried-out request.</summary>
    /// <param name="Id">The request identifier.</param>
    /// <param name="Operation">The operation it was for.</param>
    /// <param name="BodySha256">The hex SHA-256 of the request body.</param>
    /// <param name="Status">The HTTP status answered.</param>
    /// <param name="ResponseJson">The answer's body.</param>
    /// <param name="AtUtc">When it was carried out.</param>
    public sealed record Entry(string Id, string Operation, string BodySha256, int Status, string ResponseJson, DateTime AtUtc);
}
