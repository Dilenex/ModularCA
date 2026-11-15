using System.Text.Json;
using System.Text.Json.Serialization;
using ModularCA.Shared.Utils;

namespace ModularCA.Shared.Modes;

/// <summary>
/// The instance's mode, kept in a small file on this host and never in the database, so that it
/// does not replicate to a standby copy: a copy a failover starts begins with no file, and so in
/// the mode its start rule gives it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Where.</b> <see cref="FileName"/> in the directory of the hub's socket when a hub socket is
/// configured (that directory is the hub's own volume, one per copy), otherwise in the host's
/// config directory. See <see cref="PathFor"/>.
/// </para>
/// <para>
/// <b>With no file.</b> A hub socket and no file: the mode named by
/// <c>MODULARCA__HUB__STARTMODE</c>, or restricted when that is unset. No hub socket and no
/// file: full. The start mode is not written down, so it applies on every start until the hub or
/// an administrator sets a mode. See <see cref="Open"/>.
/// </para>
/// <para>
/// <b>A file that cannot be read</b> (damaged, or a mode this build does not know) holds the
/// instance restricted, source <see cref="InstanceModeSource.Unreadable"/>, until someone sets a
/// mode. Guessing full could undo a deliberate DR mode.
/// </para>
/// <para>
/// <b>More than one process.</b> Every process of the instance that can see the directory reads
/// the same file. A change made by another process is picked up within
/// <see cref="RecheckInterval"/>, from the file's time and length.
/// </para>
/// <para>
/// The file is written to a temporary name and moved into place, so a reader sees the old record
/// or the new one and never half of either, and is restricted to its owner.
/// </para>
/// </remarks>
public sealed class InstanceModeStore : IInstanceModeGate
{
    /// <summary>The file's name.</summary>
    public const string FileName = "instance-mode.json";

    /// <summary>The environment variable naming the hub's socket; unset means no hub.</summary>
    public const string HubSocketVariable = "MODULARCA__HUB__SOCKET";

    /// <summary>The environment variable naming the mode a node with a hub socket and no recorded mode starts in.</summary>
    public const string HubStartModeVariable = "MODULARCA__HUB__STARTMODE";

    /// <summary>How often, at most, the file is looked at for a change made by another process.</summary>
    public static readonly TimeSpan RecheckInterval = TimeSpan.FromSeconds(1);

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

    private readonly object _lock = new();
    private readonly InstanceModeRecord _whenNoFile;
    private readonly TimeProvider _time;
    private InstanceModeRecord _current;
    private (DateTime Written, long Length)? _stamp;
    private DateTimeOffset _checkedAt;

    /// <summary>
    /// Opens the record at <paramref name="filePath"/>, answering <paramref name="whenNoFile"/>
    /// for as long as there is no file there.
    /// </summary>
    /// <param name="filePath">The state file's full path. Its directory need not exist until a mode is set.</param>
    /// <param name="whenNoFile">The answer while no mode has been recorded.</param>
    /// <param name="time">The clock; the system's when null.</param>
    public InstanceModeStore(string filePath, InstanceModeRecord whenNoFile, TimeProvider? time = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(whenNoFile);
        FilePath = Path.GetFullPath(filePath);
        _whenNoFile = whenNoFile;
        _time = time ?? TimeProvider.System;
        _current = Load(out _stamp);
        _checkedAt = _time.GetUtcNow();
    }

    /// <summary>The state file's full path.</summary>
    public string FilePath { get; }

    /// <summary>
    /// The state file's path: beside the hub's socket when one is configured, otherwise in the
    /// host's config directory.
    /// </summary>
    /// <param name="hubSocketPath">The value of <see cref="HubSocketVariable"/>, or null or empty when unset.</param>
    /// <param name="configDirectory">The host's config directory.</param>
    public static string PathFor(string? hubSocketPath, string configDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configDirectory);
        if (string.IsNullOrWhiteSpace(hubSocketPath))
            return Path.Combine(configDirectory, FileName);
        var directory = Path.GetDirectoryName(Path.GetFullPath(hubSocketPath.Trim()));
        return Path.Combine(string.IsNullOrEmpty(directory) ? configDirectory : directory, FileName);
    }

    /// <summary>
    /// Opens the store by the start rules: with a hub socket and no file, the mode
    /// <paramref name="startMode"/> names, or restricted when it is null or empty; with no hub
    /// socket and no file, full. Throws <see cref="ArgumentException"/> when
    /// <paramref name="startMode"/> is not <c>full</c>, <c>restricted</c> or <c>dr</c>, because
    /// guessing a mode either way would be wrong.
    /// </summary>
    /// <param name="hubSocketPath">The value of <see cref="HubSocketVariable"/>, or null or empty when unset.</param>
    /// <param name="startMode">The value of <see cref="HubStartModeVariable"/>, or null or empty when unset.</param>
    /// <param name="configDirectory">The host's config directory.</param>
    /// <param name="time">The clock; the system's when null.</param>
    public static InstanceModeStore Open(string? hubSocketPath, string? startMode, string configDirectory, TimeProvider? time = null)
    {
        var clock = time ?? TimeProvider.System;
        var whenNoFile = InstanceModeRecord.DefaultFull;
        if (!string.IsNullOrWhiteSpace(hubSocketPath))
        {
            var mode = InstanceMode.Restricted;
            if (!string.IsNullOrWhiteSpace(startMode) && !InstanceModeGate.TryParse(startMode, out mode))
                throw new ArgumentException(
                    $"{HubStartModeVariable} is '{startMode}'; it takes {InstanceModeGate.NamesForMessages}.");
            whenNoFile = new InstanceModeRecord(mode, InstanceModeSource.Start, SetAtUtc: clock.GetUtcNow().UtcDateTime);
        }
        return new InstanceModeStore(PathFor(hubSocketPath, configDirectory), whenNoFile, clock);
    }

    /// <inheritdoc/>
    public InstanceModeRecord Current
    {
        get
        {
            lock (_lock)
            {
                // The absolute difference, so a clock set back does not stop the checks.
                var now = _time.GetUtcNow();
                if ((now - _checkedAt).Duration() >= RecheckInterval)
                {
                    _checkedAt = now;
                    var stamp = Stamp();
                    if (stamp != _stamp)
                        _current = Load(out _stamp);
                }
                return _current;
            }
        }
    }

    /// <summary>
    /// Sets the mode and records who set it and when. The last writer wins. The file is in place
    /// before this returns; a failure to write throws and leaves the mode as it was.
    /// </summary>
    /// <param name="mode">The new mode.</param>
    /// <param name="source">Who is setting it: the hub or an administrator.</param>
    /// <param name="setBy">The administrator's username, or the operator name the hub claimed.</param>
    /// <param name="reason">Why, when a reason was given.</param>
    /// <returns>The record now in force.</returns>
    public InstanceModeRecord Set(InstanceMode mode, InstanceModeSource source, string? setBy, string? reason)
    {
        if (!Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "Not a mode.");
        var record = new InstanceModeRecord(
            mode, source,
            string.IsNullOrWhiteSpace(setBy) ? null : setBy.Trim(),
            string.IsNullOrWhiteSpace(reason) ? null : reason.Trim(),
            _time.GetUtcNow().UtcDateTime);
        var json = JsonSerializer.Serialize(new FileModel
        {
            Version = 1,
            Mode = InstanceModeGate.NameOf(record.Mode),
            Source = SourceName(record.Source),
            SetBy = record.SetBy,
            Reason = record.Reason,
            SetAtUtc = record.SetAtUtc,
        }, Json);

        lock (_lock)
        {
            var directory = Path.GetDirectoryName(FilePath)!;
            Directory.CreateDirectory(directory);
            var temporary = FilePath + ".tmp";
            FileSecurityUtil.WriteOwnerOnly(temporary, json);
            File.Move(temporary, FilePath, overwrite: true);
            FileSecurityUtil.SetOwnerOnly(FilePath);
            _current = record;
            _stamp = Stamp();
            _checkedAt = _time.GetUtcNow();
            return record;
        }
    }

    /// <summary>The name of a source in the file and on the wire.</summary>
    /// <param name="source">The source.</param>
    public static string SourceName(InstanceModeSource source) => source switch
    {
        InstanceModeSource.Default => "default",
        InstanceModeSource.Start => "start",
        InstanceModeSource.Hub => "hub",
        InstanceModeSource.Administrator => "administrator",
        InstanceModeSource.Unreadable => "unreadable",
        _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Not a source."),
    };

    private (DateTime, long)? Stamp()
    {
        try
        {
            var info = new FileInfo(FilePath);
            return info.Exists ? (info.LastWriteTimeUtc, info.Length) : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private InstanceModeRecord Load(out (DateTime, long)? stamp)
    {
        stamp = Stamp();
        if (stamp == null)
            return _whenNoFile;
        try
        {
            var model = JsonSerializer.Deserialize<FileModel>(File.ReadAllText(FilePath), Json);
            if (model != null && InstanceModeGate.TryParse(model.Mode, out var mode))
            {
                var source = model.Source?.Trim().ToLowerInvariant() switch
                {
                    "hub" => InstanceModeSource.Hub,
                    "administrator" => InstanceModeSource.Administrator,
                    "start" => InstanceModeSource.Start,
                    _ => InstanceModeSource.Unreadable,
                };
                if (source != InstanceModeSource.Unreadable)
                    return new InstanceModeRecord(mode, source, model.SetBy, model.Reason, model.SetAtUtc?.ToUniversalTime());
            }
        }
        catch (JsonException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return new InstanceModeRecord(InstanceMode.Restricted, InstanceModeSource.Unreadable,
            Reason: $"{FilePath} could not be read as a mode record.");
    }

    private sealed class FileModel
    {
        public int Version { get; set; }
        public string? Mode { get; set; }
        public string? Source { get; set; }
        public string? SetBy { get; set; }
        public string? Reason { get; set; }
        public DateTime? SetAtUtc { get; set; }
    }
}
