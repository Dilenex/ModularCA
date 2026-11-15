namespace ModularCA.Journal;

/// <summary>
/// The few things the writer does to the journal directory: create it, create a segment and
/// append to it, flush, and rename. There is no call that truncates, rewrites or deletes,
/// because the writer does none of those. Tests substitute an implementation that fails on
/// demand; the product uses <see cref="JournalFiles.Default"/>.
/// </summary>
public interface IJournalFiles
{
    /// <summary>Creates the directory if it does not exist, readable by its owner only where the system has modes.</summary>
    void EnsureDirectory(string directory);

    /// <summary>
    /// Creates a segment file for appending. It must not exist, unless
    /// <paramref name="overStub"/> is true: then a file of that name that holds no whole record,
    /// left by a creation that was interrupted, is replaced.
    /// </summary>
    IJournalAppendFile Create(string path, bool overStub);

    /// <summary>
    /// Renames a segment. The destination must not exist, unless <paramref name="overStub"/> is
    /// true: then a destination that holds no whole record is replaced.
    /// </summary>
    void Rename(string from, string to, bool overStub);
}

/// <summary>A segment file open for appending.</summary>
public interface IJournalAppendFile : IDisposable
{
    /// <summary>Appends <paramref name="bytes"/> at the end of the file.</summary>
    void Append(ReadOnlySpan<byte> bytes);

    /// <summary>Flushes everything appended to the disk; returns only when the device has it.</summary>
    void Flush();
}

/// <summary>The journal's files on the real file system.</summary>
public sealed class JournalFiles : IJournalFiles
{
    /// <summary>The implementation the product uses.</summary>
    public static readonly JournalFiles Default = new();

    /// <inheritdoc />
    public void EnsureDirectory(string directory)
    {
        if (Directory.Exists(directory))
            return;
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(directory);
        else
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The file is opened for writing only, with no buffer of its own (the writer hands it whole
    /// batches), and shared for reading and for a rename, so the head command can read it while
    /// it is appended to. A flush is <see cref="FileStream.Flush(bool)"/> with
    /// <c>flushToDisk: true</c>.
    /// </remarks>
    public IJournalAppendFile Create(string path, bool overStub)
    {
        var options = new FileStreamOptions
        {
            Mode = overStub ? FileMode.Create : FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.Read | FileShare.Delete,
            BufferSize = 0,
            Options = FileOptions.None,
        };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new AppendFile(new FileStream(path, options));
    }

    /// <inheritdoc />
    public void Rename(string from, string to, bool overStub) => File.Move(from, to, overwrite: overStub);

    private sealed class AppendFile : IJournalAppendFile
    {
        private readonly FileStream _stream;

        public AppendFile(FileStream stream) => _stream = stream;

        public void Append(ReadOnlySpan<byte> bytes) => _stream.Write(bytes);

        public void Flush() => _stream.Flush(flushToDisk: true);

        public void Dispose() => _stream.Dispose();
    }
}

/// <summary>
/// The journal could not take a record: its directory is missing, unwritable or full, a flush
/// failed, or what is on disk is not a journal this writer may continue. Whatever was to be
/// recorded is not recorded, and what depended on it must not be returned.
/// </summary>
public sealed class JournalUnavailableException : Exception
{
    /// <summary>Creates the exception.</summary>
    public JournalUnavailableException(string message, Exception? inner = null) : base(message, inner) { }

    /// <summary>
    /// The instance the journal in the directory names, when the journal cannot be continued
    /// because it is another instance's; null for every other reason.
    /// </summary>
    public string? OtherInstanceId { get; init; }
}
