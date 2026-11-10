namespace ModularCA.Shared.Signing;

/// <summary>
/// One keystore event from the signer's journal: where it stands in the journal and what it says.
/// </summary>
/// <param name="File">The journal file's name, never a path: <c>keystore-audit-yyyyMMdd.jsonl</c>.</param>
/// <param name="Line">The event's line in that file, counted from 0.</param>
/// <param name="Json">
/// The event as one JSON object holding only the fields a keystore event has (when, the action,
/// the keystore's name, whether it succeeded, a detail), as the signer rebuilt it from the line:
/// nothing else a line might carry crosses the wire.
/// </param>
public sealed record SignerJournalEntry(string File, int Line, string Json);

/// <summary>
/// One read of the signer's journal.
/// </summary>
/// <param name="Entries">The events after the position asked for, oldest first.</param>
/// <param name="More">Whether the journal holds events after the last one returned.</param>
/// <param name="Anchor">
/// The event at the very position asked for, or null when the journal has none there. A reader
/// that remembers what it last took compares the two, and so learns that the journal is not the
/// one it read from before (the signer's directory was restored or replaced) and starts over.
/// </param>
public sealed record SignerJournalPage(IReadOnlyList<SignerJournalEntry> Entries, bool More, string? Anchor)
{
    /// <summary>A read that found nothing: no journal, or a signer that keeps none to hand over.</summary>
    public static SignerJournalPage Empty { get; } = new([], false, null);
}

/// <summary>
/// The signer's keystore events, to read and nothing else. A signer that runs apart from the
/// node records what happens to its keystores (loaded, a key appended, a keystore created, a
/// signature or pin that did not verify) in a journal on its own disk, since it cannot reach the
/// audit database. The node reads the journal through this and writes each event into the audit
/// trail. There is no call that removes, marks or changes an event: what the node has taken is
/// the node's to remember, and the journal stays whole on the signer whatever the node does.
/// </summary>
public interface ISignerEventJournal
{
    /// <summary>The most events one read returns, whatever is asked for.</summary>
    public const int MaxPageSize = 500;

    /// <summary>
    /// Reads the events after a position, oldest first: those of <paramref name="afterFile"/>
    /// on lines after <paramref name="afterLine"/>, then those of every later file.
    /// </summary>
    /// <param name="afterFile">The file of the last event the reader took; null or empty to read from the beginning.</param>
    /// <param name="afterLine">The line of that event; ignored without a file.</param>
    /// <param name="max">The most events to return; held to <see cref="MaxPageSize"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SignerJournalPage> ReadAfterAsync(string? afterFile, int afterLine, int max, CancellationToken cancellationToken = default);
}
