namespace ModularCA.Bootstrap;

/// <summary>
/// The exit statuses of <c>--restore</c> and <c>--backup-manifest</c>, and the fixed phrases their
/// last line of output starts with. The numbers are the ones the schema step and
/// <c>--upgrade-check</c> use, with the same meanings (<c>SchemaStartup.ExitCode</c>,
/// <c>AppliedThenFailedExitCode</c> and <c>TempFailExitCode</c> in ModularCA.API), so an
/// orchestrator reads one convention: 3 promises that nothing was changed, 4 says something was,
/// 75 asks for the same command again.
/// </summary>
/// <remarks>
/// "Changed" means the application database, the audit database, the keystores or the config
/// directory. Two things a refused restore may leave behind are not counted, because neither is
/// state the instance runs from: the pre-restore snapshot in the backup directory
/// (<c>pre-restore-&lt;timestamp&gt;.zip</c>), and the records of the attempt (the signer's audit
/// rows for the export of the live keystores, the signer's journal entry, the log).
/// </remarks>
public static class RestoreExit
{
    /// <summary>The restore completed, or the manifest was printed.</summary>
    public const int Done = 0;

    /// <summary>
    /// Refused, and nothing was changed: bad arguments, an archive that cannot be read or opened
    /// with the key given, an archive this build must not restore, a precondition that is not met,
    /// a node, the signer service or another restore using the application database
    /// (<see cref="RestoreResult.InUse"/>), or a database restore that failed inside its one
    /// transaction and was rolled back.
    /// </summary>
    public const int Refused = 3;

    /// <summary>
    /// Failed after something was changed, or may have been: a database now holds the archive's
    /// contents and a later step failed, or a database restore ended without its outcome known.
    /// </summary>
    public const int FailedAfterChanges = 4;

    /// <summary>A database could not be reached before anything was changed; try again.</summary>
    public const int Unreachable = 75;

    /// <summary>What the last line starts with on <see cref="Done"/>.</summary>
    public const string DoneMarker = "RESTORE: DONE";

    /// <summary>What the last line starts with on <see cref="Refused"/>.</summary>
    public const string RefusedMarker = "RESTORE: REFUSED";

    /// <summary>What the last line starts with on <see cref="FailedAfterChanges"/>.</summary>
    public const string FailedAfterChangesMarker = "RESTORE: FAILED AFTER CHANGES";

    /// <summary>What the last line starts with on <see cref="Unreachable"/>.</summary>
    public const string UnreachableMarker = "RESTORE: UNREACHABLE";
}

/// <summary>How a restore ended: its exit status and the one line that says which it was.</summary>
/// <param name="ExitCode">A status from <see cref="RestoreExit"/>.</param>
/// <param name="Verdict">
/// The last line of the restore's output. It starts with the marker of <paramref name="ExitCode"/>
/// and holds no line break.
/// </param>
public sealed record RestoreResult(int ExitCode, string Verdict)
{
    /// <summary>
    /// True when the restore was refused because a node, the signer service or another restore is
    /// using the application database (<see cref="ModularCA.Database.RestoreLock"/>). The exit
    /// status is <see cref="RestoreExit.Refused"/> and nothing was changed.
    /// </summary>
    public bool DatabaseInUse { get; init; }

    /// <summary>The restore completed.</summary>
    /// <param name="auditKept">Whether this host's audit database was kept.</param>
    /// <param name="incarnationStored">
    /// Whether this machine's incarnation was stored in the restored database. When it was not,
    /// the restore is still done, and the line says that the next start shows a roll-back notice.
    /// </param>
    public static RestoreResult Done(bool auditKept, bool incarnationStored = true) => new(RestoreExit.Done,
        $"{RestoreExit.DoneMarker} (the audit database was {(auditKept ? "kept" : "replaced with the archive's")}"
        + (incarnationStored ? "" : "; the incarnation was not stored, so the next start shows a roll-back notice")
        + "). Start the node to apply the restored state.");

    /// <summary>Refused before anything was changed.</summary>
    /// <param name="reason">Why, in a few words.</param>
    public static RestoreResult Refused(string reason) => new(RestoreExit.Refused,
        $"{RestoreExit.RefusedMarker} ({OneLine(reason)}). Nothing was changed.");

    /// <summary>
    /// Refused before anything was changed, because a node, the signer service or another restore
    /// is using the application database and has to be stopped first.
    /// </summary>
    /// <param name="reason">Who is using it and what to do (<see cref="ModularCA.Database.RestoreLock.NodeInUse"/> and its siblings).</param>
    public static RestoreResult InUse(string reason) => Refused(reason) with { DatabaseInUse = true };

    /// <summary>A database could not be reached before anything was changed.</summary>
    /// <param name="reason">Which, and how it failed.</param>
    public static RestoreResult Unreachable(string reason) => new(RestoreExit.Unreachable,
        $"{RestoreExit.UnreachableMarker} ({OneLine(reason)}); try again. Nothing was changed.");

    /// <summary>Failed after a database, a keystore or the config directory was changed, or may have been.</summary>
    /// <param name="reason">What failed, in a few words.</param>
    public static RestoreResult FailedAfterChanges(string reason) => new(RestoreExit.FailedAfterChanges,
        $"{RestoreExit.FailedAfterChangesMarker} ({OneLine(reason)}). This instance is part restored: put back the copy taken before the restore, or fix the cause and restore again, before starting the node.");

    /// <summary>A reason as it goes into a verdict: on one line, without the brackets that close it, held to a length.</summary>
    private static string OneLine(string reason)
    {
        var flat = string.Join(' ', (reason ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).TrimEnd('.');
        return flat.Length <= 300 ? flat : flat[..300] + "...";
    }
}

/// <summary>What a command-line or console restore was asked to do, beyond the archive.</summary>
public sealed record RestoreOptions
{
    /// <summary>Whether the archive's audit database replaces this host's (<c>--restore-audit</c>). False keeps the host's.</summary>
    public bool RestoreAudit { get; init; }

    /// <summary>Skips the comparison of the archive's schema with the database's and with this build. Nothing passes it today.</summary>
    public bool SkipSchemaCheck { get; init; }

    /// <summary>
    /// True asks on standard input for the word <c>RESTORE</c> before anything changes. False is for
    /// a caller that has confirmed already: <c>--unattended</c>, or the console's restore token.
    /// </summary>
    public bool Interactive { get; init; } = true;

    /// <summary>Where the archive's key comes from; null reads this host's key files.</summary>
    public BackupKeySource? Keys { get; init; }

    /// <summary>
    /// How the restore gets the application database to itself. Null, for the command line,
    /// takes the restore lock on a connection of its own
    /// (<see cref="ModularCA.Database.RestoreLock.OwnConnection"/>): refused while any node or
    /// the signer service runs. The console passes the lock of the node it runs in
    /// (<see cref="ModularCA.Database.ServingDatabaseLock"/>), which is refused only while
    /// another node, or another restore, uses the database.
    /// </summary>
    public ModularCA.Database.IRestoreExclusion? Exclusion { get; init; }
}
