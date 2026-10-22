using System.Collections.Concurrent;

namespace ModularCA.Core.Services;

/// <summary>
/// Why an SSH CA key is still a file on the node: the codes of
/// <see cref="SshKeyAwaitingImport.Code"/>, as the readiness page and the admin key list carry
/// them.
/// </summary>
public static class SshKeyImportReasons
{
    /// <summary>No file was found where the row says the key is.</summary>
    public const string FileMissing = "fileMissing";

    /// <summary>The file is there and could not be read.</summary>
    public const string FileUnreadable = "fileUnreadable";

    /// <summary>The key file is protected by a passphrase.</summary>
    public const string FileEncrypted = "fileEncrypted";

    /// <summary>The file is not an OpenSSH private key this version reads.</summary>
    public const string FileNotAKey = "fileNotAKey";

    /// <summary>The file holds another key than the one the row carries.</summary>
    public const string KeyMismatch = "keyMismatch";

    /// <summary>The public key on the row cannot be read, so no file can be matched to it.</summary>
    public const string RowUnreadable = "rowUnreadable";

    /// <summary>The key is of a type or size the signer holds no SSH CA key of.</summary>
    public const string UnsupportedKey = "unsupportedKey";

    /// <summary>The signer has not unlocked its keystore.</summary>
    public const string SignerLocked = "signerLocked";

    /// <summary>The signer could not be reached.</summary>
    public const string SignerUnreachable = "signerUnreachable";

    /// <summary>The signer predates the SSH keystore and has to be upgraded first.</summary>
    public const string SignerUpgradeRequired = "signerUpgradeRequired";

    /// <summary>The signer refused the key for a reason of its own.</summary>
    public const string SignerRefused = "signerRefused";

    /// <summary>The signer took the key and then did not list it for the row.</summary>
    public const string NotConfirmed = "notConfirmed";

    /// <summary>The import failed for a reason that is none of the others.</summary>
    public const string Failed = "failed";

    /// <summary>No import has looked at the key since this process started.</summary>
    public const string NotAttempted = "notAttempted";

    /// <summary>
    /// The sentence for a code that names no path, no host and nothing the signer or the
    /// operating system said: what the readiness page shows.
    /// </summary>
    public static string Sentence(string code) => code switch
    {
        FileMissing => "The key file is not where the key's row says it is.",
        FileUnreadable => "The key file could not be read.",
        FileEncrypted => "The key file is protected by a passphrase; only an unencrypted key file is imported.",
        FileNotAKey => "The key file is not an OpenSSH private key this version reads.",
        KeyMismatch => "The key file holds another key than the one this SSH CA publishes.",
        RowUnreadable => "The public key recorded for this SSH CA cannot be read.",
        UnsupportedKey => "The key is of a type or size the signer holds no SSH CA key of.",
        SignerLocked => "The signer has not unlocked its keystore; the import runs once it has.",
        SignerUnreachable => "The signer could not be reached; the import runs once it answers.",
        SignerUpgradeRequired => "The signer predates the SSH keystore and must be upgraded first.",
        SignerRefused => "The signer refused the key.",
        NotConfirmed => "The signer took the key and does not list it for this SSH CA; the key file was left in place.",
        NotAttempted => "The import has not looked at this key yet; it runs in the control role once the signer is unlocked.",
        _ => "The import failed; the node's log has the reason.",
    };
}

/// <summary>
/// One SSH CA key that stayed a file on the node after an import pass, and why.
/// </summary>
/// <param name="KeyId">The <c>SshCaKeys</c> row.</param>
/// <param name="Name">The SSH CA key's name.</param>
/// <param name="Code">One of <see cref="SshKeyImportReasons"/>.</param>
/// <param name="Reason">The sentence for the code, which names no path and nothing the signer said.</param>
/// <param name="Detail">The whole reason for an operator: the path looked at, what the signer answered.</param>
/// <param name="KeyFile">The path the key file was expected at, or read from; null when the row names none.</param>
/// <param name="At">When the pass decided it.</param>
public sealed record SshKeyAwaitingImport(Guid KeyId, string Name, string Code, string Reason, string Detail, string? KeyFile, DateTime At);

/// <summary>What one import pass did.</summary>
/// <param name="Imported">The keys imported in this pass, by row id.</param>
/// <param name="Awaiting">The keys that are still files, each with its reason.</param>
/// <param name="FilesPending">Imported keys whose file could not be removed yet.</param>
/// <param name="AuditsPending">Imported keys whose audit entry could not be written yet.</param>
/// <param name="WaitingOnSigner">Whether keys were left only because the signer is locked or out of reach.</param>
public sealed record SshKeyImportReport(
    IReadOnlyList<Guid> Imported, IReadOnlyList<SshKeyAwaitingImport> Awaiting, int FilesPending, int AuditsPending, bool WaitingOnSigner)
{
    /// <summary>A pass that found nothing to do.</summary>
    public static readonly SshKeyImportReport Nothing = new([], [], 0, 0, false);

    /// <summary>Whether another pass has anything left to do.</summary>
    public bool WorkRemains => Awaiting.Count > 0 || FilesPending > 0 || AuditsPending > 0;
}

/// <summary>What the retry in the background does next, from what the last pass left.</summary>
public enum SshKeyImportNext
{
    /// <summary>Nothing is left to import or to finish; the retry ends.</summary>
    Nothing,

    /// <summary>Run a pass now.</summary>
    Run,

    /// <summary>Keys were left only because the signer was locked or out of reach: run a pass as soon as it reports unlocked.</summary>
    RunWhenSignerUnlocked,

    /// <summary>Keys were left for a reason an operator has to act on; it is not yet time to look again.</summary>
    Wait,
}

/// <summary>
/// What the last import pass in this process left: the keys still awaiting import, with their
/// reasons. One instance for the process; the readiness page and the admin key list read it,
/// and the retry in the background decides from it when to run the next pass. It holds no key
/// and no key material.
/// </summary>
public sealed class SshKeyImportState
{
    private readonly ConcurrentDictionary<Guid, SshKeyAwaitingImport> _awaiting = new();
    private volatile SshKeyImportReport? _last;

    /// <summary>The report of the last pass, or null when none has run in this process.</summary>
    public SshKeyImportReport? Last => _last;

    /// <summary>When the last pass finished, or null when none has run in this process.</summary>
    public DateTime? LastRunAt { get; private set; }

    /// <summary>Why <paramref name="keyId"/> is still a file, as the last pass found it; null when it said nothing about the key.</summary>
    public SshKeyAwaitingImport? Of(Guid keyId) => _awaiting.GetValueOrDefault(keyId);

    /// <summary>
    /// What the retry does at <paramref name="now"/>. With no pass yet in this process, one
    /// runs. With nothing left, the retry ends. Keys left because the signer was locked or
    /// unreachable are tried as soon as it is unlocked; keys left for any other reason (a
    /// missing or encrypted file, a signer to upgrade, a file that could not be removed) are
    /// looked at again every <paramref name="settledInterval"/>, so a file an operator puts in
    /// place is taken without a restart.
    /// </summary>
    public SshKeyImportNext Next(DateTime now, TimeSpan settledInterval)
    {
        var last = _last;
        if (last == null)
            return SshKeyImportNext.Run;
        if (!last.WorkRemains)
            return SshKeyImportNext.Nothing;
        if (last.WaitingOnSigner)
            return SshKeyImportNext.RunWhenSignerUnlocked;
        return LastRunAt is { } ran && now - ran < settledInterval ? SshKeyImportNext.Wait : SshKeyImportNext.Run;
    }

    /// <summary>
    /// Takes the result of a pass. Returns the keys whose reason is new or has changed since the
    /// pass before, which are the ones worth a line in the log.
    /// </summary>
    public IReadOnlyList<SshKeyAwaitingImport> Record(SshKeyImportReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var changed = new List<SshKeyAwaitingImport>();
        var current = report.Awaiting.Select(a => a.KeyId).ToHashSet();
        foreach (var id in _awaiting.Keys)
        {
            if (!current.Contains(id))
                _awaiting.TryRemove(id, out _);
        }
        foreach (var awaiting in report.Awaiting)
        {
            if (!_awaiting.TryGetValue(awaiting.KeyId, out var before) || before.Code != awaiting.Code || before.Detail != awaiting.Detail)
                changed.Add(awaiting);
            _awaiting[awaiting.KeyId] = awaiting;
        }
        _last = report;
        LastRunAt = DateTime.UtcNow;
        return changed;
    }
}
