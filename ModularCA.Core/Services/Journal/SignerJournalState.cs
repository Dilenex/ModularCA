using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services.Journal;

/// <summary>
/// The signer's issuance journal as the readiness check last saw it, kept in memory so that
/// the hub's inventory can report it without calling the signer, and what that reading
/// amounts to: fine, or something an administrator should look at before a full volume stops
/// issuance.
/// </summary>
public sealed class SignerJournalState
{
    /// <summary>
    /// Free space below which the journal's volume is reported as low when the signer does not
    /// give its own level: 1 GiB, the default of <c>Signer.Journal.LowSpaceMiB</c>.
    /// </summary>
    public const long LowFreeBytes = 1L << 30;

    /// <summary>
    /// Free space below which the journal's volume is reported as nearly full when the signer
    /// does not give its own level: 128 MiB, the default of <c>Signer.Journal.CriticalSpaceMiB</c>.
    /// </summary>
    public const long CriticalFreeBytes = 128L << 20;

    /// <summary>How old the newest checkpoint may be while records wait for one, in seconds, before it is reported.</summary>
    public const int StaleCheckpointSeconds = 60;

    /// <summary>The journal is fine, or the signer keeps none.</summary>
    public const string Ok = "ok";
    /// <summary>The signer keeps no journal, or predates it.</summary>
    public const string None = "none";
    /// <summary>
    /// The signer has not answered, so nothing is known of its journal yet: it is still starting, or
    /// cannot be reached. Distinct from <see cref="None"/>, which is the signer's own answer that it
    /// keeps no journal, so that a caller who reads the check just after a start can ask again.
    /// </summary>
    public const string NotKnown = "not_known";
    /// <summary>The journal cannot take a record: certificates and CRLs are refused.</summary>
    public const string Unavailable = "unavailable";
    /// <summary>The journal's volume is nearly full.</summary>
    public const string CriticalSpace = "critical_space";
    /// <summary>The journal's volume is low on space.</summary>
    public const string LowSpace = "low_space";
    /// <summary>Records wait for a checkpoint that is not being written.</summary>
    public const string StaleCheckpoint = "stale_checkpoint";
    /// <summary>
    /// The system key changed, the signer does not hold the old one, and the journal waits for
    /// a restore marker to explain it. The signer signs and records meanwhile.
    /// </summary>
    public const string AwaitingRestoreMarker = "awaiting_restore_marker";
    /// <summary>
    /// The signer refused the last full CRL of at least one CA because it left out revoked
    /// serials. Certificates are issued and OCSP is answered; no new CRL is signed for that CA
    /// until the serials are revoked again.
    /// </summary>
    public const string CrlRefused = "crl_refused";
    /// <summary>
    /// The journal as it lay on disk when the signer started did not verify under the system key
    /// the signer holds. The signer goes on recording and checking; nothing is given back from
    /// the journal to a database that has lost revocations.
    /// </summary>
    public const string NotVerified = "not_verified";
    /// <summary>
    /// Revocations the journal holds are missing from the database and wait to be made again,
    /// because the instance is in DR mode. They are made when the mode is changed.
    /// </summary>
    public const string MergePending = "merge_pending";
    /// <summary>The node is making again the revocations the journal holds and the database lacks.</summary>
    public const string MergeRunning = "merge_running";

    /// <summary>
    /// Whether a status makes the node not ready. Only a journal that cannot take a record
    /// does: then the signer issues nothing. Every other status is a warning, and a node that
    /// reported itself not ready for a warning would have an upgrade or a roll-back reported as
    /// failed for it.
    /// </summary>
    public static bool FailsReadiness(string status) => status == Unavailable;

    private readonly object _gate = new();
    private Observation? _last;

    /// <summary>One reading of the journal.</summary>
    /// <param name="Info">What the signer reported; null when it keeps no journal.</param>
    /// <param name="AtUtc">When it was asked.</param>
    public sealed record Observation(SignerJournalInfo? Info, DateTime AtUtc);

    /// <summary>The last reading; null until the readiness check has asked.</summary>
    public Observation? Last
    {
        get { lock (_gate) return _last; }
    }

    /// <summary>Keeps a reading.</summary>
    public void Observe(SignerJournalInfo? info, DateTime atUtc)
    {
        lock (_gate)
            _last = new Observation(info, atUtc);
    }

    /// <summary>
    /// What a reading amounts to, and the sentence to show for it; the sentence is null when
    /// there is nothing to say.
    /// </summary>
    public static (string Status, string? Message) Assess(SignerJournalInfo? info, DateTime nowUtc)
    {
        if (info == null)
            return (None, null);
        if (!info.Available)
            return (Unavailable,
                "The signer's issuance journal cannot be written, so the signer issues no certificate and signs no CRL until it can. "
                + (string.IsNullOrWhiteSpace(info.Fault) ? "Check the journal's directory and the space on its volume." : info.Fault));
        // While the journal waits for a restore marker its system key is not the one it was written under: that wait is the status, below.
        if (info.Verified == false && !(info.AwaitingRestoreMarkerUntilUtc is DateTime waitingUntil && waitingUntil > nowUtc))
            return (NotVerified,
                "The signer's issuance journal did not verify when the signer started. "
                + (string.IsNullOrWhiteSpace(info.VerificationFault) ? string.Empty : info.VerificationFault + " ")
                + "The signer goes on recording and checking, and revocations a database has lost are restored only from records that a checkpoint of a key "
                + "the signer's system key signed for covers. Run --journal-verify on the journal and keep its files as they are.");
        if (info.RefusedCrls is { Count: > 0 } refused)
            return (CrlRefused,
                $"The signer refuses to sign a new CRL for {refused.Count} CA(s): the CRL would leave out {refused.Sum(r => (long)r.MissingSerials)} serial(s) that the last CRL it signed lists as revoked, "
                + "which is what a database that was taken back does. The CRLs already published stay in force until they run out; certificates are issued and OCSP is answered as before. "
                + "Revoke the serials again (a serial can be revoked without its certificate). The whole list for a CA: GET /api/v1/admin/authorities/{caId}/revoked-serials/missing-from-crl.");
        if (info.AwaitingRestoreMarkerUntilUtc is DateTime until && until > nowUtc)
            return (AwaitingRestoreMarker,
                "The signer's system key is not the one its journal was last written under, and the signer does not hold the old key. "
                + $"The journal waits {Left(until - nowUtc)} more (until {until:yyyy-MM-dd HH:mm:ss} UTC) for a restore to explain the change, and then records it without an explanation. "
                + "The signer signs and records meanwhile; only the journal's checkpoints wait.");
        var (lowLevel, criticalLevel) = Levels(info);
        if (info.FreeBytes is long free && free < criticalLevel)
            return (CriticalSpace,
                $"The volume of the signer's issuance journal has {Size(free)} free. The signer goes on issuing until a write to the journal fails; from then it issues no certificate and signs no CRL. Give the volume more space.");
        if (info.FreeBytes is long low && low < lowLevel)
            return (LowSpace,
                $"The volume of the signer's issuance journal has {Size(low)} free and the journal takes {Size(info.SizeBytes)}. A full volume stops issuance; give it more space before then.");
        if (info.UncheckpointedRecords > 0 && info.LastCheckpointAtUtc is DateTime at && (nowUtc - at).TotalSeconds > StaleCheckpointSeconds)
            return (StaleCheckpoint,
                $"The signer's issuance journal holds {info.UncheckpointedRecords} record(s) no checkpoint covers, and its last checkpoint is {(int)(nowUtc - at).TotalSeconds} seconds old. The signer's log says why.");
        return (Ok, null);
    }

    /// <summary>
    /// The two free-space levels a reading is held to: the signer's own
    /// (<c>Signer.Journal.LowSpaceMiB</c>, <c>CriticalSpaceMiB</c>; 0 is "never") when it gives
    /// them, the defaults when it does not, as a signer from before the settings.
    /// </summary>
    public static (long Low, long Critical) Levels(SignerJournalInfo info)
        => (info.LowSpaceBytes ?? LowFreeBytes, info.CriticalSpaceBytes ?? CriticalFreeBytes);

    private static string Left(TimeSpan left)
        => left.TotalSeconds < 90 ? $"{Math.Max(1, (int)left.TotalSeconds)} second(s)" : $"{(int)Math.Ceiling(left.TotalMinutes)} minute(s)";

    private static string Size(long bytes)
        => bytes >= 1L << 30 ? $"{bytes / (double)(1L << 30):0.#} GiB" : bytes >= 1L << 20 ? $"{bytes / (double)(1L << 20):0.#} MiB" : $"{bytes / 1024.0:0.#} KiB";
}
