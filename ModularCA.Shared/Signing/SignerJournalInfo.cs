using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Shared.Signing;

/// <summary>
/// The signer's journal as the signer reports it: where its chain stands and how much room it
/// has. No record, serial or key is in it.
/// </summary>
/// <param name="Available">Whether the journal can take a record now. False stops issuance and CRL signing: the signer returns nothing it could not record.</param>
/// <param name="Fault">Why it cannot, when it cannot.</param>
/// <param name="Seq">The sequence of the last record flushed.</param>
/// <param name="Hash">The hash of the last record flushed, lower-case hex.</param>
/// <param name="LastCheckpointAtUtc">When the newest checkpoint was written; null when this run of the signer has written none.</param>
/// <param name="UncheckpointedRecords">Records written since the newest checkpoint.</param>
/// <param name="SizeBytes">The bytes the journal's segments take.</param>
/// <param name="FreeBytes">The free space on the volume the journal is on; null when the signer could not read it.</param>
/// <param name="AwaitingRestoreMarkerUntilUtc">
/// When the system key changed, nothing the signer holds explains it, and the journal waits for
/// the node's restore marker: the time the wait ends, after which the change is recorded
/// without an explanation. Null otherwise. The signer signs and records during the wait; only
/// checkpoints are held back.
/// </param>
/// <param name="LowSpaceBytes">The free space below which the signer's settings call the volume low, 0 for never; null from a signer that does not say.</param>
/// <param name="CriticalSpaceBytes">The free space below which the signer's settings call the volume nearly full, 0 for never; null from a signer that does not say.</param>
/// <param name="SetAsideJournals">How many journals lie set aside in the journal's home.</param>
/// <param name="SetAsideBytes">The bytes their files take. They are on the journal's volume when the directory is, and nothing prunes them.</param>
/// <param name="RefusedCrls">The CAs whose newest CRL the signer refused because it leaves out revoked serials, and has not signed one for since; empty when there is none.</param>
/// <param name="Verified">
/// Whether the journal, as it lay on disk when the signer started, verified: its chain, every
/// checkpoint and every key block, under the system key the signer holds. Null while that is
/// still being checked. False does not stop the signer; it stops the journal being used to give
/// revocations back to a database that has lost them.
/// </param>
/// <param name="VerificationFault">Why not, when <paramref name="Verified"/> is false.</param>
/// <param name="VerifiedBytes">
/// How far the verification at the signer's start has got: the bytes of whole records read so
/// far. Null before it has begun; equal to <paramref name="VerifyTotalBytes"/> when it has read
/// to the end.
/// </param>
/// <param name="VerifyTotalBytes">The bytes of the journal's segments as they were when the verification began; null before it has begun.</param>
public sealed record SignerJournalInfo(
    bool Available,
    string? Fault,
    ulong Seq,
    string Hash,
    DateTime? LastCheckpointAtUtc,
    long UncheckpointedRecords,
    long SizeBytes,
    long? FreeBytes,
    DateTime? AwaitingRestoreMarkerUntilUtc = null,
    long? LowSpaceBytes = null,
    long? CriticalSpaceBytes = null,
    int SetAsideJournals = 0,
    long SetAsideBytes = 0,
    IReadOnlyList<SignerJournalRefusedCrl>? RefusedCrls = null,
    bool? Verified = null,
    string? VerificationFault = null,
    long? VerifiedBytes = null,
    long? VerifyTotalBytes = null);

/// <summary>
/// The revocations the signer's journal holds for one CA, for a node whose database may have
/// gone back in time: the entries of the newest full CRL the signer journaled for the CA's key,
/// changed by a delta CRL journaled after it, then by every revocation fact and released hold
/// the node asserted after that CRL, in the order they were recorded. A hold that was released
/// is not in it. One answer carries a part of the list (<paramref name="Entries"/>);
/// <paramref name="Total"/> is the whole.
/// </summary>
/// <param name="CaId">The CA.</param>
/// <param name="Trusted">
/// False when the signer does not answer from its journal: the journal did not verify under the
/// system key the signer holds, or the CA's newest CRL in it is not vouched for by a checkpoint
/// or does not carry a signature that verifies under the CA's key. There are then no entries,
/// and a node must not take anything from the answer.
/// </param>
/// <param name="NotTrustedReason">Why, when <paramref name="Trusted"/> is false.</param>
/// <param name="CrlNumber">The number of the full CRL the list starts from; null when the journal holds none for the CA and the list is facts alone.</param>
/// <param name="CrlSeq">The sequence of that CRL's record in the journal.</param>
/// <param name="Total">How many entries the whole list has.</param>
/// <param name="Entries">The entries asked for, in ascending order of serial.</param>
public sealed record SignerJournaledRevocations(Guid CaId, bool Trusted, string? NotTrustedReason, long? CrlNumber, ulong? CrlSeq, int Total,
    IReadOnlyList<SignerJournaledRevocation> Entries);

/// <summary>One revocation the journal holds.</summary>
/// <param name="Serial">The serial, hex, upper case, no leading zeros.</param>
/// <param name="Reason">The RFC 5280 reason code: the journaled CRL's, or the fact's own. 6 for a hold.</param>
/// <param name="RevokedAtUtc">The revocation date: the journaled CRL's, or the fact's own.</param>
/// <param name="Hold">Whether it is a hold that stands.</param>
/// <param name="Source"><c>crl</c>, <c>delta</c> or <c>fact</c>: where the entry comes from.</param>
/// <param name="SourceNumber">The CRL number, for <c>crl</c> and <c>delta</c>; 0 for a fact.</param>
/// <param name="SourceSeq">The sequence of the journal record it comes from.</param>
public sealed record SignerJournaledRevocation(string Serial, int Reason, DateTime RevokedAtUtc, bool Hold, string Source, long SourceNumber, ulong SourceSeq);

/// <summary>
/// A CA for which the signer refused the last full CRL it was offered, because the CRL left out
/// serials that the newest CRL in the journal lists as revoked and nothing excuses. It stands
/// until the signer signs a full CRL for that CA key, and is forgotten when the signer restarts
/// (the next CRL the node offers brings it back if it still holds).
/// </summary>
/// <param name="CaId">The CA's identifier, when the signing key belongs to a registered CA.</param>
/// <param name="CaKey">SHA-256 of the CA key's SubjectPublicKeyInfo, lower-case hex.</param>
/// <param name="MissingSerials">How many serials the refused CRL left out.</param>
/// <param name="RefusedAtUtc">When the signer last refused.</param>
/// <param name="JournaledCrlNumber">The number of the journaled CRL that lists them.</param>
public sealed record SignerJournalRefusedCrl(Guid? CaId, string CaKey, int MissingSerials, DateTime RefusedAtUtc, long JournaledCrlNumber);

/// <summary>
/// Every serial a refused CRL left out, for one CA: what the newest full CRL in the signer's
/// journal lists as revoked, that the CRL the node last offered did not list, and that is not
/// excused (it was not on hold, and it is not shown to be expired).
/// </summary>
/// <param name="CaId">The CA.</param>
/// <param name="RefusedAtUtc">When the signer last refused a CRL for it.</param>
/// <param name="JournaledCrlNumber">The number of the journaled CRL that lists the serials.</param>
/// <param name="Serials">The serials, in ascending order.</param>
public sealed record SignerJournalMissingRevocations(Guid CaId, DateTime RefusedAtUtc, long JournaledCrlNumber, IReadOnlyList<SignerJournalMissingSerial> Serials);

/// <summary>One serial a refused CRL left out, as the journaled CRL lists it.</summary>
/// <param name="Serial">The serial, hex, no leading zeros, upper case.</param>
/// <param name="Reason">The RFC 5280 reason code the journaled CRL gives; 0 when it gives none.</param>
/// <param name="RevokedAtUtc">The revocation date the journaled CRL gives.</param>
public sealed record SignerJournalMissingSerial(string Serial, int Reason, DateTime RevokedAtUtc);

/// <summary>
/// The incarnation value as the journal carries it in every record: SHA-256 of the value's
/// UTF-8 bytes with surrounding white space removed, which is the hash the node stores for its
/// continuity check, so a record matches a continuity event by comparing the two.
/// </summary>
public static class InstanceIncarnationHash
{
    /// <summary>The environment variable an orchestrator sets; the node's continuity check reads the same one.</summary>
    public const string Variable = "MODULARCA__INSTANCE__INCARNATION";

    /// <summary>The hash of <paramref name="value"/>, 32 bytes; all zero for no value.</summary>
    public static byte[] Of(string? value)
        => string.IsNullOrWhiteSpace(value) ? new byte[32] : SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim()));

    /// <summary>The hash of the value in this process's environment; all zero when none is set.</summary>
    public static byte[] FromEnvironment() => Of(Environment.GetEnvironmentVariable(Variable));

    /// <summary>The 32 bytes of a hash the node stores as hex; all zero for null, empty or malformed text.</summary>
    public static byte[] FromStoredHex(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex.Trim().Length != 64)
            return new byte[32];
        try { return Convert.FromHexString(hex.Trim()); }
        catch (FormatException) { return new byte[32]; }
    }
}
