using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Journal;

/// <summary>Where the merge of one CA's revocations from the signer's journal stands.</summary>
/// <param name="CaId">The CA.</param>
/// <param name="CaName">Its name.</param>
/// <param name="State">
/// <see cref="JournalMergeState.Running"/>, <see cref="JournalMergeState.Pending"/> (the instance
/// is in DR mode: the revocations are counted and not made), <see cref="JournalMergeState.Done"/>,
/// <see cref="JournalMergeState.NotTrusted"/> (the signer does not answer from its journal) or
/// <see cref="JournalMergeState.Failed"/> (the signer could not be asked, or a write failed; it is
/// tried again).
/// </param>
/// <param name="Merged">Revocations made again so far.</param>
/// <param name="Remaining">Journaled entries not looked at yet while running; revocations waiting to be made while pending.</param>
/// <param name="Total">Entries the journal holds for the CA.</param>
/// <param name="AtUtc">When the state was last set.</param>
/// <param name="Message">What an administrator should read, when there is something to say.</param>
public sealed record CaMergeStatus(Guid CaId, string CaName, string State, int Merged, int Remaining, int Total, DateTime AtUtc, string? Message);

/// <summary>What one pass of the merge over one CA did.</summary>
/// <param name="State">The state it ended in.</param>
/// <param name="Merged">Revocations made again in this pass.</param>
/// <param name="Pending">Revocations it would have made, in DR mode.</param>
public sealed record JournalMergeResult(string State, int Merged, int Pending);

/// <summary>
/// The merge's state for every CA, kept in memory for <c>/health/ready</c> and so that a CRL is
/// not generated for a CA before its merge has run. It is rebuilt at every start: the merge is
/// worked out again from the journal and the database, which is what makes it resumable.
/// </summary>
public sealed class JournalMergeState
{
    /// <summary>The merge is reading the journal's list and making revocations.</summary>
    public const string Running = "running";
    /// <summary>The instance is in DR mode: the missing revocations are counted and wait.</summary>
    public const string Pending = "pending";
    /// <summary>The merge ran; nothing is missing any more.</summary>
    public const string Done = "done";
    /// <summary>The signer does not answer from its journal for this CA; nothing was taken from it.</summary>
    public const string NotTrusted = "not_trusted";
    /// <summary>The signer could not be asked or a write failed; the merge is tried again.</summary>
    public const string Failed = "failed";

    private readonly ConcurrentDictionary<Guid, CaMergeStatus> _status = new();
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _locks = new();

    /// <summary>The state of every CA the merge has looked at, by name.</summary>
    public IReadOnlyList<CaMergeStatus> Snapshot() => _status.Values.OrderBy(s => s.CaName, StringComparer.Ordinal).ThenBy(s => s.CaId).ToList();

    /// <summary>The state of one CA; null when the merge has not looked at it since this process started.</summary>
    public CaMergeStatus? Of(Guid caId) => _status.TryGetValue(caId, out var status) ? status : null;

    internal void Set(CaMergeStatus status) => _status[status.CaId] = status;

    internal SemaphoreSlim LockOf(Guid caId) => _locks.GetOrAdd(caId, _ => new SemaphoreSlim(1, 1));

    /// <summary>Whether <paramref name="state"/> is one a later pass has to come back to.</summary>
    public static bool NeedsAnotherPass(string state) => state is Pending or Failed or Running;
}

/// <summary>Makes again, in the database, the revocations the signer's journal holds and the database has lost.</summary>
public interface IJournalRevocationMerge
{
    /// <summary>Runs one pass of the merge for CA <paramref name="caId"/>.</summary>
    Task<JournalMergeResult> MergeAsync(Guid caId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs the merge for the CA whose current certificate is <paramref name="caCertificateId"/>,
    /// unless it has already run to an end in this process. A CRL is generated after it.
    /// </summary>
    Task EnsureMergedAsync(Guid caCertificateId, CancellationToken cancellationToken = default);

    /// <summary>Runs a pass for the CA whose current certificate is <paramref name="caCertificateId"/>, whatever its state; null when there is no such CA.</summary>
    Task<JournalMergeResult?> MergeForCertificateAsync(Guid caCertificateId, CancellationToken cancellationToken = default);
}

/// <summary>
/// The merge (<c>docs/architecture/signer-journal.md</c>, "The merge"): after a database has gone
/// back in time, the node asks the signer for the revocations its journal holds for a CA and
/// makes again, in its own database, each one the database no longer has. It only ever adds a
/// revocation; it never releases or removes one.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it takes.</b> The signer's answer (<see cref="ISigningService.JournaledRevocationsAsync"/>):
/// the entries of the newest full CRL the signer journaled for the CA key, a newer delta's, and
/// the revocation facts recorded after it, less the holds released since. The node reads no
/// journal file. An answer that is not trusted is not used at all.
/// </para>
/// <para>
/// <b>What it does with an entry.</b> A certificate the database holds under this CA and that is
/// not revoked is revoked with the entry's date and reason (a hold as a hold), unless it has
/// expired, when it would not be on a CRL anyway. One that is revoked keeps its revocation; the
/// earlier of the two dates stands, and a hold the journal has as permanent becomes permanent.
/// A serial the database does not hold is recorded as revoked with no certificate (a tombstone,
/// as <see cref="RevokedSerialService"/> writes them), with the entry's date and reason; a hold
/// on a serial the database does not hold is passed over, because a tombstone cannot be
/// released.
/// </para>
/// <para>
/// <b>How.</b> In batches of <see cref="BatchSize"/>, each its own save, so a CA with very many
/// entries holds no long transaction and a pass that is interrupted goes on where the database
/// then stands: an entry already made again is found revoked and passed over. Each revocation
/// made is audited (<see cref="AuditActionType.RevocationMergedFromJournal"/>; above
/// <see cref="IndividualAuditLimit"/> for the CA and pass, each batch with one
/// <see cref="AuditActionType.RevocationsMergedFromJournalBatch"/>), each pass that
/// made any writes one summary (<see cref="AuditActionType.JournalRevocationMergeCompleted"/>)
/// and one continuity event that stands as a notice until an administrator acknowledges it. The
/// save queues a <c>Revocation</c> fact for each, as for any revocation.
/// </para>
/// <para>
/// <b>The mode.</b> A revocation is a restriction, so the merge runs in full, restricted and
/// maintenance mode. In DR mode it changes nothing: it counts what is missing and leaves the CA
/// <see cref="JournalMergeState.Pending"/>, and the pass that follows a change of mode makes
/// them.
/// </para>
/// </remarks>
public sealed class JournalRevocationMerge(
    IServiceScopeFactory scopes,
    ISigningService signer,
    JournalMergeState state,
    IInstanceModeGate modeGate,
    ILogger<JournalRevocationMerge> logger) : IJournalRevocationMerge
{
    /// <summary>The audit actor of everything the merge does.</summary>
    public const string Actor = "journal-merge";

    /// <summary>How many entries are looked up and written in one save.</summary>
    public const int BatchSize = 500;

    /// <summary>
    /// Up to and including this many revocations to make for one CA in one pass, each is audited
    /// with a record of its own (<see cref="AuditActionType.RevocationMergedFromJournal"/>).
    /// Above it, each save of <see cref="BatchSize"/> is audited with one record that carries
    /// its serials (<see cref="AuditActionType.RevocationsMergedFromJournalBatch"/>): a record
    /// of the audit trail is a link of its hash chain, written one at a time, and a hundred
    /// thousand of them take minutes and close to a hundred megabytes.
    /// </summary>
    /// <remarks>
    /// A constant and not a setting: the journal's settings are the signer's, and this is the
    /// node's. The pass decides from what it counted missing before it wrote anything. A pass
    /// that was interrupted is not continued in its form: the next pass counts what is still
    /// missing and decides again, and only a pass that reached its end writes a summary.
    /// </remarks>
    public const int DefaultIndividualAuditLimit = 1000;

    /// <summary>The limit in force; <see cref="DefaultIndividualAuditLimit"/> unless a test sets another.</summary>
    public int IndividualAuditLimit { get; init; } = DefaultIndividualAuditLimit;

    /// <summary>The summary's <c>AuditForm</c> when each revocation has a record of its own.</summary>
    public const string AuditFormIndividual = "individual";

    /// <summary>The summary's <c>AuditForm</c> when each batch has one record.</summary>
    public const string AuditFormBatch = "batch";

    /// <summary>How many entries are asked of the signer in one call.</summary>
    public const int PageSize = 2000;

    private const string HoldReason = nameof(RevocationReason.CertificateHold);

    private static readonly JsonSerializerOptions DetailsJson = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <inheritdoc />
    public async Task EnsureMergedAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var caId = await CaOfAsync(caCertificateId, cancellationToken);
        if (caId is not Guid id)
            return;
        await MergeAsync(id, unlessSettled: true, cancellationToken);
    }

    private static bool Settled(CaMergeStatus? known)
        => known != null && known.State is JournalMergeState.Done or JournalMergeState.NotTrusted or JournalMergeState.Pending;

    /// <inheritdoc />
    public async Task<JournalMergeResult?> MergeForCertificateAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        => await CaOfAsync(caCertificateId, cancellationToken) is Guid id ? await MergeAsync(id, cancellationToken) : null;

    private async Task<Guid?> CaOfAsync(Guid caCertificateId, CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        return await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.CertificateId == caCertificateId && !c.IsSshCa)
            .Select(c => (Guid?)c.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<JournalMergeResult> MergeAsync(Guid caId, CancellationToken cancellationToken = default)
        => MergeAsync(caId, unlessSettled: false, cancellationToken);

    private async Task<JournalMergeResult> MergeAsync(Guid caId, bool unlessSettled, CancellationToken cancellationToken)
    {
        var gate = state.LockOf(caId);
        await gate.WaitAsync(cancellationToken);
        var name = caId.ToString("D");
        try
        {
            // A pass that another caller finished while this one waited is not run twice.
            if (unlessSettled && Settled(state.Of(caId)))
                return new JournalMergeResult(state.Of(caId)!.State, 0, 0);
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            var audit = scope.ServiceProvider.GetService<IAuditService>();
            return await MergeLockedAsync(db, audit, caId, n => name = n, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The signer could not be asked, or the database refused a write. What was saved stays; the next pass goes on.
            var before = state.Of(caId);
            // Said once as a warning; while it keeps failing for the same CA, quietly.
            if (before?.State == JournalMergeState.Failed)
                logger.LogDebug(ex, "Journal merge: the pass for CA {CaId} stopped again ({Kind}).", caId, ex.GetType().Name);
            // A signer that is not up yet is what every start of a split install meets, and no fault: said plainly, without the exception.
            else if (ex is SigningRefusedException { Reason: SigningRefusalReason.SignerUnavailable })
                logger.LogInformation("Journal merge: the signer cannot be reached yet, so the pass for CA {CaId} waits; it is tried again.", caId);
            else
                logger.LogWarning(ex, "Journal merge: the pass for CA {CaId} stopped ({Kind}); it is tried again.", caId, ex.GetType().Name);
            state.Set(new CaMergeStatus(caId, name, JournalMergeState.Failed, before?.Merged ?? 0, before?.Remaining ?? 0, before?.Total ?? 0, DateTime.UtcNow,
                $"The merge could not be completed ({ex.GetType().Name}: {ex.Message}). It is tried again."));
            return new JournalMergeResult(JournalMergeState.Failed, 0, 0);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<JournalMergeResult> MergeLockedAsync(ModularCADbContext db, IAuditService? audit, Guid caId, Action<string> named, CancellationToken cancellationToken)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == caId && !c.IsSshCa)
            .Select(c => new { c.Id, c.Name, c.CertificateId, c.SpaceId, Row = c.Certificate })
            .FirstOrDefaultAsync(cancellationToken);
        if (ca?.CertificateId is not Guid caCertificateId || ca.Row == null)
            return new JournalMergeResult(JournalMergeState.Done, 0, 0);
        named(ca.Name);

        X509Certificate caCertificate = ca.Row.RawCertificate is { Length: > 0 } raw
            ? new X509CertificateParser().ReadCertificate(raw)
            : CertificateUtil.ParseFromPem(ca.Row.Pem);
        var issuerDn = caCertificate.SubjectDN.ToString();
        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, caCertificateId, caCertificate, cancellationToken);
        var deferred = !InstanceModeGate.Allows(modeGate.Current.Mode, ModeOperation.Restriction);

        var first = await signer.JournaledRevocationsAsync(caId, 0, PageSize, cancellationToken);
        if (first == null)
        {
            state.Set(new CaMergeStatus(caId, ca.Name, JournalMergeState.Done, 0, 0, 0, DateTime.UtcNow, null));
            return new JournalMergeResult(JournalMergeState.Done, 0, 0);
        }
        if (!first.Trusted)
        {
            var why = $"The signer does not answer from its journal for this CA, so no revocation was taken from it: {first.NotTrustedReason}";
            logger.LogError("Journal merge, CA {Ca}: {Why}", ca.Name, why);
            state.Set(new CaMergeStatus(caId, ca.Name, JournalMergeState.NotTrusted, 0, 0, 0, DateTime.UtcNow, why));
            return new JournalMergeResult(JournalMergeState.NotTrusted, 0, 0);
        }

        var total = first.Total;
        var looked = 0;
        var merged = new List<object>();
        var mergedCount = 0;
        var pending = 0;
        var passedOverHolds = 0;
        DateTime? listedUntilBase = null;
        TimeSpan? longestValidity = null;
        state.Set(new CaMergeStatus(caId, ca.Name, deferred ? JournalMergeState.Pending : JournalMergeState.Running, 0, total, total, DateTime.UtcNow, null));

        // The list is gone through twice when anything is missing: once to count, writing
        // nothing, and once to write. The count decides, before the first write, in which form
        // the pass is audited, so a pass is audited in one form throughout.
        var batched = false;
        var batchRecords = 0;
        async Task RunAsync(bool counting)
        {
            looked = 0;
            pending = 0;
            passedOverHolds = 0;
            var page = first;
            while (true)
            {
                foreach (var batch in page.Entries.Chunk(BatchSize))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var now = DateTime.UtcNow;
                    // One query for the certificates of a whole batch and one for its tombstones, each by
                    // the serials as the tables store them (upper-case hex; with one or two leading zeros
                    // for a row an older build wrote), so that the serial indexes answer them.
                    var forms = batch.SelectMany(e => new[] { e.Serial, "0" + e.Serial, "00" + e.Serial }).ToList();
                    // Only the columns the comparison needs are read, and nothing is tracked: at an
                    // ordinary start every entry is found as it should be and no row is loaded whole.
                    var known = await db.Certificates.AsNoTracking()
                        .Where(c => EF.Parameter(forms).Contains(c.SerialNumber))
                        .Where(c => (c.IssuerCertificateId != null && scope.Contains(c.IssuerCertificateId.Value))
                                 || (c.IssuerCertificateId == null && c.Issuer == issuerDn))
                        .Select(c => new KnownCertificate(c.CertificateId, c.SerialNumber, c.Revoked, c.RevocationReason, c.RevocationDate, c.NotAfter))
                        .ToListAsync(cancellationToken);
                    var bySerial = known.GroupBy(c => Plain(c.SerialNumber)).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
                    var changes = new List<(Guid CertificateId, bool Revoke, string? Reason, DateTime? Date)>();
                    var tombstoned = (await db.RevokedSerialTombstones.AsNoTracking()
                            .Where(t => scope.Contains(t.CaCertificateId) && EF.Parameter(forms).Contains(t.SerialNumber))
                            .Select(t => t.SerialNumber)
                            .ToListAsync(cancellationToken))
                        .Select(Plain).ToHashSet(StringComparer.Ordinal);

                    var made = new List<(SignerJournaledRevocation Entry, string What, Guid? CertificateId)>();
                    foreach (var entry in batch)
                    {
                        var reason = ReasonName(entry);
                        if (bySerial.TryGetValue(entry.Serial, out var rows))
                        {
                            foreach (var row in rows)
                            {
                                if (!row.Revoked)
                                {
                                    // An expired certificate is on no CRL: there is nothing to give back.
                                    if (row.NotAfter <= now)
                                        continue;
                                    if (counting) { pending++; continue; }
                                    changes.Add((row.CertificateId, true, reason, entry.RevokedAtUtc));
                                    made.Add((entry, "certificate", row.CertificateId));
                                }
                                else
                                {
                                    // Revoked stays revoked. The earlier date stands, and a hold the journal has as permanent becomes permanent.
                                    var permanent = !entry.Hold && string.Equals(row.RevocationReason, HoldReason, StringComparison.OrdinalIgnoreCase);
                                    var earlier = row.RevocationDate is not DateTime at || entry.RevokedAtUtc < at.AddSeconds(-1);
                                    if (!permanent && !earlier)
                                        continue;
                                    if (row.NotAfter <= now)
                                        continue;
                                    if (counting) { pending++; continue; }
                                    changes.Add((row.CertificateId, false, permanent ? reason : null, earlier ? entry.RevokedAtUtc : null));
                                    made.Add((entry, permanent ? "hold made permanent" : "earlier date", row.CertificateId));
                                }
                            }
                            continue;
                        }

                        if (tombstoned.Contains(entry.Serial))
                            continue;
                        if (entry.Hold)
                        {
                            // A hold on a certificate the database does not hold: a tombstone cannot be released, so none is made.
                            passedOverHolds++;
                            continue;
                        }
                        if (counting) { pending++; continue; }
                        longestValidity ??= await RevokedSerialService.LongestValidityAsync(db, caId, cancellationToken);
                        listedUntilBase ??= ca.Row.NotAfter;
                        var until = entry.RevokedAtUtc.Add(longestValidity.Value);
                        if (listedUntilBase is DateTime caEnd && caEnd > entry.RevokedAtUtc && caEnd < until)
                            until = caEnd;
                        db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
                        {
                            CaCertificateId = caCertificateId,
                            CertificateAuthorityId = caId,
                            IssuerDN = issuerDn,
                            SerialNumber = entry.Serial,
                            RevocationDate = entry.RevokedAtUtc,
                            RevocationReason = reason,
                            ListedUntil = until,
                            Note = $"Restored from the signer's journal after the database went back in time ({SourceText(entry)}).",
                            CreatedByUserId = null,
                            CreatedByUsername = Actor,
                            CreatedAt = now,
                        });
                        tombstoned.Add(entry.Serial);
                        made.Add((entry, "serial without a certificate", null));
                    }

                    if (changes.Count > 0)
                    {
                        // The rows to change, and only those, are loaded to be changed.
                        var ids = changes.Select(c => c.CertificateId).Distinct().ToList();
                        var rows = await db.Certificates.Where(c => ids.Contains(c.CertificateId)).ToDictionaryAsync(c => c.CertificateId, cancellationToken);
                        foreach (var change in changes)
                        {
                            if (!rows.TryGetValue(change.CertificateId, out var row))
                                continue;
                            if (change.Revoke)
                                row.Revoked = true;
                            if (change.Reason != null)
                                row.RevocationReason = change.Reason;
                            if (change.Date is DateTime date)
                                row.RevocationDate = date;
                        }
                    }

                    if (made.Count > 0)
                    {
                        try
                        {
                            await db.SaveChangesAsync(cancellationToken);
                        }
                        catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
                        {
                            // Another process made one of them at the same moment. Nothing of this batch was saved; the next pass sees what is there.
                            db.ChangeTracker.Clear();
                            throw;
                        }
                        db.ChangeTracker.Clear();
                        foreach (var (entry, what, _) in made)
                        {
                            MetricsService.CertsRevoked.WithLabels(issuerDn, ReasonName(entry)).Inc();
                            if (merged.Count < 200)
                                merged.Add(new { entry.Serial, entry.Source, entry.SourceSeq, Made = what });
                        }
                        if (batched)
                        {
                            // One record for what this save made. The serials are in its details, each with
                            // its date, its reason (a hold is the reason CertificateHold), what was made and
                            // its source; the record's target is the CA.
                            batchRecords++;
                            await TryAuditAsync(audit, AuditActionType.RevocationsMergedFromJournalBatch, "CertificateAuthority", caId.ToString(), new
                            {
                                CertificateAuthorityId = caId,
                                CaName = ca.Name,
                                Batch = batchRecords,
                                Count = made.Count,
                                JournaledCrlNumber = page.CrlNumber,
                                JournaledCrlSeq = page.CrlSeq,
                                Revocations = made.Select(m => new
                                {
                                    m.Entry.Serial,
                                    Date = m.Entry.RevokedAtUtc,
                                    Reason = ReasonName(m.Entry),
                                    Made = m.What,
                                    m.CertificateId,
                                    m.Entry.Source,
                                    SourceCrlNumber = m.Entry.Source == "fact" ? (long?)null : m.Entry.SourceNumber,
                                    m.Entry.SourceSeq,
                                }).ToList(),
                            }, caId, ca.SpaceId);
                        }
                        else foreach (var (entry, what, certificateId) in made)
                        {
                            var details = new
                            {
                                CertificateAuthorityId = caId,
                                CaName = ca.Name,
                                SerialNumber = entry.Serial,
                                RevocationDate = entry.RevokedAtUtc,
                                Reason = ReasonName(entry),
                                ReasonCode = entry.Reason,
                                entry.Hold,
                                Made = what,
                                CertificateId = certificateId,
                                entry.Source,
                                SourceCrlNumber = entry.Source == "fact" ? (long?)null : entry.SourceNumber,
                                entry.SourceSeq,
                                JournaledCrlNumber = page.CrlNumber,
                                JournaledCrlSeq = page.CrlSeq,
                            };
                            await TryAuditAsync(audit, AuditActionType.RevocationMergedFromJournal, certificateId == null ? "RevokedSerial" : "Certificate",
                                certificateId?.ToString() ?? entry.Serial, details, caId, ca.SpaceId);
                        }
                        mergedCount += made.Count;
                    }
                    looked += batch.Length;
                    state.Set(new CaMergeStatus(caId, ca.Name, deferred ? JournalMergeState.Pending : JournalMergeState.Running,
                        mergedCount, deferred ? pending : Math.Max(0, total - looked), total, DateTime.UtcNow, null));
                }

                if (page.Entries.Count == 0 || looked >= page.Total)
                    break;
                page = await signer.JournaledRevocationsAsync(caId, looked, PageSize, cancellationToken)
                       ?? throw new InvalidOperationException("The signer no longer answers for this CA's journaled revocations.");
                if (!page.Trusted)
                    throw new InvalidOperationException($"The signer stopped answering from its journal: {page.NotTrustedReason}");
            }
        }

        await RunAsync(counting: true);
        var missing = pending;
        if (!deferred && missing > 0)
        {
            batched = missing > IndividualAuditLimit;
            await RunAsync(counting: false);
        }

        if (deferred)
        {
            var waiting = pending == 0 ? null
                : $"{pending} revocation(s) that the signer's journal holds for this CA are missing from the database. The instance is in DR mode, which changes nothing: they are made when the mode is changed.";
            state.Set(new CaMergeStatus(caId, ca.Name, pending == 0 ? JournalMergeState.Done : JournalMergeState.Pending, 0, pending, total, DateTime.UtcNow, waiting));
            if (pending > 0)
                logger.LogWarning("Journal merge, CA {Ca}: {Message}", ca.Name, waiting);
            return new JournalMergeResult(pending == 0 ? JournalMergeState.Done : JournalMergeState.Pending, 0, pending);
        }

        if (mergedCount > 0)
        {
            if (batched)
                logger.LogWarning("Journal merge, CA {Ca}: {Count} revocation(s) that the signer's journal holds were missing from the database and were made again. "
                    + "The database had gone back in time. They are in the audit trail in {Records} {Action} record(s).", ca.Name, mergedCount, batchRecords, AuditActionType.RevocationsMergedFromJournalBatch);
            else
                logger.LogWarning("Journal merge, CA {Ca}: {Count} revocation(s) that the signer's journal holds were missing from the database and were made again. "
                    + "The database had gone back in time. Each is in the audit trail as {Action}.", ca.Name, mergedCount, AuditActionType.RevocationMergedFromJournal);
            var summary = new
            {
                CertificateAuthorityId = caId,
                CaName = ca.Name,
                Merged = mergedCount,
                AuditForm = batched ? AuditFormBatch : AuditFormIndividual,
                AuditAction = batched ? AuditActionType.RevocationsMergedFromJournalBatch : AuditActionType.RevocationMergedFromJournal,
                BatchRecords = batchRecords,
                IndividualAuditLimit,
                JournalEntries = total,
                JournaledCrlNumber = first.CrlNumber,
                JournaledCrlSeq = first.CrlSeq,
                HoldsOnUnknownCertificatesPassedOver = passedOverHolds,
                First = merged,
            };
            await TryAuditAsync(audit, AuditActionType.JournalRevocationMergeCompleted, "CertificateAuthority", caId.ToString(), summary, caId, ca.SpaceId);
            db.InstanceContinuityEvents.Add(new InstanceContinuityEventEntity
            {
                Kind = ContinuityEventKind.RevocationsMergedFromJournal,
                DetectedAt = DateTime.UtcNow,
                DetailsJson = JsonSerializer.Serialize(new
                {
                    detector = "journal-merge",
                    caId,
                    caName = ca.Name,
                    merged = mergedCount,
                    auditForm = batched ? AuditFormBatch : AuditFormIndividual,
                    auditAction = batched ? AuditActionType.RevocationsMergedFromJournalBatch : AuditActionType.RevocationMergedFromJournal,
                    batchRecords,
                    journalEntries = total,
                    journaledCrlNumber = first.CrlNumber,
                    journaledCrlSeq = first.CrlSeq,
                    holdsOnUnknownCertificatesPassedOver = passedOverHolds,
                    first = merged,
                }, DetailsJson),
            });
            await db.SaveChangesAsync(cancellationToken);
        }
        state.Set(new CaMergeStatus(caId, ca.Name, JournalMergeState.Done, mergedCount, 0, total, DateTime.UtcNow,
            mergedCount == 0 ? null : $"{mergedCount} revocation(s) were restored from the signer's journal."));
        return new JournalMergeResult(JournalMergeState.Done, mergedCount, 0);
    }

    /// <summary>What the comparison reads of a certificate the database holds.</summary>
    private sealed record KnownCertificate(Guid CertificateId, string SerialNumber, bool Revoked, string? RevocationReason, DateTime? RevocationDate, DateTime NotAfter);

    private static string Plain(string serial)
    {
        var trimmed = serial.Trim().TrimStart('0').ToUpperInvariant();
        return trimmed.Length == 0 ? "0" : trimmed;
    }

    private static string ReasonName(SignerJournaledRevocation entry)
        => entry.Hold ? HoldReason
            : Enum.IsDefined(typeof(RevocationReason), entry.Reason) && entry.Reason != (int)RevocationReason.CertificateHold
                ? ((RevocationReason)entry.Reason).ToString()
                : nameof(RevocationReason.Unspecified);

    private static string SourceText(SignerJournaledRevocation entry) => entry.Source switch
    {
        "fact" => $"a revocation the node recorded, journal sequence {entry.SourceSeq}",
        "delta" => $"delta CRL number {entry.SourceNumber}, journal sequence {entry.SourceSeq}",
        _ => $"CRL number {entry.SourceNumber}, journal sequence {entry.SourceSeq}",
    };

    private async Task TryAuditAsync(IAuditService? audit, string action, string targetType, string targetId, object details, Guid caId, Guid? spaceId)
    {
        if (audit == null)
            return;
        try
        {
            await audit.LogAsync(action, null, Actor, targetType, targetId, details, certificateAuthorityId: caId, spaceId: spaceId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Journal merge: the audit row {Action} for {Target} could not be written. The revocation itself is made.", action, targetId);
        }
    }
}

/// <summary>
/// Runs the merge for every X.509 CA after the node has started, in the background: the node is
/// ready without waiting for it. It comes back every <see cref="Interval"/> to a CA whose pass
/// could not finish (the signer was not reachable yet) or is pending because the instance is in
/// DR mode, so the revocations are made once the mode is changed, and stops when no CA needs
/// another pass. The control role runs it, as it runs the CRL jobs.
/// </summary>
public sealed class JournalMergeService(IServiceScopeFactory scopes, IJournalRevocationMerge merge, JournalMergeState state,
    IInstanceModeGate modeGate, ILogger<JournalMergeService> logger) : BackgroundService
{
    /// <summary>How long it waits before it comes back to a CA that needs another pass.</summary>
    public static TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(15);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (!await PassAsync(stoppingToken))
                    return;
                await Task.Delay(Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }

    /// <summary>One pass over the CAs that need one. Returns whether any still needs another.</summary>
    public async Task<bool> PassAsync(CancellationToken cancellationToken)
    {
        List<Guid> cas;
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            cas = await db.CertificateAuthorities.AsNoTracking()
                .Where(c => !c.IsSshCa && c.CertificateId != null)
                .OrderBy(c => c.Name)
                .Select(c => c.Id)
                .ToListAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogDebug(ex, "Journal merge: the CAs could not be listed yet.");
            return true;
        }

        var again = false;
        var allowed = InstanceModeGate.Allows(modeGate.Current.Mode, ModeOperation.Restriction);
        foreach (var caId in cas)
        {
            var known = state.Of(caId);
            if (known != null && !JournalMergeState.NeedsAnotherPass(known.State))
                continue;
            // Pending waits for the mode: asking the signer for the whole list again every few seconds would find the same.
            if (known?.State == JournalMergeState.Pending && !allowed)
            {
                again = true;
                continue;
            }
            var result = await merge.MergeAsync(caId, cancellationToken);
            again |= JournalMergeState.NeedsAnotherPass(result.State);
        }
        return again;
    }
}
