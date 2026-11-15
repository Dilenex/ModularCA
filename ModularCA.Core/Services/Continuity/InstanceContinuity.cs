using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Core.Services.Continuity;

/// <summary>What a start found when it compared the machine's incarnation with the stored one.</summary>
public enum IncarnationCase
{
    /// <summary>The database held nothing: the first start with this feature. The reading is stored.</summary>
    FirstSeen,
    /// <summary>The database holds what the machine reports: the same timeline.</summary>
    Same,
    /// <summary>The database holds another value: rolled back, restored, cloned or moved.</summary>
    Changed,
    /// <summary>The database holds a value and the machine reports none: the source went away.</summary>
    SourceLost,
    /// <summary>The database holds "none" and the machine now reports a value: a source appeared. The reading is stored.</summary>
    SourceAppeared,
}

/// <summary>The kinds of <see cref="InstanceContinuityEventEntity"/>.</summary>
public static class ContinuityEventKind
{
    /// <summary>The incarnation differs from the stored one.</summary>
    public const string IncarnationChanged = "IncarnationChanged";
    /// <summary>The incarnation source went away.</summary>
    public const string IncarnationSourceLost = "IncarnationSourceLost";
    /// <summary>A published CRL carries a higher number than the database's counter.</summary>
    public const string PublishedCrlAhead = "PublishedCrlAhead";
    /// <summary>Revocations the database had lost were made again from the signer's journal.</summary>
    public const string RevocationsMergedFromJournal = "RevocationsMergedFromJournal";
}

/// <summary>The newest records the application database holds, and the latest of them.</summary>
/// <param name="NewestCertificate">When the newest certificate row was created.</param>
/// <param name="NewestRequest">When the newest certificate request was submitted.</param>
/// <param name="NewestRevocation">The latest revocation date on a certificate or a tombstone.</param>
/// <param name="NewestSshCertificate">When the newest SSH certificate row was created.</param>
/// <param name="NewestCrl">When the newest stored CRL was generated.</param>
/// <param name="NewestSchedulerActivity">
/// The scheduler's last sign of life in this database: the latest lease renewal or job run. The
/// scheduler renews its lease at every tick, so on an instance that was running this is within
/// a tick of the moment the database was last written, and it is usually the latest part.
/// </param>
public sealed record EdgeOfMemory(DateTime? NewestCertificate, DateTime? NewestRequest, DateTime? NewestRevocation,
    DateTime? NewestSshCertificate, DateTime? NewestCrl, DateTime? NewestSchedulerActivity)
{
    /// <summary>The latest of the parts: everything after it on an earlier timeline is unknown here. Null for an empty database.</summary>
    public DateTime? Edge => new[] { NewestCertificate, NewestRequest, NewestRevocation, NewestSshCertificate, NewestCrl, NewestSchedulerActivity }.Max();
}

/// <summary>What <see cref="InstanceContinuity.CheckIncarnationAsync"/> found and did.</summary>
/// <param name="Case">The row of the comparison table that applied.</param>
/// <param name="Event">The event recorded for a change or a lost source; null otherwise.</param>
/// <param name="Raised">The CRL configurations whose counter the floor changed.</param>
public sealed record IncarnationCheckResult(IncarnationCase Case, InstanceContinuityEventEntity? Event, IReadOnlyList<CrlNumberFloor.Raised> Raised);

/// <summary>
/// Rollback continuity (<c>docs/architecture/rollback-continuity.md</c>, sections 1 to 3): what
/// a start does to find out that its database was taken back in time or copied, and what it
/// repairs alone when it was. It raises the CRL numbers with <see cref="CrlNumberFloor"/>, as the
/// product's own restore does, records one event and one audit row, and leaves the event as a
/// standing notice until an administrator acknowledges it. It never stops a start.
/// <para>
/// The revocations the signer's journal holds are made again by the merge
/// (<see cref="ModularCA.Core.Services.Journal.JournalRevocationMerge"/>), which records an event
/// of its own. Nothing else is replayed: certificates issued in the lost time stay unknown
/// until an administrator adopts them (<see cref="RevokedSerialService"/>). Every report says so.
/// </para>
/// </summary>
public static partial class InstanceContinuity
{
    /// <summary>The audit actor of everything a start does here.</summary>
    public const string StartActor = "startup";

    /// <summary>What every report says about the signer's journal.</summary>
    public const string JournalNote = "Revocations that the signer's journal holds are restored from it by the node; nothing else of the lost time is replayed.";

    /// <summary>
    /// The advisory lock two nodes starting against one database take in turn, so one of them
    /// compares, repairs and stores, and the other finds the stored value already current.
    /// </summary>
    private const long StartLock = 0x4D43415F494E4331; // "MCA_INC1"

    private static readonly JsonSerializerOptions DetailsJson = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// Compares <paramref name="reading"/> with the incarnation the database last saw and acts as
    /// the table in section 1 says:
    /// <list type="bullet">
    /// <item>nothing stored: stores the reading (<see cref="IncarnationCase.FirstSeen"/>);</item>
    /// <item>the same value: nothing (<see cref="IncarnationCase.Same"/>);</item>
    /// <item>another value: raises every CRL counter to the floor, records an event with the edge
    /// of memory, writes one <see cref="AuditActionType.InstanceIncarnationChanged"/> audit row and
    /// stores the reading (<see cref="IncarnationCase.Changed"/>);</item>
    /// <item>a value stored and none reported: records an event, writes one
    /// <see cref="AuditActionType.InstanceIncarnationSourceLost"/> audit row and stores "none",
    /// so the warning is given once (<see cref="IncarnationCase.SourceLost"/>);</item>
    /// <item>"none" stored and a value reported: stores it (<see cref="IncarnationCase.SourceAppeared"/>).</item>
    /// </list>
    /// On PostgreSQL the comparison, the floor, the event and the store are one transaction
    /// behind an advisory lock, so two nodes starting together do them once. The audit row is
    /// written after the commit; failing to write it is logged and does not undo the rest.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="auditDb">The audit database, for the time of its newest row; null when there is none.</param>
    /// <param name="audit">Where the audit row is written.</param>
    /// <param name="reading">What the machine reports (<see cref="IncarnationSources.Read"/>).</param>
    /// <param name="nowUtc">The time of the start.</param>
    /// <param name="logger">Receives what was found.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IncarnationCheckResult> CheckIncarnationAsync(ModularCADbContext db, AuditDbContext? auditDb,
        IAuditService audit, IncarnationReading reading, DateTimeOffset nowUtc, ILogger logger, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(reading);

        IncarnationCase found;
        InstanceContinuityEventEntity? recorded = null;
        IReadOnlyList<CrlNumberFloor.Raised> raised = [];
        string? oldTag;
        string? oldSource;

        await using (var transaction = await BeginLockedAsync(db, cancellationToken))
        {
            var stored = await db.InstanceIncarnation.FirstOrDefaultAsync(i => i.Id == InstanceIncarnationEntity.SingletonId, cancellationToken);
            oldTag = IncarnationReading.TagOf(stored?.ValueHash);
            oldSource = stored?.Source;

            if (stored == null)
                found = IncarnationCase.FirstSeen;
            else if (string.Equals(stored.ValueHash, reading.ValueHash, StringComparison.OrdinalIgnoreCase))
                found = IncarnationCase.Same;
            else if (stored.ValueHash == null)
                found = IncarnationCase.SourceAppeared;
            else if (reading.IsNone)
                found = IncarnationCase.SourceLost;
            else
                found = IncarnationCase.Changed;

            if (found == IncarnationCase.Same)
            {
                if (transaction != null)
                    await transaction.CommitAsync(cancellationToken);
                return new IncarnationCheckResult(found, null, raised);
            }

            if (found is IncarnationCase.Changed or IncarnationCase.SourceLost)
            {
                var edge = await EdgeOfMemoryAsync(db, cancellationToken);
                var auditNewest = await NewestAuditRowAsync(auditDb, logger, cancellationToken);
                long? floor = null;
                if (found == IncarnationCase.Changed)
                {
                    floor = CrlNumberFloor.FloorAt(nowUtc);
                    raised = await CrlNumberFloor.ApplyAsync(db, floor.Value, cancellationToken);
                }
                recorded = new InstanceContinuityEventEntity
                {
                    Kind = found == IncarnationCase.Changed ? ContinuityEventKind.IncarnationChanged : ContinuityEventKind.IncarnationSourceLost,
                    DetectedAt = nowUtc.UtcDateTime,
                    OldTag = oldTag,
                    NewTag = reading.Tag,
                    EdgeOfMemoryUtc = edge.Edge,
                    AuditNewestUtc = auditNewest,
                    CrlNumberFloor = floor,
                    CrlCountersRaised = raised.Count,
                    DetailsJson = JsonSerializer.Serialize(new
                    {
                        detector = "incarnation",
                        oldSource,
                        newSource = reading.Source,
                        newestCertificate = edge.NewestCertificate,
                        newestRequest = edge.NewestRequest,
                        newestRevocation = edge.NewestRevocation,
                        newestSshCertificate = edge.NewestSshCertificate,
                        newestCrl = edge.NewestCrl,
                        newestSchedulerActivity = edge.NewestSchedulerActivity,
                        crlNumbersRaised = raised.Select(r => new { r.TaskId, r.IssuerDn, r.IsDelta, r.Before, r.After }),
                        journal = JournalNote,
                    }, DetailsJson),
                };
                db.InstanceContinuityEvents.Add(recorded);
            }

            Store(db, stored, reading, nowUtc.UtcDateTime, StartActor);
            await db.SaveChangesAsync(cancellationToken);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
        }

        switch (found)
        {
            case IncarnationCase.FirstSeen:
                logger.LogInformation("Incarnation: first start with rollback detection. Stored the incarnation ({Source}, tag {Tag}).",
                    reading.Source, reading.Tag ?? "none");
                break;
            case IncarnationCase.SourceAppeared:
                logger.LogInformation("Incarnation: this machine now reports an incarnation ({Source}, tag {Tag}); the database held none. Stored it.",
                    reading.Source, reading.Tag);
                break;
            case IncarnationCase.Changed:
                logger.LogWarning("Incarnation changed from {OldTag} to {NewTag}: this instance is running from an earlier or copied state. "
                    + "Certificates issued and revocations made after {Edge} on the earlier timeline are not known here. "
                    + "CRL numbers raised to at least {Floor} on {Raised} configuration(s). " + JournalNote,
                    oldTag, reading.Tag, FormatTime(recorded!.EdgeOfMemoryUtc), recorded.CrlNumberFloor, raised.Count);
                await TryAuditAsync(audit, AuditActionType.InstanceIncarnationChanged, recorded, new
                {
                    Detector = "incarnation",
                    OldTag = oldTag,
                    NewTag = reading.Tag,
                    OldSource = oldSource,
                    NewSource = reading.Source,
                    recorded.EdgeOfMemoryUtc,
                    recorded.AuditNewestUtc,
                    Floor = recorded.CrlNumberFloor,
                    Raised = raised.Select(r => new { r.TaskId, r.IssuerDn, r.IsDelta, r.Before, r.After }),
                    Journal = JournalNote,
                    Stored = true,
                }, logger);
                break;
            case IncarnationCase.SourceLost:
                logger.LogWarning("Incarnation source went away: the database held tag {OldTag} from '{OldSource}' and this machine reports none. "
                    + "A rollback or a copy can no longer be detected from the incarnation here. Stored \"none\"; this warning is given once.",
                    oldTag, oldSource);
                await TryAuditAsync(audit, AuditActionType.InstanceIncarnationSourceLost, recorded!, new
                {
                    OldTag = oldTag,
                    OldSource = oldSource,
                    recorded!.EdgeOfMemoryUtc,
                    recorded.AuditNewestUtc,
                    CrlNumbersRaised = false,
                    Stored = IncarnationReading.NoneSource,
                }, logger);
                break;
        }

        return new IncarnationCheckResult(found, recorded, raised);
    }

    /// <summary>
    /// Stores <paramref name="reading"/> as the incarnation this database last saw, without
    /// comparing or recording an event. The product's own restore calls it: it has just raised
    /// the CRL numbers and recorded itself, so the next start must not report a second event.
    /// </summary>
    /// <param name="db">The application database, as restored.</param>
    /// <param name="reading">What this machine reports.</param>
    /// <param name="recordedBy">What stores it, for the row.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task StoreIncarnationAsync(ModularCADbContext db, IncarnationReading reading, string recordedBy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(reading);
        var stored = await db.InstanceIncarnation.FirstOrDefaultAsync(i => i.Id == InstanceIncarnationEntity.SingletonId, cancellationToken);
        Store(db, stored, reading, DateTime.UtcNow, recordedBy);
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// The newest records the application database holds (section 3): the newest certificate
    /// row, certificate request, revocation, SSH certificate and stored CRL, and the scheduler's
    /// last lease renewal or job run, which on a running instance is the closest of them to the
    /// moment the database was last written. The audit trail is not part of it: it is a separate
    /// database that a rollback of this one may not have taken back, and its newest row is
    /// reported beside the edge instead. Call it before anything in this process writes.
    /// </summary>
    public static async Task<EdgeOfMemory> EdgeOfMemoryAsync(ModularCADbContext db, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var certificate = await db.Certificates.AsNoTracking().Select(c => (DateTime?)c.CreatedAt).MaxAsync(cancellationToken);
        var request = await db.CertificateRequests.AsNoTracking().Select(r => (DateTime?)r.SubmittedAt).MaxAsync(cancellationToken);
        var revocation = await db.Certificates.AsNoTracking().Where(c => c.RevocationDate != null).Select(c => c.RevocationDate).MaxAsync(cancellationToken);
        var tombstone = await db.RevokedSerialTombstones.AsNoTracking().Select(t => (DateTime?)t.RevocationDate).MaxAsync(cancellationToken);
        var ssh = await db.SshCertificates.AsNoTracking().Select(c => (DateTime?)c.CreatedAt).MaxAsync(cancellationToken);
        var crl = await db.Crls.AsNoTracking().Select(c => (DateTime?)c.GeneratedAt).MaxAsync(cancellationToken);
        var lease = await db.SchedulerLeases.AsNoTracking().Select(l => (DateTime?)l.AcquiredAtUtc).MaxAsync(cancellationToken);
        var jobRun = await db.SchedulerJobStates.AsNoTracking().Where(j => j.LastRunUtc != null).Select(j => j.LastRunUtc).MaxAsync(cancellationToken);
        return new EdgeOfMemory(certificate, request, new[] { revocation, tombstone }.Max(), ssh, crl, new[] { lease, jobRun }.Max());
    }

    /// <summary>The events nobody has acknowledged, oldest first: the standing notice.</summary>
    public static Task<List<InstanceContinuityEventEntity>> UnacknowledgedAsync(ModularCADbContext db, CancellationToken cancellationToken = default)
        => db.InstanceContinuityEvents.AsNoTracking()
            .Where(e => e.AcknowledgedAt == null)
            .OrderBy(e => e.DetectedAt)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// Marks event <paramref name="eventId"/> acknowledged by the given administrator. Returns
    /// the event, or null when there is none; an event already acknowledged is returned as it is.
    /// </summary>
    public static async Task<InstanceContinuityEventEntity?> AcknowledgeAsync(ModularCADbContext db, Guid eventId, Guid? userId, string? username,
        CancellationToken cancellationToken = default)
    {
        var found = await db.InstanceContinuityEvents.FirstOrDefaultAsync(e => e.Id == eventId, cancellationToken);
        if (found == null || found.AcknowledgedAt != null)
            return found;
        found.AcknowledgedAt = DateTime.UtcNow;
        found.AcknowledgedByUserId = userId;
        found.AcknowledgedByUsername = username;
        await db.SaveChangesAsync(cancellationToken);
        return found;
    }

    /// <summary>The sentence the console and <c>/health/ready</c> show for <paramref name="e"/>.</summary>
    public static string MessageFor(InstanceContinuityEventEntity e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var edge = e.EdgeOfMemoryUtc is { } t
            ? $"Certificates issued and revocations made after {FormatTime(t)} on the earlier timeline are not known here."
            : "The database holds no record that dates what an earlier timeline did.";
        var numbers = e.CrlNumberFloor is { } floor
            ? $" CRL numbers were raised to at least {floor} ({e.CrlCountersRaised} configuration(s) changed)."
            : string.Empty;
        if (e.Kind == ContinuityEventKind.RevocationsMergedFromJournal)
            return MergedMessage(e);
        return e.Kind switch
        {
            ContinuityEventKind.IncarnationSourceLost =>
                "This machine no longer reports an incarnation ID, so a rollback or a copy of this instance can no longer be detected from it. "
                + "If the instance was moved to a host that sets none, acknowledge this notice. If its state was also restored or rolled back: " + edge,
            ContinuityEventKind.PublishedCrlAhead =>
                "A CRL this instance published carries a higher number than its database knows: the database was taken back in time. "
                + edge + numbers + " " + JournalNote,
            _ =>
                "This instance is running from an earlier or copied state. " + edge + numbers + " " + JournalNote,
        };
    }

    private static string MergedMessage(InstanceContinuityEventEntity e)
    {
        var count = 0;
        var name = "a certificate authority";
        var where = $"Each is in the audit trail as {AuditActionType.RevocationMergedFromJournal}.";
        try
        {
            using var details = JsonDocument.Parse(e.DetailsJson ?? "{}");
            if (details.RootElement.TryGetProperty("merged", out var merged) && merged.TryGetInt32(out var n))
                count = n;
            if (details.RootElement.TryGetProperty("auditForm", out var form) && form.ValueKind == JsonValueKind.String
                && form.GetString() == "batch")
                where = $"They are in the audit trail in {AuditActionType.RevocationsMergedFromJournalBatch} records, which carry the serials in their details.";
            if (details.RootElement.TryGetProperty("caName", out var ca) && ca.ValueKind == JsonValueKind.String)
                name = $"CA {ca.GetString()}";
        }
        catch (JsonException)
        {
            // The sentence stands without the figures.
        }
        return $"{count} revocation(s) were restored from the signer's journal for {name} after the database went back in time. "
            + "The signer had them on a CRL it signed, or the node had recorded them with it, and the database no longer did. "
            + $"{where} Nothing else that was done in the lost time was restored.";
    }

    private static string FormatTime(DateTime? time)
        => time is { } t ? t.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", System.Globalization.CultureInfo.InvariantCulture) : "(no record)";

    private static void Store(ModularCADbContext db, InstanceIncarnationEntity? stored, IncarnationReading reading, DateTime now, string recordedBy)
    {
        if (stored == null)
        {
            stored = new InstanceIncarnationEntity();
            db.InstanceIncarnation.Add(stored);
        }
        stored.Source = reading.Source;
        stored.ValueHash = reading.ValueHash;
        stored.RecordedAt = now;
        stored.RecordedBy = recordedBy;
    }

    /// <summary>
    /// On PostgreSQL, opens a transaction and takes the start lock for its length; on a provider
    /// without advisory locks (the in-memory one of the tests) returns null and the caller runs
    /// without either.
    /// </summary>
    private static async Task<Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction?> BeginLockedAsync(ModularCADbContext db, CancellationToken cancellationToken)
    {
        if (!db.Database.IsNpgsql())
            return null;
        var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({StartLock})", cancellationToken);
        return transaction;
    }

    private static async Task<DateTime?> NewestAuditRowAsync(AuditDbContext? auditDb, ILogger logger, CancellationToken cancellationToken)
    {
        if (auditDb == null)
            return null;
        try
        {
            return await auditDb.AuditLogs.AsNoTracking().Select(a => (DateTime?)a.Timestamp).MaxAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "The audit trail's newest row could not be read for the continuity report.");
            return null;
        }
    }

    private static async Task TryAuditAsync(IAuditService audit, string action, InstanceContinuityEventEntity recorded, object details, ILogger logger)
    {
        try
        {
            await audit.LogAsync(action, null, StartActor, "InstanceContinuityEvent", recorded.Id.ToString(), details);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "The audit row for continuity event {EventId} ({Action}) could not be written. The event itself is recorded and stands as a notice.",
                recorded.Id, action);
        }
    }
}
