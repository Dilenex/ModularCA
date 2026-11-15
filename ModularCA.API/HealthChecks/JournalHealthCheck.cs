using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Shared.Signing;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// The signer's issuance journal in <c>/health/ready</c>, under <c>checks.journal</c>: where its
/// chain stands, its size, the free space on its volume, the age of its last checkpoint, how
/// many facts wait in the node's queue for it, the journals set aside in its home, whether it
/// waits for a restore marker, whether it verified, the CAs whose CRL the signer refuses, and
/// the merge of lost revocations for each CA. The reading is kept
/// (<see cref="SignerJournalState"/>) for the hub's inventory.
/// </summary>
/// <remarks>
/// <b>Readiness.</b> Only <c>unavailable</c> degrades the node: a journal that cannot take a
/// record stops issuance. A degraded node answers <c>/health/ready</c> with 503 and reports
/// <c>degraded</c> to the hub's <c>health.read</c>; <c>/health/live</c>, which
/// <c>--check-ready</c> asks, still answers 200, because the check is never unhealthy:
/// revocation and revocation checking go on without the journal, and a node taken out of
/// service for it would stop answering OCSP too. Every other status (<c>none</c>,
/// <c>not_verified</c>, <c>crl_refused</c>, <c>merge_pending</c>, <c>merge_running</c>,
/// <c>awaiting_restore_marker</c>, <c>critical_space</c>, <c>low_space</c>,
/// <c>stale_checkpoint</c>) is reported and leaves the node healthy: the instance serves, and an
/// orchestrator that waits for ready after an upgrade or a roll-back must not be told it failed
/// for a warning (<see cref="SignerJournalState.FailsReadiness"/>).
/// </remarks>
public sealed class JournalHealthCheck(IServiceProvider services, SignerJournalState state) : IHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        SignerJournalInfo? info = null;
        // Whether there is a signer to ask, and whether it answered: a signer that answers "no journal"
        // and one that has not answered yet both leave info null, and are not the same thing.
        var signerAsked = false;
        var answered = false;
        try
        {
            if (services.GetService<ISigningService>() is { } signer)
            {
                signerAsked = true;
                info = await signer.JournalInfoAsync(cancellationToken);
                answered = true;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Serilog.Log.Debug(ex, "Health check: the signer's journal could not be asked about");
        }
        state.Observe(info, now);

        int? queued = null;
        IReadOnlyDictionary<Guid, (string Name, DateTime? NextUpdateUtc)> published = new Dictionary<Guid, (string, DateTime?)>();
        try
        {
            if (services.GetService<ModularCADbContext>() is { } db)
            {
                queued = await db.SignerFacts.CountAsync(cancellationToken);
                if (info?.RefusedCrls is { Count: > 0 } asked)
                    published = await CrlDeadline.PublishedForAsync(db, asked.Where(r => r.CaId != null).Select(r => r.CaId!.Value).Distinct().ToList(), cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Setup mode, or a database the main check already reports.
        }

        var (status, message) = SignerJournalState.Assess(info, now);
        if (signerAsked && !answered)
        {
            status = SignerJournalState.NotKnown;
            message = "The signer has not answered, so the state of its issuance journal is not known yet. Ask again; the signer's own check says whether it can be reached.";
        }
        // The merge of revocations from the journal, as this process knows it: a CA for each pass it has made.
        var merges = services.GetService<JournalMergeState>()?.Snapshot() ?? [];
        if (status is not (SignerJournalState.Unavailable or SignerJournalState.NotVerified or SignerJournalState.CrlRefused or SignerJournalState.None or SignerJournalState.NotKnown))
        {
            if (merges.Where(m => m.State == JournalMergeState.Pending).ToList() is { Count: > 0 } waiting)
            {
                status = SignerJournalState.MergePending;
                message = $"{waiting.Sum(m => (long)m.Remaining)} revocation(s) that the signer's journal holds are missing from the database, for {waiting.Count} CA(s). "
                    + "The instance is in DR mode, which changes nothing: they are made again when the mode is changed.";
            }
            else if (merges.Where(m => m.State == JournalMergeState.Running).ToList() is { Count: > 0 } running)
            {
                status = SignerJournalState.MergeRunning;
                message = $"Revocations that the signer's journal holds and the database lacks are being made again for {running.Count} CA(s): "
                    + $"{running.Sum(m => (long)m.Merged)} made, {running.Sum(m => (long)m.Remaining)} journal entries still to look at.";
            }
        }
        if (status == SignerJournalState.CrlRefused && merges.FirstOrDefault(m => m.State == JournalMergeState.NotTrusted) is { } untrusted)
            message += " Nothing was restored from the journal: " + untrusted.Message;
        var refused = (info?.RefusedCrls ?? []).Select(r =>
        {
            var known = r.CaId is Guid id && published.TryGetValue(id, out var found) ? found : ((string Name, DateTime? NextUpdateUtc)?)null;
            return new
            {
                caId = r.CaId,
                caName = known?.Name,
                caKey = r.CaKey,
                missingSerials = r.MissingSerials,
                refusedAtUtc = r.RefusedAtUtc,
                journaledCrlNumber = r.JournaledCrlNumber,
                publishedCrlExpiresAtUtc = known?.NextUpdateUtc,
                serialsAt = r.CaId is Guid listed ? $"/api/v1/admin/authorities/{listed:D}/revoked-serials/missing-from-crl" : null,
                // The console page a person follows a link to: the CA's page, where the serials are listed and can be revoked.
                consolePath = r.CaId is Guid shown ? ModularCA.API.Controllers.v1.Admin.AdminRevokedSerialController.MissingFromCrlConsolePath(shown) : null,
            };
        }).ToList();
        if (status == SignerJournalState.CrlRefused && refused.Where(r => r.publishedCrlExpiresAtUtc != null).Select(r => r.publishedCrlExpiresAtUtc!.Value).DefaultIfEmpty().Min() is var earliest
            && earliest != default)
            message += $" The first of the published CRLs runs out at {earliest:yyyy-MM-dd HH:mm:ss} UTC.";

        var (lowLevel, criticalLevel) = info == null ? (0L, 0L) : SignerJournalState.Levels(info);
        var report = new
        {
            status,
            message,
            available = info?.Available,
            seq = info?.Seq,
            hash = info?.Hash,
            sizeBytes = info?.SizeBytes,
            freeBytes = info?.FreeBytes,
            lowSpaceBytes = info == null ? (long?)null : lowLevel,
            criticalSpaceBytes = info == null ? (long?)null : criticalLevel,
            lastCheckpointAtUtc = info?.LastCheckpointAtUtc,
            lastCheckpointAgeSeconds = info?.LastCheckpointAtUtc is DateTime at ? (long?)Math.Max(0, (long)(now - at).TotalSeconds) : null,
            uncheckpointedRecords = info?.UncheckpointedRecords,
            queuedFacts = queued,
            awaitingRestoreMarkerUntilUtc = info?.AwaitingRestoreMarkerUntilUtc,
            awaitingRestoreMarkerSecondsLeft = info?.AwaitingRestoreMarkerUntilUtc is DateTime until && until > now ? (long?)Math.Ceiling((until - now).TotalSeconds) : null,
            setAsideJournals = info?.SetAsideJournals,
            setAsideBytes = info?.SetAsideBytes,
            refusedCrls = refused,
            verified = info?.Verified,
            verificationFault = info?.VerificationFault,
            verifiedBytes = info?.VerifiedBytes,
            verifyTotalBytes = info?.VerifyTotalBytes,
            merge = merges.Select(m => new
            {
                caId = m.CaId,
                caName = m.CaName,
                state = m.State,
                merged = m.Merged,
                remaining = m.Remaining,
                journalEntries = m.Total,
                atUtc = m.AtUtc,
                message = m.Message,
            }).ToList(),
        };
        var data = new Dictionary<string, object> { ["journal"] = report };
        return SignerJournalState.FailsReadiness(status)
            ? HealthCheckResult.Degraded(message, data: data)
            : HealthCheckResult.Healthy("Signer journal", data);
    }
}
