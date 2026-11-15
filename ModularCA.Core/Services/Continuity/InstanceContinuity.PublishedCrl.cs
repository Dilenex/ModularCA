using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Core.Services.Continuity;

/// <summary>One CRL read back from where the instance published it.</summary>
/// <param name="CaCertificateId">The CA certificate the publisher belongs to.</param>
/// <param name="Publisher">A name for the publisher, for the report.</param>
/// <param name="Der">The CRL as it was read back.</param>
public sealed record PublishedCrl(Guid CaCertificateId, string Publisher, byte[] Der);

/// <summary>One CA whose published CRL is ahead of the database.</summary>
/// <param name="CaCertificateId">The CA certificate.</param>
/// <param name="IssuerDn">Its subject DN.</param>
/// <param name="Publisher">The publisher the CRL was read back from.</param>
/// <param name="PublishedNumber">The CRL number found there.</param>
/// <param name="DatabaseNumber">The highest CRL number the database knows for that CA.</param>
public sealed record PublishedCrlAhead(Guid CaCertificateId, string IssuerDn, string Publisher, long PublishedNumber, long DatabaseNumber);

// The published-CRL check (docs/architecture/rollback-continuity.md, section 3): the detector
// that needs no incarnation source. The class is documented in InstanceContinuity.cs.
public static partial class InstanceContinuity
{
    /// <summary>
    /// Compares the CRLs the instance read back from its publishers with what the database
    /// knows. A published CRL of a CA, signed by that CA, whose number is higher than the highest
    /// number the database holds for it proves the database went back, whatever the incarnation
    /// says. It is then treated as an incarnation change: every CRL counter is raised to the
    /// floor (and past the highest published number), one event and one
    /// <see cref="AuditActionType.InstanceIncarnationChanged"/> audit row are written, and the
    /// event stands as a notice. A CRL that cannot be read, names another issuer or does not
    /// verify under the CA's key is ignored with a warning. Returns the CAs found ahead.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="auditDb">The audit database, for the time of its newest row; null when there is none.</param>
    /// <param name="audit">Where the audit row is written.</param>
    /// <param name="published">What the publishers gave back.</param>
    /// <param name="nowUtc">The time of the check.</param>
    /// <param name="logger">Receives what was found.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IReadOnlyList<PublishedCrlAhead>> CheckPublishedCrlsAsync(ModularCADbContext db, AuditDbContext? auditDb,
        IAuditService audit, IReadOnlyList<PublishedCrl> published, DateTimeOffset nowUtc, ILogger logger, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(published);
        if (published.Count == 0)
            return [];

        List<PublishedCrlAhead> ahead;
        InstanceContinuityEventEntity recorded;
        IReadOnlyList<CrlNumberFloor.Raised> raised;
        long floor;

        await using (var transaction = await BeginLockedAsync(db, cancellationToken))
        {
            // Inside the lock: a node that started a moment earlier has already raised the counters.
            ahead = await FindPublishedAheadAsync(db, published, logger, cancellationToken);
            if (ahead.Count == 0)
            {
                if (transaction != null)
                    await transaction.CommitAsync(cancellationToken);
                return ahead;
            }

            var edge = await EdgeOfMemoryAsync(db, cancellationToken);
            var auditNewest = await NewestAuditRowAsync(auditDb, logger, cancellationToken);
            floor = Math.Max(CrlNumberFloor.FloorAt(nowUtc), ahead.Max(a => a.PublishedNumber));
            raised = await CrlNumberFloor.ApplyAsync(db, floor, cancellationToken);
            recorded = new InstanceContinuityEventEntity
            {
                Kind = ContinuityEventKind.PublishedCrlAhead,
                DetectedAt = nowUtc.UtcDateTime,
                EdgeOfMemoryUtc = edge.Edge,
                AuditNewestUtc = auditNewest,
                CrlNumberFloor = floor,
                CrlCountersRaised = raised.Count,
                DetailsJson = JsonSerializer.Serialize(new
                {
                    detector = "published-crl",
                    publishedAhead = ahead,
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
            await db.SaveChangesAsync(cancellationToken);
            if (transaction != null)
                await transaction.CommitAsync(cancellationToken);
        }

        foreach (var a in ahead)
            logger.LogWarning("Published CRL ahead of the database: {Publisher} holds CRL number {Published} for {Issuer}, and the database knows {Database}. "
                + "The database was taken back in time.", a.Publisher, a.PublishedNumber, a.IssuerDn, a.DatabaseNumber);
        logger.LogWarning("This instance is running from an earlier state. Certificates issued and revocations made after {Edge} on the earlier timeline are not known here. "
            + "CRL numbers raised to at least {Floor} on {Raised} configuration(s). " + JournalNote,
            FormatTime(recorded.EdgeOfMemoryUtc), floor, raised.Count);
        await TryAuditAsync(audit, AuditActionType.InstanceIncarnationChanged, recorded, new
        {
            Detector = "published-crl",
            PublishedAhead = ahead,
            recorded.EdgeOfMemoryUtc,
            recorded.AuditNewestUtc,
            Floor = floor,
            Raised = raised.Select(r => new { r.TaskId, r.IssuerDn, r.IsDelta, r.Before, r.After }),
            Journal = JournalNote,
        }, logger);
        return ahead;
    }

    /// <summary>
    /// The published CRLs that are ahead of the database, one per CA certificate: the highest
    /// number read back that verifies under the CA's key, where it is higher than the highest
    /// number the database holds for that CA certificate (its configurations' counters and its
    /// stored CRLs). Changes nothing.
    /// </summary>
    public static async Task<List<PublishedCrlAhead>> FindPublishedAheadAsync(ModularCADbContext db, IReadOnlyList<PublishedCrl> published,
        ILogger logger, CancellationToken cancellationToken = default)
    {
        var ahead = new List<PublishedCrlAhead>();
        foreach (var group in published.GroupBy(p => p.CaCertificateId))
        {
            var caRow = await db.Certificates.AsNoTracking()
                .Where(c => c.CertificateId == group.Key)
                .Select(c => new { c.RawCertificate, c.Pem, c.SubjectDN })
                .FirstOrDefaultAsync(cancellationToken);
            if (caRow == null)
                continue;

            X509Certificate caCert;
            try
            {
                caCert = caRow.RawCertificate is { Length: > 0 } raw
                    ? new X509CertificateParser().ReadCertificate(raw)
                    : CertificateUtil.ParseFromPem(caRow.Pem);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Published-CRL check: the CA certificate {CaCertificateId} could not be read; its published CRLs are not compared.", group.Key);
                continue;
            }

            (long Number, string Publisher)? best = null;
            foreach (var item in group)
            {
                var number = VerifiedCrlNumber(item, caCert, logger);
                if (number is long n && (best == null || n > best.Value.Number))
                    best = (n, item.Publisher);
            }
            if (best == null)
                continue;

            var counter = await db.CrlConfigurations.AsNoTracking()
                .Where(c => c.CaCertificateId == group.Key)
                .Select(c => (long?)c.LastCrlNumber)
                .MaxAsync(cancellationToken) ?? 0L;
            var storedMax = await db.Crls.AsNoTracking()
                .Where(c => c.Task != null && c.Task.CaCertificateId == group.Key)
                .Select(c => (long?)c.CrlNumber)
                .MaxAsync(cancellationToken) ?? 0L;
            var known = Math.Max(counter, storedMax);
            if (best.Value.Number > known)
                ahead.Add(new PublishedCrlAhead(group.Key, caCert.SubjectDN.ToString(), best.Value.Publisher, best.Value.Number, known));
        }
        return ahead;
    }

    /// <summary>
    /// The CRL number of <paramref name="item"/> when it is a CRL of <paramref name="caCert"/>:
    /// the same issuer name and a signature that verifies under its key. Null, with a warning,
    /// for anything else: what a directory holds is only evidence when the CA signed it.
    /// </summary>
    private static long? VerifiedCrlNumber(PublishedCrl item, X509Certificate caCert, ILogger logger)
    {
        try
        {
            var crl = new X509CrlParser().ReadCrl(item.Der);
            if (crl == null)
                return null;
            if (!crl.IssuerDN.Equivalent(caCert.SubjectDN, inOrder: true))
            {
                logger.LogWarning("Published-CRL check: the CRL read back from {Publisher} names issuer {Issuer}, not {Ca}; ignored.",
                    item.Publisher, crl.IssuerDN, caCert.SubjectDN);
                return null;
            }
            crl.Verify(caCert.GetPublicKey());
            var extension = crl.GetExtensionValue(X509Extensions.CrlNumber);
            if (extension == null)
                return null;
            var value = DerInteger.GetInstance(X509ExtensionUtilities.FromExtensionValue(extension)).PositiveValue;
            return value.BitLength > 62 ? null : value.LongValueExact;
        }
        catch (Exception ex)
        {
            logger.LogWarning("Published-CRL check: the CRL read back from {Publisher} could not be read or does not verify under the CA's key ({Kind}); ignored.",
                item.Publisher, ex.GetType().Name);
            return null;
        }
    }
}
