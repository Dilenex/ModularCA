using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.HubConnection.Contract;

namespace ModularCA.Core.Services.Hub;

/// <summary>
/// Reads the inventory the hub asks for with <c>inventory.read</c>: the instance's version and
/// applied migrations, the signer as last seen, the web TLS certificate's expiry, the newest
/// backup, the scheduled jobs whose last run failed, and the X.509 CAs.
/// </summary>
/// <remarks>
/// <para>
/// <b>It only reads.</b> Every value is one the instance already holds: rows other work wrote
/// (CRLs, scheduler job states, migration history), state other checks keep in memory
/// (<see cref="SignerContactState"/>, <see cref="ApiCertificateProvider"/>), and the record the
/// backup verification job leaves beside the archives (<see cref="BackupVerificationRecord"/>).
/// It signs no CRL, verifies no archive, and does not call the signer. A few small queries and
/// one directory listing: cheap enough to ask for every minute.
/// </para>
/// <para>
/// <b>What it never returns.</b> No issued certificate, no user, no key, no secret, no audit
/// entry. The queries select names, states, numbers and dates only: no certificate or CRL
/// bytes leave the database for it. SSH CAs are left out: an SSH CA has no certificate that
/// expires, no CRL and no OCSP responder, so none of a CA's fields here would say anything.
/// </para>
/// <para>
/// A part that cannot be read (the migration history, the backup directory) is answered as
/// null and logged; it does not fail the whole read.
/// </para>
/// </remarks>
/// <param name="db">The application database.</param>
/// <param name="auditDb">The audit database, or null when the instance has none of its own.</param>
/// <param name="signer">What the readiness check last learned of the signer.</param>
/// <param name="webTls">The certificate the HTTPS listener serves.</param>
/// <param name="backupDirectory">The instance's backup directory, absolute.</param>
/// <param name="instanceVersion">The product version.</param>
/// <param name="logger">Where a part that could not be read is noted.</param>
/// <param name="timeProvider">The clock the backup's age is measured with; the system's when null.</param>
public sealed class NodeInventoryReader(
    ModularCADbContext db,
    AuditDbContext? auditDb,
    SignerContactState signer,
    ApiCertificateProvider webTls,
    string backupDirectory,
    string instanceVersion,
    ILogger logger,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>Reads the inventory.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    public async Task<HubInventory> ReadAsync(CancellationToken cancellationToken)
    {
        var schema = new HubInventorySchema(
            await ReadMigrationsAsync(db, "application", cancellationToken),
            auditDb == null ? null : await ReadMigrationsAsync(auditDb, "audit", cancellationToken));

        return new HubInventory(
            instanceVersion,
            schema,
            ReadSigner(),
            ReadWebTls(),
            ReadNewestBackup(),
            await ReadFailingJobsAsync(cancellationToken),
            await ReadCertificateAuthoritiesAsync(cancellationToken));
    }

    /// <summary>The migrations applied to <paramref name="context"/>'s database; null when its history cannot be read.</summary>
    private async Task<HubInventoryMigrations?> ReadMigrationsAsync(DbContext context, string name, CancellationToken cancellationToken)
    {
        try
        {
            if (!context.Database.IsRelational())
                return null;
            var applied = (await context.Database.GetAppliedMigrationsAsync(cancellationToken)).ToList();
            return new HubInventoryMigrations(applied.Count == 0 ? null : applied.Max(StringComparer.Ordinal), applied.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("Hub inventory: the migration history of the {Database} database could not be read ({Error})", name, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>The signer as the readiness check last saw it; null when it has not asked yet.</summary>
    private HubInventorySigner? ReadSigner()
        => signer.Last is not { } last ? null
            : new HubInventorySigner(
                !last.Reachable ? HubInventorySigner.Unreachable : last.Unlocked ? HubInventorySigner.Unlocked : HubInventorySigner.Locked,
                Utc(last.AtUtc));

    /// <summary>The expiry of the certificate the HTTPS listener serves; null when none is loaded.</summary>
    private HubInventoryWebTlsCertificate? ReadWebTls()
    {
        try
        {
            return webTls.GetCertificate() is { } certificate
                ? new HubInventoryWebTlsCertificate(certificate.NotAfter.ToUniversalTime())
                : null;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ObjectDisposedException)
        {
            logger.LogWarning("Hub inventory: the web TLS certificate could not be read ({Error})", ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// The newest archive in the backup directory, chosen as the verification job and the
    /// console choose it, with what the verification job's last run recorded for that file.
    /// </summary>
    private HubInventoryBackup? ReadNewestBackup()
    {
        try
        {
            var directory = new DirectoryInfo(backupDirectory);
            if (!directory.Exists)
                return null;
            var newest = directory.GetFiles("modularca-backup-*.*")
                .Where(f => f.Extension is ".zip" or ".enc")
                .OrderByDescending(f => f.CreationTimeUtc)
                .FirstOrDefault();
            if (newest == null)
                return null;

            var created = Utc(newest.CreationTimeUtc);
            var age = (long)Math.Max(0, (_time.GetUtcNow().UtcDateTime - created).TotalSeconds);
            var record = BackupVerificationRecord.TryRead(backupDirectory);
            var checkedArchive = record?.Archives.FirstOrDefault(a => string.Equals(a.FileName, newest.Name, StringComparison.Ordinal));
            return checkedArchive == null
                ? new HubInventoryBackup(newest.Name, created, age, null, null)
                : new HubInventoryBackup(newest.Name, created, age, checkedArchive.Valid, Utc(record!.VerifiedAtUtc));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.LogWarning("Hub inventory: the backup directory could not be read ({Error})", ex.GetType().Name);
            return null;
        }
    }

    /// <summary>The jobs whose last run the scheduler recorded as failed, or as cancelled by its timeout.</summary>
    private async Task<IReadOnlyList<HubInventoryFailingJob>> ReadFailingJobsAsync(CancellationToken cancellationToken)
    {
        var rows = await db.SchedulerJobStates.AsNoTracking()
            .Where(s => s.LastResult == "failed" || s.LastResult == "cancelled")
            .OrderBy(s => s.JobName)
            .Select(s => new { s.JobName, s.LastRunUtc })
            .ToListAsync(cancellationToken);

        // A job that runs per row keeps the state of a row that has since been deleted. Such a job
        // can be neither fixed nor cleared, so it is not reported as failing.
        var ids = rows.Select(r => PerRow(r.JobName)).Where(p => p != null).Select(p => p!.Value).ToList();
        var crlIds = ids.Where(p => p.Kind == CrlExportKind).Select(p => p.Id).ToList();
        var ldapIds = ids.Where(p => p.Kind == LdapPublisherKind).Select(p => p.Id).ToList();
        var liveCrl = crlIds.Count == 0 ? [] : await db.CrlConfigurations.AsNoTracking()
            .Where(c => crlIds.Contains(c.TaskId)).Select(c => c.TaskId).ToListAsync(cancellationToken);
        var liveLdap = ldapIds.Count == 0 ? [] : await db.LdapConfigurations.AsNoTracking()
            .Where(c => ldapIds.Contains(c.Id)).Select(c => c.Id).ToListAsync(cancellationToken);

        return rows
            .Where(r => PerRow(r.JobName) is not { } row
                || (row.Kind == CrlExportKind ? liveCrl.Contains(row.Id)
                    : row.Kind != LdapPublisherKind || liveLdap.Contains(row.Id)))
            .Select(r => new HubInventoryFailingJob(r.JobName, KindOf(r.JobName), r.LastRunUtc is { } at ? Utc(at) : null))
            .ToList();
    }

    /// <summary>The name of the CRL export job, which runs once for each CRL schedule.</summary>
    private const string CrlExportKind = "CrlExport";

    /// <summary>The name of the LDAP publisher job, which runs once for each LDAP publisher.</summary>
    private const string LdapPublisherKind = "LdapPublisher";

    /// <summary>The kind of a job: its name up to the first colon, or the whole name when it has none.</summary>
    /// <param name="jobName">The job's name as the scheduler records it.</param>
    public static string KindOf(string jobName)
    {
        var colon = jobName.IndexOf(':');
        return colon < 0 ? jobName : jobName[..colon];
    }

    /// <summary>
    /// The kind and row id of a per-row job's name (<c>Kind:id</c>); null for a job that runs
    /// once for the instance, and for a name whose part after the colon is not an id.
    /// </summary>
    /// <param name="jobName">The job's name as the scheduler records it.</param>
    private static (string Kind, Guid Id)? PerRow(string jobName)
    {
        var colon = jobName.IndexOf(':');
        return colon > 0 && Guid.TryParse(jobName[(colon + 1)..], out var id) ? (jobName[..colon], id) : null;
    }

    /// <summary>
    /// The X.509 CAs that are not deleted, each with its certificate's expiry, its newest full
    /// CRL and its delegated OCSP responder certificate's expiry. Dates and numbers are selected
    /// in the database; no certificate or CRL is loaded.
    /// </summary>
    private async Task<IReadOnlyList<HubInventoryCertificateAuthority>> ReadCertificateAuthoritiesAsync(CancellationToken cancellationToken)
    {
        // The soft-delete filter of the model leaves deleted CAs out.
        var rows = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => !ca.IsSshCa)
            .OrderBy(ca => ca.Name)
            .Select(ca => new
            {
                ca.Name,
                ca.Label,
                ca.IsEnabled,
                CertificateNotAfter = db.Certificates
                    .Where(c => c.CertificateId == ca.CertificateId)
                    .Select(c => (DateTime?)c.NotAfter)
                    .FirstOrDefault(),
                Crl = db.Crls
                    .Where(c => !c.IsDelta && c.Task!.CaCertificateId == ca.CertificateId)
                    .OrderByDescending(c => c.CrlNumber)
                    .Select(c => new { Number = (long?)c.CrlNumber, c.NextUpdate })
                    .FirstOrDefault(),
                OcspNotAfter = db.Certificates
                    .Where(c => c.CertificateId == ca.OcspResponderCertificateId)
                    .Select(c => (DateTime?)c.NotAfter)
                    .FirstOrDefault(),
            })
            .ToListAsync(cancellationToken);

        return rows.Select(r => new HubInventoryCertificateAuthority(
            r.Name,
            string.IsNullOrEmpty(r.Label) ? null : r.Label,
            r.IsEnabled ? HubInventoryCertificateAuthority.Active : HubInventoryCertificateAuthority.Disabled,
            r.CertificateNotAfter is { } notAfter ? Utc(notAfter) : null,
            r.Crl?.Number is { } number ? new HubInventoryCrl(number, Utc(r.Crl.NextUpdate)) : null,
            r.OcspNotAfter is { } ocsp ? Utc(ocsp) : null)).ToList();
    }

    /// <summary>A stored time as UTC: the databases and the file system hand back UTC values whose kind is not always set.</summary>
    private static DateTime Utc(DateTime value)
        => value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
