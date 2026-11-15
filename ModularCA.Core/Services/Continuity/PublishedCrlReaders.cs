using System.DirectoryServices.Protocols;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Scheduler;

namespace ModularCA.Core.Services.Continuity;

/// <summary>
/// Reads back the CRLs this instance published somewhere else, for the check at start that a
/// published CRL is not ahead of the database (<see cref="InstanceContinuity.CheckPublishedCrlsAsync"/>).
/// An implementation returns what it could read and never throws for a publisher that does not
/// answer: the check is evidence when it is there, not a condition of starting.
/// </summary>
public interface IPublishedCrlReader
{
    /// <summary>The CRLs read back from every configured publisher this reader knows, each with the CA certificate it belongs to.</summary>
    Task<IReadOnlyList<PublishedCrl>> ReadAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads back the CRLs the LDAP publishers wrote: for every enabled LDAP configuration that
/// publishes CRLs, the values of <c>certificateRevocationList</c> on its base DN, the entry
/// <see cref="LdapPublishHelper.PublishCrl"/> writes them to. A directory that does not answer
/// within <see cref="Timeout"/>, refuses the bind or holds no CRL there contributes nothing and
/// is logged.
/// </summary>
public sealed class LdapPublishedCrlReader(ModularCADbContext db, ILdapSecretProtector secrets, ILogger<LdapPublishedCrlReader> logger) : IPublishedCrlReader
{
    /// <summary>How long one directory is given to answer before the start goes on without it.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>The attribute the publisher writes the CRL to, and the option some directories return it under.</summary>
    private static readonly string[] CrlAttributes = ["certificateRevocationList", "certificateRevocationList;binary"];

    /// <inheritdoc />
    public async Task<IReadOnlyList<PublishedCrl>> ReadAsync(CancellationToken cancellationToken = default)
    {
        var configs = await db.LdapConfigurations.AsNoTracking()
            .Where(c => c.Enabled && c.PublishCRL)
            .ToListAsync(cancellationToken);
        if (configs.Count == 0)
            return [];

        var caIds = configs.Select(c => c.CertificateAuthorityId).Distinct().ToList();
        var caCertificates = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => caIds.Contains(ca.Id) && ca.CertificateId != null)
            .Select(ca => new { ca.Id, CertificateId = ca.CertificateId!.Value })
            .ToDictionaryAsync(ca => ca.Id, ca => ca.CertificateId, cancellationToken);

        var read = new List<PublishedCrl>();
        foreach (var config in configs)
        {
            if (!caCertificates.TryGetValue(config.CertificateAuthorityId, out var caCertificateId))
                continue;
            var publisher = $"LDAP publisher '{config.Name}' ({config.Host}:{config.Port}, {config.BaseDn})";
            var options = new LdapScheduleOptions
            {
                LdapHost = config.Host,
                LdapPort = config.Port,
                UseSsl = config.UseSsl,
                BaseDn = config.BaseDn,
                Username = config.Username,
                Password = secrets.Unprotect(config.Password),
                CertificateAuthorityId = config.CertificateAuthorityId,
                PublishCRL = true,
                TaskId = config.Id,
            };
            try
            {
                // The directory call blocks; it runs off this thread and is abandoned at the timeout.
                var values = await Task.Run(() => ReadValues(options), cancellationToken).WaitAsync(Timeout + TimeSpan.FromSeconds(5), cancellationToken);
                read.AddRange(values.Select(der => new PublishedCrl(caCertificateId, publisher, der)));
                logger.LogInformation("Published-CRL check: read {Count} CRL(s) back from {Publisher}.", values.Count, publisher);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning("Published-CRL check: {Publisher} could not be read back ({Kind}: {Message}). Its CRL is not compared at this start.",
                    publisher, ex.GetType().Name, ex.Message);
            }
        }
        return read;
    }

    private List<byte[]> ReadValues(LdapScheduleOptions options)
    {
        using var connection = LdapPublishHelper.Connect(options, Timeout, logger);
        var request = new SearchRequest(options.BaseDn, "(objectClass=*)", SearchScope.Base, CrlAttributes);
        var response = (SearchResponse)connection.SendRequest(request, Timeout);
        var values = new List<byte[]>();
        foreach (SearchResultEntry entry in response.Entries)
        {
            foreach (var name in CrlAttributes)
            {
                if (entry.Attributes[name] is not { } attribute)
                    continue;
                foreach (var value in attribute.GetValues(typeof(byte[])))
                {
                    if (value is byte[] { Length: > 0 } der)
                        values.Add(der);
                }
            }
        }
        return values;
    }
}
