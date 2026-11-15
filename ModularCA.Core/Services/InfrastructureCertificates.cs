using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// Which certificates are infrastructure: the OCSP responder, timestamp signer and CMP signer a
/// CA issues to itself. Their lifetime and shape come from the infrastructure profiles and not
/// from a requester, so the checks that judge an end-entity certificate by its validity period
/// or its subject alternative names do not apply to them.
/// </summary>
/// <remarks>
/// A certificate is infrastructure when the request that issued it is marked
/// <see cref="CertRequestEntity.IsInfrastructureCert"/>, or when it was issued under one of the
/// seeded infrastructure profiles (<see cref="InfrastructureCertProfiles.All"/>). The second
/// covers a certificate whose request row is gone.
/// </remarks>
public sealed class InfrastructureCertificates
{
    private readonly HashSet<Guid> _certificateIds;
    private readonly HashSet<Guid> _profileIds;

    private InfrastructureCertificates(HashSet<Guid> certificateIds, HashSet<Guid> profileIds)
    {
        _certificateIds = certificateIds;
        _profileIds = profileIds;
    }

    /// <summary>A set that holds nothing: no certificate is infrastructure.</summary>
    public static InfrastructureCertificates None { get; } = new([], []);

    /// <summary>Whether <paramref name="certificate"/> is an infrastructure certificate.</summary>
    public bool Contains(CertificateEntity certificate)
        => _certificateIds.Contains(certificate.CertificateId)
           || (certificate.CertProfileId is Guid profile && _profileIds.Contains(profile));

    /// <summary>
    /// Reads which certificates are infrastructure. With <paramref name="among"/>, only those
    /// certificates are looked up; without it, every one.
    /// </summary>
    /// <param name="db">The database.</param>
    /// <param name="among">The certificates the caller will ask about, or null for all.</param>
    /// <param name="ct">Cancels the read.</param>
    public static async Task<InfrastructureCertificates> LoadAsync(
        ModularCADbContext db, IReadOnlyCollection<Guid>? among = null, CancellationToken ct = default)
    {
        var requests = db.CertificateRequests.IgnoreQueryFilters().AsNoTracking()
            .Where(r => r.IsInfrastructureCert && r.IssuedCertificateId != null);
        if (among != null)
            requests = requests.Where(r => among.Contains(r.IssuedCertificateId!.Value));
        var certificateIds = (await requests.Select(r => r.IssuedCertificateId!.Value).ToListAsync(ct)).ToHashSet();

        var names = InfrastructureCertProfiles.All.Select(role => role.DefaultProfileName).ToList();
        var profileIds = (await db.CertProfiles.IgnoreQueryFilters().AsNoTracking()
            .Where(p => names.Contains(p.Name))
            .Select(p => p.Id)
            .ToListAsync(ct)).ToHashSet();

        return new InfrastructureCertificates(certificateIds, profileIds);
    }
}
