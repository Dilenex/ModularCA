using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Which CAs and CA certificates may no longer vouch for a client certificate issued beneath
/// them, read in one pass for one request. A CA is refused when it, or any CA above it, is
/// revoked or on hold (its certificate row is revoked), disabled, or deleted: the same states in
/// which <see cref="IssuingCaGuard"/> stops a CA from signing.
/// <para>
/// The walk follows the links <see cref="IssuerChainResolver"/> follows: a CA certificate's
/// <c>IssuerCertificateId</c>, falling back for a row without one to its CA row's parent, and a CA
/// row's <c>ParentCaId</c>. A CA certificate also takes the standing of the CA rows that name it
/// as their certificate. Deleted CA rows are read past the soft-delete query filter, since a
/// deleted CA is exactly what has to be seen. A link to a row that does not exist ends the walk,
/// and a cycle ends it too.
/// </para>
/// <para>
/// Only CA rows and CA certificate rows are read (ids, links and flags, never PEM), so the cost is
/// a small fixed pair of queries whatever the number of leaf certificates.
/// </para>
/// </summary>
public sealed class MtlsIssuerStanding
{
    private sealed record CaRow(Guid Id, Guid? ParentCaId, Guid? CertificateId, bool IsEnabled, bool IsDeleted, bool CertificateRevoked);

    private sealed record CaCertificateRow(Guid Id, Guid? IssuerCertificateId, bool Revoked);

    private readonly Dictionary<Guid, MtlsCredentialRefusal> _cas;
    private readonly Dictionary<Guid, MtlsCredentialRefusal> _caCertificates;

    private MtlsIssuerStanding(Dictionary<Guid, MtlsCredentialRefusal> cas, Dictionary<Guid, MtlsCredentialRefusal> caCertificates)
    {
        _cas = cas;
        _caCertificates = caCertificates;
        RefusedCaIds = [.. cas.Keys];
        RefusedCaCertificateIds = [.. caCertificates.Keys];
    }

    /// <summary>The CA rows (deleted ones included) whose leaves may not authenticate.</summary>
    public List<Guid> RefusedCaIds { get; }

    /// <summary>The CA certificates under which a leaf may not authenticate.</summary>
    public List<Guid> RefusedCaCertificateIds { get; }

    /// <summary>
    /// Why a client certificate signed by CA <paramref name="signingCaId"/> under CA certificate
    /// <paramref name="issuerCertificateId"/> may not authenticate, or
    /// <see cref="MtlsCredentialRefusal.None"/> when every CA above it is in good standing. A
    /// revoked issuer outranks a disabled one.
    /// </summary>
    /// <param name="signingCaId">The CA row that signed the certificate, when known.</param>
    /// <param name="issuerCertificateId">The CA certificate the certificate was issued under, when known.</param>
    public MtlsCredentialRefusal RefusalFor(Guid? signingCaId, Guid? issuerCertificateId)
    {
        var refusal = MtlsCredentialRefusal.None;
        if (signingCaId is Guid caId && _cas.TryGetValue(caId, out var ca))
            refusal = Worst(refusal, ca);
        if (issuerCertificateId is Guid certId && _caCertificates.TryGetValue(certId, out var cert))
            refusal = Worst(refusal, cert);
        return refusal;
    }

    /// <summary>
    /// Reads every CA row (past the soft-delete filter) and every CA certificate row, and works out
    /// which of them may no longer vouch for a client certificate.
    /// </summary>
    /// <param name="db">The context to read through.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<MtlsIssuerStanding> LoadAsync(ModularCADbContext db, CancellationToken ct = default)
    {
        var caRows = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Select(ca => new CaRow(ca.Id, ca.ParentCaId, ca.CertificateId, ca.IsEnabled, ca.IsDeleted,
                ca.Certificate != null && ca.Certificate.Revoked))
            .ToListAsync(ct);
        var certRows = await db.Certificates.AsNoTracking()
            .Where(c => c.IsCA)
            .Select(c => new CaCertificateRow(c.CertificateId, c.IssuerCertificateId, c.Revoked))
            .ToListAsync(ct);

        var cas = caRows.ToDictionary(r => r.Id);
        var certs = certRows.ToDictionary(r => r.Id);
        var namers = caRows.Where(r => r.CertificateId != null).ToLookup(r => r.CertificateId!.Value);

        // A CA row's own state; its certificate counts as revoked whether or not the row is IsCA.
        MtlsCredentialRefusal CaOwn(CaRow row)
            => row.CertificateRevoked ? MtlsCredentialRefusal.IssuerRevoked
                : row.IsDeleted || !row.IsEnabled ? MtlsCredentialRefusal.IssuerDisabled
                : MtlsCredentialRefusal.None;

        // A CA row and every row above it by ParentCaId.
        MtlsCredentialRefusal CaChain(Guid caId)
        {
            var refusal = MtlsCredentialRefusal.None;
            var visited = new HashSet<Guid>();
            for (Guid? id = caId; id is Guid current && visited.Add(current) && cas.TryGetValue(current, out var row); id = row.ParentCaId)
                refusal = Worst(refusal, CaOwn(row));
            return refusal;
        }

        // The live CA row that names a certificate, as IssuingCaGuard picks it; null when none does.
        CaRow? LiveNamer(Guid certId) => namers[certId].FirstOrDefault(r => !r.IsDeleted);

        // A CA certificate and every CA certificate above it, each with the CA rows naming it.
        MtlsCredentialRefusal CertChain(Guid certId)
        {
            var refusal = MtlsCredentialRefusal.None;
            var visited = new HashSet<Guid>();
            Guid? id = certId;
            while (id is Guid current && visited.Add(current) && certs.TryGetValue(current, out var cert))
            {
                if (cert.Revoked)
                    refusal = Worst(refusal, MtlsCredentialRefusal.IssuerRevoked);
                var live = LiveNamer(current);
                if (live == null && namers[current].Any())
                    refusal = Worst(refusal, MtlsCredentialRefusal.IssuerDisabled);
                if (live != null)
                    refusal = Worst(refusal, CaChain(live.Id));

                id = cert.IssuerCertificateId is Guid issuer
                    ? (issuer == current ? null : issuer)
                    : live?.ParentCaId is Guid parent && cas.TryGetValue(parent, out var parentRow) ? parentRow.CertificateId : null;
            }
            return refusal;
        }

        var refusedCas = new Dictionary<Guid, MtlsCredentialRefusal>();
        foreach (var row in caRows)
        {
            var refusal = CaChain(row.Id);
            if (row.CertificateId is Guid certId)
                refusal = Worst(refusal, CertChain(certId));
            if (refusal != MtlsCredentialRefusal.None)
                refusedCas[row.Id] = refusal;
        }

        var refusedCerts = new Dictionary<Guid, MtlsCredentialRefusal>();
        foreach (var cert in certRows)
        {
            var refusal = CertChain(cert.Id);
            if (refusal != MtlsCredentialRefusal.None)
                refusedCerts[cert.Id] = refusal;
        }

        return new MtlsIssuerStanding(refusedCas, refusedCerts);
    }

    /// <summary>The stronger of two refusals: revoked, then disabled, then none.</summary>
    private static MtlsCredentialRefusal Worst(MtlsCredentialRefusal a, MtlsCredentialRefusal b)
        => a == MtlsCredentialRefusal.IssuerRevoked || b == MtlsCredentialRefusal.IssuerRevoked ? MtlsCredentialRefusal.IssuerRevoked
            : a == MtlsCredentialRefusal.IssuerDisabled || b == MtlsCredentialRefusal.IssuerDisabled ? MtlsCredentialRefusal.IssuerDisabled
            : MtlsCredentialRefusal.None;
}
