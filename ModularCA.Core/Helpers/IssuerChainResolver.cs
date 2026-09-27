using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The issuer chain a PKCS#12 carries beside an end-entity certificate, and the CA the
/// certificate belongs to. Shared by the stored-key export and the held-key delivery so both
/// files carry the same chain for the same certificate.
/// </summary>
/// <param name="Chain">DER-encoded issuer certificates, nearest issuer first.</param>
/// <param name="CaId">The issuing CA, when one can be resolved.</param>
/// <param name="TenantId">The issuing CA's tenant.</param>
public sealed record IssuerChain(List<byte[]> Chain, Guid? CaId, Guid? TenantId);

/// <summary>
/// The single implementation of "walk up the issuers" for a stored certificate. Each hop follows
/// the certificate's own <see cref="CertificateEntity.IssuerCertificateId"/>, falling back to its
/// signing profile's issuer and, for a CA certificate, its CA row's parent.
/// </summary>
public static class IssuerChainResolver
{
    private sealed record CaRef(Guid Id, Guid TenantId, Guid? ParentCertificateId);

    private sealed record Hop(CertificateEntity Cert, Guid? ProfileIssuerId, CaRef? Ca);

    /// <summary>
    /// Resolves the chain for <paramref name="certEntity"/> as DER, plus the issuing CA and its
    /// tenant. The direct issuer is always included, and the root only when it is the direct
    /// issuer, so a PKCS#12 carries what a client needs to present and not the trust anchor it
    /// should already hold. With <paramref name="includeChain"/> false only the CA and tenant are resolved.
    /// </summary>
    public static async Task<IssuerChain> ResolveAsync(ModularCADbContext db, CertificateEntity certEntity, bool includeChain)
    {
        var chain = new List<byte[]>();
        Hop? self = null;
        var selfLoaded = false;
        async Task<Hop?> SelfAsync()
        {
            if (!selfLoaded)
            {
                self = await LoadHopAsync(db, certEntity.CertificateId);
                selfLoaded = true;
            }
            return self;
        }
        async Task<Guid?> ProfileIssuerAsync() => await ProfileIssuerIdAsync(db, certEntity,
            certEntity.SigningProfile == null && certEntity.SigningProfileId != null ? await SelfAsync() : null);

        var issuerId = certEntity.IssuerCertificateId is Guid linked
            ? (linked == certEntity.CertificateId ? null : linked)
            : NextIssuerId(certEntity, await ProfileIssuerAsync(), certEntity.IsCA ? (await SelfAsync())?.Ca : null);
        if (issuerId is not Guid firstId)
            return new IssuerChain(chain, null, null);

        var issuerHop = await LoadHopAsync(db, firstId);
        var owner = issuerHop?.Ca;
        if (owner == null && issuerHop != null)
            owner = SupersededOwner(db, issuerHop.Cert);
        if (owner == null)
        {
            var fallbackId = await ProfileIssuerAsync();
            if (fallbackId != null && fallbackId != firstId)
                owner = await db.CertificateAuthorities.AsNoTracking()
                    .Where(ca => ca.CertificateId == fallbackId)
                    .Select(ca => new CaRef(ca.Id, ca.TenantId, null))
                    .FirstOrDefaultAsync();
        }
        if (!includeChain || issuerHop == null)
            return new IssuerChain(chain, owner?.Id, owner?.TenantId);

        foreach (var issuer in await WalkAsync(db, certEntity, issuerHop))
            chain.Add(CertificateUtil.ParseFromPem(issuer.Pem).GetEncoded());
        return new IssuerChain(chain, owner?.Id, owner?.TenantId);
    }

    /// <summary>
    /// Returns the issuer certificates above <paramref name="cert"/>, nearest first. A self-signed
    /// root is included only when it is the direct issuer; an unresolvable parent or a cycle ends the walk.
    /// </summary>
    public static async Task<List<CertificateEntity>> ResolveIssuerCertificatesAsync(ModularCADbContext db, CertificateEntity cert)
    {
        Guid? firstId;
        if (cert.IssuerCertificateId is Guid linked)
            firstId = linked == cert.CertificateId ? null : linked;
        else
        {
            var self = await LoadHopAsync(db, cert.CertificateId);
            firstId = NextIssuerId(cert, await ProfileIssuerIdAsync(db, cert, self), self?.Ca);
        }
        if (firstId is not Guid id)
            return [];
        var first = await LoadHopAsync(db, id);
        return first == null ? [] : await WalkAsync(db, cert, first);
    }

    private static async Task<List<CertificateEntity>> WalkAsync(ModularCADbContext db, CertificateEntity cert, Hop first)
    {
        var chain = new List<CertificateEntity>();
        var visited = new HashSet<Guid> { cert.CertificateId };
        Hop? hop = first;

        while (hop != null && visited.Add(hop.Cert.CertificateId))
        {
            var issuer = hop.Cert;
            if (IsRoot(issuer))
            {
                if (chain.Count == 0)
                    chain.Add(issuer);
                break;
            }

            chain.Add(issuer);
            if (NextIssuerId(issuer, hop.ProfileIssuerId, hop.Ca) is not Guid nextId)
                break;
            hop = await LoadHopAsync(db, nextId);
        }
        return chain;
    }

    /// <summary>Whether <paramref name="cert"/> is a root: its issuer link points at itself, or, with no link, its subject and issuer DNs match.</summary>
    private static bool IsRoot(CertificateEntity cert) =>
        cert.IssuerCertificateId is Guid issuerId
            ? issuerId == cert.CertificateId
            : !string.IsNullOrEmpty(cert.Issuer) && string.Equals(cert.SubjectDN, cert.Issuer, StringComparison.OrdinalIgnoreCase);

    /// <summary>The certificate id of <paramref name="cert"/>'s issuer, or null when it is self-signed or cannot be resolved.</summary>
    private static Guid? NextIssuerId(CertificateEntity cert, Guid? profileIssuerId, CaRef? ownCa)
    {
        if (cert.IssuerCertificateId is Guid issuerCertId)
            return issuerCertId == cert.CertificateId ? null : issuerCertId;
        if (profileIssuerId != null && profileIssuerId != cert.CertificateId)
            return profileIssuerId;
        return cert.IsCA ? ownCa?.ParentCertificateId : null;
    }

    /// <summary>The issuer named by <paramref name="cert"/>'s signing profile, preferring a loaded navigation, then <paramref name="self"/>.</summary>
    private static async Task<Guid?> ProfileIssuerIdAsync(ModularCADbContext db, CertificateEntity cert, Hop? self)
    {
        if (cert.SigningProfile != null)
            return cert.SigningProfile.IssuerId;
        if (cert.SigningProfileId == null)
            return null;
        if (self != null)
            return self.ProfileIssuerId;
        return await db.SigningProfiles.AsNoTracking()
            .Where(sp => sp.Id == cert.SigningProfileId)
            .Select(sp => sp.IssuerId)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// Loads a certificate with its signing profile's issuer and the CA row it is the certificate
    /// of, in one query that projects each CA row whole, so the CA id, tenant and parent can never
    /// come from different rows. More than one CA row naming the certificate is ambiguous and
    /// yields no CA rather than a guess.
    /// </summary>
    private static async Task<Hop?> LoadHopAsync(ModularCADbContext db, Guid certificateId)
    {
        var row = await db.Certificates.AsNoTracking()
            .Where(c => c.CertificateId == certificateId)
            .Select(c => new
            {
                Cert = c,
                ProfileIssuerId = db.SigningProfiles.Where(sp => sp.Id == c.SigningProfileId).Select(sp => sp.IssuerId).FirstOrDefault(),
                Cas = db.CertificateAuthorities
                    .Where(ca => ca.CertificateId == c.CertificateId)
                    .Select(ca => new CaRef(ca.Id, ca.TenantId, ca.ParentCa == null ? null : ca.ParentCa.CertificateId))
                    .Take(2)
                    .ToList(),
            })
            .FirstOrDefaultAsync();
        if (row == null)
            return null;
        return new Hop(row.Cert, row.ProfileIssuerId, row.Cas.Count == 1 ? row.Cas[0] : null);
    }

    /// <summary>A CA certificate's owning CA and that CA's tenant.</summary>
    /// <param name="CaId">The owning CA.</param>
    /// <param name="TenantId">The owning CA's tenant.</param>
    public sealed record CaOwner(Guid CaId, Guid TenantId);

    private sealed record OwnerCandidate(Guid Id, Guid TenantId, string SubjectDn, string? Issuer, string Pem);

    /// <summary>
    /// The CA that owns <paramref name="certificateId"/> as a CA certificate: the CA whose current
    /// certificate it is, or, for a superseded CA certificate, the CA it was superseded within
    /// (see <see cref="PickSupersededOwner"/>). Null for a certificate no CA owns. This is the
    /// single definition of "a certificate belonging to a CA" that certificate access scoping and
    /// the console's scope filters share.
    /// </summary>
    public static CaOwner? OwnerOf(ModularCADbContext db, Guid certificateId)
        => OwnerOf(db, certificateId, null);

    /// <summary>
    /// As <see cref="OwnerOf(ModularCADbContext, Guid)"/>, for a certificate row already loaded.
    /// </summary>
    public static CaOwner? OwnerOf(ModularCADbContext db, CertificateEntity cert)
        => OwnerOf(db, cert.CertificateId, cert);

    private static CaOwner? OwnerOf(ModularCADbContext db, Guid certificateId, CertificateEntity? loaded)
    {
        var current = db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.CertificateId == certificateId)
            .Select(ca => new CaOwner(ca.Id, ca.TenantId))
            .Take(2).ToList();
        if (current.Count > 0)
            return current.Count == 1 ? current[0] : null;

        var cert = loaded ?? db.Certificates.AsNoTracking().FirstOrDefault(c => c.CertificateId == certificateId);
        if (cert == null || !cert.IsCA || string.IsNullOrEmpty(cert.SubjectDN))
            return null;

        var candidates = db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.Certificate != null && ca.Certificate.SubjectDN == cert.SubjectDN)
            .Select(ca => new OwnerCandidate(ca.Id, ca.TenantId, ca.Certificate!.SubjectDN, ca.Certificate.Issuer, ca.Certificate.Pem))
            .ToList();
        if (candidates.Count == 0)
            return null;

        var profileIssuer = cert.SigningProfileId == null ? null
            : db.SigningProfiles.AsNoTracking().Where(sp => sp.Id == cert.SigningProfileId).Select(sp => sp.IssuerId).FirstOrDefault();
        var hintIds = TenantHintCertificateIds(cert, profileIssuer);
        var hint = hintIds.Count == 0 ? null
            : db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.CertificateId != null && hintIds.Contains(ca.CertificateId.Value))
                .Select(ca => (Guid?)ca.TenantId).FirstOrDefault();
        return PickSupersededOwner(cert, candidates, hint);
    }

    /// <summary>
    /// Every certificate a CA owns, current and superseded, mapped to its owner — computed once
    /// for a request so a scope filter can match on a plain id list.
    /// </summary>
    public static async Task<Dictionary<Guid, CaOwner>> ResolveCaCertificateOwnersAsync(ModularCADbContext db)
    {
        var current = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.Certificate != null)
            .Select(ca => new OwnerCandidate(ca.Id, ca.TenantId, ca.Certificate!.SubjectDN, ca.Certificate.Issuer, ca.Certificate.Pem))
            .ToListAsync();
        var currentIds = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.CertificateId != null)
            .Select(ca => new { CertificateId = ca.CertificateId!.Value, ca.Id, ca.TenantId })
            .ToListAsync();

        var owners = new Dictionary<Guid, CaOwner>();
        foreach (var group in currentIds.GroupBy(r => r.CertificateId))
        {
            var distinct = group.DistinctBy(r => r.Id).ToList();
            if (distinct.Count == 1)
                owners[group.Key] = new CaOwner(distinct[0].Id, distinct[0].TenantId);
        }
        var currentCertIds = currentIds.Select(r => r.CertificateId).Distinct().ToList();

        var orphans = await db.Certificates.AsNoTracking()
            .Where(c => c.IsCA && !currentCertIds.Contains(c.CertificateId))
            .ToListAsync();
        if (orphans.Count == 0)
            return owners;

        var profileIds = orphans.Where(c => c.SigningProfileId != null).Select(c => c.SigningProfileId!.Value).Distinct().ToList();
        var profileIssuers = await db.SigningProfiles.AsNoTracking()
            .Where(sp => profileIds.Contains(sp.Id))
            .ToDictionaryAsync(sp => sp.Id, sp => sp.IssuerId);

        foreach (var orphan in orphans)
        {
            if (string.IsNullOrEmpty(orphan.SubjectDN))
                continue;
            var candidates = current.Where(c => c.SubjectDn == orphan.SubjectDN).ToList();
            if (candidates.Count == 0)
                continue;
            var profileIssuer = orphan.SigningProfileId is Guid spId ? profileIssuers.GetValueOrDefault(spId) : null;
            Guid? hint = null;
            foreach (var id in TenantHintCertificateIds(orphan, profileIssuer))
                if (owners.TryGetValue(id, out var o)) { hint = o.TenantId; break; }
            if (PickSupersededOwner(orphan, candidates, hint) is { } owner)
                owners[orphan.CertificateId] = owner;
        }
        return owners;
    }

    /// <summary>
    /// The revocation scope of a CA certificate: <paramref name="caCertificateId"/> itself plus every
    /// other CA certificate owned by the same CA (per <see cref="OwnerOf(ModularCADbContext, Guid)"/>)
    /// that carries the same subject and the same public key as <paramref name="signingCertificate"/>.
    /// A certificate issued under any of these was signed by the key that signs the CRL or OCSP
    /// response, so it is in that response's scope. A superseded CA certificate with a different key
    /// is left out: a CRL signed by the new key does not cover certificates issued by the old one.
    /// </summary>
    /// <param name="db">The context to resolve through.</param>
    /// <param name="caCertificateId">The CA certificate whose scope is wanted.</param>
    /// <param name="signingCertificate">The CA certificate of the key that signs the CRL or response.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<List<Guid>> SameKeyCaCertificateIdsAsync(
        ModularCADbContext db, Guid caCertificateId, Org.BouncyCastle.X509.X509Certificate signingCertificate,
        CancellationToken ct = default)
    {
        var ids = new List<Guid> { caCertificateId };
        var key = signingCertificate.CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
        var owner = OwnerOf(db, caCertificateId);
        if (owner == null)
            return ids;

        var subject = await db.Certificates.AsNoTracking()
            .Where(c => c.CertificateId == caCertificateId)
            .Select(c => c.SubjectDN)
            .FirstOrDefaultAsync(ct);
        if (string.IsNullOrEmpty(subject))
            return ids;

        var siblings = await db.Certificates.AsNoTracking()
            .Where(c => c.IsCA && c.SubjectDN == subject && c.CertificateId != caCertificateId)
            .Select(c => new { c.CertificateId, c.Pem })
            .ToListAsync(ct);
        foreach (var sibling in siblings)
        {
            if (string.IsNullOrWhiteSpace(sibling.Pem) || PublicKey(sibling.Pem) is not { } k || !k.AsSpan().SequenceEqual(key))
                continue;
            if (OwnerOf(db, sibling.CertificateId)?.CaId == owner.CaId)
                ids.Add(sibling.CertificateId);
        }
        return ids;
    }

    /// <summary>
    /// The CA a superseded CA certificate belonged to, as a <see cref="CaRef"/> for the chain walk.
    /// </summary>
    private static CaRef? SupersededOwner(ModularCADbContext db, CertificateEntity superseded)
    {
        if (!superseded.IsCA || string.IsNullOrEmpty(superseded.SubjectDN))
            return null;
        var owner = OwnerOf(db, superseded);
        return owner == null ? null : new CaRef(owner.CaId, owner.TenantId, null);
    }

    /// <summary>
    /// The certificates whose CA's tenant is taken as the superseded certificate's own: its issuer
    /// and its signing profile's issuer, excluding itself.
    /// </summary>
    private static List<Guid> TenantHintCertificateIds(CertificateEntity cert, Guid? profileIssuerId)
    {
        var ids = new List<Guid>(2);
        if (cert.IssuerCertificateId is Guid issuer && issuer != cert.CertificateId)
            ids.Add(issuer);
        if (profileIssuerId is Guid p && p != cert.CertificateId && !ids.Contains(p))
            ids.Add(p);
        return ids;
    }

    /// <summary>
    /// Picks the owner of a superseded CA certificate among CAs whose current certificate has the
    /// same subject. A public key or subject key identifier match ranks first; failing that, the
    /// same issuer DN, which is only trusted within the certificate's own tenant because a
    /// same-named CA in another tenant is exactly what it cannot tell apart. Either tier is
    /// restricted to <paramref name="tenantHint"/> when it is known, and more than one match in a
    /// tier is refused rather than guessed.
    /// </summary>
    private static CaOwner? PickSupersededOwner(CertificateEntity superseded, IReadOnlyList<OwnerCandidate> candidates, Guid? tenantHint)
    {
        var scoped = tenantHint is Guid t ? candidates.Where(c => c.TenantId == t).ToList() : candidates.ToList();

        var key = PublicKey(superseded.Pem);
        var ski = SubjectKeyIdentifier(superseded.Pem);
        var keyMatches = scoped
            .Where(c => (key != null && PublicKey(c.Pem) is { } k && k.AsSpan().SequenceEqual(key))
                        || (ski != null && SubjectKeyIdentifier(c.Pem) is { } s && s.AsSpan().SequenceEqual(ski)))
            .DistinctBy(c => c.Id)
            .ToList();
        if (keyMatches.Count == 1)
            return new CaOwner(keyMatches[0].Id, keyMatches[0].TenantId);
        if (keyMatches.Count > 1 || tenantHint == null)
            return null;

        var dnMatches = scoped
            .Where(c => string.Equals(c.Issuer, superseded.Issuer, StringComparison.OrdinalIgnoreCase))
            .DistinctBy(c => c.Id)
            .ToList();
        return dnMatches.Count == 1 ? new CaOwner(dnMatches[0].Id, dnMatches[0].TenantId) : null;
    }

    private static byte[]? PublicKey(string pem)
    {
        try { return CertificateUtil.ParseFromPem(pem).CertificateStructure.SubjectPublicKeyInfo.GetEncoded(); }
        catch { return null; }
    }

    private static byte[]? SubjectKeyIdentifier(string pem)
    {
        try
        {
            var ext = CertificateUtil.ParseFromPem(pem).GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectKeyIdentifier);
            return ext == null ? null
                : Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(ext.GetOctets())).GetKeyIdentifier();
        }
        catch { return null; }
    }
}
