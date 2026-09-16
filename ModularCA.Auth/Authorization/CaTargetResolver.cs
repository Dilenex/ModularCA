using System.Collections;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// What a request body names when it names the CA a mutation applies to. The policy handler
/// only sees the route, so an action whose target arrives in the body declares the target's
/// kind and the resolver turns the bound value into the CA (or CAs) to check.
/// </summary>
public enum CaTarget
{
    /// <summary>No particular CA: holding the capability on any CA is enough, as for a listing.</summary>
    AnyCa,
    /// <summary>A certificate authority id.</summary>
    Ca,
    /// <summary>A CA certificate id (<c>CertificateAuthority.CertificateId</c>), as CRL schedules and signing profiles carry.</summary>
    CaCertificate,
    /// <summary>An X.509 signing profile id; its issuer is the CA.</summary>
    SigningProfile,
    /// <summary>An X.509 request profile id.</summary>
    RequestProfile,
    /// <summary>A certificate signing request id; its signing profile names the CA.</summary>
    Csr,
    /// <summary>An issued certificate id.</summary>
    Certificate,
    /// <summary>A list of certificate serial numbers.</summary>
    Serials,
    /// <summary>An SSH CA key id.</summary>
    SshCaKey,
    /// <summary>A list of whitelist entry ids.</summary>
    Whitelists,
    /// <summary>A list of CRL schedule ids, or of objects carrying one in <c>Id</c>.</summary>
    CrlConfigurations,
}

/// <summary>The outcome of resolving a body target to CAs.</summary>
/// <param name="CaIds">Every CA the target maps to. Empty when nothing was found.</param>
/// <param name="NotFound">A named target does not exist, or a serial matched more than one certificate.</param>
/// <param name="Unscoped">
/// The target, or one of them, is not attached to any CA: a null CA id, a system-level profile,
/// a global whitelist. Such a target is a system matter, not a CA one.
/// </param>
public sealed record CaTargetResolution(IReadOnlyList<Guid> CaIds, bool NotFound, bool Unscoped)
{
    /// <summary>The value was absent or null: there is no CA to check, so system scope applies.</summary>
    public static readonly CaTargetResolution None = new([], NotFound: false, Unscoped: true);
    /// <summary>The value named something that does not exist.</summary>
    public static readonly CaTargetResolution Missing = new([], NotFound: true, Unscoped: false);
}

/// <summary>
/// The decision an action makes for a target that arrived in its body: resolve it, then require
/// the capability on every CA it maps to. A target attached to no CA needs the capability at
/// system scope; a target that names nothing is refused; <see cref="CaTarget.AnyCa"/> passes
/// for anyone holding the capability somewhere, the rule a listing already gets.
/// </summary>
public static class BodyTargetAuthorization
{
    /// <summary>Whether <paramref name="userId"/> may act on what <paramref name="value"/> names.</summary>
    public static async Task<bool> IsAllowedAsync(
        ICaGroupAuthorizationService auth, CaTargetResolver resolver, Guid userId, string capability, CaTarget target, object? value)
    {
        if (target == CaTarget.AnyCa)
        {
            return await auth.HasSystemCapabilityAsync(userId, capability)
                || (await auth.GetAccessibleCaIdsAsync(userId, capability)).Count > 0;
        }

        var resolution = await resolver.ResolveAsync(target, value);
        if (resolution.NotFound)
            return false;
        if (resolution.Unscoped && !await auth.HasSystemCapabilityAsync(userId, capability))
            return false;
        foreach (var caId in resolution.CaIds)
        {
            if (!await auth.HasCaCapabilityAsync(userId, caId, capability))
                return false;
        }
        return true;
    }
}

/// <summary>
/// Turns the bound value of a request-body field into the CA or CAs a capability must be held
/// on. Mirrors the route resolution in <see cref="CaGroupAuthorizationHandler"/>, for the
/// identifiers that only ever travel in a body. A missing or null value resolves to
/// <see cref="CaTargetResolution.None"/>; an id that names nothing resolves to
/// <see cref="CaTargetResolution.Missing"/>, so a caller can never widen a check by naming a
/// target the resolver cannot pin down.
/// </summary>
public sealed class CaTargetResolver(ModularCADbContext db)
{
    /// <summary>Resolves <paramref name="value"/> according to <paramref name="target"/>.</summary>
    public async Task<CaTargetResolution> ResolveAsync(CaTarget target, object? value)
    {
        if (target == CaTarget.AnyCa)
            return CaTargetResolution.None;

        if (target is CaTarget.Serials or CaTarget.Whitelists or CaTarget.CrlConfigurations)
            return await ResolveManyAsync(target, value);

        if (value is string text && text.Length > 0 && !Guid.TryParse(text, out _))
            return CaTargetResolution.Missing;
        var id = AsGuid(value);
        if (id == null || id == Guid.Empty)
            return CaTargetResolution.None;

        var caId = await ResolveOneAsync(target, id.Value);
        return caId switch
        {
            null => CaTargetResolution.Missing,
            _ when caId == Guid.Empty => CaTargetResolution.None,
            _ => new CaTargetResolution([caId.Value], NotFound: false, Unscoped: false),
        };
    }

    /// <summary>
    /// One target to one CA. Null means the target does not exist; <see cref="Guid.Empty"/>
    /// means it exists but belongs to no CA.
    /// </summary>
    private async Task<Guid?> ResolveOneAsync(CaTarget target, Guid id)
    {
        switch (target)
        {
            case CaTarget.Ca:
                return await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters().AnyAsync(c => c.Id == id) ? id : null;

            case CaTarget.CaCertificate:
                return await CaByCertificateAsync(id);

            case CaTarget.SigningProfile:
            {
                var sp = await db.SigningProfiles.AsNoTracking().Where(p => p.Id == id).Select(p => new { p.IssuerId }).FirstOrDefaultAsync();
                if (sp == null) return null;
                if (sp.IssuerId == null) return Guid.Empty;
                return await CaByCertificateAsync(sp.IssuerId.Value);
            }

            case CaTarget.RequestProfile:
            {
                var rp = await db.RequestProfiles.AsNoTracking().Where(p => p.Id == id).Select(p => new { p.CertificateAuthorityId }).FirstOrDefaultAsync();
                return rp == null ? null : rp.CertificateAuthorityId ?? Guid.Empty;
            }

            case CaTarget.Csr:
            {
                var csr = await db.CertificateRequests.AsNoTracking().Where(c => c.Id == id).Select(c => new { c.SigningProfileId }).FirstOrDefaultAsync();
                if (csr == null) return null;
                if (csr.SigningProfileId == null) return Guid.Empty;
                return await ResolveOneAsync(CaTarget.SigningProfile, csr.SigningProfileId.Value);
            }

            case CaTarget.Certificate:
            {
                var cert = await db.Certificates.AsNoTracking().Where(c => c.CertificateId == id)
                    .Select(c => new { c.SigningProfileId, c.IssuerCertificateId }).FirstOrDefaultAsync();
                if (cert == null) return null;
                return await CaOfCertificateAsync(cert.SigningProfileId, cert.IssuerCertificateId);
            }

            case CaTarget.SshCaKey:
            {
                var key = await db.SshCaKeys.AsNoTracking().Where(k => k.Id == id).Select(k => new { k.CertificateAuthorityId }).FirstOrDefaultAsync();
                return key?.CertificateAuthorityId;
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(target), target, "Not a single-id target");
        }
    }

    private async Task<CaTargetResolution> ResolveManyAsync(CaTarget target, object? value)
    {
        if (value is not IEnumerable items || value is string)
            return CaTargetResolution.None;

        var cas = new List<Guid>();
        var unscoped = false;
        var any = false;
        foreach (var item in items)
        {
            any = true;
            Guid? caId;
            switch (target)
            {
                case CaTarget.Serials:
                {
                    var serial = item?.ToString();
                    if (string.IsNullOrWhiteSpace(serial)) return CaTargetResolution.Missing;
                    var cert = await db.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
                    if (cert == null) return CaTargetResolution.Missing;
                    caId = await CaOfCertificateAsync(cert.SigningProfileId, cert.IssuerCertificateId);
                    break;
                }
                case CaTarget.Whitelists:
                {
                    var id = AsGuid(item);
                    if (id == null) return CaTargetResolution.Missing;
                    var w = await db.Whitelists.AsNoTracking().Where(x => x.Id == id).Select(x => new { x.CertificateAuthorityId }).FirstOrDefaultAsync();
                    if (w == null) return CaTargetResolution.Missing;
                    caId = w.CertificateAuthorityId ?? Guid.Empty;
                    break;
                }
                case CaTarget.CrlConfigurations:
                {
                    var id = AsGuid(item) ?? AsGuid(item?.GetType().GetProperty("Id")?.GetValue(item));
                    if (id == null) return CaTargetResolution.Missing;
                    var crl = await db.CrlConfigurations.AsNoTracking().Where(x => x.TaskId == id).Select(x => new { x.CaCertificateId }).FirstOrDefaultAsync();
                    if (crl == null) return CaTargetResolution.Missing;
                    caId = await CaByCertificateAsync(crl.CaCertificateId);
                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(target), target, "Not a list target");
            }

            if (caId == null) return CaTargetResolution.Missing;
            if (caId == Guid.Empty) unscoped = true;
            else if (!cas.Contains(caId.Value)) cas.Add(caId.Value);
        }

        if (!any)
            return CaTargetResolution.None;
        return new CaTargetResolution(cas, NotFound: false, Unscoped: unscoped);
    }

    /// <summary>The CA whose certificate this is, or null when no CA owns it.</summary>
    private async Task<Guid?> CaByCertificateAsync(Guid certificateId)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters()
            .Where(c => c.CertificateId == certificateId).Select(c => new { c.Id }).FirstOrDefaultAsync();
        return ca?.Id;
    }

    /// <summary>
    /// The CA that issued a certificate: through its signing profile, else through its issuer
    /// certificate. A certificate with neither (imported, or a root) belongs to no CA.
    /// </summary>
    private async Task<Guid?> CaOfCertificateAsync(Guid? signingProfileId, Guid? issuerCertificateId)
    {
        if (signingProfileId != null)
        {
            var viaProfile = await ResolveOneAsync(CaTarget.SigningProfile, signingProfileId.Value);
            if (viaProfile != null && viaProfile != Guid.Empty) return viaProfile;
        }
        if (issuerCertificateId != null)
        {
            var viaIssuer = await CaByCertificateAsync(issuerCertificateId.Value);
            if (viaIssuer != null) return viaIssuer;
        }
        return Guid.Empty;
    }

    private static Guid? AsGuid(object? value) => value switch
    {
        null => null,
        Guid g => g,
        string s when Guid.TryParse(s, out var g) => g,
        string => null,
        _ => null,
    };
}
