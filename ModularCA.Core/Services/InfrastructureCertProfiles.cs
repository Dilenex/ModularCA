using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Models;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>One of the certificates a CA issues to itself: what it is called, which profile it defaults to and what that profile must list.</summary>
/// <param name="Key">The name the API and the console use for it.</param>
/// <param name="CertType">The words appended to the CA's common name in the certificate's subject.</param>
/// <param name="DefaultProfileName">The seeded profile used when the CA names none.</param>
/// <param name="RequiredEkuOid">The extended key usage the profile must list, or null when it needs digitalSignature only.</param>
/// <param name="RequiredEkuName">That usage's catalog name, as the console stores it.</param>
/// <param name="RequiredUsageWords">What to call the required usage in a refusal.</param>
public sealed record InfrastructureCertRole(
    string Key, string CertType, string DefaultProfileName,
    string? RequiredEkuOid, string? RequiredEkuName, string RequiredUsageWords);

/// <summary>
/// Which certificate profile a CA's timestamp signer, OCSP responder and CMP signer are issued
/// under: the profile the CA names, or the seeded default when it names none.
/// </summary>
public static class InfrastructureCertProfiles
{
    /// <summary>The timestamp signer.</summary>
    public static readonly InfrastructureCertRole Tsa = new(
        "tsa", "TSA", SystemCertProfiles.Tsa, "1.3.6.1.5.5.7.3.8", "timeStamping", "time stamping");

    /// <summary>The delegated OCSP responder.</summary>
    public static readonly InfrastructureCertRole OcspResponder = new(
        "ocspResponder", "OCSP Responder", SystemCertProfiles.OcspResponder, "1.3.6.1.5.5.7.3.9", "OCSPSigning", "OCSP signing");

    /// <summary>The CMP message signer.</summary>
    public static readonly InfrastructureCertRole CmpSigner = new(
        "cmpSigner", "CMP Signer", SystemCertProfiles.CmpSigner, null, null, "the digitalSignature key usage");

    /// <summary>Every role, in the order the console lists them.</summary>
    public static readonly IReadOnlyList<InfrastructureCertRole> All = [OcspResponder, Tsa, CmpSigner];

    /// <summary>The profile <paramref name="ca"/> names for <paramref name="role"/>, or null for the default.</summary>
    public static Guid? ChosenId(CertificateAuthorityEntity ca, InfrastructureCertRole role)
        => role == Tsa ? ca.TsaCertProfileId
         : role == OcspResponder ? ca.OcspResponderCertProfileId
         : ca.CmpSignerCertProfileId;

    /// <summary>Names <paramref name="profileId"/> (null for the default) as the profile of <paramref name="role"/> on <paramref name="ca"/>.</summary>
    public static void Choose(CertificateAuthorityEntity ca, InfrastructureCertRole role, Guid? profileId)
    {
        if (role == Tsa) ca.TsaCertProfileId = profileId;
        else if (role == OcspResponder) ca.OcspResponderCertProfileId = profileId;
        else ca.CmpSignerCertProfileId = profileId;
    }

    /// <summary>
    /// The profile <paramref name="role"/> is issued under: the one named by
    /// <paramref name="chosenProfileId"/>, or the seeded default when that is null. Null when
    /// the profile does not exist.
    /// </summary>
    public static Task<CertProfileEntity?> ResolveAsync(
        ModularCADbContext db, Guid? chosenProfileId, InfrastructureCertRole role, CancellationToken ct = default)
        => chosenProfileId is Guid id
            ? db.CertProfiles.FirstOrDefaultAsync(cp => cp.Id == id, ct)
            : db.CertProfiles.FirstOrDefaultAsync(cp => cp.Name == role.DefaultProfileName, ct);

    /// <summary>
    /// The profile issuance works from: <paramref name="profile"/> merged with
    /// <paramref name="parent"/> when it inherits from it, as itself otherwise.
    /// </summary>
    /// <param name="profile">The certificate profile.</param>
    /// <param name="parent">The profile it inherits from, or null (<see cref="ParentOfAsync"/>).</param>
    /// <param name="db">The database whose usage catalog the merge compares usages through, as issuance does; null compares them by spelling.</param>
    public static EffectiveCertProfile Effective(CertProfileEntity profile, CertProfileEntity? parent, ModularCADbContext? db = null)
        => (db == null
                ? ProfileResolutionService.ForLoadedRows(NullLogger<ProfileResolutionService>.Instance)
                : new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance))
            .ResolveLoaded(profile, parent);

    /// <summary>The profile <paramref name="profile"/> inherits from, or null when it inherits from none.</summary>
    public static async Task<CertProfileEntity?> ParentOfAsync(ModularCADbContext db, CertProfileEntity profile, CancellationToken ct = default)
        => profile.InheritanceEnabled && profile.InheritsFromId is Guid parentId
            ? await db.CertProfiles.AsNoTracking().FirstOrDefaultAsync(cp => cp.Id == parentId, ct)
            : null;

    /// <summary>
    /// Why <paramref name="profile"/> cannot be the profile of <paramref name="role"/>, or null
    /// when it can: a CA profile issues no end-entity certificate, and a profile that does not
    /// list the usage the role exists for yields a certificate that cannot do its job. Issuance
    /// works from the profile after inheritance, so the usages are read from that
    /// (<see cref="Effective"/>), with <paramref name="parent"/> the profile it inherits from.
    /// </summary>
    /// <param name="profile">The certificate profile.</param>
    /// <param name="role">The certificate it would issue.</param>
    /// <param name="parent">The profile <paramref name="profile"/> inherits from, or null when it inherits from none.</param>
    /// <param name="db">The database, for the usage catalog (<see cref="Effective"/>).</param>
    public static string? WhyUnsuitable(CertProfileEntity profile, InfrastructureCertRole role, CertProfileEntity? parent = null, ModularCADbContext? db = null)
    {
        if (profile.IsCaProfile)
            return $"The certificate profile '{profile.Name}' is a CA profile; a {role.CertType} certificate needs an end-entity profile.";
        var effective = Effective(profile, parent, db);
        if (role.RequiredEkuOid != null)
        {
            if (!ListsExtendedKeyUsage(effective.ExtendedKeyUsages, role.RequiredEkuOid, role.RequiredEkuName!))
                return $"The certificate profile '{profile.Name}' does not list {role.RequiredUsageWords} ({role.RequiredEkuOid}) among its "
                     + "extended key usages, so a certificate issued from it would not work. Add the usage to that certificate profile and try again.";
            return null;
        }
        if (!ListsDigitalSignature(effective.KeyUsages))
            return $"The certificate profile '{profile.Name}' does not list the digitalSignature key usage, so no CMP client would "
                 + "accept a certificate issued from it as a message signer. Add the usage to that certificate profile and try again.";
        return null;
    }

    /// <summary>
    /// Why <paramref name="ca"/> cannot name <paramref name="profile"/> for <paramref name="role"/>,
    /// or null when it can: <see cref="WhyUnsuitable"/>, and the profile must be one the CA may
    /// issue under (<see cref="CertProfileScope"/>).
    /// </summary>
    /// <param name="profile">The certificate profile.</param>
    /// <param name="role">The certificate it would issue.</param>
    /// <param name="ca">The CA that would name it.</param>
    /// <param name="parent">The profile <paramref name="profile"/> inherits from, or null when it inherits from none.</param>
    /// <param name="db">The database, for the usage catalog (<see cref="Effective"/>).</param>
    public static string? WhyNotChoosable(CertProfileEntity profile, InfrastructureCertRole role, CertificateAuthorityEntity ca, CertProfileEntity? parent = null, ModularCADbContext? db = null)
        => !CertProfileScope.Admits(profile, ca)
            ? $"The certificate profile '{profile.Name}' belongs to another scope than this CA. Use a profile of the CA's own space, one bound to this CA, or an instance-wide profile."
            : WhyUnsuitable(profile, role, parent, db);

    /// <summary>
    /// The CAs that name <paramref name="profileId"/> for one of their own certificates, with the
    /// role each names it for. Soft-deleted CAs are included: their rows still hold the reference.
    /// </summary>
    public static async Task<List<(Guid CaId, string CaName, InfrastructureCertRole Role)>> UsesAsync(
        ModularCADbContext db, Guid profileId, CancellationToken ct = default)
    {
        var cas = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.TsaCertProfileId == profileId || ca.OcspResponderCertProfileId == profileId || ca.CmpSignerCertProfileId == profileId)
            .OrderBy(ca => ca.Name)
            .ToListAsync(ct);
        return cas.SelectMany(ca => All.Where(role => ChosenId(ca, role) == profileId).Select(role => (ca.Id, ca.Name, role))).ToList();
    }

    /// <summary>
    /// Why changing <paramref name="profile"/> to <paramref name="changed"/> would leave a CA unable
    /// to issue one of its own certificates, or null when it would not: a profile a CA issues its
    /// timestamp signer, OCSP responder or CMP signer from (by name as the default, or because the
    /// CA names it) must keep the usage that certificate exists for after inheritance, and so must
    /// every such profile that inherits from it.
    /// </summary>
    /// <param name="db">The database.</param>
    /// <param name="profile">The profile as stored.</param>
    /// <param name="changed">The profile as it would be: its kind, usages and inheritance.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<string?> WhyUsagesWouldBeLostAsync(
        ModularCADbContext db, CertProfileEntity profile, CertProfileEntity changed, CancellationToken ct = default)
    {
        var uses = await UsesAsync(db, profile.Id, ct);
        var changedParent = await ParentOfAsync(db, changed, ct);
        foreach (var role in RolesOf(profile.Name, uses))
        {
            if (WhyUnsuitable(changed, role, changedParent, db) is string reason)
                return $"{reason} {WhoIssues(role, uses)}";
        }

        var children = await db.CertProfiles.AsNoTracking()
            .Where(c => c.InheritanceEnabled && c.InheritsFromId == profile.Id)
            .ToListAsync(ct);
        foreach (var child in children)
        {
            var childUses = await UsesAsync(db, child.Id, ct);
            foreach (var role in RolesOf(child.Name, childUses))
            {
                if (WhyUnsuitable(child, role, changed, db) is string reason)
                    return $"{reason} It inherits its usages from '{profile.Name}', and this change would leave it without them. {WhoIssues(role, childUses)}";
            }
        }
        return null;
    }

    /// <summary>The certificates a profile named <paramref name="name"/> issues for CAs: the ones CAs name it for, and the one it is the default of.</summary>
    private static List<InfrastructureCertRole> RolesOf(string name, List<(Guid CaId, string CaName, InfrastructureCertRole Role)> uses)
        => uses.Select(u => u.Role)
            .Concat(All.Where(r => string.Equals(r.DefaultProfileName, name, StringComparison.OrdinalIgnoreCase)))
            .Distinct()
            .ToList();

    /// <summary>Which CAs issue <paramref name="role"/>'s certificate from the profile, for a refusal.</summary>
    private static string WhoIssues(InfrastructureCertRole role, List<(Guid CaId, string CaName, InfrastructureCertRole Role)> uses)
    {
        var users = uses.Where(u => u.Role == role).Select(u => u.CaName).ToList();
        return users.Count > 0
            ? $"{string.Join(", ", users)} " + (users.Count == 1 ? "issues its" : "issue their") + $" {role.CertType} certificate from it."
            : $"Every CA that names no other profile issues its {role.CertType} certificate from it.";
    }

    /// <summary>Whether the stored extended key usage list <paramref name="storedJson"/> names the usage, by OID or by catalog name.</summary>
    internal static bool ListsExtendedKeyUsage(string? storedJson, string oid, string friendly)
    {
        List<string> listed;
        try
        {
            listed = JsonSerializer.Deserialize<List<string>>(
                string.IsNullOrWhiteSpace(storedJson) ? "[]" : storedJson, SafeJsonOptions.Default) ?? [];
        }
        catch (JsonException)
        {
            return false;
        }
        return listed.Any(r => r != null
            && (string.Equals(r.Trim(), oid, StringComparison.Ordinal)
                || UsageCatalogResolver.Canonicalize(r) == UsageCatalogResolver.Canonicalize(oid)
                || UsageCatalogResolver.Canonicalize(r) == UsageCatalogResolver.Canonicalize(friendly)));
    }

    /// <summary>Whether the stored key usage list <paramref name="stored"/> includes digitalSignature; an unreadable list does not.</summary>
    internal static bool ListsDigitalSignature(string? stored)
    {
        try
        {
            return (X509KeyUsageUtil.ParseKeyUsages(stored ?? string.Empty) & KeyUsage.DigitalSignature) != 0;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
