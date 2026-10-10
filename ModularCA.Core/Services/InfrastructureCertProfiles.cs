using Microsoft.EntityFrameworkCore;
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
    /// Why <paramref name="profile"/> cannot be the profile of <paramref name="role"/>, or null
    /// when it can: a CA profile issues no end-entity certificate, and a profile that does not
    /// list the usage the role exists for yields a certificate that cannot do its job. Issuance
    /// emits what the profile itself lists, so the profile's own lists are read, not inherited ones.
    /// </summary>
    public static string? WhyUnsuitable(CertProfileEntity profile, InfrastructureCertRole role)
    {
        if (profile.IsCaProfile)
            return $"The certificate profile '{profile.Name}' is a CA profile; a {role.CertType} certificate needs an end-entity profile.";
        if (role.RequiredEkuOid != null)
        {
            if (!ListsExtendedKeyUsage(profile.ExtendedKeyUsages, role.RequiredEkuOid, role.RequiredEkuName!))
                return $"The certificate profile '{profile.Name}' does not list {role.RequiredUsageWords} ({role.RequiredEkuOid}) among its "
                     + "extended key usages, so a certificate issued from it would not work. Add the usage to that certificate profile and try again.";
            return null;
        }
        if (!ListsDigitalSignature(profile.KeyUsages))
            return $"The certificate profile '{profile.Name}' does not list the digitalSignature key usage, so no CMP client would "
                 + "accept a certificate issued from it as a message signer. Add the usage to that certificate profile and try again.";
        return null;
    }

    /// <summary>
    /// Why <paramref name="ca"/> cannot name <paramref name="profile"/> for <paramref name="role"/>,
    /// or null when it can: <see cref="WhyUnsuitable"/>, and the profile must be one the CA may
    /// issue under (<see cref="CertProfileScope"/>).
    /// </summary>
    public static string? WhyNotChoosable(CertProfileEntity profile, InfrastructureCertRole role, CertificateAuthorityEntity ca)
        => !CertProfileScope.Admits(profile, ca)
            ? $"The certificate profile '{profile.Name}' belongs to another scope than this CA. Use a profile of the CA's own space, one bound to this CA, or an instance-wide profile."
            : WhyUnsuitable(profile, role);

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
