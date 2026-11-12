using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// The OID catalog's key usage and extended key usage rows, read once, and the check every
/// writer of a certificate profile runs against them (<see cref="CertProfileUsageValidation"/>):
/// <see cref="CertProfileService"/> on create and update, which refuses with
/// <c>MCA-PRF-002</c>, and <see cref="PolicySyncService"/> for the profiles a policy file
/// creates or updates, which skips the profile and reports the same message in its result.
/// </summary>
internal sealed class CertProfileUsageCatalog
{
    private readonly List<(string? Oid, string? FriendlyName)> _standard;
    private readonly List<(string? Oid, string? FriendlyName)> _extended;

    private CertProfileUsageCatalog(
        List<(string? Oid, string? FriendlyName)> standard, List<(string? Oid, string? FriendlyName)> extended)
    {
        _standard = standard;
        _extended = extended;
    }

    /// <summary>Reads the catalog's Standard and Extended rows from <paramref name="db"/>.</summary>
    public static async Task<CertProfileUsageCatalog> LoadAsync(ModularCADbContext db)
    {
        var rows = await db.OIDOptions.AsNoTracking()
            .Where(o => o.KeyUsage == "Standard" || o.KeyUsage == "Extended")
            .Select(o => new { o.OID, o.FriendlyName, o.KeyUsage })
            .ToListAsync();
        List<(string? Oid, string? FriendlyName)> Of(string kind)
            => rows.Where(o => o.KeyUsage == kind).Select(o => ((string?)o.OID, (string?)o.FriendlyName)).ToList();
        return new CertProfileUsageCatalog(Of("Standard"), Of("Extended"));
    }

    /// <summary>
    /// True when the fields hold no entry that needs the catalog: every entry is one the profile
    /// already stores (<paramref name="storedKeyUsages"/>, <paramref name="storedExtendedKeyUsages"/>),
    /// or there is none. Lets a caller skip the catalog read for a save that adds no usage.
    /// </summary>
    public static bool NothingToResolve(
        string? keyUsages, string? extendedKeyUsages, string? storedKeyUsages, string? storedExtendedKeyUsages)
        => CertProfileUsageValidation.CheckKeyUsages(keyUsages, [], storedKeyUsages).IsValid
            && CertProfileUsageValidation.CheckExtendedKeyUsages(extendedKeyUsages, [], storedExtendedKeyUsages).IsValid;

    /// <summary>
    /// What is wrong with a profile's usages, or null: a key usage or an extended key usage the
    /// catalog cannot resolve, by friendly name or OID in any spelling issuance resolves, or
    /// <c>anyExtendedKeyUsage</c>. The fields are read as a JSON array or a comma-separated list.
    /// Entries the profile already stores are not checked again, so a profile written before this
    /// check can still be changed; pass null for both on a create.
    /// </summary>
    /// <param name="keyUsages">The key usages being written.</param>
    /// <param name="extendedKeyUsages">The extended key usages being written.</param>
    /// <param name="storedKeyUsages">The key usages the profile stores now, or null on a create.</param>
    /// <param name="storedExtendedKeyUsages">The extended key usages the profile stores now, or null on a create.</param>
    public string? Problem(
        string? keyUsages, string? extendedKeyUsages, string? storedKeyUsages, string? storedExtendedKeyUsages)
    {
        var problems = new List<string>();
        var standard = CertProfileUsageValidation.CheckKeyUsages(keyUsages, _standard, storedKeyUsages);
        if (!standard.IsValid)
            problems.Add(CertProfileUsageValidation.DescribeFailure("KeyUsages", standard));
        var extended = CertProfileUsageValidation.CheckExtendedKeyUsages(extendedKeyUsages, _extended, storedExtendedKeyUsages);
        if (!extended.IsValid)
            problems.Add(CertProfileUsageValidation.DescribeFailure("ExtendedKeyUsages", extended));
        return problems.Count == 0 ? null : string.Join(" ", problems);
    }
}
