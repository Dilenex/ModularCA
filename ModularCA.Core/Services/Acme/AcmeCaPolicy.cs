using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Which CAs serve ACME, and which CA an account's records belong to. The directory, new-account
/// and new-order ask the same question, so a CA whose directory is refused cannot be reached by
/// posting to its endpoints directly.
/// </summary>
public static class AcmeCaPolicy
{
    /// <summary>The label prefix reserved for the CAs bootstrap creates, which never serve enrollment.</summary>
    public const string SystemLabelPrefix = "system-";

    /// <summary>
    /// Why <paramref name="ca"/> does not serve ACME, or null when it does. Refused: a disabled or
    /// deleted CA, an SSH CA, a CA with a reserved <c>system-</c> label, and a CA without an
    /// enabled ACME configuration (a missing row counts as not enabled).
    /// </summary>
    public static async Task<string?> RefusalAsync(ModularCADbContext db, CertificateAuthorityEntity ca, CancellationToken ct = default)
    {
        var name = ca.Label ?? ca.Name;
        if (!ca.IsEnabled || ca.IsDeleted)
            return $"CA '{name}' is disabled.";
        if (ca.IsSshCa)
            return $"CA '{name}' is an SSH CA and does not serve ACME.";
        if (ca.Label != null && ca.Label.StartsWith(SystemLabelPrefix, StringComparison.OrdinalIgnoreCase))
            return $"CA '{name}' is reserved for the system and does not serve ACME.";

        var enabled = await db.CaProtocolConfigs.AsNoTracking()
            .Where(c => c.CaId == ca.Id && c.Protocol == "ACME")
            .Select(c => (bool?)c.IsEnabled)
            .FirstOrDefaultAsync(ct);
        return enabled == true ? null : $"ACME is not enabled for CA '{name}'.";
    }

    /// <summary>
    /// The path, after the public base URL, under which the resources of an order placed at the
    /// CA labelled <paramref name="caLabel"/> are served: <c>/acme/{label}</c>, or the label-less
    /// <c>/api/v1/acme</c> for a CA without a label. Either addresses the CA the account is bound
    /// to, so the URLs stay valid when the default CA changes.
    /// </summary>
    public static string PathPrefix(string? caLabel)
        => string.IsNullOrWhiteSpace(caLabel) ? "/api/v1/acme" : $"/acme/{caLabel}";

    /// <summary>
    /// The CA ACME account <paramref name="accountId"/> is bound to, whatever its state (a deleted
    /// CA included), for stamping the account's audit records; null when the account is unbound.
    /// </summary>
    public static async Task<CertificateAuthorityEntity?> BoundCaAsync(ModularCADbContext db, Guid accountId, CancellationToken ct = default)
    {
        var caId = await db.AcmeAccounts.AsNoTracking()
            .Where(a => a.Id == accountId)
            .Select(a => a.CertificateAuthorityId)
            .FirstOrDefaultAsync(ct);
        if (caId == null)
            return null;
        return await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == caId, ct);
    }
}
