using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Errors;

namespace ModularCA.Core.Services;

/// <summary>
/// The rules every path that names a CA applies: a label matches
/// <c>^[a-z0-9][a-z0-9-]{0,62}$</c>, carries no reserved prefix unless the caller is bootstrap,
/// and a label (compared case-insensitively) or name is unique across the instance, soft-deleted
/// CAs included, because a label is the path of the CRL, OCSP, AIA and enrolment URLs of every
/// certificate its CA issued. A label may change only while nothing references it
/// (<see cref="EnsureLabelChangeableAsync"/>), so a label that was used is never freed for reuse.
/// </summary>
public static class CaLabelRules
{
    private static readonly System.Text.RegularExpressions.Regex Pattern =
        new(@"^[a-z0-9][a-z0-9-]{0,62}$", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Prefixes kept for the CAs and groups bootstrap creates: <c>space-</c> names a space's
    /// groups from 0.4.0, and <c>org-</c> named them before.
    /// </summary>
    public static readonly string[] ReservedPrefixes = ["system-", "space-", "org-"];

    /// <summary>
    /// Throws <see cref="ArgumentException"/> when <paramref name="label"/> does not match the
    /// label pattern, or, unless <paramref name="allowReserved"/>, starts with a reserved prefix.
    /// </summary>
    public static void Validate(string? label, bool allowReserved = false, string paramName = "label")
    {
        if (string.IsNullOrEmpty(label) || !Pattern.IsMatch(label))
            throw new ArgumentException(
                $"Invalid CA label '{label}'. Labels must match ^[a-z0-9][a-z0-9-]{{0,62}}$.", paramName);
        if (!allowReserved && ReservedPrefixes.Any(p => label.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException(
                $"CA label '{label}' uses a reserved prefix (system- / space- / org-). Choose a different label.", paramName);
    }

    /// <summary>
    /// Throws <see cref="ResourceConflictException"/> when another CA than
    /// <paramref name="exceptCaId"/>, soft-deleted ones included, already has
    /// <paramref name="label"/> (ignoring case) or <paramref name="name"/>. Either may be null to skip it.
    /// </summary>
    public static async Task EnsureUniqueAsync(ModularCADbContext db, string? label, string? name, Guid? exceptCaId = null)
    {
        if (label != null)
        {
            var lowered = label.ToLowerInvariant();
            if (await db.CertificateAuthorities.IgnoreQueryFilters()
                    .AnyAsync(c => c.Id != exceptCaId && c.Label != null && c.Label.ToLower() == lowered))
                throw new ResourceConflictException(
                    $"A CA with label '{label}' already exists in this instance, or did and was deleted. Labels are never reused.",
                    ErrorCodes.NameAlreadyTaken);
        }
        if (name != null
            && await db.CertificateAuthorities.IgnoreQueryFilters().AnyAsync(c => c.Id != exceptCaId && c.Name == name))
            throw new ResourceConflictException(
                $"A CA named '{name}' already exists in this instance, or did and was deleted.", ErrorCodes.NameAlreadyTaken);
    }

    /// <summary>
    /// What references CA <paramref name="caId"/> or its current <paramref name="label"/> (compared
    /// ignoring case): issued certificates (<see cref="Helpers.IssuerChainResolver.HasIssuedAsync"/>),
    /// ACME accounts bound to the CA or registered under the label, ACME orders placed under the
    /// label or by such an account, and protocol audit records (EST, SCEP, CMP, MSAE, ACME) naming
    /// the label, read from <paramref name="auditDb"/> when one is configured. Empty when nothing does.
    /// </summary>
    public static async Task<IReadOnlyList<string>> LabelReferencesAsync(
        ModularCADbContext db, AuditDbContext? auditDb, Guid caId, string? label, CancellationToken ct = default)
    {
        var references = new List<string>();
        if (await Helpers.IssuerChainResolver.HasIssuedAsync(db, caId))
            references.Add("issued certificates");

        var lowered = label?.ToLowerInvariant();
        if (await db.AcmeAccounts.AsNoTracking().AnyAsync(a => a.CertificateAuthorityId == caId
                || (lowered != null && a.CaLabel != null && a.CaLabel.ToLower() == lowered), ct))
            references.Add("ACME accounts");
        if (await db.AcmeOrders.AsNoTracking().AnyAsync(o => (lowered != null && o.CaLabel != null && o.CaLabel.ToLower() == lowered)
                || db.AcmeAccounts.Any(a => a.Id == o.AccountId && a.CertificateAuthorityId == caId), ct))
            references.Add("ACME orders");

        if (auditDb != null && lowered != null)
        {
            var audited = new List<string>();
            if (await auditDb.AuditEst.AsNoTracking().AnyAsync(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered, ct)) audited.Add("EST");
            if (await auditDb.AuditScep.AsNoTracking().AnyAsync(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered, ct)) audited.Add("SCEP");
            if (await auditDb.AuditCmp.AsNoTracking().AnyAsync(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered, ct)) audited.Add("CMP");
            if (await auditDb.AuditMsae.AsNoTracking().AnyAsync(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered, ct)) audited.Add("MSAE");
            if (await auditDb.AuditAcme.AsNoTracking().AnyAsync(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered, ct)) audited.Add("ACME");
            if (audited.Count > 0)
                references.Add($"protocol audit records ({string.Join(", ", audited)})");
        }
        return references;
    }

    /// <summary>
    /// Throws <see cref="ResourceConflictException"/> (<see cref="ErrorCodes.CaLabelLocked"/>) naming
    /// what references the label when CA <paramref name="caId"/>'s <paramref name="label"/> may no
    /// longer change: a label may change only while nothing references it
    /// (<see cref="LabelReferencesAsync"/>), and is fixed for good after that, so a label once
    /// used is never freed for another CA.
    /// </summary>
    public static async Task EnsureLabelChangeableAsync(
        ModularCADbContext db, AuditDbContext? auditDb, Guid caId, string? label, CancellationToken ct = default)
    {
        var references = await LabelReferencesAsync(db, auditDb, caId, label, ct);
        if (references.Count == 0)
            return;
        throw new ResourceConflictException(
            $"The label '{label}' cannot be changed because {string.Join(", ", references)} name this CA by it. A label is fixed "
            + "once anything references it: it is in the CRL, OCSP and AIA URLs of the certificates the CA issued, in the "
            + "account URLs ACME clients keep, and in the audit trail. Its name can be changed.",
            ErrorCodes.CaLabelLocked);
    }

    /// <summary>
    /// Whether <paramref name="ex"/> is a unique violation on <c>CertificateAuthorities</c>: a
    /// label or name another request took between <see cref="EnsureUniqueAsync"/> and the save.
    /// </summary>
    public static bool IsNameRace(DbUpdateException ex)
    {
        for (var inner = ex.InnerException; inner != null; inner = inner.InnerException)
            if (inner is Npgsql.PostgresException pg && pg.SqlState == PostgresErrorUtil.UniqueViolation
                && pg.TableName == "CertificateAuthorities")
                return true;
        return false;
    }

    /// <summary>The conflict a lost <see cref="IsNameRace"/> is reported as (409).</summary>
    public static ResourceConflictException NameRaceConflict(string? label, string? name) => new(
        $"Another CA took the label '{label}' or the name '{name}' while this one was being saved. Labels and names are unique across the instance.",
        ErrorCodes.NameAlreadyTaken);
}
