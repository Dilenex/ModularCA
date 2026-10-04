using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services;

/// <summary>
/// Names the CAs marked default when there is more than one. The 0.4.0 fold into one instance
/// can leave several, one from each former scope. A label-less request still
/// resolves to one CA (<see cref="CaResolverService.DefaultCandidates"/> breaks the tie by name),
/// but the operator should choose it. Making a CA the default clears the others, and is safe for
/// ACME clients: an existing account keeps using the CA it is bound to, and only new
/// registrations follow the default. Read-only.
/// </summary>
public static class DefaultCaCheck
{
    /// <summary>
    /// The startup warning naming the default CAs a label-less request could resolve to (enabled,
    /// X.509, no <c>system-</c> label) and the one in use, or null when at most one is default.
    /// It says that existing ACME accounts are unaffected by the choice.
    /// </summary>
    public static async Task<string?> WarningAsync(ModularCADbContext db, CancellationToken ct = default)
    {
        var defaults = await CaResolverService.DefaultCandidates(db.CertificateAuthorities.AsNoTracking())
            .Where(c => c.IsDefault)
            .Select(c => c.Label ?? c.Name)
            .ToListAsync(ct);
        if (defaults.Count < 2) return null;

        var used = await CaResolverService.DefaultCandidates(db.CertificateAuthorities.AsNoTracking())
            .Select(c => c.Label ?? c.Name)
            .FirstOrDefaultAsync(ct);
        return $"{defaults.Count} CAs are marked default: {string.Join(", ", defaults)}. Requests that name no CA "
            + $"(new ACME registrations and the label-less EST, SCEP, CMP and timestamp endpoints) go to {used ?? "none of them"}. "
            + "Existing ACME accounts keep using the CA they registered at, whichever CA is the default. "
            + "Make one CA the default in the console; that clears the others.";
    }
}
