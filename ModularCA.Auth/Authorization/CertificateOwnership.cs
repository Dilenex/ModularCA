using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Which certificates are an account's own, as opposed to the certificates its roles let it view.
/// An operator or administrator of a CA may view every certificate of that CA; its own are the few
/// it asked for or was given.
/// </summary>
public static class CertificateOwnership
{
    /// <summary>
    /// The ids of the certificates that are <paramref name="userId"/>'s own: those issued from a
    /// certificate request the account made, and those a certificate access entry names the
    /// account on. This narrows a list; it grants nothing, and a caller still applies the view
    /// check to what it returns.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="userId">The account.</param>
    public static async Task<HashSet<Guid>> OwnedByAsync(ModularCADbContext db, Guid userId)
    {
        var own = new HashSet<Guid>(await db.CertificateRequests.AsNoTracking()
            .Where(r => r.RequestorUserId == userId && r.IssuedCertificateId != null)
            .Select(r => r.IssuedCertificateId!.Value)
            .ToListAsync());
        own.UnionWith(await db.CertificateAccessLists.AsNoTracking()
            .Where(a => a.UserId == userId)
            .Select(a => a.CertificateId)
            .ToListAsync());
        return own;
    }
}
