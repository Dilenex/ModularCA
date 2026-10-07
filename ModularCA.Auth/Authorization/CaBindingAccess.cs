using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Whether a caller may bind a profile, template or key to a CA named in the request body. The
/// route-driven policy handler checks the row's current CA, never the one the body moves it to,
/// so every create or rebind that takes a CA from the body asks this as well.
/// </summary>
public static class CaBindingAccess
{
    /// <summary>The answer of <see cref="CheckAsync"/>.</summary>
    public enum Verdict
    {
        /// <summary>The binding is allowed.</summary>
        Allowed,
        /// <summary>The CA does not exist or is outside the caller's fence.</summary>
        NotFound,
        /// <summary>The caller lacks the capability on the CA, or across the scope for no CA.</summary>
        Forbidden,
        /// <summary>The CA belongs to another scope than the row it would be bound to.</summary>
        ScopeMismatch,
    }

    /// <summary>
    /// Checks binding a row of <paramref name="ownerSpaceId"/> (null for the instance) to
    /// <paramref name="caId"/>: the CA must exist inside <paramref name="fence"/>, the user must
    /// hold <paramref name="capability"/> on it, and it must belong to the row's own scope. With
    /// no CA, the row is unbound, which needs <paramref name="capability"/> across the scope it
    /// keeps once unbound: a row with a space of its own stays in it, but a row whose only scope
    /// is its CA becomes instance-wide, so its caller must pass null for
    /// <paramref name="ownerSpaceId"/> and the check needs system scope.
    /// </summary>
    public static async Task<Verdict> CheckAsync(ICaGroupAuthorizationService auth, ModularCADbContext db, SpaceFence fence,
        Guid userId, Guid? caId, Guid? ownerSpaceId, string capability)
    {
        if (caId is not Guid id)
            return await auth.HasScopeCapabilityAsync(userId, ownerSpaceId, capability) ? Verdict.Allowed : Verdict.Forbidden;

        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == id)
            .Select(c => new { c.SpaceId })
            .FirstOrDefaultAsync();
        if (ca == null || !fence.Allows(ca.SpaceId))
            return Verdict.NotFound;
        if (!await auth.HasCaCapabilityAsync(userId, id, capability))
            return Verdict.Forbidden;
        return ca.SpaceId == ownerSpaceId ? Verdict.Allowed : Verdict.ScopeMismatch;
    }

    /// <summary>
    /// The response for a refused <paramref name="verdict"/>: 404, 403 or 400; null when allowed.
    /// </summary>
    public static IActionResult? ToResult(Verdict verdict) => verdict switch
    {
        Verdict.Allowed => null,
        Verdict.NotFound => new NotFoundObjectResult(new { error = "CA not found" }),
        Verdict.Forbidden => new ObjectResult(new { error = "You lack the capability on the target CA." }) { StatusCode = 403 },
        _ => new BadRequestObjectResult(new { error = "The target CA belongs to another scope than the row being bound to it." }),
    };
}
