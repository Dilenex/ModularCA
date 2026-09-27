using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Services;

/// <summary>
/// The write half of refresh-token rotation: revoking the presented token and inserting its
/// successor as one atomic step, so two requests carrying the same token cannot both rotate it.
/// </summary>
public static class RefreshTokenRotation
{
    /// <summary>
    /// Revokes the presented token with a conditional UPDATE that only matches while it is still
    /// live, and inserts <paramref name="successor"/> in the same transaction. When the UPDATE
    /// matches nothing, another request already rotated or revoked the token: that is reuse, so the
    /// whole family is revoked, nothing is inserted, and false is returned.
    /// </summary>
    /// <param name="db">The context to write through.</param>
    /// <param name="presentedId">Id of the refresh token the client presented.</param>
    /// <param name="familyId">The presented token's family, revoked on reuse.</param>
    /// <param name="successor">The rotated token to insert; its <c>Token</c> hash is recorded as the replacement.</param>
    /// <param name="now">The revocation instant.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True when this call rotated the token; false on reuse.</returns>
    public static async Task<bool> RotateAsync(
        ModularCADbContext db, Guid presentedId, Guid? familyId, RefreshTokenEntity successor, DateTime now,
        CancellationToken ct = default)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var replacedBy = successor.Token;
        var claimed = await db.RefreshTokens
            .Where(t => t.Id == presentedId && !t.IsRevoked)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.IsRevoked, true)
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.ReplacedByToken, replacedBy), ct);

        if (claimed == 0)
        {
            if (familyId is Guid family)
                await db.RefreshTokens
                    .Where(t => t.FamilyId == family && !t.IsRevoked)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(t => t.IsRevoked, true)
                        .SetProperty(t => t.RevokedAt, now), ct);
            await tx.CommitAsync(ct);
            return false;
        }

        db.RefreshTokens.Add(successor);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return true;
    }
}
