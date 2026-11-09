using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Helpers;

/// <summary>The temporary account lockout shared by every sign-in path.</summary>
public static class AccountLockout
{
    /// <summary>
    /// Clears <paramref name="user"/>'s temporary lockout when it has run out at
    /// <paramref name="nowUtc"/>: the failure count goes back to zero and the lockout end is
    /// removed, in the database as well as on the entity. Returns whether it cleared one.
    /// <para>
    /// The database row is written at once, and only while its lockout is still the elapsed one, so
    /// a lockout another request has just set is not cleared. Clearing the entity alone was not
    /// enough: a wrong password then incremented the count still stored in the database, reloaded it
    /// at or past the threshold, and locked the account again on its first attempt.
    /// </para>
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="user">The account, as loaded by the caller.</param>
    /// <param name="nowUtc">The current instant.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<bool> ClearElapsedAsync(ModularCADbContext db, UserEntity user, DateTime nowUtc, CancellationToken ct = default)
    {
        if (user.LockoutEndUtc is not { } lockoutEnd || lockoutEnd > nowUtc)
            return false;

        if (db.Database.IsRelational())
            await db.Users
                .Where(u => u.Id == user.Id && u.LockoutEndUtc != null && u.LockoutEndUtc <= nowUtc)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(u => u.FailedLoginAttempts, 0)
                    .SetProperty(u => u.LockoutEndUtc, (DateTime?)null), ct);
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;
        return true;
    }
}
