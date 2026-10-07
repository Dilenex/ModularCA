using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--unlock-user &lt;username&gt;</c>: the recovery for an account no one left can unlock, such as
/// the only system-super hard-locked under <c>LockoutMinutes = 0</c>. Runs on the host as the
/// service user with the application credentials in db.yaml, never over HTTP, so it grants nothing
/// that reading db.yaml does not. Clears the lock, any temporary lockout and the failed-login
/// count, and rotates the security stamp. It does not re-enable a disabled account or touch
/// passwords or MFA. Each unlock is written to the hash-chained audit trail as
/// <see cref="AuditActionType.UserUnlockedOnHost"/> by <see cref="Actor"/>.
/// </summary>
public static class UnlockUserCommand
{
    /// <summary>The flag, followed by the username.</summary>
    public const string Flag = "--unlock-user";

    /// <summary>The actor the audit record names.</summary>
    public const string Actor = "host:break-glass";

    /// <summary>
    /// Unlocks <paramref name="username"/> and records it in <paramref name="auditDb"/>. When the
    /// audit database is null or cannot be written, the account is still unlocked and a loud warning
    /// says no audit record was written. Returns the process exit code: 0 on success, 1 when the
    /// account does not exist.
    /// </summary>
    public static async Task<int> RunAsync(ModularCADbContext db, AuditDbContext? auditDb, string username, TextWriter output)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            output.WriteLine($"No account named '{username}'.");
            return 1;
        }
        user.IsLocked = false;
        user.LockoutEndUtc = null;
        user.FailedLoginAttempts = 0;
        user.SecurityStamp = Guid.NewGuid().ToString();
        await db.SaveChangesAsync();
        output.WriteLine($"Unlocked '{user.Username}'.{(user.IsActive ? "" : " The account is still disabled.")}");

        try
        {
            if (auditDb == null) throw new InvalidOperationException("db.yaml configures no audit database");
            await new AuditHashChainService().AppendAsync(auditDb, new AuditLogEntity
            {
                ActionType = AuditActionType.UserUnlockedOnHost,
                ActorUsername = Actor,
                TargetEntityType = "User",
                TargetEntityId = user.Id.ToString(),
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(new
                {
                    user.Username,
                    StillDisabled = !user.IsActive,
                    Host = Environment.MachineName,
                    OsUser = Environment.UserName,
                }),
            });
            output.WriteLine("Recorded in the audit trail.");
        }
        catch (Exception ex)
        {
            output.WriteLine("****************************************************************");
            output.WriteLine($"WARNING: NO AUDIT RECORD WAS WRITTEN FOR THIS UNLOCK ({ex.GetType().Name}: {ex.Message}).");
            output.WriteLine("The account is unlocked. Record by hand who ran this, when and why.");
            output.WriteLine("****************************************************************");
        }
        return 0;
    }
}
