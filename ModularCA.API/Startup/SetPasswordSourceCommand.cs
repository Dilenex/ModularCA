using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--set-password-source &lt;username&gt; &lt;Inherit|Local|Directory&gt;</c>: sets an account's
/// password source on the host, for the case the console cannot cover because nobody may change
/// their own source: the only administrator of an install making their account Local, so it signs
/// in through an LDAP outage. Like <see cref="UnlockUserCommand"/> it runs on the host as the
/// service user with the application credentials in db.yaml, never over HTTP, so it grants nothing
/// that reading db.yaml does not. A change ends the account's sessions as the console's does: the
/// security stamp is rotated and every refresh token revoked. Each change is written to the
/// hash-chained audit trail as <see cref="AuditActionType.UserPasswordSourceSetOnHost"/> by
/// <see cref="UnlockUserCommand.Actor"/>.
/// </summary>
public static class SetPasswordSourceCommand
{
    /// <summary>The flag, followed by the username and the source.</summary>
    public const string Flag = "--set-password-source";

    /// <summary>The usage line printed for missing or wrong arguments.</summary>
    public const string Usage = "Usage: --set-password-source <username> <Inherit|Local|Directory>   (run as the service user after bootstrap)";

    /// <summary>
    /// Parses a source name, ignoring case. Only the three defined names are accepted, not numbers.
    /// </summary>
    /// <param name="text">The name given on the command line.</param>
    /// <param name="source">The source, when the name is one of the three.</param>
    /// <returns>True when <paramref name="text"/> names a source.</returns>
    public static bool TryParseSource(string? text, out PasswordSource source)
    {
        source = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        foreach (var value in Enum.GetValues<PasswordSource>())
        {
            if (string.Equals(value.ToString(), text.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                source = value;
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Sets <paramref name="username"/>'s password source to <paramref name="sourceText"/> and
    /// records it in <paramref name="auditDb"/>. A source the account already has changes nothing
    /// and writes no record. When the audit database is null or cannot be written, the change still
    /// stands and a loud warning says no audit record was written. Returns the process exit code:
    /// 0 on success or no change, 1 when the account does not exist or the source is not one of
    /// Inherit, Local and Directory.
    /// </summary>
    /// <param name="db">The application database, with the db.yaml credentials.</param>
    /// <param name="auditDb">The audit database, or null when db.yaml configures none.</param>
    /// <param name="username">The account to change.</param>
    /// <param name="sourceText">The new source, by name.</param>
    /// <param name="output">Where the outcome is written.</param>
    public static async Task<int> RunAsync(ModularCADbContext db, AuditDbContext? auditDb, string username, string? sourceText, TextWriter output)
    {
        if (!TryParseSource(sourceText, out var source))
        {
            output.WriteLine($"'{sourceText}' is not a password source. Use Inherit, Local or Directory.");
            return 1;
        }
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            output.WriteLine($"No account named '{username}'.");
            return 1;
        }
        if (user.PasswordSource == source)
        {
            output.WriteLine($"'{user.Username}' already has the password source {source}; nothing changed.");
            return 0;
        }

        var previous = user.PasswordSource;
        user.PasswordSource = source;
        user.SecurityStamp = Guid.NewGuid().ToString();
        var now = DateTime.UtcNow;
        foreach (var token in await db.RefreshTokens.Where(t => t.UserId == user.Id && !t.IsRevoked).ToListAsync())
        {
            token.IsRevoked = true;
            token.RevokedAt = now;
        }
        await db.SaveChangesAsync();
        output.WriteLine($"Set the password source of '{user.Username}' from {previous} to {source}; its sessions are ended.");
        if (source == PasswordSource.Local && string.IsNullOrEmpty(user.PasswordHash))
            output.WriteLine("The account has no local password yet: set one, or it cannot sign in with a password.");

        try
        {
            if (auditDb == null) throw new InvalidOperationException("db.yaml configures no audit database");
            await new AuditHashChainService().AppendAsync(auditDb, new AuditLogEntity
            {
                ActionType = AuditActionType.UserPasswordSourceSetOnHost,
                ActorUsername = UnlockUserCommand.Actor,
                TargetEntityType = "User",
                TargetEntityId = user.Id.ToString(),
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(new
                {
                    user.Username,
                    Old = previous.ToString(),
                    New = source.ToString(),
                    Host = Environment.MachineName,
                    OsUser = Environment.UserName,
                }),
            });
            output.WriteLine("Recorded in the audit trail.");
        }
        catch (Exception ex)
        {
            output.WriteLine("****************************************************************");
            output.WriteLine($"WARNING: NO AUDIT RECORD WAS WRITTEN FOR THIS CHANGE ({ex.GetType().Name}: {ex.Message}).");
            output.WriteLine("The password source is changed. Record by hand who ran this, when and why.");
            output.WriteLine("****************************************************************");
        }
        return 0;
    }
}
