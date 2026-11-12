using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.API.Startup;

/// <summary>
/// The host commands for one-time account claims (<see cref="AccountClaims"/>):
/// <list type="bullet">
/// <item><c>--new-claim-token</c> generates a token and prints it with the bootstrap.yaml line that
/// carries its hash, for whoever writes bootstrap.yaml (the operator, or a hub that must never hold
/// the first administrator's password). It touches nothing and needs no database.</item>
/// <item><c>--issue-claim-token &lt;username&gt; [--claim-lifetime-hours &lt;hours&gt;]</c> generates a
/// token for an existing account, replaces any claim it has, and prints the token once. It is the
/// way in again when a bootstrap claim expired unused, and a host-side handover for any local
/// account. Like <see cref="SetPasswordSourceCommand"/> it runs on the host as the service user
/// with the credentials in db.yaml, never over HTTP, so it grants nothing that reading db.yaml does
/// not; each issue is written to the audit trail as
/// <see cref="AuditActionType.UserClaimTokenIssuedOnHost"/> by <see cref="UnlockUserCommand.Actor"/>,
/// without the token.</item>
/// </list>
/// The token is printed to the terminal that ran the command and nowhere else; it is not logged.
/// </summary>
public static class ClaimTokenCommand
{
    /// <summary>The flag that generates a token and its bootstrap.yaml line.</summary>
    public const string NewFlag = "--new-claim-token";

    /// <summary>The flag, followed by a username, that issues a claim for an account.</summary>
    public const string IssueFlag = "--issue-claim-token";

    /// <summary>The optional flag, followed by a number of hours, that sets the claim's lifetime.</summary>
    public const string LifetimeFlag = "--claim-lifetime-hours";

    /// <summary>The usage line printed for missing or wrong arguments.</summary>
    public const string Usage = "Usage: --issue-claim-token <username> [--claim-lifetime-hours <1-8760>]   (run as the service user after bootstrap)";

    /// <summary>
    /// Prints a new token and the bootstrap.yaml line holding its hash. Returns 0.
    /// </summary>
    /// <param name="output">Where the token and the line are written.</param>
    public static int RunNew(TextWriter output)
    {
        var token = AccountClaims.NewToken();
        output.WriteLine("Claim token. It is shown only this once; give it to the person who will claim the account:");
        output.WriteLine();
        output.WriteLine($"    {token}");
        output.WriteLine();
        output.WriteLine("Line for bootstrap.yaml, under Administration: (the hash only; the token never goes in the file)");
        output.WriteLine();
        output.WriteLine($"  ClaimTokenSha256: \"{AccountClaims.HashHex(token)}\"");
        return 0;
    }

    /// <summary>
    /// Parses a lifetime in hours: null text is the default, seven days; otherwise a whole number
    /// from 1 to 8760.
    /// </summary>
    /// <param name="text">The value given after <see cref="LifetimeFlag"/>, or null when it was not given.</param>
    /// <param name="lifetime">The lifetime, when the text is acceptable.</param>
    /// <returns>True when <paramref name="text"/> is null or an acceptable number of hours.</returns>
    public static bool TryParseLifetime(string? text, out TimeSpan lifetime)
    {
        lifetime = AccountClaims.DefaultLifetime;
        if (text == null) return true;
        if (!int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var hours)
            || hours < 1 || hours > AccountClaims.MaxLifetime.TotalHours)
            return false;
        lifetime = TimeSpan.FromHours(hours);
        return true;
    }

    /// <summary>
    /// Issues a claim on <paramref name="username"/>, replacing any it has, prints the token once,
    /// and records the issue in <paramref name="auditDb"/>. The account must be claimable
    /// (<see cref="AccountClaims.IsClaimable"/>): active, not a service identity, and not a
    /// Directory account, whose password a claim could not set. The account's current password, if
    /// any, keeps working until the claim is used. When the audit database is null or cannot be
    /// written, the claim still stands and a loud warning says no audit record was written. Returns
    /// the process exit code: 0 on success, 1 when the account does not exist or cannot be claimed,
    /// or the lifetime is not 1 to 8760 hours.
    /// </summary>
    /// <param name="db">The application database, with the db.yaml credentials.</param>
    /// <param name="auditDb">The audit database, or null when db.yaml configures none.</param>
    /// <param name="username">The account to issue the claim for.</param>
    /// <param name="lifetimeText">The lifetime in hours as given, or null for seven days.</param>
    /// <param name="output">Where the token and the outcome are written.</param>
    /// <param name="now">The current time (UTC); the clock when null.</param>
    public static async Task<int> RunIssueAsync(
        ModularCADbContext db, AuditDbContext? auditDb, string username, string? lifetimeText, TextWriter output, DateTime? now = null)
    {
        if (!TryParseLifetime(lifetimeText, out var lifetime))
        {
            output.WriteLine($"'{lifetimeText}' is not a claim lifetime. Give a whole number of hours from 1 to {(int)AccountClaims.MaxLifetime.TotalHours}.");
            return 1;
        }
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            output.WriteLine($"No account named '{username}'.");
            return 1;
        }
        if (!AccountClaims.IsClaimable(user))
        {
            output.WriteLine(user.PasswordSource == PasswordSource.Directory
                ? $"'{user.Username}' is a Directory account: its password is in the directory, so a claim could not set it."
                : $"'{user.Username}' cannot be claimed: it is disabled or a service identity.");
            return 1;
        }

        var at = now ?? DateTime.UtcNow;
        var expiresAt = at + lifetime;
        var token = AccountClaims.NewToken();
        var replaced = await AccountClaims.IssueAsync(db, user, AccountClaims.Hash(token), expiresAt, UnlockUserCommand.Actor, at);

        output.WriteLine($"Claim token for '{user.Username}'. It is shown only this once:");
        output.WriteLine();
        output.WriteLine($"    {token}");
        output.WriteLine();
        output.WriteLine($"It sets the account's password once, at the console's sign-in page under \"Have a claim token?\" (/claim),");
        output.WriteLine($"until {expiresAt:yyyy-MM-dd HH:mm} UTC.{(replaced ? " The account's earlier claim no longer works." : "")}");
        if (!string.IsNullOrEmpty(user.PasswordHash))
            output.WriteLine("The account's current password keeps working until the claim is used.");

        try
        {
            if (auditDb == null) throw new InvalidOperationException("db.yaml configures no audit database");
            await new AuditHashChainService().AppendAsync(auditDb, new AuditLogEntity
            {
                ActionType = AuditActionType.UserClaimTokenIssuedOnHost,
                ActorUsername = UnlockUserCommand.Actor,
                TargetEntityType = "User",
                TargetEntityId = user.Id.ToString(),
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(new
                {
                    user.Username,
                    ExpiresAt = expiresAt,
                    Replaced = replaced,
                    Host = Environment.MachineName,
                    OsUser = Environment.UserName,
                }),
            });
            output.WriteLine("Recorded in the audit trail.");
        }
        catch (Exception ex)
        {
            output.WriteLine("****************************************************************");
            output.WriteLine($"WARNING: NO AUDIT RECORD WAS WRITTEN FOR THIS CLAIM ({ex.GetType().Name}: {ex.Message}).");
            output.WriteLine("The claim stands. Record by hand who ran this, when and why.");
            output.WriteLine("****************************************************************");
        }
        return 0;
    }
}
