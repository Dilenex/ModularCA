using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Utils;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.Auth.Services;

/// <summary>Why <see cref="AccountClaims.RedeemAsync"/> did or did not set a password.</summary>
public enum ClaimOutcome
{
    /// <summary>The claim was used: the password is set and the claim deleted.</summary>
    Claimed,

    /// <summary>The new password fails the password policy. Checked before the token, so it says nothing about the claim.</summary>
    WeakPassword,

    /// <summary>
    /// The token matches no claim, the claim has expired or was used meanwhile, or the account cannot
    /// be claimed. Callers answer every one of these the same way.
    /// </summary>
    Refused,
}

/// <summary>
/// What <see cref="AccountClaims.RedeemAsync"/> did. <see cref="Reason"/> is for the audit trail
/// only and must never reach the caller, who gets one answer for every refusal.
/// </summary>
/// <param name="Outcome">Whether the password was set.</param>
/// <param name="User">The account claimed, or the account the claim named when it was refused for the account's state; null otherwise.</param>
/// <param name="Reason">Why a claim was refused (<c>no_match</c>, <c>expired</c>, <c>already_used</c>, <c>not_claimable</c>); null when claimed.</param>
/// <param name="PolicyErrors">The password policy's objections, for <see cref="ClaimOutcome.WeakPassword"/>.</param>
/// <param name="ReplacedPasswordHash">The account's password hash before the claim; empty when it had no password.</param>
/// <param name="Claim">The claim that was used or refused, when the token matched one.</param>
public sealed record ClaimRedemption(
    ClaimOutcome Outcome,
    UserEntity? User,
    string? Reason,
    IReadOnlyList<string> PolicyErrors,
    string ReplacedPasswordHash,
    UserClaimTokenEntity? Claim);

/// <summary>
/// One-time account claims (<see cref="UserClaimTokenEntity"/>): a token generated outside the
/// instance, of which the instance keeps only the SHA-256, that sets an account's password once.
/// The headless bootstrap uses it to hand over the first administrator without making a password
/// that has to come back out of the instance; <c>--issue-claim-token</c> issues one on the host.
/// </summary>
public static class AccountClaims
{
    /// <summary>Random bytes in a token: 256 bits, so a plain SHA-256 of it is enough to store.</summary>
    public const int TokenBytes = 32;

    /// <summary>How long a claim lasts when nothing says otherwise.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(7);

    /// <summary>The longest lifetime a claim may be given.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(365);

    /// <summary><see cref="UserClaimTokenEntity.IssuedBy"/> for a claim the headless bootstrap recorded.</summary>
    public const string IssuedByBootstrap = "bootstrap";

    /// <summary>
    /// A new token: <see cref="TokenBytes"/> random bytes, base64url without padding (43 characters).
    /// </summary>
    public static string NewToken() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes));

    /// <summary>
    /// SHA-256 of a token's UTF-8 text, with surrounding whitespace removed first so a token pasted
    /// with a stray newline still matches. The same as <c>printf %s "$token" | sha256sum</c>.
    /// </summary>
    /// <param name="token">The token as presented.</param>
    public static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token.Trim()));

    /// <summary>The lowercase hex of <see cref="Hash"/>: what bootstrap.yaml's <c>Administration.ClaimTokenSha256</c> holds.</summary>
    /// <param name="token">The token.</param>
    public static string HashHex(string token) => Convert.ToHexStringLower(Hash(token));

    /// <summary>
    /// Parses a SHA-256 written as 64 hex digits, either case, with surrounding whitespace ignored.
    /// </summary>
    /// <param name="hex">The text, as bootstrap.yaml gives it.</param>
    /// <param name="hash">The 32 bytes, when the text is a SHA-256.</param>
    /// <returns>True when <paramref name="hex"/> is 64 hex digits.</returns>
    public static bool TryParseHashHex(string? hex, out byte[] hash)
    {
        hash = [];
        var text = hex?.Trim();
        if (text is not { Length: 64 } || !text.All(Uri.IsHexDigit)) return false;
        hash = Convert.FromHexString(text);
        return true;
    }

    /// <summary>
    /// Whether an account may hold and redeem a claim: an active person (not a service identity)
    /// whose password is local. A Directory account's password lives in the directory, so a local
    /// password set by a claim would never be used.
    /// </summary>
    /// <param name="user">The account.</param>
    public static bool IsClaimable(UserEntity user)
        => user.IsActive && !user.IsServiceIdentity && !user.IsDeleted && user.PasswordSource != PasswordSource.Directory;

    /// <summary>
    /// Records a claim on <paramref name="user"/>, replacing any claim the account already has, and
    /// saves. Returns whether one was replaced.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="user">The account, already saved.</param>
    /// <param name="tokenHash">SHA-256 of the token (<see cref="Hash"/>).</param>
    /// <param name="expiresAt">When the claim stops working (UTC).</param>
    /// <param name="issuedBy">What issued it, for <see cref="UserClaimTokenEntity.IssuedBy"/>.</param>
    /// <param name="now">The current time (UTC).</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<bool> IssueAsync(
        ModularCADbContext db, UserEntity user, byte[] tokenHash, DateTime expiresAt, string issuedBy, DateTime now,
        CancellationToken ct = default)
    {
        if (tokenHash.Length != SHA256.HashSizeInBytes)
            throw new ArgumentException("A claim token hash is 32 bytes.", nameof(tokenHash));
        var existing = await db.UserClaimTokens.Where(c => c.UserId == user.Id).ToListAsync(ct);
        db.UserClaimTokens.RemoveRange(existing);
        if (existing.Count > 0)
            await db.SaveChangesAsync(ct);
        db.UserClaimTokens.Add(new UserClaimTokenEntity
        {
            UserId = user.Id,
            TokenHash = tokenHash,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            IssuedBy = issuedBy,
        });
        await db.SaveChangesAsync(ct);
        return existing.Count > 0;
    }

    /// <summary>
    /// Sets an account's password with a claim token, once. In order:
    /// <list type="number">
    /// <item>The new password is checked against the password policy, before the token, so a weak
    /// password is reported without saying anything about the claim.</item>
    /// <item>The token's hash is compared with every claim's in constant time, without stopping at a
    /// match. There is a claim per account being handed over, so the table stays small.</item>
    /// <item>An expired claim, or one whose account is not <see cref="IsClaimable"/>, is refused.</item>
    /// <item>The claim is deleted with a conditional delete in the same transaction as the password
    /// change, so two requests with one token cannot both set a password.</item>
    /// <item>The password is set and recorded in the password history; the forced change at next
    /// sign-in is cleared (the holder of the token chose it), the password source is left as it is,
    /// the security stamp is rotated, any lockout (temporary or hard) and the failed-login count are cleared,
    /// the expiry date is reset by the policy, and every refresh token is revoked
    /// (<see cref="UserSessionTermination.EndAllSessionsSetBasedAsync"/>, in the same transaction).</item>
    /// </list>
    /// Needs a relational provider (it uses a transaction and set-based updates).
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="token">The token as presented.</param>
    /// <param name="newPassword">The password to set.</param>
    /// <param name="now">The current time (UTC).</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<ClaimRedemption> RedeemAsync(
        ModularCADbContext db, string token, string newPassword, DateTime now, CancellationToken ct = default)
    {
        var policy = await db.PasswordPolicies.FirstOrDefaultAsync(ct) ?? new PasswordPolicyEntity();
        var policyErrors = PasswordPolicyService.Validate(newPassword, policy);
        if (policyErrors.Count > 0)
            return new ClaimRedemption(ClaimOutcome.WeakPassword, null, null, policyErrors, string.Empty, null);

        var presented = Hash(token);
        UserClaimTokenEntity? match = null;
        foreach (var claim in await db.UserClaimTokens.AsNoTracking().ToListAsync(ct))
        {
            // No early exit: every claim is compared whether or not one already matched.
            if (CryptographicOperations.FixedTimeEquals(presented, claim.TokenHash))
                match = claim;
        }
        if (match == null)
            return Refused("no_match", null, null);
        if (match.ExpiresAt <= now)
            return Refused("expired", null, match);

        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == match.UserId, ct);
        if (user == null || !IsClaimable(user))
            return Refused("not_claimable", user, match);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var deleted = await db.UserClaimTokens
            .Where(c => c.Id == match.Id && c.ExpiresAt > now)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0)
        {
            await tx.RollbackAsync(ct);
            return Refused("already_used", user, match);
        }

        var replacedHash = user.PasswordHash ?? string.Empty;
        var newHash = PasswordUtil.HashPassword(newPassword);
        user.PasswordHash = newHash;
        await new PasswordPolicyService(db).RecordPasswordHistoryAsync(user.Id, newHash);
        user.PasswordChangeOnNextLogon = false;
        // A lockout here comes from failed sign-ins, and an account waiting to be claimed has no
        // password to get right, so guessing at it locks it for nothing. The claim was issued by
        // the bootstrap or on the host, both of which may unlock an account anyway.
        user.IsLocked = false;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;
        if (!user.PasswordNeverExpires && policy.MaxAgeDays > 0)
            user.PasswordExpirationDate = now.AddDays(policy.MaxAgeDays);
        // Saves the changes above with the rotated stamp and revokes the refresh tokens, inside tx.
        await UserSessionTermination.EndAllSessionsSetBasedAsync(db, user, now, ct);
        await tx.CommitAsync(ct);
        return new ClaimRedemption(ClaimOutcome.Claimed, user, null, [], replacedHash, match);

        static ClaimRedemption Refused(string reason, UserEntity? user, UserClaimTokenEntity? claim)
            => new(ClaimOutcome.Refused, user, reason, [], string.Empty, claim);
    }
}
