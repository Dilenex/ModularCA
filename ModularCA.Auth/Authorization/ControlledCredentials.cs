using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Reads the credential and account state a controlled-user ceremony pins at initiation and
/// compares at execute, so a ceremony cannot promote an account whose password or MFA someone
/// replaced while it waited, or apply an identity change to an account that has moved on; and the
/// recent credential resets a promotion discloses to its approvers and bars from approving it.
/// </summary>
public static class ControlledCredentials
{
    /// <summary>The credential state of each of <paramref name="userIds"/> that exists.</summary>
    public static async Task<List<ControlledCredentialSnapshot>> SnapshotAsync(ModularCADbContext db, IReadOnlyCollection<Guid> userIds)
    {
        var result = new List<ControlledCredentialSnapshot>();
        if (userIds.Count == 0) return result;
        var ids = userIds.ToList();
        var users = await db.Users.AsNoTracking()
            .Where(u => ids.Contains(u.Id))
            .Select(u => new { u.Id, u.SecurityStamp, u.MfaEnrolledAt })
            .ToListAsync();
        foreach (var u in users)
            result.Add(new ControlledCredentialSnapshot(u.Id, u.SecurityStamp, await MfaMarkerAsync(db, u.Id, u.MfaEnrolledAt)));
        return result;
    }

    /// <summary>
    /// True when an account in <paramref name="snapshots"/> that still exists has a different
    /// security stamp or MFA marker now. An account deleted since is not promoted, so it is skipped.
    /// </summary>
    public static async Task<bool> AnyChangedAsync(ModularCADbContext db, IReadOnlyCollection<ControlledCredentialSnapshot> snapshots)
    {
        var now = await SnapshotAsync(db, snapshots.Select(s => s.UserId).ToList());
        return snapshots.Any(s => now.FirstOrDefault(n => n.UserId == s.UserId) is { } current && current != s);
    }

    /// <summary>
    /// True when <paramref name="now"/> still matches <paramref name="before"/> for <paramref name="change"/>:
    /// the username, email, enabled and locked state always, and the password-expiry and
    /// forced-change flags only when the change sets them, since every password change moves those.
    /// </summary>
    public static bool Unchanged(ControlledAccountState before, ControlledAccountState now, ControlledIdentityChange change)
        => now.Username == before.Username && now.Email == before.Email
           && now.IsActive == before.IsActive && now.IsLocked == before.IsLocked
           && (change.PasswordNeverExpires == null || now.PasswordNeverExpires == before.PasswordNeverExpires)
           && (change.PasswordChangeOnNextLogon == null || now.PasswordChangeOnNextLogon == before.PasswordChangeOnNextLogon);

    /// <summary>
    /// The password resets, MFA resets and creations of <paramref name="userIds"/> since
    /// <paramref name="since"/>, by anyone, newest first, read from the audit trail: direct resets
    /// (<c>UserPasswordReset</c>, <c>UserUpdated</c> with action <c>MfaReset</c>), ceremony-executed
    /// ones (the same, and <c>ControlledUserChangeApplied</c>), and <c>UserCreated</c>. One record
    /// per account, kind, actor and day. Throws when the audit database cannot be read.
    /// </summary>
    public static async Task<List<ControlledCredentialReset>> RecentResetsAsync(
        ModularCADbContext db, AuditDbContext audit, IReadOnlyCollection<Guid> userIds, DateTime since)
    {
        if (userIds.Count == 0) return [];
        var ids = userIds.Select(id => id.ToString()).ToList();
        var rows = await audit.AuditLogs.AsNoTracking()
            .Where(a => a.TargetEntityType == "User" && a.TargetEntityId != null && ids.Contains(a.TargetEntityId)
                && a.Timestamp >= since && a.Success
                && (a.ActionType == AuditActionType.UserPasswordReset || a.ActionType == AuditActionType.UserUpdated
                    || a.ActionType == AuditActionType.ControlledUserChangeApplied || a.ActionType == AuditActionType.UserCreated))
            .Select(a => new { a.TargetEntityId, a.ActionType, a.DetailsJson, a.ActorUserId, a.ActorUsername, a.Timestamp })
            .ToListAsync();

        var guids = userIds.ToList();
        var names = await db.Users.AsNoTracking().Where(u => guids.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.Username);
        return rows
            .Select(r => (Row: r, What: r.ActionType switch
            {
                AuditActionType.UserPasswordReset => ControlledCredentialReset.Password,
                AuditActionType.UserCreated => ControlledCredentialReset.Created,
                AuditActionType.UserUpdated => Detail(r.DetailsJson, "Action") == "MfaReset" ? ControlledCredentialReset.Mfa : null,
                _ => Detail(r.DetailsJson, "ChangeType") switch
                {
                    "ResetPassword" => ControlledCredentialReset.Password,
                    "ResetMfa" => ControlledCredentialReset.Mfa,
                    _ => null,
                },
            }))
            .Where(x => x.What != null && Guid.TryParse(x.Row.TargetEntityId, out _))
            .OrderByDescending(x => x.Row.Timestamp)
            .Select(x =>
            {
                var userId = Guid.Parse(x.Row.TargetEntityId!);
                return new ControlledCredentialReset(userId, names.GetValueOrDefault(userId), x.What!, x.Row.ActorUserId, x.Row.ActorUsername, x.Row.Timestamp);
            })
            .DistinctBy(r => (r.UserId, r.What, r.ActorUserId, r.ActorUsername, r.At.Date))
            .ToList();
    }

    /// <summary>
    /// The id and username of each of <paramref name="userIds"/> that must change its password at
    /// next logon, which an administrator's password reset sets: a password an administrator set
    /// and the account has not changed since. Read from the account itself, so it holds when the
    /// audit record of the reset was never written; who set it, and when, is unknown.
    /// </summary>
    public static async Task<List<(Guid Id, string Username)>> PasswordsSetByAdministratorAsync(ModularCADbContext db, IReadOnlyCollection<Guid> userIds)
    {
        if (userIds.Count == 0) return [];
        var ids = userIds.ToList();
        var rows = await db.Users.AsNoTracking()
            .Where(u => ids.Contains(u.Id) && u.PasswordChangeOnNextLogon)
            .Select(u => new { u.Id, u.Username })
            .ToListAsync();
        return rows.Select(r => (r.Id, r.Username)).ToList();
    }

    /// <summary>The string value of top-level property <paramref name="name"/> (any case) of an audit record's details, or null.</summary>
    private static string? Detail(string? detailsJson, string name)
    {
        if (string.IsNullOrEmpty(detailsJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(detailsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            foreach (var p in doc.RootElement.EnumerateObject())
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                    return p.Value.GetString();
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The account's identity and access state, or null when it does not exist.</summary>
    public static Task<ControlledAccountState?> AccountStateAsync(ModularCADbContext db, Guid userId)
        => db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new ControlledAccountState(u.Username, u.Email, u.IsActive, u.IsLocked, u.PasswordNeverExpires, u.PasswordChangeOnNextLogon))
            .FirstOrDefaultAsync();

    /// <summary>
    /// SHA-256 over the account's MFA enrolment time and the ids of its TOTP secrets (with their
    /// verified flag), WebAuthn credentials, unrevoked mTLS credentials and unused recovery codes.
    /// Counters that change on every sign-in are left out.
    /// </summary>
    private static async Task<string> MfaMarkerAsync(ModularCADbContext db, Guid userId, DateTime? mfaEnrolledAt)
    {
        var parts = new List<string> { "e:" + (mfaEnrolledAt?.Ticks.ToString() ?? "-") };
        parts.AddRange((await db.TotpSecrets.AsNoTracking().Where(t => t.UserId == userId)
            .Select(t => new { t.Id, t.IsVerified }).ToListAsync()).Select(t => $"t:{t.Id}:{t.IsVerified}"));
        parts.AddRange((await db.Fido2Credentials.AsNoTracking().Where(c => c.UserId == userId)
            .Select(c => c.Id).ToListAsync()).Select(id => $"f:{id}"));
        parts.AddRange((await db.MtlsCredentials.AsNoTracking().Where(c => c.UserId == userId && !c.IsRevoked)
            .Select(c => c.Id).ToListAsync()).Select(id => $"m:{id}"));
        parts.AddRange((await db.TotpRecoveryCodes.AsNoTracking().Where(c => c.UserId == userId && c.UsedAt == null)
            .Select(c => c.Id).ToListAsync()).Select(id => $"r:{id}"));
        parts.Sort(StringComparer.Ordinal);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", parts))));
    }
}
