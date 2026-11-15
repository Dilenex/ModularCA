using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Spends an ACME external account binding key (RFC 8555 §7.3.4) on one account. A key binds one
/// account: of several new-account requests that present the same key at once, every one can pass
/// the check that it is unused, so the key is claimed with a conditional UPDATE and only the
/// request whose UPDATE changes the row may go on. On PostgreSQL a second UPDATE of the row waits
/// for the first's transaction and then finds the key used, so run the claim, the account write and
/// <see cref="RecordAccountAsync"/> in one transaction: a failure after the claim then releases it.
/// </summary>
public static class AcmeEabKeyClaim
{
    /// <summary>
    /// Marks EAB key <paramref name="eabKeyId"/> used at <paramref name="nowUtc"/> if, and only if,
    /// it is not used yet. Returns whether this call claimed it; false means another request did.
    /// The in-memory provider, which cannot execute ExecuteUpdate, gets a tracked check-and-set
    /// with no such guarantee; it serves the unit tests only.
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="eabKeyId">The EAB key row's id.</param>
    /// <param name="nowUtc">The time the key is spent.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<bool> TryClaimAsync(ModularCADbContext db, Guid eabKeyId, DateTime nowUtc, CancellationToken ct = default)
    {
        if (db.Database.IsRelational())
        {
            var claimed = await db.AcmeEabKeys
                .Where(k => k.Id == eabKeyId && !k.IsUsed)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(k => k.IsUsed, true)
                    .SetProperty(k => k.UsedAt, (DateTime?)nowUtc), ct) == 1;
            if (claimed)
                await QueueSpentFactAsync(db, eabKeyId, nowUtc, ct);
            return claimed;
        }

        var key = await db.AcmeEabKeys.FirstOrDefaultAsync(k => k.Id == eabKeyId, ct);
        if (key == null || key.IsUsed)
            return false;
        key.IsUsed = true;
        key.UsedAt = nowUtc;
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// Queues the fact that the key was spent for the signer's journal: a one-time token used
    /// with no certificate issued. The bulk statement above is not seen by the change tracker,
    /// which queues this fact for the tracked path. A fact that cannot be queued does not undo
    /// the claim.
    /// </summary>
    private static async Task QueueSpentFactAsync(ModularCADbContext db, Guid eabKeyId, DateTime nowUtc, CancellationToken ct)
    {
        try
        {
            await db.QueueSignerFactNowAsync(ModularCA.Journal.RecordType.SpentWithoutCertificate,
                new ModularCA.Journal.SpentWithoutCertificatePayload(ModularCA.Journal.TokenKind.AcmeExternalAccountBinding, eabKeyId.ToString("D"),
                    ModularCA.Journal.JournalFormat.ToMicros(new DateTimeOffset(DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc)))).Encode(), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The key is spent either way; the journal goes without this one fact.
        }
    }

    /// <summary>
    /// Records <paramref name="accountId"/> as the account EAB key <paramref name="eabKeyId"/> was
    /// spent on, after <see cref="TryClaimAsync"/> claimed it for that account. Writes only a key
    /// that names no account yet.
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="eabKeyId">The EAB key row's id.</param>
    /// <param name="accountId">The ACME account the key bound.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task RecordAccountAsync(ModularCADbContext db, Guid eabKeyId, Guid accountId, CancellationToken ct = default)
    {
        if (db.Database.IsRelational())
        {
            await db.AcmeEabKeys
                .Where(k => k.Id == eabKeyId && k.UsedByAccountId == null)
                .ExecuteUpdateAsync(s => s.SetProperty(k => k.UsedByAccountId, (Guid?)accountId), ct);
            return;
        }

        var key = await db.AcmeEabKeys.FirstOrDefaultAsync(k => k.Id == eabKeyId, ct);
        if (key == null || key.UsedByAccountId != null)
            return;
        key.UsedByAccountId = accountId;
        await db.SaveChangesAsync(ct);
    }
}
