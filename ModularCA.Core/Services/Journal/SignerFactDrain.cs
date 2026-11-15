using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services.Journal;

/// <summary>
/// Offers the queued facts to the signer, oldest first, and removes each once the signer has
/// flushed its record (<c>docs/architecture/signer-journal.md</c>, "Facts the node asserts").
/// The queue is a table of the application database (<see cref="SignerFactEntity"/>), written
/// in the same save as the change a fact describes, so it survives a restart of the node and
/// holds no fact for a change that was rolled back. A fact the signer does not take stays
/// queued and is offered again, after a wait that grows to five minutes; it never stops or
/// undoes what it describes.
/// </summary>
/// <remarks>
/// Several processes of one instance may drain the same queue: each takes its rows with
/// <c>FOR UPDATE SKIP LOCKED</c>, so a fact is offered by one of them. Should a process stop
/// between the signer's answer and the removal of the row, the fact is recorded twice, which
/// the facts tolerate: each states something that is true however often it is said.
/// </remarks>
public sealed class SignerFactDrain : BackgroundService
{
    /// <summary>The caller the signer records for a fact.</summary>
    public const string Caller = nameof(SignerFactDrain);

    private static readonly TimeSpan Idle = TimeSpan.FromSeconds(15);
    /// <summary>How many facts one pass takes from the queue.</summary>
    public const int Batch = 500;

    private readonly IServiceScopeFactory _scopes;
    private readonly ISigningService _signer;
    private readonly ILogger<SignerFactDrain> _logger;
    private readonly SemaphoreSlim _signal = new(0, 1);

    /// <summary>Creates the drain.</summary>
    public SignerFactDrain(IServiceScopeFactory scopes, ISigningService signer, ILogger<SignerFactDrain> logger)
    {
        _scopes = scopes;
        _signer = signer;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        void Wake()
        {
            try { _signal.Release(); }
            catch (SemaphoreFullException) { /* already asked to look */ }
        }
        ModularCADbContext.SignerFactQueued += Wake;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var more = false;
                try
                {
                    using var scope = _scopes.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                    more = await DrainOnceAsync(db, _signer, _logger, stoppingToken) == Batch;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("The queue of facts for the signer's journal could not be read ({Kind}: {Message}); it is read again shortly.",
                        ex.GetType().Name, ex.Message);
                }
                if (more)
                    continue;
                try
                {
                    await _signal.WaitAsync(Idle, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            ModularCADbContext.SignerFactQueued -= Wake;
        }
    }

    /// <summary>
    /// What a fact is about, for the order in which facts must reach the journal: the CA key
    /// and serial of a revocation or a released hold. Null for every other fact, which is
    /// offered alone, after everything before it.
    /// </summary>
    private static string? SubjectOf(SignerFactEntity fact)
    {
        try
        {
            switch ((ushort)fact.Type)
            {
                case RecordType.Revocation:
                    var revoked = RevocationPayload.Decode(fact.Payload);
                    return Convert.ToHexStringLower(revoked.CaKey) + "/" + Convert.ToHexStringLower(revoked.Serial);
                case RecordType.Unrevocation:
                    var released = UnrevocationPayload.Decode(fact.Payload);
                    return Convert.ToHexStringLower(released.CaKey) + "/" + Convert.ToHexStringLower(released.Serial);
                default:
                    return null;
            }
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Offers up to a batch of the facts that are due and returns how many it looked at. A fact
    /// the signer took is removed; one it did not is kept with the reason and a later time to
    /// try again.
    /// </summary>
    public static async Task<int> DrainOnceAsync(ModularCADbContext db, ISigningService signer, ILogger logger, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        await using var transaction = db.Database.IsNpgsql() ? await db.Database.BeginTransactionAsync(cancellationToken) : null;
        var due = db.Database.IsNpgsql()
            ? await db.SignerFacts.FromSqlInterpolated(
                $"""SELECT * FROM "SignerFactQueue" WHERE "NextAttemptAt" IS NULL OR "NextAttemptAt" <= {now} ORDER BY "Id" LIMIT {Batch} FOR UPDATE SKIP LOCKED""")
                .ToListAsync(cancellationToken)
            : await db.SignerFacts.Where(f => f.NextAttemptAt == null || f.NextAttemptAt <= now).OrderBy(f => f.Id).Take(Batch).ToListAsync(cancellationToken);
        if (due.Count == 0)
            return 0;

        // Facts are offered a wave at a time and not one by one: the signer flushes its journal
        // once for all the records that arrive together, where one fact after another costs a
        // flush each. Order matters only between facts about the same thing (a hold and its
        // release), so a wave holds revocation facts of different serials and nothing else; any
        // other fact, and a second fact about a serial already in the wave, waits for the wave
        // before it to be answered.
        var context = new SigningContext(Caller, SigningPurpose.JournalFact, null, null);
        var stopped = false;
        var index = 0;
        while (index < due.Count && !stopped)
        {
            var wave = new List<SignerFactEntity>();
            var subjects = new HashSet<string>(StringComparer.Ordinal);
            while (index < due.Count)
            {
                var subject = SubjectOf(due[index]);
                if (wave.Count > 0 && (subject == null || !subjects.Add(subject)))
                    break;
                if (subject != null)
                    subjects.Add(subject);
                wave.Add(due[index++]);
                if (subject == null)
                    break;
            }

            var offered = wave.Select(async fact =>
            {
                try
                {
                    await signer.RecordFactAsync((ushort)fact.Type, fact.Payload, context, cancellationToken);
                    return (SigningRefusedException?)null;
                }
                catch (SigningRefusedException ex)
                {
                    return ex;
                }
            }).ToList();
            var answers = await Task.WhenAll(offered);

            for (var i = 0; i < wave.Count; i++)
            {
                var fact = wave[i];
                if (answers[i] is not { } ex)
                {
                    db.SignerFacts.Remove(fact);
                    continue;
                }
                fact.Attempts++;
                fact.LastError = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message;
                // A fact the signer will never take is looked at once a day, so that it is seen and not lost.
                var wait = ex.Reason == SigningRefusalReason.FactNotAccepted
                    ? TimeSpan.FromDays(1)
                    : TimeSpan.FromSeconds(Math.Min(300, 5 * Math.Pow(2, Math.Min(fact.Attempts, 6))));
                fact.NextAttemptAt = now + wait;
                if (ex.Reason is SigningRefusalReason.OperationUnsupported or SigningRefusalReason.JournalUnavailable or SigningRefusalReason.SignerUnavailable or SigningRefusalReason.SignerLocked)
                {
                    // The signer as a whole cannot take facts now: the rest of the batch waits with this one.
                    if (!stopped)
                        logger.LogDebug("The signer did not take a fact for its journal ({Reason}: {Message}); {Count} fact(s) stay queued.", ex.Reason, ex.Message, due.Count);
                    stopped = true;
                    continue;
                }
                logger.LogWarning("The signer did not take the {Type} fact {Id} for its journal ({Reason}: {Message}); it stays queued.",
                    RecordType.Name((ushort)fact.Type), fact.Id, ex.Reason, ex.Message);
            }
        }
        if (stopped)
        {
            for (; index < due.Count; index++)
                due[index].NextAttemptAt = now + TimeSpan.FromSeconds(5);
        }

        db.SuppressSignerFacts = true;
        await db.SaveChangesAsync(cancellationToken);
        if (transaction != null)
            await transaction.CommitAsync(cancellationToken);
        return due.Count;
    }
}
