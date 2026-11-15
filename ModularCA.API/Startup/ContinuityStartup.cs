using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Continuity;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// What the continuity step of this start left, for <c>/health/ready</c>: whether the incarnation
/// was compared, with which outcome, and the fault if the comparison itself failed.
/// </summary>
public sealed class ContinuityStartState
{
    /// <summary>The comparison's outcome; null when this process did not compare (it does not run the control role) or the comparison failed.</summary>
    public IncarnationCase? Case { get; private set; }

    /// <summary>Why the comparison failed, when it did. The start went on without it.</summary>
    public string? Fault { get; private set; }

    /// <summary>Whether the published-CRL check of this start has run, and how many publishers' CRLs it compared.</summary>
    public int? PublishedCrlsCompared { get; private set; }

    /// <summary>Records the outcome of the incarnation comparison.</summary>
    public void Compared(IncarnationCase found) { Case = found; Fault = null; }

    /// <summary>Records that the incarnation comparison could not be made.</summary>
    public void Failed(string fault) => Fault = fault;

    /// <summary>Records that the published-CRL check ran over <paramref name="count"/> CRL(s) read back.</summary>
    public void PublishedCompared(int count) => PublishedCrlsCompared = count;
}

/// <summary>
/// The continuity step of a start (<c>docs/architecture/rollback-continuity.md</c>, sections 1
/// and 2): once the schema is current and the settings are read, and before the web host, the
/// scheduler or any CRL generation exists in this process, the control role compares the
/// machine's incarnation with the one the database last saw
/// (<see cref="InstanceContinuity.CheckIncarnationAsync"/>). Like the settings step it runs over
/// connections of its own.
/// <para>
/// It never stops a start. A changed incarnation is repaired and reported; a comparison that
/// cannot be made at all (a database fault a moment after the schema check passed) is logged as
/// an error, shown in <c>/health/ready</c>, and tried again at the next start, since nothing was
/// stored.
/// </para>
/// </summary>
public static class ContinuityStartup
{
    /// <summary>
    /// Compares and acts, and records the outcome in <paramref name="state"/>.
    /// </summary>
    /// <param name="config">This host's configuration, for the two databases.</param>
    /// <param name="state">Where the outcome is left for the health check.</param>
    /// <param name="reading">What the machine reports; read from <see cref="IncarnationSources.Default"/> when null.</param>
    public static async Task RunAsync(SystemConfig config, ContinuityStartState state, IncarnationReading? reading = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(state);
        try
        {
            reading ??= IncarnationSources.Read();
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(PostgresConnection.Build(config.DB.App)).Options);
            await using var auditDb = string.IsNullOrWhiteSpace(config.DB.Audit.Database) ? null
                : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                    .UseNpgsql(PostgresConnection.Build(config.DB.Audit)).Options);
            using var loggers = new Serilog.Extensions.Logging.SerilogLoggerFactory(Log.Logger);

            var result = await InstanceContinuity.CheckIncarnationAsync(db, auditDb, new HostAuditService(auditDb), reading,
                DateTimeOffset.UtcNow, loggers.CreateLogger("ModularCA.Continuity"));
            state.Compared(result.Case);

            switch (result.Case)
            {
                case IncarnationCase.Changed:
                    Console.WriteLine("[CONTINUITY] This instance is running from an earlier or copied state (incarnation "
                        + $"{result.Event?.OldTag} -> {result.Event?.NewTag}). CRL numbers were raised on {result.Raised.Count} configuration(s). "
                        + InstanceContinuity.JournalNote + " The console shows the notice until an administrator acknowledges it.");
                    break;
                case IncarnationCase.SourceLost:
                    Console.WriteLine("[CONTINUITY] This machine no longer reports an incarnation ID; \"none\" is stored and the console shows a notice once.");
                    break;
                case IncarnationCase.FirstSeen:
                case IncarnationCase.SourceAppeared:
                    Console.WriteLine($"[CONTINUITY] Incarnation stored (source: {reading.Source}).");
                    break;
            }
        }
        catch (Exception ex)
        {
            state.Failed($"{ex.GetType().Name}: {ex.Message}");
            Log.Error(ex, "The incarnation could not be compared with the one the database last saw. The start goes on; a rollback or a copy of this "
                + "instance is not detected at this start, and the comparison is made again at the next one.");
            Console.Error.WriteLine($"[CONTINUITY] The incarnation could not be compared ({ex.GetType().Name}: {ex.Message}). The start goes on.");
        }
    }
}
