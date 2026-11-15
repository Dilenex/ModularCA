using System.Diagnostics;
using Microsoft.Extensions.Hosting.Systemd;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using Serilog;

namespace ModularCA.API.Startup;

public static partial class SchemaStartup
{
    /// <summary>How often a starting process asks again while a restore holds the database.</summary>
    private static readonly TimeSpan RestoreLockPoll = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Takes the lock a long-running process holds on the application database while it runs
    /// (<see cref="RestoreLock"/>), before the schema check and before anything else in the start
    /// reads or writes that database, so that a restore and a start (its migrations above all)
    /// never run at the same moment. Returns the exit code to stop with, or
    /// <see langword="null"/> to go on starting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A restore holds the database.</b> Logged once; the process asks again every second for
    /// up to <c>Schema.RestoreWaitSeconds</c> (60). When the restore ends in that time the start
    /// goes on. Otherwise the process exits with <see cref="TempFailExitCode"/> (75): starting it
    /// again is the cure, and it starts once the restore has finished.
    /// </para>
    /// <para>
    /// <b>The server cannot be reached.</b> Waited for with backoff for up to
    /// <c>Schema.WaitSeconds</c>, as the schema check waits, then <see cref="TempFailExitCode"/>.
    /// </para>
    /// <para>
    /// <b>The database is missing, or refuses this role.</b> Not decided here: the start goes on
    /// without the lock and the schema check, which follows at once, refuses what an operator
    /// must fix (status 3) or leaves a database that does not exist yet to setup recovery. The
    /// lock is then taken in the background as soon as the database answers.
    /// </para>
    /// <para>
    /// On every path that returns <see langword="null"/> the lock's keeper is running
    /// (<see cref="ServingDatabaseLock.StartKeeping"/>). A systemd heartbeat extends the start
    /// timeout throughout.
    /// </para>
    /// </remarks>
    /// <param name="servingLock">This process's lock, not yet taken.</param>
    /// <param name="instance">The application database, for the messages.</param>
    /// <param name="config">The two wait budgets.</param>
    /// <param name="notifier">The systemd notifier, or null when not running under systemd.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<int?> TakeServingLockAsync(
        ServingDatabaseLock servingLock, DbInstance instance, SchemaConfig? config, ISystemdNotifier? notifier, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(servingLock);
        ArgumentNullException.ThrowIfNull(instance);
        config ??= new SchemaConfig();
        var restoreBudget = TimeSpan.FromSeconds(Math.Max(0, config.RestoreWaitSeconds));
        var reachBudget = TimeSpan.FromSeconds(Math.Max(0, config.WaitSeconds));
        await using var heartbeat = new Heartbeat(notifier, "Taking the restore lock", "Restore lock taken; checking the database schema");

        Stopwatch? restoreWait = null;
        Stopwatch? reachWait = null;
        var delay = FirstDelay;
        for (; ; )
        {
            var attempt = await servingLock.TryTakeAsync(ct);
            switch (attempt.Kind)
            {
                case ServingLockAttemptKind.Held:
                    if (restoreWait != null)
                        LockInfo($"The restore of the application database finished after {restoreWait.Elapsed.TotalSeconds:0} s; the start goes on.");
                    servingLock.StartKeeping();
                    return null;

                case ServingLockAttemptKind.Busy:
                    reachWait = null;
                    if (restoreWait == null)
                    {
                        restoreWait = Stopwatch.StartNew();
                        LockWarn($"A restore is running on the application database '{instance.Database}' on {instance.Host}:{instance.Port}. "
                            + $"This process does not start beside it: waiting up to {restoreBudget.TotalSeconds:0} s for the restore to finish (Schema.RestoreWaitSeconds).");
                        heartbeat.Update("Waiting for a restore of the application database to finish");
                    }
                    if (restoreWait.Elapsed >= restoreBudget)
                    {
                        LockError($"A restore of the application database '{instance.Database}' was still running after {restoreBudget.TotalSeconds:0} s "
                            + $"(Schema.RestoreWaitSeconds), so this process did not start. Exiting with status {TempFailExitCode} so the service manager "
                            + "starts it again; it starts once the restore has finished.");
                        return TempFailExitCode;
                    }
                    await Task.Delay(Min(RestoreLockPoll, restoreBudget - restoreWait.Elapsed), ct);
                    break;

                case ServingLockAttemptKind.Unreachable:
                    var cause = attempt.Error is null ? "no answer" : SchemaFailure.Describe(attempt.Error);
                    if (reachWait == null)
                    {
                        reachWait = Stopwatch.StartNew();
                        LockInfo($"Waiting: the application database at {instance.Host}:{instance.Port} cannot be reached ({cause}). "
                            + $"Giving up at {DateTimeOffset.Now + reachBudget:HH:mm:ss} (Schema.WaitSeconds).");
                        heartbeat.Update("Waiting for the application database to answer");
                    }
                    if (reachWait.Elapsed >= reachBudget)
                    {
                        LockError($"Gave up after {reachBudget.TotalSeconds:0} s (Schema.WaitSeconds): the application database at "
                            + $"{instance.Host}:{instance.Port} cannot be reached ({cause}). Exiting with status {TempFailExitCode} so the service manager retries.");
                        return TempFailExitCode;
                    }
                    await Task.Delay(Min(Jitter(delay), reachBudget - reachWait.Elapsed), ct);
                    delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, MaxDelay.Ticks));
                    break;

                default:
                    LockInfo("The restore lock was not taken: the application database is missing or refuses this role "
                        + $"({(attempt.Error is null ? "no detail" : SchemaFailure.Describe(attempt.Error))}). The schema check decides whether this start goes on; "
                        + "the lock is taken once the database answers.");
                    servingLock.StartKeeping();
                    return null;
            }
        }
    }

    /// <summary>
    /// Makes a serving process end itself, with <see cref="TempFailExitCode"/> (75), as soon as
    /// it finds that a restore took the application database while it was running: its lock
    /// connection had dropped and a restore got in meanwhile. What the process holds in memory is
    /// from before the restore, so it must not go on serving, with or without a health probe to
    /// notice. A service manager that restarts on failure (the packaged units restart on every
    /// status but 3 and 4) starts it again, and that start waits for the restore to finish.
    /// Where nothing restarts the process, it stays stopped until someone starts it.
    /// </summary>
    /// <param name="servingLock">This process's lock.</param>
    /// <param name="holder">"node" or "signer", for the message.</param>
    /// <param name="exit">Ends the process with the given status; replaced in tests.</param>
    public static void ExitWhenRestoreFoundBeside(ServingDatabaseLock servingLock, string holder, Action<int>? exit = null)
    {
        ArgumentNullException.ThrowIfNull(servingLock);
        exit ??= static code =>
        {
            Log.CloseAndFlush();
            Environment.Exit(code);
        };
        servingLock.RestoreFoundBeside = () =>
        {
            LockError($"A restore is running on the application database while this {holder} is running. What this process holds in memory "
                + $"is from before the restore, so it stops now. Exiting with status {TempFailExitCode} so the service manager starts it again; "
                + "it starts once the restore has finished.");
            exit(TempFailExitCode);
        };
    }

    /// <summary>The shorter of two waits, never negative.</summary>
    private static TimeSpan Min(TimeSpan a, TimeSpan b)
    {
        var shorter = a < b ? a : b;
        return shorter < TimeSpan.Zero ? TimeSpan.Zero : shorter;
    }

    /// <summary>Writes a give-up of the restore lock step to stderr and to Serilog.</summary>
    private static void LockError(string message)
    {
        Console.Error.WriteLine($"[ERROR] {message}");
        Log.Error("Restore lock: {Message}", message);
    }

    /// <summary>Writes a warning of the restore lock step to the console and to Serilog.</summary>
    private static void LockWarn(string message)
    {
        Console.WriteLine($"[WARNING] {message}");
        Log.Warning("Restore lock: {Message}", message);
    }

    /// <summary>Writes progress of the restore lock step to the console and to Serilog.</summary>
    private static void LockInfo(string message)
    {
        Console.WriteLine($"[STARTUP] {message}");
        Log.Information("Restore lock: {Message}", message);
    }
}
