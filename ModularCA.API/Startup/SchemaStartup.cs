using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting.Systemd;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Npgsql;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>One database the startup schema check covers.</summary>
/// <param name="Name">"application" or "audit", for the messages.</param>
/// <param name="Kind">Which database it is.</param>
/// <param name="Instance">Its <c>db.yaml</c> connection settings: the runtime role.</param>
public sealed record SchemaTarget(string Name, DatabaseKind Kind, DbInstance Instance);

/// <summary>What <c>--upgrade-check</c> concluded for one database.</summary>
public enum UpgradeReadiness
{
    /// <summary>The upgrade would apply cleanly, or there is nothing to apply.</summary>
    Clean,

    /// <summary>The control role's start would refuse, or the operator must act first.</summary>
    Refused,

    /// <summary>The database could not be reached, or was locked: try again.</summary>
    Unreachable,

    /// <summary>
    /// Migrations are pending and were not rehearsed: the read-only check
    /// (<c>--upgrade-check --read-only</c>) found nothing to refuse, and the full check must still run.
    /// </summary>
    PendingNotRehearsed,
}

/// <summary>
/// Applies <see cref="SchemaVersionGate"/> and <see cref="SchemaOwnership"/> at process start,
/// to every database the process uses, before anything is written to either.
/// </summary>
/// <remarks>
/// <para>
/// Phase 1 reads each database as its runtime role on a dedicated connection that gives up on a
/// lock after 3 s, so a read never queues behind the control role's migration lock. Phase 2
/// decides: a newer-than-build or unmanaged schema, a misconfiguration, or an object the role
/// cannot read stops the process with <see cref="ExitCode"/>, whatever the role; an unreachable
/// database, a migration in progress, or (a non-control role) migrations only the control role
/// applies are waited for, up to <c>Schema.WaitSeconds</c>, then the process exits with
/// <see cref="TempFailExitCode"/> so the service manager retries. The control role refuses to
/// migrate a database whose runtime role does not own it. Phase 3, the control role only, first
/// dry-runs every pending migration of the application database, then of the audit database
/// (<see cref="SchemaVersionGate.DryRunPendingAsync"/>, rolled back), and refuses having applied
/// nothing if one fails; it then applies the application database's migrations, then the audit
/// database's, each on its own connection with the migration time budget. A transient failure
/// in either step goes back to phase 1 after a backoff, within <c>Schema.WaitSeconds</c>, instead
/// of exiting. Phase 4 reads both again. A heartbeat extends the systemd start timeout every 20 s
/// through every phase.
/// </para>
/// <para>
/// A missing or empty database is not refused: bootstrap creates it, and the control role's
/// setup recovery owns that case. The runtime never creates a baseline. Setup mode never calls
/// this.
/// </para>
/// </remarks>
public static partial class SchemaStartup
{
    /// <summary>
    /// The exit code when the operator must act: a schema this build does not match, a
    /// misconfigured connection, broken ownership, or a migration that failed for good. An enabled
    /// HSM that cannot be initialised exits with it too: each restart would try the PIN again, and a
    /// wrong one locks a token after a few tries. From the schema step it also promises that the
    /// step applied nothing (see <see cref="AppliedThenFailedExitCode"/>). Units carry
    /// <c>RestartPreventExitStatus=3</c>; the node's, which alone applies migrations, <c>3 4</c>.
    /// </summary>
    public const int ExitCode = 3;

    /// <summary>
    /// The exit code when the operator must act and this start changed a database before it
    /// stopped: a migration committed, or may have, and then the schema step failed for good.
    /// <see cref="ExitCode"/> from the schema step therefore promises that the step applied
    /// nothing, so the previous release can run on the same data; this one says the data must be
    /// restored first, because migrations have no downgrade. An orchestrator that upgrades by
    /// stop, swap and start reads the two apart. <see cref="TempFailExitCode"/> makes no such
    /// promise either way: it asks for the same build to be started again. Only the role that
    /// applies migrations can return it; the node's unit carries <c>RestartPreventExitStatus=3 4</c>.
    /// </summary>
    public const int AppliedThenFailedExitCode = 4;

    /// <summary>
    /// The exit code the schema step stops with: <paramref name="exit"/>, except that a stop the
    /// operator must act on (<see cref="ExitCode"/>) becomes
    /// <see cref="AppliedThenFailedExitCode"/> when this start has changed a database.
    /// </summary>
    /// <param name="exit">The code the step arrived at.</param>
    /// <param name="changedADatabase">Whether a migration committed, or may have, in this start.</param>
    internal static int ExitAfter(int exit, bool changedADatabase)
        => changedADatabase && exit == ExitCode ? AppliedThenFailedExitCode : exit;

    /// <summary>What this start has done to the databases so far, across the retries of the schema step.</summary>
    private sealed class StartChanges
    {
        /// <summary>True once a migration committed, or may have.</summary>
        public bool ChangedADatabase;
    }

    /// <summary>
    /// The exit code for a condition that passes on its own (EX_TEMPFAIL): the wait ran out, or a
    /// migration failed on a lock, a deadlock or a lost connection. The service manager retries.
    /// </summary>
    public const int TempFailExitCode = 75;

    /// <summary>
    /// The exit code of <c>--upgrade-check --read-only</c> when migrations are pending and nothing
    /// it can read refuses them: nothing was rehearsed, no migration lock was taken, and the full
    /// <c>--upgrade-check</c> must still be run with the node stopped. Only that command returns
    /// it; a starting service never does, so no unit lists it in <c>RestartPreventExitStatus</c>.
    /// </summary>
    public const int PendingNotRehearsedExitCode = 5;

    /// <summary>
    /// What the last line of <c>--upgrade-check --read-only</c> starts with when it exits
    /// <see cref="PendingNotRehearsedExitCode"/>. Scripts match on it; it shares no prefix with the
    /// <c>UPGRADE CHECK: ...</c> verdict lines.
    /// </summary>
    public const string PendingNotRehearsedMarker = "UPGRADE PENDING, NOT REHEARSED";

    private const int GateConnectTimeoutSeconds = 10;
    private const int GateCommandTimeoutSeconds = 15;
    private const int GateLockTimeoutMilliseconds = 3000;
    private const int ReadOnlyCheckLockTimeoutMilliseconds = 500;
    private const long ExtendTimeoutMicroseconds = 90_000_000;
    private const long PostGateExtendTimeoutMicroseconds = 300_000_000;
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan ProgressLogInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(30);
    private static readonly AsyncLocal<Func<DatabaseKind, string, int, DbContext>?> ContextFactoryOverride = new();
    private static readonly AsyncLocal<TimeSpan?> HeartbeatIntervalOverride = new();

    /// <summary>
    /// Replaces the 20 s heartbeat interval, for the calling async flow only, or restores it
    /// when null. For tests that watch the heartbeat.
    /// </summary>
    internal static void UseHeartbeatInterval(TimeSpan? interval) => HeartbeatIntervalOverride.Value = interval;

    /// <summary>
    /// Replaces the contexts this class builds, for the calling async flow only, with
    /// <paramref name="factory"/> (kind, connection string, command timeout in seconds), or
    /// restores the real ones when null. For tests that need migrations of their own.
    /// </summary>
    internal static void UseContextFactory(Func<DatabaseKind, string, int, DbContext>? factory) =>
        ContextFactoryOverride.Value = factory;

    /// <summary>
    /// Checks every database in <paramref name="targets"/> against this build and, when
    /// <paramref name="appliesMigrations"/> is true, dry-runs everything pending in every database,
    /// then applies it, or refuses having applied nothing when a dry run fails. A refusal in one
    /// database does not stop the others' dry runs, so the journal lists every refusal found. A dry run or a
    /// migration that fails on a transient error (a lock timeout, a deadlock, a lost or refused
    /// connection) is retried in process, from phase 1, with backoff, for up to
    /// <c>Schema.WaitSeconds</c> from the first such failure. A systemd heartbeat runs throughout. Returns the exit code to
    /// stop with (<see cref="ExitCode"/>, <see cref="AppliedThenFailedExitCode"/> when the stop
    /// came after this start had changed a database, or <see cref="TempFailExitCode"/> once a
    /// wait or the retries run out), or <see langword="null"/> to continue starting.
    /// </summary>
    /// <param name="targets">The databases this process uses, the application database first.</param>
    /// <param name="appliesMigrations">True for the control role only.</param>
    /// <param name="config">The wait and migration time budgets.</param>
    /// <param name="notifier">The systemd notifier, or null when not running under systemd.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<int?> EnforceAllAsync(
        IReadOnlyList<SchemaTarget> targets,
        bool appliesMigrations,
        SchemaConfig? config,
        ISystemdNotifier? notifier,
        CancellationToken ct = default)
    {
        var changes = new StartChanges();
        var exit = await EnforceCoreAsync(targets, appliesMigrations, config, notifier, changes, ct);
        if (exit is not int code)
            return null;
        var final = ExitAfter(code, changes.ChangedADatabase);
        if (final == AppliedThenFailedExitCode)
            Fatal($"This start applied migrations before it stopped, so the databases are no longer as the previous release left them: "
                + $"exiting with status {AppliedThenFailedExitCode}, not {ExitCode}. Fix the cause and start this release again, "
                + "or restore both databases from the backup taken before the upgrade before running the previous release.");
        else if (code == TempFailExitCode && changes.ChangedADatabase)
            Warn("This start applied migrations before it stopped. Starting this release again continues from where it stopped; "
                + "the previous release cannot run on these databases without a restore.");
        return final;
    }

    /// <summary>
    /// <see cref="EnforceAllAsync"/> itself, recording in <paramref name="changes"/> whether a
    /// migration committed.
    /// </summary>
    private static async Task<int?> EnforceCoreAsync(
        IReadOnlyList<SchemaTarget> targets,
        bool appliesMigrations,
        SchemaConfig? config,
        ISystemdNotifier? notifier,
        StartChanges changes,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count == 0)
            return null;
        config ??= new SchemaConfig();
        var budget = TimeSpan.FromSeconds(Math.Max(0, config.WaitSeconds));
        await using var heartbeat = new Heartbeat(notifier, "Checking the database schema");

        Stopwatch? retrying = null;
        var retryDelay = FirstDelay;
        for (var pass = 1; ; pass++)
        {
            var window = retrying is null ? budget : budget - retrying.Elapsed;
            var observations = await WaitForDecisionAsync(targets, appliesMigrations, window, heartbeat, ct);
            if (observations.Exit is int waitExit)
                return waitExit;
            var observed = observations.Observed!;

            if (pass == 1)
            {
                foreach (var o in observed)
                {
                    if (o.Ownership is not { } report)
                        continue;
                    foreach (var warning in SchemaOwnership.Warnings(report))
                        Warn(warning);
                    if (!report.IsSound && o.Verdict != SchemaVerdict.ApplyPending)
                        Warn(SchemaOwnership.DriftWarning(report, o.Target.Instance.Port));
                }
            }

            var toApply = observed.Where(o => o.Verdict == SchemaVerdict.ApplyPending).ToList();
            if (toApply.Count == 0)
            {
                Info("Schema check passed: " + string.Join(", ", observed.Select(Summary)) + ".");
                return null;
            }

            foreach (var o in toApply)
            {
                await using var db = CreateMigrationContext(o.Target, config);
                if (db.Database.HasPendingModelChanges())
                {
                    Fatal($"This build's {o.Target.Name} model differs from its latest migration; the build is defective; "
                        + "nothing was applied to either database. Install a correct build.");
                    return ExitCode;
                }
            }

            string? transient = null;
            int? refused = null;
            foreach (var o in toApply)
            {
                var outcome = await DryRunAsync(o, config, heartbeat, ct);
                if (outcome.Exit is int dryRunExit)
                {
                    refused ??= dryRunExit;
                    continue;
                }
                if (outcome.Retry is { } retry && refused is null)
                {
                    transient = retry;
                    break;
                }
            }
            if (refused is int refusedExit)
                return refusedExit;
            foreach (var o in transient is null ? toApply : [])
            {
                var outcome = await ApplyAsync(o, config, heartbeat, ct);
                changes.ChangedADatabase |= outcome.ChangedDatabase;
                if (outcome.Exit is int applyExit)
                    return applyExit;
                if (outcome.Retry is { } retry)
                {
                    transient = retry;
                    break;
                }
            }
            if (transient is null)
                return await VerifyAsync(targets, observed, heartbeat, ct);

            retrying ??= Stopwatch.StartNew();
            var left = budget - retrying.Elapsed;
            if (left <= TimeSpan.Zero)
            {
                Fatal($"{transient} Retried for {budget.TotalSeconds:0} s (Schema.WaitSeconds) without success; "
                    + $"exiting with status {TempFailExitCode} so the service manager retries.");
                return TempFailExitCode;
            }
            var sleep = Jitter(retryDelay);
            if (sleep > left)
                sleep = left;
            Warn($"{transient} This is expected to pass: retrying in {sleep.TotalSeconds:0} s; "
                + $"giving up at {DateTimeOffset.Now + left:HH:mm:ss} (Schema.WaitSeconds).");
            heartbeat.Update("Retrying a migration that failed on a transient error");
            await Task.Delay(sleep, ct);
            retryDelay = TimeSpan.FromTicks(Math.Min(retryDelay.Ticks * 2, MaxDelay.Ticks));
        }
    }

    /// <summary>
    /// The read-only <c>--db-ownership check</c> verb: probes each database as its runtime role,
    /// prints the report, the warnings and the repair. Returns 0 when every database is sound,
    /// <see cref="ExitCode"/> otherwise. Changes nothing.
    /// </summary>
    /// <param name="targets">The databases to check.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<int> CheckOwnershipAsync(IReadOnlyList<SchemaTarget> targets, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var sound = true;
        foreach (var target in targets)
        {
            await using var db = CreateContext(target.Kind, GateReadConnectionString(target.Instance), GateCommandTimeoutSeconds);
            OwnershipReport report;
            try
            {
                report = await SchemaOwnership.ProbeAsync(db.Database.GetDbConnection(), target.Kind, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                Console.Error.WriteLine($"{target.Name}: could not be read as '{target.Instance.Username}': {SchemaFailure.Describe(ex)}");
                sound = false;
                continue;
            }
            Console.WriteLine($"{target.Name}: database '{report.Database}', role '{report.Role}', database owner '{report.DatabaseOwner}', "
                + $"PostgreSQL {report.ServerVersionNum / 10000}");
            Console.WriteLine($"  objects not owned: {report.NotOwned.Count}; can create tables: {Yes(report.CanCreateTables)}; "
                + $"can create schemas: {Yes(report.CanCreateSchema)}; can become database owner: {Yes(report.CanBecomeDbOwner)}; "
                + $"administrative attributes: {Yes(report.AdminAttributes)}");
            foreach (var o in report.NotOwned.Take(50))
                Console.WriteLine($"    {o.Object} ({o.Kind}) owned by {o.Owner}{(o.Usable ? "" : ", not readable")}");
            if (report.NotOwned.Count > 50)
                Console.WriteLine($"    ... and {report.NotOwned.Count - 50} more");
            foreach (var warning in SchemaOwnership.Warnings(report))
                Console.WriteLine($"  warning: {warning}");
            if (report.IsSound)
            {
                Console.WriteLine("  sound: the control role can migrate this database.");
                continue;
            }
            sound = false;
            Console.WriteLine("  NOT sound: " + SchemaOwnership.DriftWarning(report, target.Instance.Port));
        }
        return sound ? 0 : ExitCode;
    }

    /// <summary>
    /// The <c>--upgrade-check</c> verb: reads each database as its runtime role, as phase 1 does,
    /// and where migrations are pending checks the model and dry-runs them on the migration
    /// connection (<see cref="SchemaVersionGate.DryRunPendingAsync"/>, rolled back). Prints each
    /// database's schema, ownership and dry-run result, every refusal the dry run found listed
    /// with its message, then a one-line verdict. Applies nothing. Returns
    /// <see cref="UpgradeCheckExitCode"/> of the findings.
    /// <para>
    /// With <paramref name="scopes"/>, the integration keys' configured <c>SpaceId</c> values, it
    /// also refuses a key fenced to a scope the pending migrations delete, or to a space that does
    /// not exist, as on a host checked after another one already upgraded the database
    /// (<see cref="FoldedScopeFindingAsync"/>), read-only.
    /// </para>
    /// <para>
    /// With <paramref name="installDirectory"/> it also reports the SSH CA keys that are still
    /// files on the node (<see cref="SshUpgradeAsync"/>): how many the first start will import
    /// into the signer, or a refusal naming each enabled SSH CA whose key file is missing or is
    /// not its key on this host. It then notes, without refusing, the SSH signing profiles
    /// whose certificates carry fewer extensions now that none is added by default, and, where
    /// there is an SSH CA key, what SSH login names change for requests and how many live user
    /// certificates carry a name other than their key id.
    /// </para>
    /// <para>
    /// With an audit database among the targets it also notes, without refusing, which
    /// certificates the enrollment protocols issued in the last
    /// <see cref="ModularCA.Core.Services.RequestProfileUpgradeCheck.Days"/> days would be refused
    /// if requested again under the request profile each protocol uses now
    /// (<see cref="RequestProfileUpgradeNoteAsync"/>).
    /// </para>
    /// <para>
    /// With <paramref name="readOnly"/> (<c>--upgrade-check --read-only</c>) it does all of the
    /// above except the dry run, for running beside a node that is still serving. Every connection
    /// it opens is the read-only check connection (<see cref="ReadOnlyCheckConnectionString"/>):
    /// the server refuses a write on it, and a statement gives up on a lock after
    /// <c>500 ms</c>. No migration connection is opened, so no migration lock is taken and nothing
    /// is rehearsed. Where migrations are pending and nothing read refuses them, the database's
    /// finding is <see cref="UpgradeReadiness.PendingNotRehearsed"/>, the last line starts with
    /// <see cref="PendingNotRehearsedMarker"/> and lists the pending migrations of each database,
    /// and the exit status is <see cref="PendingNotRehearsedExitCode"/>. What only the dry run can
    /// find (a migration's own refusal on the data, a statement that fails or times out) is not
    /// found.
    /// </para>
    /// </summary>
    /// <param name="targets">The databases the control role checks, the application database first.</param>
    /// <param name="config">The migration time budgets the dry run runs under.</param>
    /// <param name="output">Where the report goes; the console when null.</param>
    /// <param name="scopes">The integration keys whose <c>SpaceId</c> is set, by config key name; none when null.</param>
    /// <param name="installDirectory">The installed application directory, the parent of the config directory checked; null to leave the SSH CA keys out.</param>
    /// <param name="readOnly">True to read only: no dry run, no migration lock, no write.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<int> UpgradeCheckAsync(
        IReadOnlyList<SchemaTarget> targets, SchemaConfig? config, TextWriter? output = null,
        IReadOnlyList<(string Key, string Value)>? scopes = null, string? installDirectory = null,
        bool readOnly = false, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        config ??= new SchemaConfig();
        output ??= Console.Out;
        var findings = new List<UpgradeFinding>();
        Observation? application = null;
        Observation? audit = null;
        foreach (var target in targets)
        {
            var instance = target.Instance;
            output.WriteLine($"{target.Name}: database '{instance.Database}' on {instance.Host}:{instance.Port} as '{instance.Username}'");
            var observed = await ObserveAsync(target, appliesMigrations: true, ct, readOnly);
            if (target.Kind == DatabaseKind.Application)
                application = observed;
            else if (target.Kind == DatabaseKind.Audit)
                audit = observed;
            Report(output, await AssessUpgradeAsync(observed, config, output, readOnly, ct), findings);
        }
        if (scopes is { Count: > 0 } && application is { State.Presence: DatabasePresence.Managed or DatabasePresence.Unmanaged })
        {
            output.WriteLine("configuration: integration key scopes");
            Report(output, await FoldedScopeFindingAsync(application.Target, scopes, readOnly, ct), findings);
        }
        if (installDirectory != null && application is { State.Presence: DatabasePresence.Managed or DatabasePresence.Unmanaged })
        {
            output.WriteLine($"{ModularCA.Core.Services.SshUpgradeCheck.KeysFindingName}: key files on this host, under {installDirectory}");
            var ssh = await SshUpgradeAsync(application.Target, installDirectory, readOnly, ct);
            Report(output, ssh.Keys, findings);
            if (ssh.ProfilesNote != null)
            {
                output.WriteLine("SSH signing profiles");
                output.WriteLine("  note: " + ssh.ProfilesNote.ReplaceLineEndings(Environment.NewLine + "    "));
            }
            if (ssh.LoginNamesNote != null)
            {
                output.WriteLine("SSH login names");
                output.WriteLine("  note: " + ssh.LoginNamesNote.ReplaceLineEndings(Environment.NewLine + "    "));
            }
        }
        if (application is { State.Presence: DatabasePresence.Managed or DatabasePresence.Unmanaged }
            && audit is { State.Presence: DatabasePresence.Managed or DatabasePresence.Unmanaged })
        {
            var note = await RequestProfileUpgradeNoteAsync(application.Target, audit.Target, readOnly, ct);
            if (note != null)
            {
                output.WriteLine(ModularCA.Core.Services.RequestProfileUpgradeCheck.NoteName);
                output.WriteLine("  note: " + note.ReplaceLineEndings(Environment.NewLine + "    "));
            }
        }
        output.WriteLine(UpgradeCheckVerdict(findings));
        return UpgradeCheckExitCode(findings.Select(f => f.Readiness));
    }

    /// <summary>Prints <paramref name="finding"/>'s readiness and detail, and adds it to <paramref name="findings"/>.</summary>
    private static void Report(TextWriter output, UpgradeFinding finding, List<UpgradeFinding> findings)
    {
        output.WriteLine($"  {finding.Readiness switch
        {
            UpgradeReadiness.Clean => "ok",
            UpgradeReadiness.Refused => "REFUSED",
            UpgradeReadiness.PendingNotRehearsed => "PENDING, NOT REHEARSED",
            _ => "UNREACHABLE",
        }}: {finding.Detail.ReplaceLineEndings(Environment.NewLine + "    ")}");
        findings.Add(finding);
    }

    /// <summary>
    /// The exit status of <c>--upgrade-check</c>: <see cref="ExitCode"/> when any database would
    /// be refused, otherwise <see cref="TempFailExitCode"/> when any could not be reached or was
    /// locked, otherwise <see cref="PendingNotRehearsedExitCode"/> when the read-only check left
    /// any database's pending migrations unrehearsed, otherwise 0.
    /// </summary>
    internal static int UpgradeCheckExitCode(IEnumerable<UpgradeReadiness> readiness)
    {
        var all = readiness.ToList();
        return all.Contains(UpgradeReadiness.Refused) ? ExitCode
            : all.Contains(UpgradeReadiness.Unreachable) ? TempFailExitCode
            : all.Contains(UpgradeReadiness.PendingNotRehearsed) ? PendingNotRehearsedExitCode
            : 0;
    }

    /// <summary>
    /// The final one-line verdict of <c>--upgrade-check</c>. The read-only check's "pending, not
    /// rehearsed" line starts with <see cref="PendingNotRehearsedMarker"/>, not with
    /// <c>UPGRADE CHECK:</c>, and lists each database's pending migrations.
    /// </summary>
    internal static string UpgradeCheckVerdict(IReadOnlyList<UpgradeFinding> findings)
    {
        string Of(UpgradeReadiness r) => string.Join("; ", findings.Where(f => f.Readiness == r).Select(f => f.Summary));
        return UpgradeCheckExitCode(findings.Select(f => f.Readiness)) switch
        {
            ExitCode => $"UPGRADE CHECK: REFUSED ({Of(UpgradeReadiness.Refused)}). Nothing was changed.",
            TempFailExitCode => $"UPGRADE CHECK: UNREACHABLE ({Of(UpgradeReadiness.Unreachable)}); try again. Nothing was changed.",
            PendingNotRehearsedExitCode => $"{PendingNotRehearsedMarker} ({Of(UpgradeReadiness.PendingNotRehearsed)}). "
                + "Nothing was rehearsed and nothing was changed: stop the node and run --upgrade-check without --read-only before upgrading.",
            _ => findings.Sum(f => f.Pending) is var n and > 0
                ? $"UPGRADE CHECK: PASS ({n} pending migration(s) would apply cleanly). Nothing was changed."
                : "UPGRADE CHECK: PASS (nothing to apply). Nothing was changed.",
        };
    }

    /// <summary>
    /// What <c>--upgrade-check</c> concludes for one database from <paramref name="o"/>, refusing
    /// exactly what the control role's start refuses, and an unsound ownership even with nothing
    /// pending. Prints the schema, ownership and dry-run lines to <paramref name="output"/> as it goes.
    /// A dry run that found a refusal is refused even when it then stopped on a transient error.
    /// With <paramref name="readOnly"/> nothing is rehearsed and no migration connection is opened:
    /// pending migrations are checked only for what this build alone decides (a model that differs
    /// from its latest migration, a migration with a statement outside a transaction, which the dry
    /// run could not rehearse either) and are otherwise reported as
    /// <see cref="UpgradeReadiness.PendingNotRehearsed"/>.
    /// </summary>
    private static async Task<UpgradeFinding> AssessUpgradeAsync(
        Observation o, SchemaConfig config, TextWriter output, bool readOnly, CancellationToken ct)
    {
        var name = o.Target.Name;
        var port = o.Target.Instance.Port;
        UpgradeFinding Refuse(string summary, string detail) => new(name, UpgradeReadiness.Refused, $"{name}: {summary}", detail, 0);

        if (o.Failure is SchemaFailureKind.Unreachable or SchemaFailureKind.MigrationInProgress)
        {
            var why = o.Failure == SchemaFailureKind.Unreachable ? "cannot be reached" : "is locked, most likely by a migration in progress";
            return new(name, UpgradeReadiness.Unreachable, $"{name} {why}", $"The {name} database {why}: {SchemaFailure.Describe(o.Error!)}.", 0);
        }
        if (o.Failure == SchemaFailureKind.Misconfigured)
            return Refuse("could not be read", MisconfiguredMessage(o));

        var state = o.State!;
        output.WriteLine("  schema: " + (state.Presence switch
        {
            DatabasePresence.Missing => "the database does not exist (bootstrap creates it)",
            DatabasePresence.Empty => "no tables (bootstrap creates the schema)",
            DatabasePresence.Unmanaged => "tables but no migration history",
            _ when state.Unknown.Count > 0 => $"newer than this build: {string.Join(", ", state.Unknown)}",
            _ when state.Pending.Count > 0 => $"{state.Applied.Count} applied; {state.Pending.Count} pending: {string.Join(", ", state.Pending)}",
            _ => $"current ({state.Applied.Count} applied)",
        }));
        if (o.Ownership is { } report)
        {
            output.WriteLine($"  ownership: {(report.IsSound ? "sound" : "NOT sound")}; objects not owned by '{report.Role}': {report.NotOwned.Count}; "
                + $"PostgreSQL {report.ServerVersionNum / 10000}");
            foreach (var warning in SchemaOwnership.Warnings(report))
                output.WriteLine($"  warning: {warning}");
            if (report.ServerVersionNum < PostgresRoleLayout.MinimumServerVersionNum)
                return Refuse("PostgreSQL too old", $"The {name} database runs on PostgreSQL {report.ServerVersionNum / 10000}; this release needs PostgreSQL 14 or later.");
        }
        if (o.Verdict is SchemaVerdict.NewerThanBuild or SchemaVerdict.Unmanaged)
            return Refuse(o.Verdict == SchemaVerdict.NewerThanBuild ? "schema newer than this build" : "tables but no migration history",
                SchemaVersionGate.RefusalMessage(o.Verdict.Value, state, name)!);
        if (o.Ownership is { IsSound: false } unsound)
            return Refuse("ownership not sound", unsound.Unusable || state.Pending.Count > 0
                ? SchemaOwnership.RefusalMessage(unsound, state.Pending, port)
                : SchemaOwnership.DriftWarning(unsound, port));
        if (o.Verdict == SchemaVerdict.Unbootstrapped)
            return new(name, UpgradeReadiness.Clean, name, "nothing to upgrade: bootstrap creates this database's schema.", 0);
        if (o.Verdict != SchemaVerdict.ApplyPending)
            return new(name, UpgradeReadiness.Clean, name, "current: nothing to apply.", 0);

        // The read-only check never builds a migration connection: this context is only asked about
        // its model and its migrations' commands, and is never opened.
        await using var db = readOnly
            ? CreateContext(o.Target.Kind, ReadOnlyCheckConnectionString(o.Target.Instance), GateCommandTimeoutSeconds)
            : CreateMigrationContext(o.Target, config);
        if (db.Database.HasPendingModelChanges())
            return Refuse("defective build", $"This build's {name} model differs from its latest migration; the build is defective.");
        if (readOnly)
        {
            if (FirstNotRehearsable(db, state.Pending) is { } outsideTransaction)
            {
                var unrehearsable = new DryRunResult(state.Pending, [], outsideTransaction, null, NotRehearsable: true);
                return Refuse(SchemaVersionGate.DryRunSummary(unrehearsable), SchemaVersionGate.DryRunFailedMessage(name, unrehearsable));
            }
            var ids = string.Join(", ", state.Pending);
            output.WriteLine("  dry run: not run (--read-only); no migration lock was taken.");
            return new(name, UpgradeReadiness.PendingNotRehearsed, $"{name}: {ids}",
                $"{state.Pending.Count} migration(s) pending: {ids}. Nothing was rehearsed: whether they apply cleanly is not known "
                + "until --upgrade-check runs without --read-only, with the node stopped.", 0);
        }
        var timeout = config.MigrationCommandTimeoutSeconds > 0 ? config.MigrationCommandTimeoutSeconds : (int?)null;
        var result = await SchemaVersionGate.DryRunPendingAsync(db, ct);
        if (result.Passed)
        {
            output.WriteLine($"  dry run: passed; {result.Rehearsed.Count} migration(s) ran in one transaction and were rolled back.");
            return new(name, UpgradeReadiness.Clean, name, $"would apply {result.Rehearsed.Count} migration(s) cleanly.", result.Rehearsed.Count);
        }
        var message = SchemaVersionGate.DryRunFailedMessage(name, result, timeout);
        var summary = SchemaVersionGate.DryRunSummary(result);
        output.WriteLine("  dry run: " + summary);
        if (result.Refusals.Count == 0 && result.Error is { } error && SchemaFailure.TransientForMigration(error))
            return new(name, UpgradeReadiness.Unreachable, $"{name} dry run hit a transient error", message, 0);
        return Refuse(summary, message);
    }

    /// <summary>
    /// The first of <paramref name="pending"/> that runs a statement outside a transaction, which
    /// the dry run refuses to rehearse, or null when none does or it cannot be told. Decided from
    /// the migrations' generated commands (<see cref="SchemaVersionGate.UpCommands"/>), as the dry
    /// run decides it, without a connection.
    /// </summary>
    private static string? FirstNotRehearsable(DbContext db, IReadOnlyList<string> pending)
    {
        try
        {
            return pending.FirstOrDefault(id => SchemaVersionGate.UpCommands(db, id).Any(c => c.TransactionSuppressed));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>What <c>--upgrade-check</c> concluded for one database.</summary>
    /// <param name="Name">The database, as named in the messages.</param>
    /// <param name="Readiness">The conclusion.</param>
    /// <param name="Summary">A few words for the one-line verdict.</param>
    /// <param name="Detail">The full reason, with its fix.</param>
    /// <param name="Pending">The migrations that would apply cleanly.</param>
    internal sealed record UpgradeFinding(string Name, UpgradeReadiness Readiness, string Summary, string Detail, int Pending);

    /// <summary>What phase 1 saw for one database.</summary>
    private sealed class Observation(SchemaTarget target)
    {
        public SchemaTarget Target { get; } = target;
        public SchemaState? State { get; set; }
        public SchemaVerdict? Verdict { get; set; }
        public OwnershipReport? Ownership { get; set; }
        public Exception? Error { get; set; }
        public SchemaFailureKind? Failure { get; set; }
    }

    /// <summary>How phases 1 and 2 ended: an exit code, or the observations to proceed with.</summary>
    private sealed record WaitOutcome(int? Exit, IReadOnlyList<Observation>? Observed);

    /// <summary>What phase 2 concluded.</summary>
    private enum Decision { Proceed, Wait, Refuse }

    /// <summary>
    /// Runs phases 1 and 2 until they reach a decision: refuse, proceed, or give up waiting
    /// after <paramref name="budget"/>. Backs off from 2 s to 30 s with jitter, updates the
    /// heartbeat's status on every attempt, and logs progress at most once a minute unless the
    /// state changes.
    /// </summary>
    private static async Task<WaitOutcome> WaitForDecisionAsync(
        IReadOnlyList<SchemaTarget> targets, bool appliesMigrations, TimeSpan budget,
        Heartbeat heartbeat, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        if (budget < TimeSpan.Zero)
            budget = TimeSpan.Zero;
        var giveUpAt = DateTimeOffset.Now + budget;
        var delay = FirstDelay;
        string? lastState = null;
        var lastLog = TimeSpan.MinValue;
        for (var attempt = 1; ; attempt++)
        {
            heartbeat.Update(attempt == 1 ? "Checking the database schema" : $"Checking the database schema (attempt {attempt})");
            var observed = new List<Observation>();
            foreach (var target in targets)
                observed.Add(await ObserveAsync(target, appliesMigrations, ct));

            var (decision, messages) = Decide(observed, appliesMigrations);
            if (decision == Decision.Refuse)
            {
                foreach (var message in messages)
                    Fatal(message);
                return new WaitOutcome(ExitCode, null);
            }
            if (decision == Decision.Proceed)
            {
                if (attempt > 1)
                    Info($"The databases are ready after {clock.Elapsed.TotalSeconds:0} s.");
                return new WaitOutcome(null, observed);
            }

            var reason = string.Join(" ", messages);
            if (clock.Elapsed >= budget)
            {
                Error($"Gave up after {budget.TotalSeconds:0} s (Schema.WaitSeconds): {reason} "
                    + $"Exiting with status {TempFailExitCode} so the service manager retries.");
                return new WaitOutcome(TempFailExitCode, null);
            }

            var sleep = Jitter(delay);
            var remaining = budget - clock.Elapsed;
            if (sleep > remaining)
                sleep = remaining;
            var state = string.Join("|", observed.Select(o => $"{o.Target.Name}:{o.Failure?.ToString() ?? o.Verdict?.ToString()}"));
            if (state != lastState || clock.Elapsed - lastLog >= ProgressLogInterval)
            {
                Info($"Waiting: {reason} Attempt {attempt}; next check in {sleep.TotalSeconds:0} s; giving up at {giveUpAt:HH:mm:ss}.");
                lastState = state;
                lastLog = clock.Elapsed;
            }
            heartbeat.Update("Waiting: " + reason);
            await Task.Delay(sleep, ct);
            delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, MaxDelay.Ticks));
        }
    }

    /// <summary>
    /// Phase 1 for one database: reads presence and history, then the ownership report, as the
    /// runtime role on a gate-read connection, or on the read-only check connection with
    /// <paramref name="readOnlyCheck"/>. Failures are recorded and classified, not thrown.
    /// </summary>
    private static async Task<Observation> ObserveAsync(
        SchemaTarget target, bool appliesMigrations, CancellationToken ct, bool readOnlyCheck = false)
    {
        var o = new Observation(target);
        await using var db = CreateContext(target.Kind, CheckReadConnectionString(target.Instance, readOnlyCheck), GateCommandTimeoutSeconds);
        try
        {
            o.State = await SchemaVersionGate.ReadAsync(db, ct);
            o.Verdict = SchemaVersionGate.Evaluate(o.State, appliesMigrations);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            o.Error = ex;
            o.Failure = SchemaFailure.Classify(ex);
        }

        if (o.Failure == SchemaFailureKind.Missing)
        {
            o.State = new SchemaState([], db.Database.GetMigrations().ToList()) { Presence = DatabasePresence.Missing };
            o.Verdict = SchemaVerdict.Unbootstrapped;
            o.Error = null;
            o.Failure = null;
        }

        var probe = o.State is { Presence: DatabasePresence.Managed or DatabasePresence.Unmanaged }
            || (o.Failure == SchemaFailureKind.Misconfigured && o.Error is not SchemaConnectException);
        if (probe)
        {
            try
            {
                o.Ownership = await SchemaOwnership.ProbeAsync(db.Database.GetDbConnection(), target.Kind, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (o.Error is null)
                {
                    o.Error = ex;
                    o.Failure = SchemaFailure.Classify(ex);
                }
            }
        }
        return o;
    }

    /// <summary>
    /// Phase 2: refuse on anything the operator must fix, in either database; wait on anything
    /// that passes on its own; otherwise proceed. The control role also refuses to migrate a
    /// database its runtime role does not own, before anything is applied to either.
    /// </summary>
    private static (Decision Decision, IReadOnlyList<string> Messages) Decide(IReadOnlyList<Observation> observed, bool appliesMigrations)
    {
        var refusals = new List<string>();
        foreach (var o in observed)
        {
            var port = o.Target.Instance.Port;
            if (o.Failure == SchemaFailureKind.Misconfigured)
            {
                refusals.Add(MisconfiguredMessage(o));
                continue;
            }
            if (o.Ownership is { } version && version.ServerVersionNum < PostgresRoleLayout.MinimumServerVersionNum)
                refusals.Add($"The {o.Target.Name} database runs on PostgreSQL {version.ServerVersionNum / 10000}; "
                    + "this release needs PostgreSQL 14 or later. Nothing was applied to either database.");
            if (o.Verdict is SchemaVerdict.NewerThanBuild or SchemaVerdict.Unmanaged)
                refusals.Add(SchemaVersionGate.RefusalMessage(o.Verdict.Value, o.State!, o.Target.Name)!);
            if (o.Ownership is { Unusable: true } unusable)
                refusals.Add(SchemaOwnership.RefusalMessage(unusable, o.State?.Pending, port));
        }
        if (refusals.Count > 0)
            return (Decision.Refuse, refusals);

        var waits = new List<string>();
        foreach (var o in observed)
        {
            var instance = o.Target.Instance;
            switch (o.Failure)
            {
                case SchemaFailureKind.MigrationInProgress:
                    waits.Add($"The {o.Target.Name} database is locked, most likely by a migration in progress ({SchemaFailure.Describe(o.Error!)}).");
                    continue;
                case SchemaFailureKind.Unreachable:
                    waits.Add($"The {o.Target.Name} database at {instance.Host}:{instance.Port} cannot be reached ({SchemaFailure.Describe(o.Error!)}).");
                    continue;
            }
            if (!appliesMigrations && o.Verdict == SchemaVerdict.PendingForControlRole)
                waits.Add(SchemaVersionGate.RefusalMessage(SchemaVerdict.PendingForControlRole, o.State!, o.Target.Name)!);
        }
        if (waits.Count > 0)
            return (Decision.Wait, waits);

        if (appliesMigrations)
        {
            var unsound = observed
                .Where(o => o.Verdict == SchemaVerdict.ApplyPending && o.Ownership is { IsSound: false })
                .Select(o => SchemaOwnership.RefusalMessage(o.Ownership!, o.State!.Pending, o.Target.Instance.Port))
                .ToList();
            if (unsound.Count > 0)
                return (Decision.Refuse, unsound);
        }
        return (Decision.Proceed, []);
    }

    /// <summary>The refusal for a misconfigured connection or an unreadable schema, with its likely fix.</summary>
    private static string MisconfiguredMessage(Observation o)
    {
        var instance = o.Target.Instance;
        var cause = SchemaFailure.Describe(o.Error!);
        if (o.Ownership is { IsSound: false } report)
            return $"The {o.Target.Name} database could not be read: {cause}. "
                + SchemaOwnership.RefusalMessage(report, o.State?.Pending, instance.Port);
        var hint = SchemaFailure.SqlState(o.Error!) switch
        {
            "28P01" => " Check the password for this role in db.yaml.",
            "28000" => " PostgreSQL refused the login: allow this role from this host in pg_hba.conf.",
            "42501" => " The role lacks a privilege it needs on its own database.",
            _ when SchemaFailure.IsTlsFailure(o.Error!) => " TLS failed: check SslMode in db.yaml and the server certificate.",
            _ => "",
        };
        return $"The {o.Target.Name} database '{instance.Database}' on {instance.Host}:{instance.Port} could not be read as "
            + $"'{instance.Username}': {cause}.{hint} Nothing was applied to either database.";
    }

    /// <summary>How a step of phase 3 ended for one database: an exit code, a transient failure to retry, or neither when it passed.</summary>
    private sealed record ApplyOutcome(int? Exit, string? Retry)
    {
        /// <summary>True when the step committed a migration, or may have. Never true for a dry run.</summary>
        public bool ChangedDatabase { get; init; }

        /// <summary>The dry run passed: nothing was applied.</summary>
        public static readonly ApplyOutcome Applied = new(null, null);

        /// <summary>Every pending migration of the database was applied.</summary>
        public static readonly ApplyOutcome Migrated = new(null, null) { ChangedDatabase = true };
    }

    /// <summary>
    /// The first step of phase 3 for one database: rehearses every pending migration in one
    /// transaction on a migration connection and rolls it back. Refusals, listed in one message
    /// with everything else the dry run found, or a migration that cannot be rehearsed, return
    /// <see cref="ExitCode"/> with nothing applied to either database; a transient failure with no
    /// refusal before it returns its description for the caller to retry.
    /// </summary>
    private static async Task<ApplyOutcome> DryRunAsync(Observation o, SchemaConfig config, Heartbeat heartbeat, CancellationToken ct)
    {
        var name = o.Target.Name;
        heartbeat.Update($"Dry-running {o.State!.Pending.Count} {name} migration(s)");
        DryRunResult result;
        await using (var db = CreateMigrationContext(o.Target, config))
            result = await SchemaVersionGate.DryRunPendingAsync(db, ct);

        var timeout = config.MigrationCommandTimeoutSeconds > 0 ? config.MigrationCommandTimeoutSeconds : (int?)null;
        if (result.Passed)
        {
            Info($"Dry run passed: {result.Rehearsed.Count} {name} migration(s) ran in one transaction and were rolled back.");
            return ApplyOutcome.Applied;
        }
        var message = SchemaVersionGate.DryRunFailedMessage(name, result, timeout, "either database");
        if (result.Refusals.Count == 0 && result.Error is { } error && SchemaFailure.TransientForMigration(error))
            return new ApplyOutcome(null, message);
        var advice = result.Error is { } e && SchemaFailure.IsStatementTimeout(e)
            ? " If the statement needs longer, raise Schema.MigrationCommandTimeoutSeconds (0 means no limit)."
            : "";
        Fatal(message + " Fix the cause and start again, or run the previous release." + advice);
        if (result.Error is not null)
            Log.Fatal(result.Error, "The dry run of the {Context} database failed at {Migration}", name, result.Migration ?? "(before any migration)");
        return new ApplyOutcome(ExitCode, null);
    }

    /// <summary>
    /// Phase 3 for one database: applies its pending migrations on a migration connection while
    /// the heartbeat extends the systemd start timeout. A failure the operator must fix returns
    /// <see cref="ExitCode"/>; a transient one returns its description for the caller to retry.
    /// Every outcome says whether a migration committed, or may have
    /// (<see cref="ApplyOutcome.ChangedDatabase"/>), which the caller turns into
    /// <see cref="AppliedThenFailedExitCode"/> when the start then stops for good.
    /// </summary>
    private static async Task<ApplyOutcome> ApplyAsync(Observation o, SchemaConfig config, Heartbeat heartbeat, CancellationToken ct)
    {
        var pending = o.State!.Pending;
        var name = o.Target.Name;
        Info($"Applying {pending.Count} {name} migration(s): {string.Join(", ", pending)}");
        heartbeat.Update($"Applying {pending.Count} {name} migration(s)");
        MigrationFailure? failure = null;
        Exception? thrown = null;
        await using (var db = CreateMigrationContext(o.Target, config))
        {
            try
            {
                failure = await SchemaVersionGate.ApplyPendingAsync(db, o.State, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                thrown = ex;
            }
        }

        var timeout = config.MigrationCommandTimeoutSeconds > 0 ? config.MigrationCommandTimeoutSeconds : (int?)null;
        if (thrown is not null)
        {
            // The history is read before each migration, so one may have committed before this read failed.
            var message = $"The {name} migration history could not be read while applying migrations: {SchemaFailure.Describe(thrown, timeout)}.";
            if (SchemaFailure.TransientForMigration(thrown))
                return new ApplyOutcome(null, message) { ChangedDatabase = true };
            Fatal(message + " Fix the cause and start again.");
            return new ApplyOutcome(ExitCode, null) { ChangedDatabase = true };
        }
        if (failure is not null)
        {
            var message = SchemaVersionGate.MigrationFailedMessage(name, failure, timeout);
            if (SchemaFailure.TransientForMigration(failure.Error))
            {
                Log.Warning(failure.Error, "Migration {Migration} of the {Context} database failed on a transient error", failure.Migration, name);
                return new ApplyOutcome(null, message) { ChangedDatabase = failure.MayHaveChangedDatabase };
            }
            var advice = SchemaFailure.IsStatementTimeout(failure.Error)
                ? " If the statement needs longer, raise Schema.MigrationCommandTimeoutSeconds (0 means no limit)."
                : "";
            Fatal(message + advice);
            Log.Fatal(failure.Error, "Migration {Migration} of the {Context} database failed", failure.Migration, name);
            return new ApplyOutcome(ExitCode, null) { ChangedDatabase = failure.MayHaveChangedDatabase };
        }
        Info($"{name} migrations applied.");
        return ApplyOutcome.Migrated;
    }

    /// <summary>
    /// Phase 4: reads every database again. A database that was migrated must now be current;
    /// the others must not have changed verdict.
    /// </summary>
    private static async Task<int?> VerifyAsync(
        IReadOnlyList<SchemaTarget> targets, IReadOnlyList<Observation> before, Heartbeat heartbeat, CancellationToken ct)
    {
        heartbeat.Update("Verifying the database schema");
        var summaries = new List<string>();
        foreach (var target in targets)
        {
            var o = await ObserveAsync(target, appliesMigrations: true, ct);
            var expected = before.First(b => b.Target == target).Verdict == SchemaVerdict.Unbootstrapped
                ? SchemaVerdict.Unbootstrapped
                : SchemaVerdict.Current;
            if (o.Error is not null)
            {
                var retry = SchemaFailure.Transient(o.Error);
                Fatal($"The {target.Name} database could not be read after migrating: {SchemaFailure.Describe(o.Error)}.");
                return retry ? TempFailExitCode : ExitCode;
            }
            if (o.Verdict != expected)
            {
                Fatal($"The {target.Name} database is {o.Verdict} after migrating, not {expected}. "
                    + (o.State is { } s ? $"Applied: {string.Join(", ", s.Applied)}; pending: {string.Join(", ", s.Pending)}. " : "")
                    + "The service will not start on a schema this build does not match.");
                return ExitCode;
            }
            summaries.Add(Summary(o));
        }
        Info("Schema check passed: " + string.Join(", ", summaries) + ".");
        return null;
    }

    /// <summary>"application current", "audit missing", and so on.</summary>
    private static string Summary(Observation o) => o.Verdict switch
    {
        SchemaVerdict.Unbootstrapped when o.State?.Presence == DatabasePresence.Missing =>
            $"{o.Target.Name} does not exist yet (bootstrap creates it)",
        SchemaVerdict.Unbootstrapped => $"{o.Target.Name} is empty (bootstrap creates the schema)",
        SchemaVerdict.Current => $"{o.Target.Name} current",
        var v => $"{o.Target.Name} {v}",
    };

    /// <summary>
    /// A context on the gate-read connection: unpooled, a 10 s connect timeout, a 15 s command
    /// timeout, and a 3 s lock timeout so a read reports a migration in progress instead of
    /// queueing behind it.
    /// </summary>
    internal static string GateReadConnectionString(DbInstance instance) =>
        new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance))
        {
            Pooling = false,
            Timeout = GateConnectTimeoutSeconds,
            CommandTimeout = GateCommandTimeoutSeconds,
            Options = $"-c lock_timeout={GateLockTimeoutMilliseconds}",
        }.ConnectionString;

    /// <summary>
    /// The connection <c>--upgrade-check --read-only</c> reads with, beside a node that is still
    /// serving: the gate-read connection with <c>default_transaction_read_only=on</c>, so the
    /// server refuses any write on it, and a 500 ms <c>lock_timeout</c>, so a read that finds its
    /// table locked ACCESS EXCLUSIVE (a migration in progress) is reported at once instead of
    /// queueing. Its reads take ACCESS SHARE at most, which conflicts with nothing a serving node
    /// takes.
    /// </summary>
    internal static string ReadOnlyCheckConnectionString(DbInstance instance) =>
        new NpgsqlConnectionStringBuilder(GateReadConnectionString(instance))
        {
            Options = $"-c lock_timeout={ReadOnlyCheckLockTimeoutMilliseconds} -c default_transaction_read_only=on",
        }.ConnectionString;

    /// <summary>
    /// The connection <c>--upgrade-check</c> reads with: <see cref="ReadOnlyCheckConnectionString"/>
    /// for the read-only check, otherwise <see cref="GateReadConnectionString"/>.
    /// </summary>
    private static string CheckReadConnectionString(DbInstance instance, bool readOnlyCheck) =>
        readOnlyCheck ? ReadOnlyCheckConnectionString(instance) : GateReadConnectionString(instance);

    /// <summary>
    /// The migration connection: unpooled, <c>lock_timeout</c> from
    /// <c>Schema.MigrationLockTimeoutSeconds</c>, and <c>statement_timeout</c> from
    /// <c>Schema.MigrationCommandTimeoutSeconds</c> with a slightly longer client timeout behind it
    /// (<see cref="MigrationConnection"/>, shared with bootstrap and <c>modularca-migrate</c>).
    /// </summary>
    internal static string MigrationConnectionString(DbInstance instance, SchemaConfig config) =>
        MigrationConnection.ConnectionString(instance, config);

    /// <summary>The client-side command timeout for migrations: the server's limit plus a margin, or 0 for none.</summary>
    private static int MigrationClientTimeoutSeconds(SchemaConfig config) =>
        MigrationConnection.ClientTimeoutSeconds(config);

    /// <summary>A context of <paramref name="target"/>'s kind on its migration connection.</summary>
    private static DbContext CreateMigrationContext(SchemaTarget target, SchemaConfig config) =>
        CreateContext(target.Kind, MigrationConnectionString(target.Instance, config), MigrationClientTimeoutSeconds(config));

    /// <summary>
    /// A standalone context of <paramref name="kind"/> on <paramref name="connectionString"/>,
    /// or the <see cref="UseContextFactory"/> override's. Never the DI contexts, whose 30 s
    /// command timeout serves requests.
    /// </summary>
    private static DbContext CreateContext(DatabaseKind kind, string connectionString, int commandTimeoutSeconds) =>
        ContextFactoryOverride.Value?.Invoke(kind, connectionString, commandTimeoutSeconds) ?? kind switch
    {
        DatabaseKind.Application => new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(connectionString, o => o.CommandTimeout(commandTimeoutSeconds)).Options),
        _ => new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(connectionString, o => o.CommandTimeout(commandTimeoutSeconds)).Options),
    };

    /// <summary><paramref name="delay"/> plus or minus 20%.</summary>
    private static TimeSpan Jitter(TimeSpan delay) =>
        TimeSpan.FromMilliseconds(delay.TotalMilliseconds * (0.8 + Random.Shared.NextDouble() * 0.4));

    /// <summary>Sends STATUS and extends the systemd start timeout by 90 s, when under systemd.</summary>
    private static void Notify(ISystemdNotifier? notifier, string status)
    {
        if (notifier is not { IsEnabled: true })
            return;
        var line = status.ReplaceLineEndings(" ");
        if (line.Length > 200)
            line = line[..200];
        try
        {
            notifier.Notify(new ServiceState($"STATUS={line}\nEXTEND_TIMEOUT_USEC={ExtendTimeoutMicroseconds}"));
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "systemd notification failed");
        }
    }

    /// <summary>Writes a refusal to stderr and to Serilog.</summary>
    private static void Fatal(string message)
    {
        Console.Error.WriteLine($"[FATAL] {message}");
        Log.Fatal("Schema check refused start: {Message}", message);
    }

    /// <summary>Writes a give-up to stderr and to Serilog.</summary>
    private static void Error(string message)
    {
        Console.Error.WriteLine($"[ERROR] {message}");
        Log.Error("Schema check: {Message}", message);
    }

    /// <summary>Writes a warning to the console and to Serilog.</summary>
    private static void Warn(string message)
    {
        Console.WriteLine($"[WARNING] {message}");
        Log.Warning("Schema check: {Message}", message);
    }

    /// <summary>Writes progress to the console and to Serilog.</summary>
    private static void Info(string message)
    {
        Console.WriteLine($"[STARTUP] {message}");
        Log.Information("Schema check: {Message}", message);
    }

    /// <summary>"yes" or "no".</summary>
    private static string Yes(bool value) => value ? "yes" : "no";

    /// <summary>
    /// Sends STATUS with EXTEND_TIMEOUT_USEC at once, on every <see cref="Update"/>, and every
    /// 20 s in the background until disposed, so no phase (a read against a hung server, a wait,
    /// a long migration) trips the unit's start timeout. Does nothing outside systemd.
    /// </summary>
    private sealed class Heartbeat : IAsyncDisposable
    {
        private readonly CancellationTokenSource _stop = new();
        private readonly ISystemdNotifier? _notifier;
        private readonly Task _loop;
        private volatile string _status;

        /// <summary>Starts the heartbeat with <paramref name="status"/>.</summary>
        public Heartbeat(ISystemdNotifier? notifier, string status)
        {
            _status = status;
            if (notifier is not { IsEnabled: true })
            {
                _loop = Task.CompletedTask;
                return;
            }
            _notifier = notifier;
            Notify(notifier, status);
            _loop = RunAsync(HeartbeatIntervalOverride.Value ?? HeartbeatInterval, _stop.Token);
        }

        /// <summary>Replaces the status, sends it now, and repeats it from then on.</summary>
        public void Update(string status)
        {
            _status = status;
            if (_notifier is not null)
                Notify(_notifier, status);
        }

        /// <summary>Repeats the current status every <paramref name="interval"/> until <paramref name="ct"/> is cancelled.</summary>
        private async Task RunAsync(TimeSpan interval, CancellationToken ct)
        {
            using var timer = new PeriodicTimer(interval);
            try
            {
                while (await timer.WaitForNextTickAsync(ct))
                    Notify(_notifier!, _status);
            }
            catch (OperationCanceledException)
            {
            }
        }

        /// <summary>
        /// Stops the heartbeat and waits for it, then extends the start timeout once more so the
        /// startup work after the gate (keystore unlock, backfills) is not cut short by a start
        /// that has already run past the unit's timeout.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            await _loop;
            _stop.Dispose();
            _notifier?.Notify(new ServiceState(
                $"STATUS=Schema check complete; starting\nEXTEND_TIMEOUT_USEC={PostGateExtendTimeoutMicroseconds}"));
        }
    }
}
