using System.Reflection;
using Microsoft.Extensions.Logging;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// What needs no database of the mutual exclusion between a restore and a running process, and
/// of the restore's last line: the fixed keys, the words of each refusal, where in a start the
/// lock is taken and which commands never come near it, the scheduler's hold, and the store of
/// the incarnation that is tried again. The behavior on real connections is in
/// <c>PostgresRestoreLockTests</c>, and with the real program in the restore drills.
/// </summary>
public sealed class RestoreExclusionTests
{
    private static readonly string Repo = RepoRoot();
    private static readonly string Startup = File.ReadAllText(Path.Combine(Repo, "ModularCA.API", "StartModularCA.cs"));

    [Fact]
    public void The_lock_keys_are_fixed_and_documented()
    {
        // pg_advisory_lock(1296253266, 1) for a node, (1296253266, 2) for a signer-only process.
        Assert.Equal(1296253266, RestoreLock.LockClass);
        Assert.Equal("MCAR", System.Text.Encoding.ASCII.GetString(BitConverter.GetBytes(RestoreLock.LockClass).Reverse().ToArray()));
        Assert.Equal(1, RestoreLock.NodeKey);
        Assert.Equal(2, RestoreLock.SignerKey);
        foreach (var document in new[] { Path.Combine("packaging", "README-DEPLOY.md"), Path.Combine("docs", "architecture", "restore-exclusion.md") })
        {
            var text = File.ReadAllText(Path.Combine(Repo, document));
            Assert.Contains("1296253266", text);
            Assert.Contains("Schema.RestoreWaitSeconds", text);
        }
        // The lock's connection is one no other code can be handed.
        var builder = new Npgsql.NpgsqlConnectionStringBuilder(RestoreLock.ConnectionString("Host=db.example;Database=app;Username=u"));
        Assert.False(builder.Pooling);
        Assert.Equal("ModularCA restore lock", builder.ApplicationName);
    }

    [Fact]
    public void A_refusal_for_a_database_in_use_says_who_uses_it_that_it_must_be_stopped_and_that_nothing_was_changed()
    {
        foreach (var reason in new[] { RestoreLock.NodeInUse, RestoreLock.SignerInUse, RestoreLock.OtherNodeInUse })
        {
            var refused = RestoreResult.InUse(reason);
            Assert.Equal(3, refused.ExitCode);
            Assert.True(refused.DatabaseInUse);
            Assert.Equal($"RESTORE: REFUSED ({reason}). Nothing was changed.", refused.Verdict);
            Assert.Contains("stop", reason);
            // The reason sits inside the verdict's brackets and carries none of its own.
            Assert.DoesNotContain('(', reason);
            Assert.DoesNotContain(')', reason);
            Assert.True(reason.Length < 300);
        }
        Assert.Contains("a node is serving from this application database, or another restore is running on it", RestoreLock.NodeInUse);
        Assert.Contains("the signer service is running", RestoreLock.SignerInUse);
        Assert.Contains("another node is serving from this application database, or another restore is running on it", RestoreLock.OtherNodeInUse);
        Assert.False(RestoreResult.Refused("anything else").DatabaseInUse);
    }

    [Fact]
    public void The_last_line_of_a_restore_says_when_the_incarnation_was_not_stored_and_is_still_done()
    {
        Assert.Equal("RESTORE: DONE (the audit database was kept). Start the node to apply the restored state.",
            RestoreResult.Done(auditKept: true).Verdict);
        Assert.Equal("RESTORE: DONE (the audit database was replaced with the archive's). Start the node to apply the restored state.",
            RestoreResult.Done(auditKept: false, incarnationStored: true).Verdict);

        var kept = RestoreResult.Done(auditKept: true, incarnationStored: false);
        Assert.Equal(0, kept.ExitCode);
        Assert.Equal("RESTORE: DONE (the audit database was kept; the incarnation was not stored, so the next start shows a roll-back notice). "
            + "Start the node to apply the restored state.", kept.Verdict);
        var replaced = RestoreResult.Done(auditKept: false, incarnationStored: false);
        Assert.Equal(0, replaced.ExitCode);
        Assert.StartsWith("RESTORE: DONE (the audit database was replaced with the archive's; the incarnation was not stored", replaced.Verdict);

        // The restore passes on what the store returned.
        var restore = File.ReadAllText(Path.Combine(Repo, "ModularCA.Bootstrap", "BackupRestore.cs"));
        Assert.Contains("var incarnationStored = await StoreIncarnationAfterRestoreAsync(AppConnectionString(target));", restore);
        Assert.Contains("return RestoreResult.Done(auditKept: !auditRestored, incarnationStored);", restore);
    }

    [Fact]
    public async Task The_store_of_the_incarnation_is_tried_four_times_over_seven_seconds()
    {
        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)], BackupRestore.IncarnationStoreRetryDelays);
        var reading = IncarnationReading.From("injected", "retry");
        TimeSpan[] quick = [TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(40), TimeSpan.FromMilliseconds(80)];

        // It fails every time: every attempt is made, each after its wait, and the answer is "not stored".
        var attempts = new List<(int Attempt, TimeSpan At)>();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var stored = await BackupRestore.StoreIncarnationAfterRestoreAsync("Host=unused", reading, quick, (attempt, _) =>
        {
            attempts.Add((attempt, clock.Elapsed));
            throw new InvalidOperationException("the database is not ready");
        });
        Assert.False(stored);
        Assert.Equal([1, 2, 3, 4], attempts.Select(a => a.Attempt));
        Assert.True(attempts[3].At - attempts[0].At >= TimeSpan.FromMilliseconds(130), "the waits between the attempts were not kept");

        // It fails twice and then goes through: stored, and no further attempt is made.
        var calls = 0;
        IncarnationReading? given = null;
        stored = await BackupRestore.StoreIncarnationAfterRestoreAsync("Host=unused", reading, quick, (attempt, r) =>
        {
            calls++;
            if (attempt < 3)
                throw new TimeoutException("not yet");
            given = r;
            return Task.CompletedTask;
        });
        Assert.True(stored);
        Assert.Equal(3, calls);
        Assert.Same(reading, given);
    }

    /// <summary>
    /// A start takes the lock before the schema check, which is before every other read or
    /// write of the application database; and every one-off command has left before it.
    /// </summary>
    [Theory]
    [InlineData("BackupManifestCommand.Run(")]
    [InlineData("JournalCommands.Run(")]
    [InlineData("RestoreCommand.RunAsync(")]
    [InlineData("SchemaStartup.CheckOwnershipAsync(")]
    [InlineData("UpgradeCheckCommand.RunAsync(")]
    [InlineData("UnlockUserCommand.RunAsync(")]
    [InlineData("SetPasswordSourceCommand.RunAsync(")]
    [InlineData("ClaimTokenCommand.RunNew(")]
    [InlineData("ClaimTokenCommand.RunIssueAsync(")]
    [InlineData("HubTokenCommand.RunNew(")]
    [InlineData("SettingsCommand.RunAsync(")]
    [InlineData("SignerDirectoryMigration.Run(")]
    [InlineData("SignerIdentityCommands.Run(")]
    [InlineData("NodeReadinessCheck.RunAsync(")]
    [InlineData("SignerRole.RunAsync(")]
    public void A_one_off_command_has_left_before_the_node_takes_its_lock(string command)
    {
        var taken = Startup.IndexOf("SchemaStartup.TakeServingLockAsync(", StringComparison.Ordinal);
        Assert.True(taken > 0, "StartModularCA no longer takes the restore lock.");
        Assert.Equal(taken, Startup.LastIndexOf("SchemaStartup.TakeServingLockAsync(", StringComparison.Ordinal));
        var at = Startup.IndexOf(command, StringComparison.Ordinal);
        Assert.True(at > 0, $"'{command}' is no longer in StartModularCA.");
        Assert.True(at < taken, $"'{command}' runs after the restore lock is taken.");
    }

    [Fact]
    public void The_node_and_the_signer_take_their_lock_before_the_schema_check_and_exit_with_what_it_returns()
    {
        var taken = Startup.IndexOf("SchemaStartup.TakeServingLockAsync(", StringComparison.Ordinal);
        var gate = Startup.IndexOf("SchemaStartup.EnforceAllAsync(", StringComparison.Ordinal);
        Assert.InRange(taken, 1, gate);
        Assert.Contains("new ModularCA.Database.ServingDatabaseLock(appConnStr, ModularCA.Database.RestoreLock.NodeKey,", Startup);
        Assert.Contains("Environment.Exit(lockCode);", Startup[taken..gate]);
        // Setup mode has no database to lock: the step is inside the block setup mode skips.
        Assert.True(Startup.LastIndexOf("if (!isSetupMode)", taken, StringComparison.Ordinal) > Startup.LastIndexOf("var servingLock =", taken, StringComparison.Ordinal));
        // The scheduler, the console's restore and the health answer read the same lock.
        Assert.Contains("() => servingLock.HoldReason", Startup);
        Assert.Contains(".AddCheck<ModularCA.API.HealthChecks.RestoreLockHealthCheck>(\"restore-lock\")", Startup);
        Assert.Contains("Exclusion = _servingLock,", File.ReadAllText(Path.Combine(Repo, "ModularCA.API", "Controllers", "v1", "Admin", "AdminBackupController.cs")));

        var signer = File.ReadAllText(Path.Combine(Repo, "ModularCA.API", "Startup", "SignerRole.cs"));
        var signerTaken = signer.IndexOf("SchemaStartup.TakeServingLockAsync(", StringComparison.Ordinal);
        Assert.InRange(signerTaken, 1, signer.IndexOf("SchemaStartup.EnforceAllAsync(", StringComparison.Ordinal));
        Assert.Contains("new ServingDatabaseLock(appConnStr, RestoreLock.SignerKey,", signer);
        Assert.Contains("return lockCode;", signer);
        Assert.True(signerTaken < signer.IndexOf("SignerBootstrap.Unlock(", StringComparison.Ordinal));

        // The command-line restore passes no lock of its own making: it takes both keys on its own connection.
        Assert.DoesNotContain("Exclusion", File.ReadAllText(Path.Combine(Repo, "ModularCA.API", "Startup", "RestoreCommand.cs")));
    }

    /// <summary>
    /// Nothing but a restore and a starting long-running process touches the lock: the files that
    /// name it are these, so a one-off command cannot have come to take or respect it unnoticed.
    /// </summary>
    [Fact]
    public void Only_the_restore_the_start_and_what_reports_on_them_name_the_lock()
    {
        string[] words = ["RestoreLock.", "ServingDatabaseLock", "TakeServingLockAsync", "IRestoreExclusion", "OwnConnectionRestoreExclusion"];
        var naming = Directory.EnumerateDirectories(Repo, "ModularCA.*")
            .SelectMany(project => Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .Where(file => { var text = File.ReadAllText(file); return words.Any(w => text.Contains(w, StringComparison.Ordinal)); })
            .Select(file => Path.GetRelativePath(Repo, file).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
        [
            "ModularCA.API/Controllers/v1/Admin/AdminBackupController.cs",
            "ModularCA.API/HealthChecks/RestoreLockHealthCheck.cs",
            "ModularCA.API/StartModularCA.cs",
            "ModularCA.API/Startup/SchemaStartup.RestoreLock.cs",
            "ModularCA.API/Startup/SignerRole.cs",
            "ModularCA.Bootstrap/BackupRestore.cs",
            "ModularCA.Bootstrap/RestoreOutcome.cs",
            "ModularCA.Database/RestoreLock.cs",
        ], naming);
    }

    [Fact]
    public void The_wait_for_a_restore_is_a_setting_of_the_host_with_a_default_of_a_minute()
    {
        Assert.Equal(60, new SchemaConfig().RestoreWaitSeconds);
        Assert.Contains("#   RestoreWaitSeconds: 60", File.ReadAllText(Path.Combine(Repo, "config", "config.yaml.example")));
        Assert.Contains("Schema.RestoreWaitSeconds", File.ReadAllText(Path.Combine(Repo, "docs", "architecture", "settings-store.md")));
    }

    private sealed class Lines : ILogger<SchedulerService>
    {
        public List<(LogLevel Level, string Text)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary>A service provider nothing may ask anything of.</summary>
    private sealed class Untouchable : IServiceProvider
    {
        public int Asked { get; private set; }
        public object? GetService(Type serviceType)
        {
            Asked++;
            throw new InvalidOperationException($"{serviceType.Name} was asked for while the scheduler is held.");
        }
    }

    [Fact]
    public async Task The_scheduler_runs_nothing_and_reads_nothing_while_the_restore_lock_says_to_hold_and_says_so_once()
    {
        var log = new Lines();
        var services = new Untouchable();
        string? reason = "A restore is running on the application database while this process is running.";
        var scheduler = new SchedulerService(services, log, new SystemConfig(), heldBecause: () => reason);
        var poll = typeof(SchedulerService).GetMethod("PollCycleAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

        await (Task)poll.Invoke(scheduler, [CancellationToken.None])!;
        await (Task)poll.Invoke(scheduler, [CancellationToken.None])!;

        Assert.Equal(0, services.Asked);
        var said = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, said.Level);
        Assert.Contains("holding every scheduled job. A restore is running", said.Text);

        // The reason changes (the restore ended; the process must be restarted): said once more.
        reason = "A restore replaced the application database while this process was running.";
        await (Task)poll.Invoke(scheduler, [CancellationToken.None])!;
        Assert.Equal(2, log.Entries.Count);

        // No reason: the cycle goes on to its work, which here is the first thing it asks the provider for.
        reason = null;
        await Assert.ThrowsAsync<InvalidOperationException>(() => (Task)poll.Invoke(scheduler, [CancellationToken.None])!);
        Assert.True(services.Asked > 0);
        Assert.Contains(log.Entries, e => e.Text.Contains("scheduled jobs are no longer held"));
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
