using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// A node that holds the signer in process wrote its keystore events to
/// <c>logs/bootstrap-audit-*.jsonl</c> and recorded them in the audit trail only when it next
/// started. These tests run the recorder the node now runs beside the real keystore service: a
/// key committed through the in-process signer becomes an audit row while the node is up, with
/// nothing else called; the drain of the next start then finds the file recorded and adds no
/// row; and an audit database that is away costs nothing but time.
/// </summary>
[Collection(KeystoreAuditLogCollection.Name)]
public sealed class LocalKeystoreEventRecorderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-local-events-" + Guid.NewGuid().ToString("N"));
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";
    private readonly string _logs;
    private readonly ServiceProvider _services;
    private volatile bool _auditDown;

    /// <summary>Points the keystore service's events at a <c>logs/</c> of this test's own, as one process has them.</summary>
    public LocalKeystoreEventRecorderTests()
    {
        _logs = Path.Combine(_root, "logs");
        Directory.CreateDirectory(_root);
        KeystoreService.AuditLogDirectory = _logs;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;

        var services = new ServiceCollection();
        services.AddDbContext<AuditDbContext>(o => o.UseInMemoryDatabase(_auditName));
        services.AddScoped<IAuditService>(sp => _auditDown
            ? new ModularCA.Tests.TestUtils.RecordingAuditService()
            : new AuditService(NullLogger<AuditService>.Instance, sp.GetRequiredService<AuditDbContext>(), hashChain: new AuditHashChainService()));
        services.AddScoped(sp => new BootstrapAuditReplayService(
            sp.GetRequiredService<IAuditService>(), NullLogger<BootstrapAuditReplayService>.Instance, sp.GetRequiredService<AuditDbContext>()));
        _services = services.BuildServiceProvider();
    }

    /// <summary>Gives the keystore service its default file back and removes the directory.</summary>
    public void Dispose()
    {
        KeystoreService.AuditLogDirectory = null;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        _services.Dispose();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private LocalKeystoreEventRecorder Recorder(TimeSpan? retry = null) => new(
        _services.GetRequiredService<IServiceScopeFactory>(), NullLogger<LocalKeystoreEventRecorder>.Instance)
    {
        Settle = TimeSpan.FromMilliseconds(50),
        RetryInterval = retry ?? TimeSpan.FromSeconds(60),
    };

    private List<AuditLogEntity> Rows()
    {
        using var auditDb = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);
        return auditDb.AuditLogs.AsNoTracking().ToList();
    }

    /// <summary>Waits, for at most twenty seconds, until the trail holds <paramref name="count"/> rows; nothing is called meanwhile.</summary>
    private async Task<List<AuditLogEntity>> WaitForRowsAsync(int count)
    {
        for (var i = 0; i < 200 && Rows().Count < count; i++)
            await Task.Delay(100);
        return Rows();
    }

    private static string EntryId(AuditLogEntity row)
        => JsonDocument.Parse(row.DetailsJson!).RootElement.GetProperty(BootstrapAuditReplayService.EntryIdProperty).GetString()!;

    [Fact]
    public async Task A_keystore_event_of_a_running_single_process_becomes_an_audit_row_when_it_happens_and_the_next_drain_adds_nothing()
    {
        // The node starts: its keystores are unlocked before anything listens.
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = world.CreateInProcessSigner();
        using var stop = new CancellationTokenSource();
        var running = Recorder().RunAsync(stop.Token);

        // What was written before the recorder listened is taken by its first pass.
        Assert.Equal(
            [AuditActionType.KeystoreLoaded, AuditActionType.KeystoreLoaded],
            (await WaitForRowsAsync(2)).Select(r => r.ActionType));

        // While it runs, a key is committed: ssh-ca.keystore is created, then appended to.
        await SignerKeystoreEventDeliveryTests.CommitSshKeyAsync(world, signer);
        var afterCreate = await WaitForRowsAsync(3);
        Assert.Single(afterCreate, r => r.ActionType == AuditActionType.KeystoreInitialized && r.TargetEntityId == KeyRef.SshKeystore);

        await SignerKeystoreEventDeliveryTests.CommitSshKeyAsync(world, signer);
        var rows = await WaitForRowsAsync(4);
        Assert.Single(rows, r => r.ActionType == AuditActionType.KeystoreAppended && r.TargetEntityId == KeyRef.SshKeystore);
        Assert.Equal(4, rows.Count);
        Assert.All(rows, row =>
        {
            Assert.Equal("Keystore", row.TargetEntityType);
            Assert.Equal(BootstrapAuditReplayService.Actor, row.ActorUsername);
            Assert.True(row.Success);
            Assert.False(string.IsNullOrEmpty(row.RecordHash));
        });
        Assert.Equal(4, rows.Select(EntryId).Distinct().Count());

        // The file is still where the keystore service writes it, whole.
        var file = Assert.Single(Directory.GetFiles(_logs, "bootstrap-audit-*.jsonl"));
        Assert.Equal(4, File.ReadAllLines(file).Length);
        Assert.Empty(Directory.GetFiles(_logs, "*.replayed"));

        stop.Cancel();
        await running;

        // The next start drains the file: every line is already in the trail, and none is written again.
        using (var scope = _services.CreateScope())
        {
            var drained = await scope.ServiceProvider.GetRequiredService<BootstrapAuditReplayService>().ReplayPendingAsync(_logs);
            Assert.Empty(drained.Failures);
            Assert.Equal((1, 0, 4), (drained.FilesReplayed, drained.Recorded, drained.AlreadyRecorded));
        }
        Assert.Equal(4, Rows().Count);
        Assert.Single(Directory.GetFiles(_logs, "*.replayed"));

        // Stopped, the recorder no longer listens: an event stays in its file for the next start.
        world.Restart();
        await Task.Delay(500);
        Assert.Equal(4, Rows().Count);
    }

    [Fact]
    public async Task An_audit_database_that_is_away_delays_the_rows_and_loses_none()
    {
        _auditDown = true;
        using var stop = new CancellationTokenSource();
        var running = Recorder(retry: TimeSpan.FromMilliseconds(300)).RunAsync(stop.Token);

        SignerTestWorld.CreateWithKeystoreFiles();
        await Task.Delay(1500);
        Assert.Empty(Rows());

        // The audit database is back; no new event is needed for the waiting ones to be recorded.
        _auditDown = false;
        var rows = await WaitForRowsAsync(2);
        Assert.Equal([AuditActionType.KeystoreLoaded, AuditActionType.KeystoreLoaded], rows.Select(r => r.ActionType));
        await Task.Delay(1000);
        Assert.Equal(2, Rows().Count);

        stop.Cancel();
        await running;
    }

    /// <summary>
    /// The pass itself: a line still being written waits, a line it recorded is not recorded by
    /// the next pass or by the file's replay, and lines a replay wrote before are not written here.
    /// </summary>
    [Fact]
    public async Task A_pass_records_only_whole_lines_the_trail_lacks_under_the_ids_the_replay_uses()
    {
        Directory.CreateDirectory(_logs);
        var file = Path.Combine(_logs, "bootstrap-audit-20261110.jsonl");
        const string first = "{\"timestamp\":\"2026-11-10T08:00:00Z\",\"action\":\"KeystoreLoaded\",\"keystoreName\":\"ca-certs.keystore\",\"success\":true,\"detail\":\"entries=4 format=v4\",\"instanceId\":\"a\"}";
        const string second = "{\"timestamp\":\"2026-11-10T09:00:00Z\",\"action\":\"KeystoreSignatureFailed\",\"keystoreName\":\"ca-trust.keystore\",\"success\":false,\"detail\":\"File signature is invalid\",\"instanceId\":\"a\"}";
        File.WriteAllText(file, first + "\n" + "not json\n" + second[..40]);

        using var scope = _services.CreateScope();
        var replay = scope.ServiceProvider.GetRequiredService<BootstrapAuditReplayService>();

        var partial = await replay.RecordNewLinesAsync(_logs);
        Assert.Equal(new NewLinesRecordResult(1, 0, null), partial);

        File.AppendAllText(file, second[40..] + "\n");
        var whole = await replay.RecordNewLinesAsync(_logs);
        Assert.Equal(new NewLinesRecordResult(1, 1, null), whole);
        Assert.Equal(new NewLinesRecordResult(0, 2, null), await replay.RecordNewLinesAsync(_logs));

        var rows = Rows();
        Assert.Equal(2, rows.Count);
        var failed = Assert.Single(rows, r => !r.Success);
        Assert.Equal(AuditActionType.KeystoreSignatureFailed, failed.ActionType);
        Assert.Equal("File signature is invalid", failed.ErrorMessage);
        Assert.Equal(
            new[] { BootstrapAuditReplayService.EntryId("bootstrap-audit-20261110.jsonl", 0, first), BootstrapAuditReplayService.EntryId("bootstrap-audit-20261110.jsonl", 2, second) }.Order(),
            rows.Select(EntryId).Order());

        var drained = await replay.ReplayPendingAsync(_logs);
        Assert.Equal((1, 0, 2), (drained.FilesReplayed, drained.Recorded, drained.AlreadyRecorded));
        Assert.Equal(2, Rows().Count);

        // And the other way about: what a replay recorded, a pass over the same lines does not.
        File.WriteAllText(Path.Combine(_logs, "bootstrap-audit-20261111.jsonl"), first + "\n");
        var again = await replay.ReplayPendingAsync(_logs);
        Assert.Equal(1, again.Recorded);
        File.Move(Path.Combine(_logs, "bootstrap-audit-20261111.jsonl.replayed"), Path.Combine(_logs, "bootstrap-audit-20261111.jsonl"));
        Assert.Equal(new NewLinesRecordResult(0, 1, null), await replay.RecordNewLinesAsync(_logs));
        Assert.Equal(3, Rows().Count);
    }

    [Fact]
    public async Task Without_an_audit_database_a_pass_refuses_rather_than_record_a_line_twice()
    {
        var replay = new BootstrapAuditReplayService(
            new ModularCA.Tests.TestUtils.RecordingAuditService(), NullLogger<BootstrapAuditReplayService>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => replay.RecordNewLinesAsync(_logs));
    }

    /// <summary>
    /// The node runs the recorder where the audit trail is written from, the control role, with
    /// the signer in process and an audit database; a node with a remote signer runs the delivery
    /// from the journal instead, never both.
    /// </summary>
    [Fact]
    public void The_control_role_of_a_node_with_the_signer_in_process_runs_the_recorder()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var startup = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs"));
        var guard = startup.IndexOf("if (!isSetupMode && controlActive && !signerIsRemote && !string.IsNullOrWhiteSpace(config.DB.Audit.Database))", StringComparison.Ordinal);
        var hosted = startup.IndexOf("AddHostedService<ModularCA.API.Services.LocalKeystoreEventRecorderService>()", StringComparison.Ordinal);
        Assert.True(guard > 0 && hosted > guard && hosted - guard < 700, "the recorder must be registered behind its guard");
        Assert.Equal(hosted, startup.LastIndexOf("AddHostedService<ModularCA.API.Services.LocalKeystoreEventRecorderService>()", StringComparison.Ordinal));

        var service = File.ReadAllText(Path.Combine(dir.FullName, "ModularCA.API", "Services", "LocalKeystoreEventRecorderService.cs"));
        Assert.Contains("ExecuteAsync(CancellationToken stoppingToken) => _recorder.RunAsync(stoppingToken);", service);
    }
}
