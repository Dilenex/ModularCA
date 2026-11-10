using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The bootstrap writes the audit records its steps queued into the audit database itself, so
/// they do not depend on a <c>logs/</c> that an init container loses: the rows the node's replay
/// would have written, by <c>system-bootstrap</c>, on the hash chain. The file stays the
/// fallback; a line is never recorded twice, whichever process replays it and however far an
/// earlier pass got; and the file never holds a secret. A file the audit database refused is
/// moved into <c>config/audit-pending</c>, which a pod keeps where it does not keep the
/// bootstrap's <c>logs/</c>, and the node replays it from there.
/// </summary>
[Collection(BootstrapAuditLogCollection.Name)]
public sealed class BootstrapAuditDrainTests : IDisposable
{
    private readonly string _base = Path.Combine(Path.GetTempPath(), $"mca-audit-drain-{Guid.NewGuid():N}");
    private readonly string _logs;
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";

    /// <summary>An application directory of the test's own, with the bootstrap's queue in its logs/.</summary>
    public BootstrapAuditDrainTests()
    {
        _logs = Path.Combine(_base, "logs");
        BootstrapAuditLog.LogDirectory = _logs;
    }

    public void Dispose()
    {
        BootstrapAuditLog.LogDirectory = null;
        if (Directory.Exists(_base))
            Directory.Delete(_base, recursive: true);
    }

    /// <summary>Where the bootstrap keeps what the audit database refused: config/audit-pending.</summary>
    private string PendingDir => BootstrapAuditReplayService.PendingDirectory(_base);

    private string[] Kept() => Directory.Exists(PendingDir)
        ? Directory.GetFiles(PendingDir, "bootstrap-audit-*.jsonl", SearchOption.AllDirectories)
        : [];

    /// <summary>The node's replay at start, over the application directory: config/audit-pending, then logs/.</summary>
    private Task<BootstrapAuditReplayResult> NodeStart(AuditDbContext auditDb)
        => new BootstrapAuditReplayService(
            new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService()),
            NullLogger<BootstrapAuditReplayService>.Instance, auditDb).ReplayAllAsync(_base);

    /// <summary>
    /// The pod: the audit database refuses the bootstrap's write, and the bootstrap's logs/ goes
    /// with its container. The file is in config/audit-pending by then, under its own name and
    /// for its owner alone, and the node's first start records it once.
    /// </summary>
    [Fact]
    public async Task A_file_the_audit_database_refused_is_kept_in_config_and_replayed_by_the_node()
    {
        QueueKeystoreWriteAndDecision();
        var name = Path.GetFileName(Assert.Single(Pending()));
        var output = new StringWriter();

        Assert.False(await BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("the audit database is away"), output, PendingDir));

        Assert.Empty(Pending());
        var kept = Assert.Single(Kept());
        Assert.Equal(Path.Combine(PendingDir, name), kept);
        Assert.Contains("[WARNING]", output.ToString());
        Assert.Contains($"They are kept in {PendingDir} and are recorded when the node next starts.", output.ToString());
        Assert.DoesNotContain("they are lost", output.ToString());
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(PendingDir));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(kept));
        }

        // The bootstrap's container is gone, and its logs/ with it.
        Directory.Delete(_logs, recursive: true);

        using var auditDb = AuditDb();
        var first = await NodeStart(auditDb);
        Assert.Empty(first.Failures);
        Assert.Equal((1, 2, 0), (first.FilesReplayed, first.Recorded, first.AlreadyRecorded));
        Assert.Equal(2, auditDb.AuditLogs.Count());
        Assert.Empty(Kept());
        Assert.Single(Directory.GetFiles(PendingDir, "*.replayed"));

        var second = await NodeStart(auditDb);
        Assert.Equal((0, 0, 0), (second.FilesReplayed, second.Recorded, second.AlreadyRecorded));
        Assert.Equal(2, auditDb.AuditLogs.Count());
    }

    /// <summary>
    /// The audit database went away part of the way through the bootstrap's own write. The file
    /// keeps its name when it is moved, so the lines already written keep their ids and the node
    /// writes only the rest.
    /// </summary>
    [Fact]
    public async Task A_file_written_in_part_and_then_kept_gains_no_duplicate_rows_from_the_node()
    {
        QueueKeystoreWriteAndDecision();
        BootstrapAuditLog.LogKeystoreWrite("ca-trust.keystore", AuditActionType.KeystoreKeyAdded);
        using (var partialDb = AuditDb())
        {
            var real = new AuditService(NullLogger<AuditService>.Instance, partialDb, hashChain: new AuditHashChainService());
            var partial = await NodeReplay(partialDb, _logs, new FailingFromAuditService(real, failFromCall: 2));
            Assert.Single(partial.Failures);
        }
        Assert.False(await BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("the audit database is away"), TextWriter.Null, PendingDir));
        Assert.Empty(Pending());

        using var auditDb = AuditDb();
        var node = await NodeStart(auditDb);

        Assert.Empty(node.Failures);
        Assert.Equal((2, 1), (node.Recorded, node.AlreadyRecorded));
        Assert.Equal(3, auditDb.AuditLogs.Count());
        Assert.Equal(3, auditDb.AuditLogs.Select(r => r.DetailsJson).Distinct().Count());
    }

    /// <summary>
    /// A second file of the same day while the first still waits: it does not replace the first
    /// and is not renamed (a line's id comes from its file's name), and the node replays both.
    /// </summary>
    [Fact]
    public async Task A_second_refused_file_of_the_same_name_is_kept_beside_the_first()
    {
        Task<bool> RefusedDrain() => BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("the audit database is away"), TextWriter.Null, PendingDir);

        QueueKeystoreWriteAndDecision();
        var name = Path.GetFileName(Assert.Single(Pending()));
        Assert.False(await RefusedDrain());
        BootstrapAuditLog.LogKeystoreWrite("ssh-ca.keystore", AuditActionType.KeystoreKeyAdded);
        Assert.False(await RefusedDrain());

        Assert.Empty(Pending());
        Assert.Equal([Path.Combine(PendingDir, "1", name), Path.Combine(PendingDir, name)], Kept().Order(StringComparer.Ordinal));

        using var auditDb = AuditDb();
        var node = await NodeStart(auditDb);
        Assert.Empty(node.Failures);
        Assert.Equal((2, 3), (node.FilesReplayed, node.Recorded));
        Assert.Equal(3, auditDb.AuditLogs.Count());
        Assert.Empty(Kept());
    }

    /// <summary>What is kept for the node is the queued file as it was: scrubbed when it was written, never a secret.</summary>
    [Fact]
    public async Task The_kept_file_holds_no_sensitive_named_value()
    {
        BootstrapAuditLog.LogSetupDecision(AuditActionType.SecurityPolicyUpdated, "SecurityPolicy", "instance",
            new { SetupChoice = "Probe", ApiKey = "s3cr3t-key-value", Nested = new { BindPassword = "hunter2-value", Pin = "pin-9f3x-value" } });
        BootstrapAuditLog.LogKeystoreWrite("ca-certs.keystore", AuditActionType.KeystoreKeyAdded, "CN=System Signing CA", "abcd");

        Assert.False(await BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("the audit database is away"), TextWriter.Null, PendingDir));

        var text = File.ReadAllText(Assert.Single(Kept()));
        Assert.DoesNotContain("s3cr3t-key-value", text);
        Assert.DoesNotContain("hunter2-value", text);
        Assert.DoesNotContain("pin-9f3x-value", text);
        Assert.Contains("\"SetupChoice\":\"Probe\"", text);

        using var auditDb = AuditDb();
        await NodeStart(auditDb);
        Assert.All(auditDb.AuditLogs, row =>
        {
            Assert.DoesNotContain("s3cr3t-key-value", row.DetailsJson);
            Assert.DoesNotContain("hunter2-value", row.DetailsJson);
        });
    }

    /// <summary>A drain that wrote everything keeps nothing: config/audit-pending is not even made.</summary>
    [Fact]
    public async Task A_drain_that_wrote_everything_keeps_nothing_in_config()
    {
        QueueKeystoreWriteAndDecision();

        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, TextWriter.Null, PendingDir));

        Assert.False(Directory.Exists(PendingDir));
    }

    private AuditDbContext AuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);

    /// <summary>Queues what a bootstrap queues: a keystore write and a setup decision.</summary>
    private static void QueueKeystoreWriteAndDecision()
    {
        BootstrapAuditLog.LogKeystoreWrite("ca-certs.keystore", AuditActionType.KeystoreKeyAdded, "CN=System Signing CA", "abcd");
        BootstrapAuditLog.LogSetupDecision(AuditActionType.SecurityPolicyUpdated, "SecurityPolicy", "instance",
            new { SetupChoice = "MultipleAdministrators", MultipleAdministrators = false });
    }

    private string[] Pending() => Directory.Exists(_logs) ? Directory.GetFiles(_logs, "bootstrap-audit-*.jsonl") : [];

    /// <summary>The node's replay, on the real audit service, which logs a failed write and goes on.</summary>
    private static Task<BootstrapAuditReplayResult> NodeReplay(AuditDbContext auditDb, string logs, IAuditService? audit = null)
        => new BootstrapAuditReplayService(
            audit ?? new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService()),
            NullLogger<BootstrapAuditReplayService>.Instance, auditDb).ReplayPendingAsync(logs);

    [Fact]
    public async Task The_bootstrap_writes_its_queued_records_into_the_audit_database_as_the_replay_would()
    {
        QueueKeystoreWriteAndDecision();
        var output = new StringWriter();

        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, output));

        using var auditDb = AuditDb();
        Assert.Equal(2, auditDb.AuditLogs.Count());
        Assert.All(auditDb.AuditLogs, row =>
        {
            Assert.Equal("system-bootstrap", row.ActorUsername);
            Assert.Null(row.ActorUserId);
            Assert.Equal("local", row.SourceIp);
            Assert.True(row.Success);
            Assert.False(string.IsNullOrEmpty(row.RecordHash));
            Assert.Equal(AuditHashChainService.CurrentHashVersion, row.HashVersion);
            Assert.DoesNotContain("***", row.DetailsJson);
        });

        var keystore = auditDb.AuditLogs.Single(r => r.ActionType == AuditActionType.KeystoreKeyAdded);
        Assert.Equal(("Keystore", "ca-certs.keystore"), (keystore.TargetEntityType, keystore.TargetEntityId));
        using (var details = JsonDocument.Parse(keystore.DetailsJson!))
        {
            Assert.True(details.RootElement.GetProperty("ReplayedFromBootstrap").GetBoolean());
            Assert.Equal("CN=System Signing CA", details.RootElement.GetProperty("SubjectDn").GetString());
            Assert.Equal("abcd", details.RootElement.GetProperty("Thumbprint").GetString());
            Assert.Equal(32, details.RootElement.GetProperty(BootstrapAuditReplayService.EntryIdProperty).GetString()!.Length);
        }

        var decision = auditDb.AuditLogs.Single(r => r.ActionType == AuditActionType.SecurityPolicyUpdated);
        Assert.Equal(("SecurityPolicy", "instance"), (decision.TargetEntityType, decision.TargetEntityId));
        using (var details = JsonDocument.Parse(decision.DetailsJson!))
            Assert.False(details.RootElement.GetProperty("Decision").GetProperty("MultipleAdministrators").GetBoolean());

        Assert.Empty(Pending());
        Assert.Single(Directory.GetFiles(_logs, "*.replayed"));
        Assert.Contains("2 setup record(s) written to the audit trail", output.ToString());
        Assert.DoesNotContain("[WARNING]", output.ToString());
    }

    [Fact]
    public async Task Nothing_queued_opens_no_database_and_says_nothing()
    {
        var output = new StringWriter();

        Assert.True(await BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("must not be opened"), output));

        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task When_the_audit_database_refuses_the_file_is_kept_and_the_nodes_first_start_records_it_once()
    {
        QueueKeystoreWriteAndDecision();
        var output = new StringWriter();

        Assert.False(await BootstrapAuditDrain.RunAsync(
            () => throw new InvalidOperationException("the audit database is away"), output));

        Assert.Contains("[WARNING]", output.ToString());
        Assert.Contains("the audit database is away", output.ToString());
        Assert.Single(Pending());

        using var auditDb = AuditDb();
        var first = await NodeReplay(auditDb, _logs);
        Assert.Equal((1, 2, 0), (first.FilesReplayed, first.Recorded, first.AlreadyRecorded));
        Assert.Empty(first.Failures);
        Assert.Equal(2, auditDb.AuditLogs.Count());
        Assert.Empty(Pending());
    }

    /// <summary>
    /// Both paths ran over the same file: the bootstrap wrote the rows and the file came back
    /// (its rename did not hold). The node writes nothing more.
    /// </summary>
    [Fact]
    public async Task A_file_the_bootstrap_already_wrote_gains_no_rows_when_the_node_replays_it()
    {
        QueueKeystoreWriteAndDecision();
        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, TextWriter.Null));
        var replayed = Assert.Single(Directory.GetFiles(_logs, "*.replayed"));
        File.Move(replayed, replayed[..^".replayed".Length]);

        using var auditDb = AuditDb();
        var again = await NodeReplay(auditDb, _logs);

        Assert.Equal((1, 0, 2), (again.FilesReplayed, again.Recorded, again.AlreadyRecorded));
        Assert.Equal(2, auditDb.AuditLogs.Count());
        Assert.Empty(Pending());

        // And the bootstrap over a file the node already wrote, the other way round.
        replayed = Assert.Single(Directory.GetFiles(_logs, "*.replayed"));
        File.Move(replayed, replayed[..^".replayed".Length]);
        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, TextWriter.Null));
        Assert.Equal(2, auditDb.AuditLogs.Count());
    }

    /// <summary>
    /// A pass that got part of the way through a file leaves it in place; the next pass writes
    /// only what is missing.
    /// </summary>
    [Fact]
    public async Task A_file_written_in_part_is_left_and_finished_without_duplicates()
    {
        QueueKeystoreWriteAndDecision();
        BootstrapAuditLog.LogKeystoreWrite("ssh.keystore", AuditActionType.KeystoreKeyAdded);

        using var auditDb = AuditDb();
        var real = new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
        var partial = await NodeReplay(auditDb, _logs, new FailingFromAuditService(real, failFromCall: 2));

        Assert.Equal(0, partial.FilesReplayed);
        Assert.Single(partial.Failures);
        Assert.Single(Pending());
        Assert.Equal(1, auditDb.AuditLogs.Count());

        var finished = await NodeReplay(auditDb, _logs);
        Assert.Equal((1, 2, 1), (finished.FilesReplayed, finished.Recorded, finished.AlreadyRecorded));
        Assert.Equal(3, auditDb.AuditLogs.Count());
        Assert.Equal(3, auditDb.AuditLogs.Select(r => r.DetailsJson).Distinct().Count());
        Assert.Empty(Pending());
    }

    /// <summary>
    /// The node's audit service logs a failed write and carries on. The file is not marked
    /// replayed on its word: only once the rows are in the audit database.
    /// </summary>
    [Fact]
    public async Task A_file_is_not_marked_replayed_when_its_rows_did_not_reach_the_audit_database()
    {
        QueueKeystoreWriteAndDecision();

        using var auditDb = AuditDb();
        var swallowed = await NodeReplay(auditDb, _logs, new RecordingAuditService());

        Assert.Equal(0, swallowed.FilesReplayed);
        Assert.Contains("did not reach the audit database", Assert.Single(swallowed.Failures));
        Assert.Single(Pending());
        Assert.Empty(auditDb.AuditLogs);
    }

    [Fact]
    public async Task The_file_never_holds_a_sensitive_named_value_and_neither_does_the_row()
    {
        BootstrapAuditLog.LogSetupDecision(AuditActionType.SecurityPolicyUpdated, "SecurityPolicy", "instance",
            new { SetupChoice = "Probe", ApiKey = "s3cr3t-key-value", Nested = new { BindPassword = "hunter2-value" }, RequireKeyCeremony = true });

        var text = File.ReadAllText(Assert.Single(Pending()));
        Assert.DoesNotContain("s3cr3t-key-value", text);
        Assert.DoesNotContain("hunter2-value", text);
        Assert.Contains("\"SetupChoice\":\"Probe\"", text);
        // A switch is kept: it cannot carry a secret.
        Assert.Contains("\"RequireKeyCeremony\":true", text);

        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, TextWriter.Null));
        using var auditDb = AuditDb();
        var row = Assert.Single(auditDb.AuditLogs);
        Assert.DoesNotContain("s3cr3t-key-value", row.DetailsJson);
        Assert.DoesNotContain("hunter2-value", row.DetailsJson);
    }

    [Fact]
    public void The_same_line_of_the_same_file_has_the_same_id_and_any_other_line_another()
    {
        var id = BootstrapAuditReplayService.EntryId("bootstrap-audit-20261109.jsonl", 0, "{\"action\":\"A\"}");
        Assert.Equal(id, BootstrapAuditReplayService.EntryId("bootstrap-audit-20261109.jsonl", 0, "{\"action\":\"A\"}"));
        Assert.NotEqual(id, BootstrapAuditReplayService.EntryId("bootstrap-audit-20261109.jsonl", 1, "{\"action\":\"A\"}"));
        Assert.NotEqual(id, BootstrapAuditReplayService.EntryId("bootstrap-audit-20261110.jsonl", 0, "{\"action\":\"A\"}"));
        Assert.NotEqual(id, BootstrapAuditReplayService.EntryId("bootstrap-audit-20261109.jsonl", 0, "{\"action\":\"B\"}"));
        // The audit scrubber must not blank the property that holds it.
        Assert.Contains(id, AuditJsonScrubber.SerializeAndScrub(new { BootstrapEntryId = id }));
    }

    /// <summary>Passes calls to <paramref name="inner"/> until call number <paramref name="failFromCall"/>, then throws.</summary>
    private sealed class FailingFromAuditService(IAuditService inner, int failFromCall) : IAuditService
    {
        private int _calls;

        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => ++_calls >= failFromCall
                ? throw new InvalidOperationException("the audit database went away")
                : inner.LogAsync(actionType, actorUserId, actorUsername, targetEntityType, targetEntityId, details,
                    sourceIp, success, errorMessage, certificateAuthorityId, spaceId);
    }
}
