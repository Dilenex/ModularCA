using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.Hub;
using ModularCA.HubConnection.Client;
using ModularCA.HubConnection.Contract;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Settings;
using Xunit;

namespace ModularCA.Tests.Hub;

/// <summary>
/// <c>backup.prune</c> on the hub's local connection, over a real Unix domain socket against the
/// real listener and the node's real operations, deleting real files from a backup directory.
/// The files are created one after another, so their creation times are in that order; where a
/// test needs them old, it moves the clock the operations measure from.
/// </summary>
public sealed class HubBackupPruneTests : IAsyncLifetime
{
    private sealed record Audited(string Action, string? Actor, Guid? ActorId, string? TargetId, object? Details, bool Success, string? Error);

    private sealed class Audit : IAuditService
    {
        public List<Audited> Entries { get; } = [];
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            lock (Entries) Entries.Add(new Audited(actionType, actorUsername, actorUserId, targetEntityId, details, success, errorMessage));
            return Task.CompletedTask;
        }
    }

    /// <summary>A settings store nothing is asked of.</summary>
    private class NoStore : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => throw new NotSupportedException(targetMethod?.Name);
    }

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mp-" + Guid.NewGuid().ToString("N")[..10]);
    private readonly Audit _audit = new();
    private readonly SystemConfig _config = new();
    private NodeHubOperations _operations = null!;
    private WebApplication? _host;

    private string SocketPath => Path.Combine(_dir, "hub.sock");
    private string BackupDirectory => Path.Combine(_dir, "backups");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(BackupDirectory);
        _config.Backup.OutputPath = BackupDirectory;
        // The floor has its own test; elsewhere it is off, so that files made a moment ago can go.
        _config.Backup.MinimumRetentionDays = 0;

        var services = new ServiceCollection().AddSingleton<IAuditService>(_audit)
            .AddSingleton(DispatchProxy.Create<ISettingsStore, NoStore>()).BuildServiceProvider();
        _operations = new NodeHubOperations(
            InstanceModeStore.Open(SocketPath, null, Path.Combine(_dir, "config")), _config,
            services.GetRequiredService<IServiceScopeFactory>(),
            _ => Task.FromResult(new HubHealthReport("healthy")),
            _ => throw new NotSupportedException("no backup is taken in these tests"),
            null, "0.4.5-test");

        var options = new HubLocalHostOptions(SocketPath, LedgerPath: Path.Combine(_dir, HubRequestLedger.FileName));
        _host = HubLocalHost.Build(options, _operations, b => b.Logging.ClearProviders());
        await HubLocalHost.StartAsync(_host, options);
    }

    public async Task DisposeAsync()
    {
        if (_host != null) await _host.DisposeAsync();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private HubLocalClient Client(string? operatorName = "alice@hub") => new(SocketPath, null, operatorName, TimeSpan.FromSeconds(20));

    /// <summary>Creates archives oldest first and returns their names in that order.</summary>
    private List<string> Archives(int count, int from = 1)
    {
        var names = new List<string>();
        for (var i = from; i < from + count; i++)
        {
            var name = $"modularca-backup-202601{i:00}-020000-{Guid.NewGuid():N}.enc";
            File.WriteAllText(Path.Combine(BackupDirectory, name), new string('x', i));
            names.Add(name);
            Thread.Sleep(40);
        }
        return names;
    }

    private List<string> OnDisk() => Directory.GetFiles(BackupDirectory).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList()!;

    private static object? Detail(Audited entry, string name) => entry.Details!.GetType().GetProperty(name)!.GetValue(entry.Details);

    private static async Task<HttpResponseMessage> PostAsync(HubLocalClient client, string body, string? requestId)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, HubLocalContract.Paths.BackupPrune)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        if (requestId != null)
            request.Headers.Add(HubLocalContract.RequestIdHeader, requestId);
        return await client.SendRawAsync(request);
    }

    [Fact]
    public async Task Hello_lists_the_prune_operation_under_contract_1_1()
    {
        using var client = Client();

        var theirs = await client.HelloAsync();

        Assert.Equal("1.2", HubLocalContract.Version);
        Assert.Equal("1.2", theirs.ContractVersion);
        Assert.Contains("backup.prune", theirs.Operations);
        Assert.Equal("backup.prune", HubLocalContract.Operations.All[^1]);
        Assert.Equal("/hub/v1/backup/prune", HubLocalContract.Paths.BackupPrune);
        Assert.Equal(HubLocalContract.Operations.BackupPrune, HubLocalHost.OperationOf("POST", "/hub/v1/backup/prune"));
        Assert.Null(HubLocalHost.OperationOf("GET", "/hub/v1/backup/prune"));
    }

    [Fact]
    public async Task A_hub_that_speaks_1_0_is_still_accepted()
    {
        var names = Archives(3);
        // A client whose only contract header is the old version, as a 1.0 hub sends it.
        using var http = new HttpClient(new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Unspecified);
                await socket.ConnectAsync(new System.Net.Sockets.UnixDomainSocketEndPoint(SocketPath), cancellationToken);
                return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
            },
        }) { BaseAddress = new Uri("http://hub.local") };
        http.DefaultRequestHeaders.Add(HubLocalContract.ContractHeader, "1.0");

        using var hello = await http.PostAsync(HubLocalContract.Paths.Hello,
            new StringContent("""{"contractVersion":"1.0","operations":["hello","health.read","mode.read","mode.set","backup.create","affiliation-token.replace"]}""", Encoding.UTF8, "application/json"));
        using var mode = await http.GetAsync(HubLocalContract.Paths.Mode);
        using var prune = new HttpRequestMessage(HttpMethod.Post, HubLocalContract.Paths.BackupPrune)
        {
            Content = new StringContent("""{"keep":1}""", Encoding.UTF8, "application/json"),
            Headers = { { HubLocalContract.RequestIdHeader, "old-hub-1" } },
        };
        using var pruned = await http.SendAsync(prune);

        Assert.Equal(HttpStatusCode.OK, hello.StatusCode);
        var answer = JsonSerializer.Deserialize<HubHello>(await hello.Content.ReadAsStringAsync(), HubLocalContract.Json)!;
        Assert.Equal("1.2", answer.ContractVersion);
        Assert.Contains("backup.prune", answer.Operations);
        Assert.Equal(HttpStatusCode.OK, mode.StatusCode);
        Assert.Equal(HttpStatusCode.OK, pruned.StatusCode);
        Assert.Equal([names[2]], OnDisk());
    }

    [Fact]
    public async Task The_newest_archives_are_kept_and_the_answer_says_what_was_deleted_and_what_remains()
    {
        var names = Archives(5);
        File.WriteAllText(Path.Combine(BackupDirectory, "pre-restore-20260101-000000.zip"), "not a backup archive");
        using var client = Client();

        var answer = await client.PruneBackupsAsync(keep: 2, maxAgeDays: null, "prune-1");

        Assert.Equal([names[2], names[1], names[0]], answer.Deleted.Select(f => f.FileName));
        Assert.Equal([names[4], names[3]], answer.Remaining.Select(f => f.FileName));
        Assert.Equal(5, answer.Remaining[0].SizeBytes);
        Assert.Empty(answer.KeptByMinimumRetention);
        Assert.Empty(answer.NotDeleted);
        Assert.Equal(new[] { names[3], names[4], "pre-restore-20260101-000000.zip" }.Order(StringComparer.Ordinal), OnDisk());
    }

    [Fact]
    public async Task The_newest_archive_is_never_deleted()
    {
        var names = Archives(3);
        _operations.UtcNow = () => DateTime.UtcNow.AddDays(90);
        using var client = Client();

        var byAge = await client.PruneBackupsAsync(keep: null, maxAgeDays: 1, "prune-age");
        var byBoth = await client.PruneBackupsAsync(keep: 1, maxAgeDays: 1, "prune-both");

        Assert.Equal(2, byAge.Deleted.Count);
        Assert.Equal([names[2]], byAge.Remaining.Select(f => f.FileName));
        Assert.Empty(byBoth.Deleted);
        Assert.Equal([names[2]], OnDisk());
    }

    [Fact]
    public async Task An_archive_within_the_age_is_kept()
    {
        Archives(3);
        using var client = Client();

        var answer = await client.PruneBackupsAsync(keep: null, maxAgeDays: 1, "prune-young");

        Assert.Empty(answer.Deleted);
        Assert.Equal(3, answer.Remaining.Count);
        Assert.Equal(3, OnDisk().Count);
    }

    [Fact]
    public async Task The_instances_minimum_retention_is_the_same_floor_as_for_its_own_backups()
    {
        var names = Archives(4);
        _config.Backup.MinimumRetentionDays = 3;
        using var client = Client();

        var young = await client.PruneBackupsAsync(keep: 1, maxAgeDays: null, "floor-1");

        Assert.Empty(young.Deleted);
        Assert.Equal([names[2], names[1], names[0]], young.KeptByMinimumRetention);
        Assert.Equal(4, OnDisk().Count);

        _operations.UtcNow = () => DateTime.UtcNow.AddDays(4);
        var aged = await client.PruneBackupsAsync(keep: 1, maxAgeDays: null, "floor-2");

        Assert.Equal(3, aged.Deleted.Count);
        Assert.Equal([names[3]], OnDisk());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"keep":null,"maxAgeDays":null}""")]
    [InlineData("""{"keep":0}""")]
    [InlineData("""{"keep":-1}""")]
    [InlineData("""{"keep":10001}""")]
    [InlineData("""{"maxAgeDays":0}""")]
    [InlineData("""{"maxAgeDays":-7}""")]
    [InlineData("""{"keep":2,"maxAgeDays":0}""")]
    [InlineData("""{"keep":"all"}""")]
    [InlineData("""{"keep":1.5}""")]
    [InlineData("not json")]
    [InlineData("")]
    public async Task Values_that_make_no_sense_are_refused_and_nothing_is_deleted(string body)
    {
        Archives(3);
        using var client = Client();

        using var response = await PostAsync(client, body, "bad-1");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = JsonSerializer.Deserialize<HubError>(await response.Content.ReadAsStringAsync(), HubLocalContract.Json)!;
        Assert.Equal(HubLocalContract.Errors.InvalidRequest, error.Error);
        Assert.Equal(3, OnDisk().Count);
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.BackupsPruned);
        var refused = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.HubRequestRefused);
        Assert.Equal("backup.prune", refused.TargetId);
        Assert.Equal("hub", refused.Actor);
    }

    [Fact]
    public async Task It_needs_the_request_identifier()
    {
        Archives(3);
        using var client = Client();

        using var response = await PostAsync(client, """{"keep":1}""", requestId: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HubLocalContract.Errors.RequestIdRequired, await response.Content.ReadAsStringAsync());
        Assert.Equal(3, OnDisk().Count);
    }

    [Fact]
    public async Task The_same_request_sent_again_is_answered_from_the_first_and_deletes_nothing_more()
    {
        var first = Archives(4);
        using var client = Client();

        using var one = await PostAsync(client, """{"keep":2}""", "once-1");
        var firstAnswer = await one.Content.ReadAsStringAsync();
        // Three more archives arrive. A second prune would delete three; a repeat of the first must not.
        var later = Archives(3, from: 5);
        using var two = await PostAsync(client, """{"keep":2}""", "once-1");

        Assert.Equal(HttpStatusCode.OK, one.StatusCode);
        Assert.False(one.Headers.Contains(HubLocalContract.ReplayedHeader));
        Assert.Equal(HttpStatusCode.OK, two.StatusCode);
        Assert.Equal("true", two.Headers.GetValues(HubLocalContract.ReplayedHeader).Single());
        Assert.Equal(firstAnswer, await two.Content.ReadAsStringAsync());
        Assert.Equal(first.Skip(2).Concat(later).Order(StringComparer.Ordinal), OnDisk());
        Assert.Single(_audit.Entries, e => e.Action == AuditActionType.BackupsPruned);

        // The same identifier for another request is refused, and still nothing more goes.
        using var other = await PostAsync(client, """{"keep":1}""", "once-1");
        Assert.Equal(HttpStatusCode.Conflict, other.StatusCode);
        Assert.Equal(5, OnDisk().Count);
    }

    [Fact]
    public async Task One_prune_is_one_record_under_the_hub_that_lists_what_was_deleted()
    {
        var names = Archives(4);
        using var client = Client(operatorName: "carol@hub");

        await client.PruneBackupsAsync(keep: 1, maxAgeDays: 30, "audit-1");

        var record = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.BackupsPruned);
        Assert.Equal("hub", record.Actor);
        Assert.Null(record.ActorId);
        Assert.True(record.Success);
        Assert.Equal("carol@hub", Detail(record, "ClaimedOperator"));
        Assert.Equal(1, Detail(record, "Keep"));
        Assert.Equal(30, Detail(record, "MaxAgeDays"));
        Assert.Equal([names[2], names[1], names[0]], ((IEnumerable<string>)Detail(record, "Deleted")!).ToList());
        Assert.Equal(1, Detail(record, "Remaining"));
        // The request itself is recorded as every changing request is, with its identifier.
        var request = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.HubRequestServed);
        Assert.Equal("backup.prune", request.TargetId);
        Assert.Equal("audit-1", Detail(request, "RequestId"));
        Assert.All(_audit.Entries, e => Assert.Equal("hub", e.Actor));
    }

    [Fact]
    public async Task An_empty_backup_directory_is_pruned_to_nothing_without_error()
    {
        using var client = Client();

        var answer = await client.PruneBackupsAsync(keep: 3, maxAgeDays: null, "empty-1");

        Assert.Empty(answer.Deleted);
        Assert.Empty(answer.Remaining);
    }
}
