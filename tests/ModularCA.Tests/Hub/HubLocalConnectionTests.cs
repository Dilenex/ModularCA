using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.Settings;
using ModularCA.HubConnection.Client;
using ModularCA.HubConnection.Contract;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Settings;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Hub;

/// <summary>
/// The hub's local connection, driven over a real Unix domain socket against the real listener
/// (<see cref="HubLocalHost"/>) and the node's real operations (<see cref="NodeHubOperations"/>),
/// with the mode in a real state file. Health and the backup itself are stood in for. Kestrel
/// listens on a Unix socket on Windows 10 and later as well, so these run on both.
/// </summary>
public sealed class HubLocalConnectionTests : IAsyncLifetime
{
    private const string Token = "kQ3vX0d8m1c5Zr7tYb2Ns9Lw4Hf6Pj0aUe3Gi8Ro1Vk";

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

    /// <summary>A settings store nothing is asked of: the save itself is a delegate these tests supply.</summary>
    private class NoStore : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => throw new NotSupportedException(targetMethod?.Name);
    }

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mh-" + Guid.NewGuid().ToString("N")[..10]);
    private readonly Audit _audit = new();
    private readonly SystemConfig _config = new();
    private readonly List<string> _saved = [];
    private int _backups;
    private bool _backupFails;
    private int _inventoryReads;

    /// <summary>What the stand-in for the identifier's reader answers: not known, until a test says otherwise.</summary>
    private InstanceIdReading _instanceId = new(null, false);

    /// <summary>The inventory the stand-in reader answers: every optional part has nothing to say.</summary>
    private static readonly HubInventory EmptyInventory = new(
        "0.4.5-test", new HubInventorySchema(new HubInventoryMigrations("20261101000000_Newest", 3), null), null, null, null, [], []);
    private InstanceModeStore _modes = null!;
    private WebApplication? _host;

    private string SocketPath => Path.Combine(_dir, "hub.sock");

    public Task InitializeAsync()
    {
        Directory.CreateDirectory(_dir);
        _modes = InstanceModeStore.Open(SocketPath, null, Path.Combine(_dir, "config"));
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_host != null) await _host.DisposeAsync();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private NodeHubOperations Operations()
    {
        var services = new ServiceCollection().AddSingleton<IAuditService>(_audit)
            .AddSingleton(DispatchProxy.Create<ISettingsStore, NoStore>()).BuildServiceProvider();
        return new NodeHubOperations(
            _modes, _config, services.GetRequiredService<IServiceScopeFactory>(),
            _ => Task.FromResult(new HubHealthReport("healthy", JsonSerializer.SerializeToElement(new { database = new { status = "ok" } }))),
            _ =>
            {
                Interlocked.Increment(ref _backups);
                if (_backupFails) throw new InvalidOperationException("The backup failed with exit code 1.");
                return Task.FromResult(new HubBackupResult($"modularca-backup-{_backups}.zip", 4096, DateTime.UtcNow));
            },
            (_, actor, reason, _) => { _saved.Add($"{actor.Name}: {reason}"); return Task.CompletedTask; },
            "0.4.5-test")
        {
            Inventory = _ => { Interlocked.Increment(ref _inventoryReads); return Task.FromResult(EmptyInventory); },
            InstanceId = _ => Task.FromResult(_instanceId),
        };
    }

    private async Task StartAsync(UnixFileMode mode = HubLocalHostOptions.DefaultSocketMode)
    {
        if (_host != null) await _host.DisposeAsync();
        var options = new HubLocalHostOptions(SocketPath, mode, Path.Combine(_dir, HubRequestLedger.FileName));
        _host = HubLocalHost.Build(options, Operations(), b => b.Logging.ClearProviders());
        await HubLocalHost.StartAsync(_host, options);
    }

    private void GiveToken(string token = Token)
        => _config.Hub.AffiliationTokenSha256 = Convert.ToHexString(HubLocalHost.HashToken(token)).ToLowerInvariant();

    private HubLocalClient Client(string? token = null, string? operatorName = "alice@hub") => new(SocketPath, token, operatorName, TimeSpan.FromSeconds(20));

    private static object? Detail(Audited entry, string name) => entry.Details!.GetType().GetProperty(name)!.GetValue(entry.Details);

    /// <summary>Sends bytes on a raw connection and returns everything the listener answers before it closes or goes quiet.</summary>
    private async Task<string> RawAsync(string request)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath));
        await socket.SendAsync(Encoding.ASCII.GetBytes(request));
        var buffer = new byte[8192];
        var answer = new StringBuilder();
        using var quiet = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            // The answers are chunked: the last chunk is the empty one.
            while (!answer.ToString().EndsWith("\r\n0\r\n\r\n", StringComparison.Ordinal))
            {
                var read = await socket.ReceiveAsync(buffer, quiet.Token);
                if (read == 0) break;
                answer.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException) { }
        return answer.ToString();
    }

    // ---- an instance with no hub opens nothing for one --------------------------------------------

    [Fact]
    public void With_the_variable_unset_the_node_hosts_no_hub_listener()
    {
        var connection = ApiAssembly.TypeNamed("ModularCA.API.Startup.HubLocalConnection");
        var roles = ApiAssembly.TypeNamed("ModularCA.API.Startup.ActiveRoles");
        var role = ApiAssembly.TypeNamed("ModularCA.API.Startup.ProcessRole");
        object Roles(string name) => Activator.CreateInstance(roles, Enum.Parse(role, name))!;
        bool Hosts(string? socket, string roleName, bool setup) => (bool)connection.GetMethod("Hosts")!.Invoke(null, [socket, Roles(roleName), setup])!;

        Assert.False(Hosts(null, "All", false));
        Assert.False(Hosts("", "All", false));
        Assert.False(Hosts("   ", "Control", false));
        Assert.True(Hosts("/run/modularca-hub/hub.sock", "All", false));
        Assert.True(Hosts("/run/modularca-hub/hub.sock", "Control", false));
        // The control role hosts it; a process without that role, and the setup wizard, do not.
        Assert.False(Hosts("/run/modularca-hub/hub.sock", "Validation", false));
        Assert.False(Hosts("/run/modularca-hub/hub.sock", "Enrollment", false));
        Assert.False(Hosts("/run/modularca-hub/hub.sock", "All", true));
    }

    [Fact]
    public void The_node_opens_the_listener_only_behind_that_check_and_reads_the_socket_from_the_environment_alone()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "ModularCA.sln"))) root = Path.GetDirectoryName(root)!;
        var startup = File.ReadAllText(Path.Combine(root, "ModularCA.API", "StartModularCA.cs"));

        var start = startup.IndexOf("HubLocalConnection.StartAsync(", StringComparison.Ordinal);
        Assert.True(start > 0);
        Assert.Equal(start, startup.LastIndexOf("HubLocalConnection.StartAsync(", StringComparison.Ordinal));
        var guard = startup.LastIndexOf("if (ModularCA.API.Startup.HubLocalConnection.Hosts(hubSocketPath, activeRoles, isSetupMode))", start, StringComparison.Ordinal);
        Assert.InRange(start - guard, 1, 200);
        Assert.Contains("Environment.GetEnvironmentVariable(ModularCA.Shared.Modes.InstanceModeStore.HubSocketVariable)", startup);
        Assert.Equal(HubLocalHostOptions.SocketVariable, InstanceModeStore.HubSocketVariable);
        Assert.DoesNotContain("ListenUnixSocket", startup);
    }

    // ---- apart from the ordinary listeners ---------------------------------------------------------

    [Fact]
    public void Nothing_on_the_ordinary_listeners_routes_to_a_hub_request()
    {
        // The hub's requests are served by a host of their own. The node's host has no route under
        // the hub's prefix: no controller, and no endpoint mapped in the startup file.
        foreach (var controller in ApiAssembly.ControllerTypes())
        {
            var templates = controller.GetCustomAttributes(true).OfType<RouteAttribute>().Select(r => r.Template)
                .Concat(controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
                    .SelectMany(m => m.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>().Select(a => a.Template)));
            Assert.All(templates, t => Assert.False((t ?? "").TrimStart('/').StartsWith("hub", StringComparison.OrdinalIgnoreCase), $"{controller.Name}: {t}"));
        }
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "ModularCA.sln"))) root = Path.GetDirectoryName(root)!;
        Assert.DoesNotContain("/hub/", File.ReadAllText(Path.Combine(root, "ModularCA.API", "StartModularCA.cs")));
        Assert.DoesNotContain(typeof(IHubLocalOperations).Assembly.GetTypes(), t => typeof(ControllerBase).IsAssignableFrom(t));
    }

    [Theory]
    [InlineData("GET", "/health/ready")]
    [InlineData("GET", "/api/v1/admin/users")]
    [InlineData("POST", "/api/v1/auth/login")]
    [InlineData("GET", "/")]
    [InlineData("POST", "/hub/v1/stop")]
    [InlineData("POST", "/hub/v1/inventory")]
    [InlineData("DELETE", "/hub/v1/mode")]
    [InlineData("GET", "/hub/v2/health")]
    public async Task A_request_outside_the_list_is_refused_and_audited(string method, string path)
    {
        await StartAsync();
        using var client = Client();

        using var response = await client.SendRawAsync(new HttpRequestMessage(new HttpMethod(method), path));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var error = JsonSerializer.Deserialize<HubError>(await response.Content.ReadAsStringAsync(), HubLocalContract.Json)!;
        Assert.Equal(HubLocalContract.Errors.OperationNotListed, error.Error);
        Assert.Equal(HubLocalContract.Operations.All, error.Operations);

        var audited = Assert.Single(_audit.Entries);
        Assert.Equal(AuditActionType.HubRequestRefused, audited.Action);
        Assert.Equal(NodeHubOperations.Actor, audited.Actor);
        Assert.Null(audited.ActorId);
        Assert.False(audited.Success);
        Assert.Equal($"{method} {path}", audited.TargetId);
        Assert.Equal("alice@hub", Detail(audited, "ClaimedOperator"));
    }

    [Fact]
    public void The_list_is_exactly_health_mode_backup_and_token_replacement()
    {
        Assert.Equal(
            ["hello", "health.read", "mode.read", "mode.set", "backup.create", "affiliation-token.replace", "inventory.read", "backup.prune"],
            HubLocalContract.Operations.All);
        Assert.Null(HubLocalHost.OperationOf("POST", "/hub/v1/stop"));
        Assert.Null(HubLocalHost.OperationOf("POST", "/hub/v1/mode"));
        Assert.Equal("mode.set", HubLocalHost.OperationOf("put", "/hub/v1/mode/"));
    }

    // ---- the token ------------------------------------------------------------------------------

    [Fact]
    public async Task With_no_hash_the_request_is_served_and_health_says_the_check_is_off()
    {
        await StartAsync();
        using var client = Client();

        var health = await client.ReadHealthAsync();

        Assert.Equal(HubLocalContract.TokenCheckOff, health.TokenCheck);
        Assert.Equal("healthy", health.Status);
        Assert.Equal("restricted", health.Mode.Mode);
        Assert.Equal("start", health.Mode.Source);
        Assert.Equal("0.4.5-test", health.InstanceVersion);
        Assert.Equal(HubLocalContract.Version, health.ContractVersion);
        Assert.Equal("ok", health.Checks!.Value.GetProperty("database").GetProperty("status").GetString());
        Assert.Equal(HubLocalContract.TokenCheckOff, (await client.HelloAsync()).TokenCheck);

        var served = _audit.Entries.Where(e => e.Action == AuditActionType.HubRequestServed).ToList();
        Assert.Equal(2, served.Count);
        Assert.All(served, e => Assert.Equal(HubLocalContract.TokenCheckOff, Detail(e, "TokenCheck")));
    }

    /// <summary>
    /// A hub polls health every few seconds. Served reads are counted and written as one record
    /// per interval, the first at once; a change, a refusal and a failure are each still their
    /// own record.
    /// </summary>
    [Fact]
    public async Task Served_reads_are_counted_into_one_record_per_interval()
    {
        var now = new DateTime(2026, 11, 12, 10, 0, 0, DateTimeKind.Utc);
        var operations = Operations();
        operations.UtcNow = () => now;
        HubRequestRecord Read(string operation) => new(operation, "GET", "/hub/v1/x", 200, null, null, "alice@hub", HubLocalContract.Version, false, HubLocalContract.TokenCheckOff);

        await operations.AuditAsync(Read(HubLocalContract.Operations.HealthRead), CancellationToken.None);
        var first = Assert.Single(_audit.Entries);
        Assert.Equal((AuditActionType.HubRequestServed, "reads"), (first.Action, first.TargetId));

        for (var i = 0; i < 40; i++)
        {
            now = now.AddSeconds(5);
            await operations.AuditAsync(Read(i % 4 == 0 ? HubLocalContract.Operations.ModeRead : HubLocalContract.Operations.HealthRead), CancellationToken.None);
        }
        Assert.Single(_audit.Entries);

        // A refusal inside the interval is its own record, at once.
        await operations.AuditAsync(new HubRequestRecord(null, "GET", "/hub/v1/users", 404, HubLocalContract.Errors.OperationNotListed,
            null, "alice@hub", HubLocalContract.Version, false, HubLocalContract.TokenCheckOff), CancellationToken.None);
        Assert.Equal(2, _audit.Entries.Count);
        Assert.Equal(AuditActionType.HubRequestRefused, _audit.Entries[1].Action);

        now = now.Add(operations.ReadAuditInterval);
        await operations.AuditAsync(Read(HubLocalContract.Operations.HealthRead), CancellationToken.None);
        Assert.Equal(3, _audit.Entries.Count);
        var counts = (Dictionary<string, int>)Detail(_audit.Entries[2], "Counts")!;
        Assert.Equal(31, counts[HubLocalContract.Operations.HealthRead]);
        Assert.Equal(10, counts[HubLocalContract.Operations.ModeRead]);
    }

    [Fact]
    public async Task With_a_hash_the_right_token_is_served_and_health_says_the_check_is_enforced()
    {
        GiveToken();
        await StartAsync();
        using var client = Client(Token);

        Assert.Equal(HubLocalContract.TokenCheckEnforced, (await client.ReadHealthAsync()).TokenCheck);
    }

    [Theory]
    [InlineData(null, HubLocalContract.Errors.TokenRequired)]
    [InlineData("not-the-token", HubLocalContract.Errors.TokenInvalid)]
    [InlineData("kQ3vX0d8m1c5Zr7tYb2Ns9Lw4Hf6Pj0aUe3Gi8Ro1VK", HubLocalContract.Errors.TokenInvalid)]
    public async Task With_a_hash_a_missing_or_wrong_token_gets_nothing_on_any_operation(string? token, string expected)
    {
        GiveToken();
        await StartAsync();
        using var client = Client(token);

        var refusals = new List<HubLocalException>
        {
            await Assert.ThrowsAsync<HubLocalException>(() => client.ReadHealthAsync()),
            await Assert.ThrowsAsync<HubLocalException>(() => client.ReadModeAsync()),
            await Assert.ThrowsAsync<HubLocalException>(() => client.HelloAsync()),
            await Assert.ThrowsAsync<HubLocalException>(() => client.SetModeAsync("full", "x", "r-1")),
            await Assert.ThrowsAsync<HubLocalException>(() => client.CreateBackupAsync("r-2")),
            await Assert.ThrowsAsync<HubLocalException>(() => client.ReplaceAffiliationTokenAsync(new string('a', 64), "r-3")),
            await Assert.ThrowsAsync<HubLocalException>(() => client.ReadInventoryAsync()),
        };

        Assert.All(refusals, r => { Assert.Equal(401, r.Status); Assert.Equal(expected, r.Code); });
        Assert.Equal(InstanceMode.Restricted, _modes.Current.Mode);
        Assert.Equal(0, _backups);
        Assert.Empty(_saved);
        Assert.Equal(0, _inventoryReads);
        Assert.Equal(7, _audit.Entries.Count);
        Assert.All(_audit.Entries, e => { Assert.Equal(AuditActionType.HubRequestRefused, e.Action); Assert.Equal(expected, e.Error); });
    }

    [Fact]
    public async Task A_wrong_token_is_refused_before_the_body_is_read()
    {
        GiveToken();
        await StartAsync();

        // The headers promise a body that is never sent. A listener that read the body before
        // checking the token would wait for it; this one answers from the headers alone.
        var answer = await RawAsync(
            "PUT /hub/v1/mode HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer wrong\r\n"
            + $"{HubLocalContract.ContractHeader}: 1.0\r\n{HubLocalContract.RequestIdHeader}: r-1\r\n"
            + "Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 401", answer);
        Assert.Contains(HubLocalContract.Errors.TokenInvalid, answer);
        Assert.Equal(InstanceMode.Restricted, _modes.Current.Mode);
    }

    [Fact]
    public async Task With_the_right_token_the_same_unsent_body_is_waited_for()
    {
        GiveToken();
        await StartAsync();

        var answer = await RawAsync(
            $"PUT /hub/v1/mode HTTP/1.1\r\nHost: hub.local\r\nAuthorization: Bearer {Token}\r\n"
            + $"{HubLocalContract.ContractHeader}: 1.0\r\n{HubLocalContract.RequestIdHeader}: r-1\r\n"
            + "Content-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"mode\":\"full\"}         ");

        Assert.StartsWith("HTTP/1.1 200", answer);
        Assert.Equal(InstanceMode.Full, _modes.Current.Mode);
    }

    [Fact]
    public async Task The_hub_replaces_its_token_old_token_in_new_hash_in()
    {
        GiveToken();
        await StartAsync();
        const string newToken = "a-new-token-made-by-the-hub-0123456789abcdef";
        var newHash = Convert.ToHexString(HubLocalHost.HashToken(newToken)).ToLowerInvariant();

        using (var old = Client(Token))
            Assert.Equal(HubLocalContract.TokenCheckEnforced, (await old.ReplaceAffiliationTokenAsync(newHash, "rot-1")).TokenCheck);

        Assert.Equal(newHash, _config.Hub.AffiliationTokenSha256);
        Assert.Equal(["hub: The hub replaced its affiliation token"], _saved);
        using (var old = Client(Token))
            Assert.Equal(HubLocalContract.Errors.TokenInvalid, (await Assert.ThrowsAsync<HubLocalException>(() => old.ReadModeAsync())).Code);
        using (var current = Client(newToken))
            Assert.Equal("restricted", (await current.ReadModeAsync()).Mode);

        var replaced = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.HubAffiliationTokenReplaced);
        Assert.Equal(NodeHubOperations.Actor, replaced.Actor);
        Assert.Equal(true, Detail(replaced, "Replaced"));
        Assert.DoesNotContain(_audit.Entries, e => JsonSerializer.Serialize(e.Details).Contains(newToken, StringComparison.Ordinal));
    }

    [Fact]
    public async Task While_the_check_is_off_the_hub_can_give_the_first_hash_and_the_check_is_then_on()
    {
        await StartAsync();
        var hash = Convert.ToHexString(HubLocalHost.HashToken(Token)).ToLowerInvariant();

        using (var open = Client())
        {
            await open.ReplaceAffiliationTokenAsync(hash, "first-1");
            Assert.Equal(HubLocalContract.Errors.TokenRequired, (await Assert.ThrowsAsync<HubLocalException>(() => open.ReadHealthAsync())).Code);
        }
        using var withToken = Client(Token);
        Assert.Equal(HubLocalContract.TokenCheckEnforced, (await withToken.ReadHealthAsync()).TokenCheck);
        Assert.Equal(["hub: The hub gave its first affiliation token"], _saved);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("the-token-itself-instead-of-its-hash")]
    public async Task A_new_hash_that_is_not_a_sha256_is_refused_and_the_old_token_stays(string notAHash)
    {
        GiveToken();
        await StartAsync();
        using var client = Client(Token);

        var refusal = await Assert.ThrowsAsync<HubLocalException>(() => client.ReplaceAffiliationTokenAsync(notAHash, "rot-1"));

        Assert.Equal(HubLocalContract.Errors.InvalidRequest, refusal.Code);
        Assert.Equal("restricted", (await client.ReadModeAsync()).Mode);
    }

    [Fact]
    public void A_stored_hash_that_is_not_a_sha256_refuses_every_token_and_does_not_turn_the_check_off()
    {
        _config.Hub.AffiliationTokenSha256 = "garbage";
        var hash = Operations().AffiliationTokenHash;

        Assert.NotNull(hash);
        Assert.Equal(new byte[32], hash);
    }

    // ---- versions -----------------------------------------------------------------------------

    [Fact]
    public async Task Each_side_states_its_contract_version_and_operations()
    {
        await StartAsync();
        using var client = Client();

        var theirs = await client.HelloAsync();

        Assert.Equal("1.1", theirs.ContractVersion);
        Assert.Equal(HubLocalContract.Operations.All, theirs.Operations);
        Assert.Equal("0.4.5-test", theirs.InstanceVersion);
    }

    // ---- the identifier in hello ----------------------------------------------------------------

    private const string InstanceId = "9f2c4a1b8e7d6350f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708";

    /// <summary>The body of the instance's answer to a hello sent on a raw connection, as it is on the wire.</summary>
    private async Task<JsonElement> RawHelloAsync()
    {
        const string hello = "{\"contractVersion\":\"1.1\",\"operations\":[\"hello\"]}";
        var answer = await RawAsync($"POST /hub/v1/hello HTTP/1.1\r\nHost: hub.local\r\n{HubLocalContract.ContractHeader}: 1.1\r\n"
            + $"Content-Type: application/json\r\nContent-Length: {hello.Length}\r\n\r\n{hello}");
        Assert.StartsWith("HTTP/1.1 200", answer);
        var json = answer[answer.IndexOf('{')..(answer.LastIndexOf('}') + 1)];
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    [Fact]
    public async Task Hello_carries_the_instance_identifier_and_the_contract_stays_1_1()
    {
        _instanceId = new InstanceIdReading(InstanceId, true);
        await StartAsync();
        using var client = Client();

        var theirs = await client.HelloAsync();
        var wire = await RawHelloAsync();

        Assert.Equal(InstanceId, theirs.InstanceId);
        Assert.Equal("1.1", theirs.ContractVersion);
        Assert.Equal("1.1", HubLocalContract.Version);
        Assert.Equal(InstanceId, wire.GetProperty("instanceId").GetString());
        // One field was added to the answer and nothing else.
        Assert.Equal(["contractVersion", "instanceId", "instanceVersion", "operations", "tokenCheck"],
            wire.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        // The hub's own hello does not carry one.
        Assert.Null(new HubHello(HubLocalContract.Version, HubLocalContract.Operations.All).InstanceId);
    }

    [Fact]
    public async Task Hello_carries_no_identifier_when_the_instance_does_not_know_it()
    {
        await StartAsync();
        using var client = Client();

        Assert.Null((await client.HelloAsync()).InstanceId);
        var wire = await RawHelloAsync();
        Assert.False(wire.TryGetProperty("instanceId", out _));
        Assert.Equal(["contractVersion", "instanceVersion", "operations", "tokenCheck"],
            wire.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));

        // Before the first start of a build that stores it, hello gives the derived fingerprint
        // the manifest gives; once one is stored, that one, for good.
        _instanceId = new InstanceIdReading(InstanceId, false);
        Assert.Equal(InstanceId, (await client.HelloAsync()).InstanceId);
        _instanceId = new InstanceIdReading(new string('a', 64), true);
        Assert.Equal(new string('a', 64), (await client.HelloAsync()).InstanceId);
        _instanceId = new InstanceIdReading(InstanceId, true);
        Assert.Equal(new string('a', 64), (await client.HelloAsync()).InstanceId);
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.HubRequestRefused);
    }

    [Theory]
    [InlineData("1.0", true)]
    [InlineData("1.7", true)]
    [InlineData(" 1.12 ", true)]
    [InlineData("2.0", false)]
    [InlineData("0.9", false)]
    [InlineData("1", false)]
    [InlineData("one", false)]
    [InlineData(null, false)]
    public async Task A_request_of_the_same_major_version_is_served_and_any_other_is_refused(string? version, bool served)
    {
        Assert.Equal(served, HubLocalContract.IsCompatible(version));
        await StartAsync();

        var answer = await RawAsync("GET /hub/v1/mode HTTP/1.1\r\nHost: hub.local\r\n"
            + (version == null ? "" : $"{HubLocalContract.ContractHeader}: {version}\r\n") + "\r\n");

        if (served)
        {
            Assert.StartsWith("HTTP/1.1 200", answer);
            return;
        }
        Assert.StartsWith("HTTP/1.1 400", answer);
        Assert.Contains(HubLocalContract.Errors.ContractVersionUnsupported, answer);
        Assert.Contains("\"contractVersion\":\"1.1\"", answer);
        Assert.Equal(HubLocalContract.Errors.ContractVersionUnsupported, Assert.Single(_audit.Entries).Error);
    }

    [Fact]
    public async Task A_hub_that_states_another_major_version_in_its_hello_is_refused()
    {
        await StartAsync();
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, HubLocalContract.Paths.Hello)
        {
            Content = new StringContent("{\"contractVersion\":\"2.0\",\"operations\":[\"health.read\",\"fleet.adopt\"]}", Encoding.UTF8, "application/json"),
        };

        using var response = await client.SendRawAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HubLocalContract.Errors.ContractVersionUnsupported, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Fields_this_version_does_not_know_are_ignored_so_the_contract_can_grow()
    {
        await StartAsync();
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Put, HubLocalContract.Paths.Mode)
        {
            Content = new StringContent("{\"mode\":\"full\",\"reason\":\"ok\",\"addedIn\":\"1.3\"}", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add(HubLocalContract.RequestIdHeader, "grow-1");

        using var response = await client.SendRawAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(InstanceMode.Full, _modes.Current.Mode);
    }

    // ---- the mode ------------------------------------------------------------------------------

    [Fact]
    public async Task The_hub_sets_the_mode_and_the_record_says_the_hub_set_it_and_who_it_named()
    {
        await StartAsync();
        using var client = Client(operatorName: "alice@hub");

        var set = await client.SetModeAsync("dr", "failing over to site B", "mode-1");

        Assert.Equal("dr", set.Mode);
        Assert.Equal("hub", set.Source);
        Assert.Equal("alice@hub", set.SetBy);
        Assert.Equal("failing over to site B", set.Reason);
        Assert.NotNull(set.SetAtUtc);
        Assert.Equal(set, await client.ReadModeAsync());
        Assert.Equal(set, (await client.ReadHealthAsync()).Mode);
        Assert.Equal(new InstanceModeRecord(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, "alice@hub", "failing over to site B", set.SetAtUtc), _modes.Current);
        // It is in the state file beside the socket, so it survives a restart of the node.
        Assert.Equal(InstanceMode.DisasterRecovery, InstanceModeStore.Open(SocketPath, "full", Path.Combine(_dir, "config")).Current.Mode);
        Assert.True(File.Exists(Path.Combine(_dir, InstanceModeStore.FileName)));

        var changed = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.InstanceModeChanged);
        Assert.Equal(NodeHubOperations.Actor, changed.Actor);
        Assert.Equal("restricted", Detail(changed, "From"));
        Assert.Equal("dr", Detail(changed, "To"));
        Assert.Equal("alice@hub", Detail(changed, "ClaimedOperator"));
    }

    [Fact]
    public async Task The_last_writer_wins_between_the_hub_and_an_administrator()
    {
        await StartAsync();
        using var client = Client();

        await client.SetModeAsync("dr", null, "mode-1");
        _modes.Set(InstanceMode.Full, InstanceModeSource.Administrator, "root", "the hub went silent");
        var seen = await client.ReadModeAsync();

        Assert.Equal(("full", "administrator", "root"), (seen.Mode, seen.Source, seen.SetBy));

        await client.SetModeAsync("restricted", null, "mode-2");
        Assert.Equal(InstanceModeSource.Hub, _modes.Current.Source);
    }

    [Theory]
    [InlineData("{\"mode\":\"standby\"}")]
    [InlineData("{\"mode\":\"\"}")]
    [InlineData("{}")]
    [InlineData("not json")]
    [InlineData("")]
    public async Task A_mode_that_is_not_one_is_refused_and_nothing_changes(string body)
    {
        await StartAsync();
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Put, HubLocalContract.Paths.Mode) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Add(HubLocalContract.RequestIdHeader, "bad-1");

        using var response = await client.SendRawAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HubLocalContract.Errors.InvalidRequest, await response.Content.ReadAsStringAsync());
        Assert.Equal(InstanceModeSource.Start, _modes.Current.Source);
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.InstanceModeChanged);
    }

    // ---- once ----------------------------------------------------------------------------------

    [Fact]
    public async Task A_backup_is_asked_for_and_recorded_under_the_hub()
    {
        await StartAsync();
        using var client = Client();

        var backup = await client.CreateBackupAsync("backup-1");

        Assert.Equal("modularca-backup-1.zip", backup.FileName);
        Assert.Equal(4096, backup.SizeBytes);
        Assert.Equal(1, _backups);
        var created = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.BackupCreated);
        Assert.Equal(NodeHubOperations.Actor, created.Actor);
        Assert.True(created.Success);
        Assert.Equal("modularca-backup-1.zip", created.TargetId);
    }

    [Fact]
    public async Task A_repeated_request_identifier_is_done_once_even_across_a_restart_of_the_node()
    {
        await StartAsync();
        using var client = Client();
        using var first = await SendBackupAsync(client, "backup-7");
        using var again = await SendBackupAsync(client, "backup-7");

        await StartAsync();
        using var afterRestart = Client();
        using var third = await SendBackupAsync(afterRestart, "backup-7");
        using var other = await SendBackupAsync(afterRestart, "backup-8");

        Assert.Equal(2, _backups);
        Assert.False(first.Headers.Contains(HubLocalContract.ReplayedHeader));
        Assert.Equal("true", again.Headers.GetValues(HubLocalContract.ReplayedHeader).Single());
        Assert.Equal("true", third.Headers.GetValues(HubLocalContract.ReplayedHeader).Single());
        var body = await first.Content.ReadAsStringAsync();
        Assert.Equal(body, await again.Content.ReadAsStringAsync());
        Assert.Equal(body, await third.Content.ReadAsStringAsync());
        Assert.NotEqual(body, await other.Content.ReadAsStringAsync());

        Assert.Equal(2, _audit.Entries.Count(e => e.Action == AuditActionType.BackupCreated));
        var served = _audit.Entries.Where(e => e.Action == AuditActionType.HubRequestServed).ToList();
        Assert.Equal(4, served.Count);
        Assert.Equal(2, served.Count(e => (bool)Detail(e, "Replayed")!));
    }

    private static async Task<HttpResponseMessage> SendBackupAsync(HubLocalClient client, string requestId)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, HubLocalContract.Paths.Backup) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        request.Headers.Add(HubLocalContract.RequestIdHeader, requestId);
        var response = await client.SendRawAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return response;
    }

    [Fact]
    public async Task A_repeated_mode_request_does_not_undo_what_an_administrator_set_in_between()
    {
        await StartAsync();
        using var client = Client();

        await client.SetModeAsync("dr", "failover", "mode-9");
        _modes.Set(InstanceMode.Full, InstanceModeSource.Administrator, "root", "recovered by hand");
        var repeated = await client.SetModeAsync("dr", "failover", "mode-9");

        Assert.Equal("dr", repeated.Mode);
        Assert.Equal(InstanceMode.Full, _modes.Current.Mode);
        Assert.Single(_audit.Entries, e => e.Action == AuditActionType.InstanceModeChanged);
    }

    [Fact]
    public async Task A_request_identifier_used_again_for_a_different_request_is_refused()
    {
        await StartAsync();
        using var client = Client();
        await client.SetModeAsync("dr", null, "id-1");

        var otherBody = await Assert.ThrowsAsync<HubLocalException>(() => client.SetModeAsync("full", null, "id-1"));
        var otherOperation = await Assert.ThrowsAsync<HubLocalException>(() => client.CreateBackupAsync("id-1"));

        Assert.Equal((409, HubLocalContract.Errors.RequestIdReused), (otherBody.Status, otherBody.Code));
        Assert.Equal(HubLocalContract.Errors.RequestIdReused, otherOperation.Code);
        Assert.Equal(InstanceMode.DisasterRecovery, _modes.Current.Mode);
        Assert.Equal(0, _backups);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("has spaces")]
    [InlineData("semi;colon")]
    public async Task A_request_that_changes_something_needs_a_request_identifier(string? requestId)
    {
        await StartAsync();
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, HubLocalContract.Paths.Backup) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        if (requestId != null) request.Headers.TryAddWithoutValidation(HubLocalContract.RequestIdHeader, requestId);

        using var response = await client.SendRawAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HubLocalContract.Errors.RequestIdRequired, await response.Content.ReadAsStringAsync());
        Assert.Equal(0, _backups);
    }

    [Fact]
    public async Task A_backup_that_fails_is_reported_recorded_and_can_be_asked_for_again_with_the_same_identifier()
    {
        await StartAsync();
        using var client = Client();
        _backupFails = true;

        var failure = await Assert.ThrowsAsync<HubLocalException>(() => client.CreateBackupAsync("backup-3"));

        Assert.Equal((500, HubLocalContract.Errors.BackupFailed), (failure.Status, failure.Code));
        Assert.DoesNotContain("exit code", failure.Message);
        var failed = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.BackupCreated);
        Assert.False(failed.Success);
        Assert.Equal(HubLocalContract.Errors.BackupFailed, Assert.Single(_audit.Entries, e => e.Action == AuditActionType.HubRequestRefused).Error);

        _backupFails = false;
        Assert.Equal("modularca-backup-2.zip", (await client.CreateBackupAsync("backup-3")).FileName);
    }

    // ---- the inventory (contract 1.1) -------------------------------------------------------------

    [Fact]
    public async Task The_inventory_is_read_over_the_socket_and_what_has_nothing_to_say_is_sent_as_null()
    {
        GiveToken();
        await StartAsync();
        using var client = Client(Token);

        var inventory = await client.ReadInventoryAsync();

        Assert.Equivalent(EmptyInventory, inventory, strict: true);
        Assert.Equal(1, _inventoryReads);
        using var raw = await client.SendRawAsync(new HttpRequestMessage(HttpMethod.Get, "/hub/v1/inventory/"));
        Assert.Equal(HttpStatusCode.OK, raw.StatusCode);
        Assert.Equal(
            "{\"instanceVersion\":\"0.4.5-test\",\"schema\":{\"application\":{\"newestMigration\":\"20261101000000_Newest\",\"appliedCount\":3},\"audit\":null},"
            + "\"signer\":null,\"webTlsCertificate\":null,\"newestBackup\":null,\"failingJobs\":[],\"certificateAuthorities\":[]}",
            await raw.Content.ReadAsStringAsync());
        Assert.Equal("inventory.read", HubLocalHost.OperationOf("GET", "/hub/v1/inventory"));
        // It is a read: it takes no request identifier and is never replayed from the ledger.
        Assert.False(raw.Headers.Contains(HubLocalContract.ReplayedHeader));
        Assert.Equal(0, _backups);
        Assert.Equal(InstanceMode.Restricted, _modes.Current.Mode);
    }

    /// <summary>
    /// Raising the minor version for the new operation does not shut out a hub built against
    /// 1.0: its requests and its hello are served as before, and the hello tells it what this
    /// instance now has.
    /// </summary>
    [Fact]
    public async Task A_hub_that_speaks_1_0_is_still_served_and_is_told_of_the_new_operation()
    {
        await StartAsync();

        var health = await RawAsync($"GET /hub/v1/health HTTP/1.1\r\nHost: hub.local\r\n{HubLocalContract.ContractHeader}: 1.0\r\n\r\n");
        var inventory = await RawAsync($"GET /hub/v1/inventory HTTP/1.1\r\nHost: hub.local\r\n{HubLocalContract.ContractHeader}: 1.0\r\n\r\n");
        const string hello = "{\"contractVersion\":\"1.0\",\"operations\":[\"hello\",\"health.read\",\"mode.read\",\"mode.set\",\"backup.create\",\"affiliation-token.replace\"]}";
        var answer = await RawAsync($"POST /hub/v1/hello HTTP/1.1\r\nHost: hub.local\r\n{HubLocalContract.ContractHeader}: 1.0\r\n"
            + $"Content-Type: application/json\r\nContent-Length: {hello.Length}\r\n\r\n{hello}");

        Assert.StartsWith("HTTP/1.1 200", health);
        Assert.StartsWith("HTTP/1.1 200", inventory);
        Assert.Contains("\"certificateAuthorities\":[]", inventory);
        Assert.StartsWith("HTTP/1.1 200", answer);
        Assert.Contains("\"contractVersion\":\"1.1\"", answer);
        Assert.Contains("\"inventory.read\"", answer);
        Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.HubRequestRefused);
    }

    /// <summary>
    /// A hub polls the inventory every minute or so. Like health and the mode it is counted, and
    /// one record per interval carries the count; it is never one record per request.
    /// </summary>
    [Fact]
    public async Task Inventory_reads_are_counted_with_the_other_reads_and_not_recorded_one_by_one()
    {
        await StartAsync();
        using var client = Client();

        for (var i = 0; i < 6; i++)
            await client.ReadInventoryAsync();
        await client.ReadHealthAsync();

        Assert.Equal(6, _inventoryReads);
        var only = Assert.Single(_audit.Entries);
        Assert.Equal((AuditActionType.HubRequestServed, "reads"), (only.Action, only.TargetId));
        Assert.Equal(1, ((Dictionary<string, int>)Detail(only, "Counts")!)[HubLocalContract.Operations.InventoryRead]);

        // The same through the node's operations with the clock in hand: the reads inside the
        // interval are carried by the first record after it.
        var now = new DateTime(2026, 11, 12, 10, 0, 0, DateTimeKind.Utc);
        var operations = Operations();
        operations.UtcNow = () => now;
        _audit.Entries.Clear();
        HubRequestRecord Read(string operation) => new(operation, "GET", "/hub/v1/x", 200, null, null, "alice@hub", HubLocalContract.Version, false, HubLocalContract.TokenCheckOff);

        await operations.AuditAsync(Read(HubLocalContract.Operations.InventoryRead), CancellationToken.None);
        Assert.Single(_audit.Entries);
        for (var i = 0; i < 4; i++)
        {
            now = now.AddMinutes(1);
            await operations.AuditAsync(Read(HubLocalContract.Operations.InventoryRead), CancellationToken.None);
            await operations.AuditAsync(Read(HubLocalContract.Operations.HealthRead), CancellationToken.None);
        }
        Assert.Single(_audit.Entries);

        now = now.Add(operations.ReadAuditInterval);
        await operations.AuditAsync(Read(HubLocalContract.Operations.InventoryRead), CancellationToken.None);
        Assert.Equal(2, _audit.Entries.Count);
        var counts = (Dictionary<string, int>)Detail(_audit.Entries[1], "Counts")!;
        Assert.Equal(5, counts[HubLocalContract.Operations.InventoryRead]);
        Assert.Equal(4, counts[HubLocalContract.Operations.HealthRead]);

        // A refused inventory read is its own record, as every refusal is.
        await operations.AuditAsync(new HubRequestRecord(HubLocalContract.Operations.InventoryRead, "GET", "/hub/v1/inventory", 400,
            HubLocalContract.Errors.ContractVersionUnsupported, null, null, "2.0", false, HubLocalContract.TokenCheckOff), CancellationToken.None);
        Assert.Equal(AuditActionType.HubRequestRefused, _audit.Entries[2].Action);
    }

    [Fact]
    public async Task An_inventory_that_cannot_be_read_is_a_failure_recorded_on_its_own()
    {
        var options = new HubLocalHostOptions(SocketPath, HubLocalHostOptions.DefaultSocketMode, Path.Combine(_dir, HubRequestLedger.FileName));
        var services = new ServiceCollection().AddSingleton<IAuditService>(_audit).BuildServiceProvider();
        // A node that was given no reader: the read throws inside the node.
        var operations = new NodeHubOperations(_modes, _config, services.GetRequiredService<IServiceScopeFactory>(),
            _ => throw new NotSupportedException(), _ => throw new NotSupportedException(), null, "0.4.5-test");
        _host = HubLocalHost.Build(options, operations, b => b.Logging.ClearProviders());
        await HubLocalHost.StartAsync(_host, options);
        using var client = Client();

        var failure = await Assert.ThrowsAsync<HubLocalException>(() => client.ReadInventoryAsync());

        Assert.Equal((500, HubLocalContract.Errors.InternalError), (failure.Status, failure.Code));
        var audited = Assert.Single(_audit.Entries);
        Assert.Equal((AuditActionType.HubRequestRefused, "inventory.read"), (audited.Action, audited.TargetId));
    }

    // ---- the audit trail and the socket ---------------------------------------------------------

    [Fact]
    public async Task Every_request_is_recorded_under_the_hub_with_the_operator_it_claimed()
    {
        await StartAsync();
        using var client = Client(operatorName: "  carol@hub\u0007 ");

        await client.HelloAsync();
        await client.ReadHealthAsync();
        await client.ReadModeAsync();
        await client.SetModeAsync("full", "ready", "all-1");
        await client.CreateBackupAsync("all-2");

        var requests = _audit.Entries.Where(e => e.Action == AuditActionType.HubRequestServed).ToList();
        // The two reads are one record: the first read is written at once and the second is
        // counted towards the next (see Served_reads_are_counted_into_one_record_per_interval).
        Assert.Equal(["hello", "reads", "mode.set", "backup.create"], requests.Select(e => e.TargetId));
        Assert.All(_audit.Entries, e => { Assert.Equal("hub", e.Actor); Assert.Null(e.ActorId); });
        Assert.All(requests, e => Assert.Equal("carol@hub", Detail(e, "ClaimedOperator")));
        Assert.Equal("all-1", Detail(requests[2], "RequestId"));
        Assert.Equal("1.1", Detail(requests[0], "ContractVersion"));
    }

    [Fact]
    public async Task The_socket_file_has_the_mode_asked_for()
    {
        await StartAsync();
        Assert.True(File.Exists(SocketPath));
        if (OperatingSystem.IsWindows()) return;

        Assert.Equal(HubLocalHostOptions.DefaultSocketMode, File.GetUnixFileMode(SocketPath));

        await StartAsync(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(SocketPath));
    }

    [Fact]
    public async Task A_socket_file_left_by_a_run_that_did_not_stop_cleanly_does_not_stop_the_next_start()
    {
        await File.WriteAllTextAsync(SocketPath, "stale");

        await StartAsync();

        using var client = Client();
        Assert.Equal("restricted", (await client.ReadModeAsync()).Mode);
    }

    [Theory]
    [InlineData(null, "0660")]
    [InlineData("", "0660")]
    [InlineData("0660", "0660")]
    [InlineData("660", "0660")]
    [InlineData("0600", "0600")]
    [InlineData("0666", "0666")]
    [InlineData(" 0620 ", "0620")]
    public void The_socket_mode_is_settable(string? text, string expected)
        => Assert.Equal(Convert.ToInt32(expected, 8), (int)HubLocalHostOptions.ParseSocketMode(text));

    [Theory]
    [InlineData("0770")]
    [InlineData("0060")]
    [InlineData("4660")]
    [InlineData("rw-rw----")]
    [InlineData("66")]
    [InlineData("0888")]
    public void A_socket_mode_that_is_not_read_and_write_bits_stops_the_start(string text)
        => Assert.Contains(HubLocalHostOptions.SocketModeVariable, Assert.Throws<ArgumentException>(() => HubLocalHostOptions.ParseSocketMode(text)).Message);

    [Fact]
    public void A_socket_path_too_long_for_a_unix_socket_is_refused_with_its_reason()
    {
        var path = Path.Combine(_dir, new string('x', 120), "hub.sock");
        var ex = Assert.Throws<ArgumentException>(() => HubLocalHost.Build(new HubLocalHostOptions(path), Operations()));
        Assert.Contains(HubLocalHostOptions.SocketVariable, ex.Message);
    }
}
