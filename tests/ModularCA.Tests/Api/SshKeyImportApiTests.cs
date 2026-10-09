using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.Ssh;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// What the node shows of the import of SSH CA key files (<c>docs/architecture/ssh-keystore.md</c>,
/// stage 4): the signer's entry on the readiness page, the admin key list, the plaintext notice,
/// and the retry that imports once a signer locked at start has been unlocked.
/// </summary>
public sealed class SshKeyImportApiTests
{
    private const string Admin = "ModularCA.API.Controllers.v1.Admin.AdminSshController";
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "ssh-operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>The admin SSH controller over an install, for a caller with or without instance scope.</summary>
    private static object AdminController(LegacySshInstall install, ModularCADbContext db, bool instanceScope = true)
    {
        var actor = install.Node.Actor.UserId!.Value;
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(Admin),
            SshServices.Ca(db, install.Node.Relay, install.Node.Audit), new CurrentUserStub(actor), db, new SystemConfig(),
            new KeyCeremonyService(db, new RecordingAuditService()),
            (IDistributedCache)new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            (ISigningService)install.Node.Relay, install.State, SshServices.LoginNames(db, install.Node.Audit))!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: instanceScope, isSystemAdmin: instanceScope));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, [])!;

    private static JsonElement Json(IActionResult result)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsAssignableFrom<ObjectResult>(result).Value, Web)).RootElement;

    // ---- The admin key list ----------------------------------------------------------------------

    [Fact]
    public async Task The_admin_key_list_says_for_each_key_whether_the_signer_holds_it_and_why_not()
    {
        using var install = new LegacySshInstall();
        var imported = install.Seed("A Imported", "ed25519");
        var missing = install.Seed("B Missing", "p256", writeFile: false);
        await install.Import().RunAsync();
        var created = await install.Node.CreateCaAsync("C Created");

        using var db = install.Node.Reopen();
        var listed = Json(await Call(AdminController(install, db), "GetCaKeys")).EnumerateArray().ToDictionary(k => k.GetProperty("id").GetGuid());

        Assert.Equal(3, listed.Count);
        var held = listed[imported.Id];
        Assert.Equal("signer", held.GetProperty("keyStorage").GetString());
        Assert.Equal("held", held.GetProperty("signerState").GetString());
        Assert.Equal(JsonValueKind.Null, held.GetProperty("signerStateCode").ValueKind);
        Assert.Equal(JsonValueKind.Null, held.GetProperty("signerStateReason").ValueKind);
        Assert.Equal(JsonValueKind.String, held.GetProperty("importedAt").ValueKind);

        var awaiting = listed[missing.Id];
        Assert.Equal("legacyFile", awaiting.GetProperty("keyStorage").GetString());
        Assert.Equal("awaitingImport", awaiting.GetProperty("signerState").GetString());
        Assert.Equal("fileMissing", awaiting.GetProperty("signerStateCode").GetString());
        Assert.Contains(install.FileOf(missing), awaiting.GetProperty("signerStateReason").GetString());
        Assert.Equal(install.FileOf(missing), awaiting.GetProperty("keyFile").GetString());
        Assert.Equal(JsonValueKind.Null, awaiting.GetProperty("importedAt").ValueKind);

        Assert.Equal("held", listed[created.Id].GetProperty("signerState").GetString());
        Assert.Equal(JsonValueKind.Null, listed[created.Id].GetProperty("importedAt").ValueKind);
        // What the list carried before is still there.
        Assert.EndsWith($"/ssh/ca-keys/{created.Id}/krl", listed[created.Id].GetProperty("krlUrl").GetString());
        Assert.Equal(created.PublicKey, listed[created.Id].GetProperty("publicKey").GetString());

        // A caller without instance scope sees no SSH CA key, and so nothing of their files.
        Assert.Empty(Json(await Call(AdminController(install, db, instanceScope: false), "GetCaKeys")).EnumerateArray());
    }

    // ---- The plaintext notice --------------------------------------------------------------------

    [Fact]
    public async Task The_plaintext_notice_route_says_which_keys_were_files_and_when_they_were_imported()
    {
        using var install = new LegacySshInstall();
        using var db = install.Node.Reopen();

        // An install whose SSH CA keys were always the signer's has no notice.
        await install.Node.CreateCaAsync("Signer Born");
        var none = Json(await Call(AdminController(install, db), "GetPlaintextNotice"));
        Assert.False(none.GetProperty("applies").GetBoolean());
        Assert.Empty(none.GetProperty("keys").EnumerateArray());

        var imported = install.Seed("A Imported", "p384");
        install.Seed("B Missing", "p256", writeFile: false);
        await install.Import().RunAsync();

        var notice = Json(await Call(AdminController(install, db), "GetPlaintextNotice"));

        Assert.True(notice.GetProperty("applies").GetBoolean());
        Assert.Equal(1, notice.GetProperty("awaitingImport").GetInt32());
        var key = Assert.Single(notice.GetProperty("keys").EnumerateArray());
        Assert.Equal(imported.Id, key.GetProperty("id").GetGuid());
        Assert.Equal("A Imported", key.GetProperty("name").GetString());
        Assert.Equal(SshFixtures.CaPublic("p384").Fingerprint, key.GetProperty("fingerprint").GetString());
        Assert.Equal(install.FileOf(imported), key.GetProperty("keyFile").GetString());
        Assert.True(key.GetProperty("keyFileRemoved").GetBoolean());
        Assert.Equal(key.GetProperty("importedAt").GetDateTime(), notice.GetProperty("lastImportedAt").GetDateTime());
        Assert.Equal(JsonValueKind.Array, notice.GetProperty("earlierArchives").ValueKind);
        Assert.Contains("Rotating an SSH CA", notice.GetProperty("message").GetString());

        // SSH CAs are instance CAs: without instance scope there is no such notice.
        Assert.IsType<NotFoundResult>(await Call(AdminController(install, db, instanceScope: false), "GetPlaintextNotice"));
    }

    // ---- Readiness -------------------------------------------------------------------------------

    /// <summary>The <c>signer</c> entry of <c>/health/ready</c>, as the route writes it.</summary>
    private static async Task<(HealthStatus Status, JsonElement Signer)> SignerReadinessAsync(LegacySshInstall install, ISigningService signer, SshKeyImportState? state)
    {
        using var db = install.Node.Reopen();
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.ModularCAHealthCheck"),
            db, install.Node.Keystore, signer, new ApiCertificateProvider(), new SystemConfig(), null, state)!;
        var result = await check.CheckHealthAsync(new HealthCheckContext());
        return (result.Status, JsonDocument.Parse(JsonSerializer.Serialize(result.Data["signer"], Web)).RootElement);
    }

    [Fact]
    public async Task The_readiness_page_counts_the_ssh_keys_and_names_those_awaiting_import_with_their_reasons_and_no_path()
    {
        using var install = new LegacySshInstall();
        var imported = install.Seed("A Imported", "ed25519");
        var missing = install.Seed("B Missing", "p256", writeFile: false);
        var uncommitted = Guid.NewGuid();
        using (var db = install.Node.Reopen())
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "C Uncommitted", Label = "c-uncommitted", Type = "SSH", IsSshCa = true, IsEnabled = true };
            db.CertificateAuthorities.Add(ca);
            db.SshCaKeys.Add(new SshCaKeyEntity
            {
                Id = uncommitted, Name = "C Uncommitted", KeyType = "ed25519", CertificateAuthorityId = ca.Id,
                PublicKey = SshFixtures.Text("ca-p521.pub").Trim(), KeyStorage = SshCaKeyStorage.Signer, IsUserCa = true, MaxValidityHours = 24,
            });
            db.SaveChanges();
        }

        // Before any import pass: the two legacy keys await import, with the reason that none has looked at them yet.
        var (_, before) = await SignerReadinessAsync(install, install.Node.Relay, install.State);
        Assert.Equal(2, before.GetProperty("sshKeys").GetProperty("awaitingImport").GetArrayLength());
        Assert.All(before.GetProperty("sshKeys").GetProperty("awaitingImport").EnumerateArray(), k => Assert.Equal("notAttempted", k.GetProperty("reasonCode").GetString()));

        await install.Import().RunAsync();
        var (_, signer) = await SignerReadinessAsync(install, install.Node.Relay, install.State);

        // What the entry had is still there.
        Assert.True(signer.GetProperty("unlocked").GetBoolean());
        Assert.Equal("software", signer.GetProperty("backend").GetString());
        Assert.Equal(JsonValueKind.Number, signer.GetProperty("keyCount").ValueKind);

        var ssh = signer.GetProperty("sshKeys");
        Assert.Equal(3, ssh.GetProperty("total").GetInt32());
        Assert.Equal(1, ssh.GetProperty("held").GetInt32());
        var awaiting = Assert.Single(ssh.GetProperty("awaitingImport").EnumerateArray());
        Assert.Equal(missing.Id, awaiting.GetProperty("id").GetGuid());
        Assert.Equal("B Missing", awaiting.GetProperty("name").GetString());
        Assert.Equal("fileMissing", awaiting.GetProperty("reasonCode").GetString());
        Assert.Equal(SshKeyImportReasons.Sentence(SshKeyImportReasons.FileMissing), awaiting.GetProperty("reason").GetString());
        var notHeld = Assert.Single(ssh.GetProperty("notHeld").EnumerateArray());
        Assert.Equal(uncommitted, notHeld.GetProperty("id").GetGuid());
        Assert.Equal("signerHoldsNoKey", notHeld.GetProperty("reasonCode").GetString());
        _ = imported;

        // The readiness payload names no path and repeats nothing a file or the signer said.
        var text = signer.GetRawText();
        Assert.DoesNotContain(Path.GetFileName(install.BaseDirectory), text);
        Assert.DoesNotContain("ssh-ca-keys", text);
        Assert.DoesNotContain("looked for", text);
    }

    [Fact]
    public async Task An_ssh_key_that_is_not_held_never_makes_the_signer_entry_unhealthy_and_a_locked_signer_still_does()
    {
        using var install = new LegacySshInstall();
        install.Seed("A Missing", "ed25519", writeFile: false);
        await install.Import().RunAsync();

        var (_, unlocked) = await SignerReadinessAsync(install, install.Node.Relay, install.State);
        Assert.Equal("healthy", unlocked.GetProperty("status").GetString());
        Assert.Equal(1, unlocked.GetProperty("sshKeys").GetProperty("awaitingImport").GetArrayLength());

        var (_, locked) = await SignerReadinessAsync(install, install.LockedSigner(), install.State);
        Assert.Equal("unhealthy", locked.GetProperty("status").GetString());
        Assert.False(locked.GetProperty("unlocked").GetBoolean());
        Assert.Equal(1, locked.GetProperty("sshKeys").GetProperty("awaitingImport").GetArrayLength());

        // An install with no SSH CA at all: the entry is as before, with nothing to count.
        using var plain = new LegacySshInstall();
        var (_, none) = await SignerReadinessAsync(plain, plain.Node.Relay, plain.State);
        Assert.Equal(0, none.GetProperty("sshKeys").GetProperty("total").GetInt32());
        Assert.Empty(none.GetProperty("sshKeys").GetProperty("awaitingImport").EnumerateArray());
    }

    // ---- Registration ---------------------------------------------------------------------------

    /// <summary>
    /// The import, its state and the retry resolve from a container that registers them the way
    /// the node does: by type, with nothing supplied for the import's base directory or the
    /// retry's intervals. The start runs the import inside a catch, so a registration that could
    /// not be resolved would not stop the node; it would leave every key file where it is.
    /// </summary>
    [Fact]
    public async Task The_import_its_state_and_the_retry_resolve_as_the_node_registers_them()
    {
        using var install = new LegacySshInstall();
        var retryType = ApiAssembly.TypeNamed("ModularCA.API.Services.SshKeyImportRetryService");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped(_ => install.Node.Reopen());
        services.AddSingleton<ISigningService>(install.Node.Relay);
        services.AddScoped<IAuditService>(_ => install.Node.Audit);
        services.AddSingleton<SshKeyImportState>();
        services.AddScoped<SshKeyFileImport>();
        services.AddSingleton(typeof(IHostedService), retryType);
        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        using (var scope = provider.CreateScope())
        {
            var import = scope.ServiceProvider.GetRequiredService<SshKeyFileImport>();
            var report = await import.RunAsync();
            Assert.False(report.WorkRemains);
        }
        Assert.NotNull(provider.GetRequiredService<SshKeyImportState>().Last);
        Assert.IsType(retryType, Assert.Single(provider.GetServices<IHostedService>()));

        // And the node does register them: the import and its state for every process, the retry for the control role.
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !File.Exists(Path.Combine(root.FullName, "ModularCA.sln")))
            root = root.Parent;
        var start = File.ReadAllText(Path.Combine(root!.FullName, "ModularCA.API", "StartModularCA.cs"));
        Assert.Contains("builder.Services.AddSingleton<ModularCA.Core.Services.SshKeyImportState>();", start);
        Assert.Contains("builder.Services.AddScoped<ModularCA.Core.Services.SshKeyFileImport>();", start);
        Assert.Contains("builder.Services.AddHostedService<ModularCA.API.Services.SshKeyImportRetryService>();", start);
        // The pass at start comes after the unwrap of a restore's pending secrets, which is what puts restored key files back.
        var unwrap = start.IndexOf("BackupWrappedSecrets.ApplyPendingAsync(", StringComparison.Ordinal);
        var import2 = start.IndexOf("GetRequiredService<ModularCA.Core.Services.SshKeyFileImport>().RunAsync()", StringComparison.Ordinal);
        Assert.True(unwrap > 0 && import2 > unwrap, "The import at start must run after the pending secrets of a restore are unwrapped.");
    }

    // ---- The retry in the background -------------------------------------------------------------

    /// <summary>The scopes the hosted retry resolves its import from: one install's, over one signer.</summary>
    private static ServiceProvider ImportServices(LegacySshInstall install, ISigningService signer)
    {
        var services = new ServiceCollection();
        services.AddSingleton(install.State);
        services.AddScoped(_ => new SshKeyFileImport(install.Node.Reopen(), signer, install.Node.Audit, install.State,
            NullLogger<SshKeyFileImport>.Instance, install.BaseDirectory));
        return services.BuildServiceProvider();
    }

    private static IHostedService RetryService(ServiceProvider services, ISigningService signer, SshKeyImportState state, TimeSpan interval, TimeSpan settled)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Services.SshKeyImportRetryService");
        var logger = Activator.CreateInstance(typeof(NullLogger<>).MakeGenericType(type))!;
        return (IHostedService)Activator.CreateInstance(type, services.GetRequiredService<IServiceScopeFactory>(), signer, state, logger, interval, settled)!;
    }

    private static async Task<bool> EventuallyAsync(Func<bool> condition, int seconds = 20)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < until)
        {
            if (condition())
                return true;
            await Task.Delay(25);
        }
        return condition();
    }

    [Fact]
    public async Task A_signer_locked_at_start_and_unlocked_later_has_its_keys_imported_without_a_restart()
    {
        using var install = new LegacySshInstall();
        var keys = new[] { install.Seed("A SSH", "ed25519"), install.Seed("B SSH", "p256") };
        var signer = new SwappableSigner(install.LockedSigner());
        await using var services = ImportServices(install, signer);

        // The pass at start: the signer is locked, nothing is imported.
        using (var scope = services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<SshKeyFileImport>().RunAsync();
        Assert.All(keys, k => Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(k.Id).KeyStorage));

        var retry = RetryService(services, signer, install.State, TimeSpan.FromMilliseconds(20), TimeSpan.FromHours(1));
        await retry.StartAsync(CancellationToken.None);
        try
        {
            // While it stays locked the retry asks the signer and imports nothing.
            await Task.Delay(300);
            Assert.All(keys, k => Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(k.Id).KeyStorage));
            Assert.All(keys, k => Assert.True(File.Exists(install.FileOf(k))));

            // The signer is unlocked. Nobody restarts anything.
            signer.Current = install.Node.RealSigner;

            Assert.True(await EventuallyAsync(() => keys.All(k => install.Row(k.Id).KeyStorage == SshCaKeyStorage.Signer)),
                "The keys were not imported after the signer was unlocked.");
            Assert.True(await EventuallyAsync(() => keys.All(k => !File.Exists(install.FileOf(k)))));
            Assert.Equal(2, install.Node.Persistence.SshAppended.Count);
        }
        finally
        {
            await retry.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task The_retry_takes_a_key_file_an_operator_puts_in_place_and_ends_once_nothing_is_left()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("A SSH", "p384", writeFile: false);
        await using var services = ImportServices(install, install.Node.Relay);
        using (var scope = services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<SshKeyFileImport>().RunAsync();
        Assert.Equal(SshKeyImportReasons.FileMissing, install.State.Of(key.Id)!.Code);

        // Keys left for a reason an operator acts on are looked at again at the settled interval, here a short one.
        var retry = RetryService(services, install.Node.Relay, install.State, TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(60));
        await retry.StartAsync(CancellationToken.None);
        try
        {
            await Task.Delay(200);
            Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(key.Id).KeyStorage);

            Directory.CreateDirectory(install.DefaultKeyDirectory);
            File.Copy(SshFixtures.PathOf("ca-p384.testkey"), install.FileOf(key));

            Assert.True(await EventuallyAsync(() => install.Row(key.Id).KeyStorage == SshCaKeyStorage.Signer), "The key file put in place was not imported.");
            Assert.True(await EventuallyAsync(() => install.State.Next(DateTime.UtcNow, TimeSpan.Zero) == SshKeyImportNext.Nothing));
            // With nothing left it has ended by itself.
            var executing = ((BackgroundService)retry).ExecuteTask!;
            Assert.True(await EventuallyAsync(() => executing.IsCompleted), "The retry kept running with nothing left to import.");
        }
        finally
        {
            await retry.StopAsync(CancellationToken.None);
        }
    }
}
