using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Modes;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Renewal of a CA certificate through the real controllers, over the real creation, renewal
/// and ceremony services and the in-process signer: directly where the scope waives ceremonies,
/// through an approved ceremony where it requires them, refused for a caller without the right,
/// and refused outside full mode.
/// </summary>
public sealed class CaRenewalEndpointTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id, string name) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = name };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>The renewal world with accounts: two system administrators and one account with no right.</summary>
    private sealed class Bench : IAsyncDisposable
    {
        public CaCertificateRenewalTests.World World { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public RecordingAuditService Audit { get; } = new();
        public Guid Admin { get; }
        public Guid SecondAdmin { get; }
        public Guid Nobody { get; }

        public Bench()
        {
            var db = World.W.Db;
            var super = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-super", DisplayName = "system-super", IsSystemGroup = true, IsSystemTierSuper = true };
            db.CaGroups.Add(super);
            foreach (var capability in Capabilities.AdministratorTemplate)
                db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = super.Id, Capability = capability });
            db.SaveChanges();
            Admin = User("first-admin", super);
            SecondAdmin = User("second-admin", super);
            Nobody = User("nobody", null);
        }

        private Guid User(string name, CaGroupEntity? group)
        {
            var db = World.W.Db;
            var user = new UserEntity { Id = Guid.NewGuid(), Username = name, Email = $"{name}@example.test" };
            db.Users.Add(user);
            if (group != null)
                db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = user.Id });
            db.SaveChanges();
            return user.Id;
        }

        public string NameOf(Guid actor) => World.W.Db.Users.Single(u => u.Id == actor).Username;

        private object New(string typeName, Guid actor, IInstanceModeGate? gate, params object?[] args)
        {
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
            var services = new ServiceCollection()
                .AddSingleton<ICurrentUserService>(new CurrentUserStub(actor, NameOf(actor)))
                .AddSingleton(gate == null ? World.Renewal : new CaCertificateRenewalService(World.W.Db, World.W.Signer, World.W.World.Keystore,
                    InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ICaServiceUrlService>.Create(), World.Crls,
                    NullLogger<CaCertificateRenewalService>.Instance, gate));
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
                RequestServices = services.BuildServiceProvider(),
            };
            SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
            controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return controller;
        }

        public object CaController(Guid actor, IInstanceModeGate? gate = null)
            => New(Ns + "AdminCaController", actor, gate,
                null, new CurrentUserStub(actor, NameOf(actor)), World.W.Db, Audit, World.W.Creation, Cache, new RecordingAlertService(),
                new CaGroupAuthorizationService(World.W.Db, NullLogger<CaGroupAuthorizationService>.Instance),
                new KeyCeremonyService(World.W.Db, Audit), null, null);

        public object CeremonyController(Guid actor)
            => New(Ns + "AdminKeyCeremonyController", actor, null,
                new KeyCeremonyService(World.W.Db, Audit), new CurrentUserStub(actor, NameOf(actor)), Audit, Cache, new RecordingAlertService(), World.W.Creation, World.W.Db,
                new CaGroupAuthorizationService(World.W.Db, NullLogger<CaGroupAuthorizationService>.Instance), null, null,
                new SpacePolicyChangeService(World.W.Db, new KeyCeremonyService(World.W.Db, new RecordingAuditService()), NullLogger<SpacePolicyChangeService>.Instance),
                new ControlledUserCeremonyService(World.W.Db, new KeyCeremonyService(World.W.Db, new RecordingAuditService()), null!, NullLogger<ControlledUserCeremonyService>.Instance));

        public string StepUp(Guid actor, string op, string target)
        {
            var token = Guid.NewGuid().ToString("N");
            Cache.SetString($"mfa-stepup:{actor}:{op}:{target}", token);
            return token;
        }

        public Task<IActionResult> RenewAsync(Guid actor, Guid caId, int years, IInstanceModeGate? gate = null, List<string>? acknowledge = null)
        {
            var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminCaController+RenewCaCertificateRequest"))!;
            body.GetType().GetProperty("ValidityYears")!.SetValue(body, years);
            body.GetType().GetProperty("Acknowledge")!.SetValue(body, acknowledge);
            return Call(CaController(actor, gate), "RenewCertificate", caId, body);
        }

        public static async Task<IActionResult> Call(object controller, string method, params object?[] args)
            => await (Task<IActionResult>)controller.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.Public)!.Invoke(controller, args)!;

        public ValueTask DisposeAsync() => World.DisposeAsync();
    }

    private static JsonElement Json(IActionResult result) => JsonSerializer.SerializeToElement(Assert.IsType<OkObjectResult>(result).Value);

    [Fact]
    public async Task A_root_is_renewed_directly_where_its_scope_waives_ceremonies_and_its_history_lists_both_certificates()
    {
        await using var bench = new Bench();
        var w = bench.World.W;
        var root = await w.CreateRootAsync("Endpoint Root", null, null);
        var oldSerial = w.Db.Certificates.Single(c => c.CertificateId == root.CertificateId).SerialNumber;

        var answer = Json(await bench.RenewAsync(bench.Admin, root.Id, 20));

        Assert.False(answer.GetProperty("requiresCeremony").GetBoolean());
        Assert.Equal(oldSerial, answer.GetProperty("previousSerialNumber").GetString());
        var newSerial = answer.GetProperty("serialNumber").GetString();
        Assert.NotEqual(oldSerial, newSerial);
        Assert.Contains("was not revoked", answer.GetProperty("message").GetString());
        Assert.Equal(answer.GetProperty("certificateId").GetGuid(), bench.World.Ca(root.Id).CertificateId);
        Assert.Contains(bench.Audit.Entries, e => e.Action == AuditActionType.CaCertificateRenewed);

        w.Db.ChangeTracker.Clear();
        var history = Json(await Bench.Call(bench.CaController(bench.Admin), "GetCertificateHistory", root.Id));
        Assert.Equal(2, history.GetArrayLength());
        Assert.True(history[0].GetProperty("IsCurrent").GetBoolean());
        Assert.Equal(newSerial, history[0].GetProperty("SerialNumber").GetString());
        Assert.Equal("Renewal", history[0].GetProperty("Origin").GetString());
        Assert.Equal("first-admin", history[0].GetProperty("Actor").GetString());
        Assert.False(history[1].GetProperty("IsCurrent").GetBoolean());
        Assert.Equal(oldSerial, history[1].GetProperty("SerialNumber").GetString());
        Assert.Equal("Initial", history[1].GetProperty("Origin").GetString());
        Assert.False(history[1].GetProperty("Revoked").GetBoolean());
        Assert.Equal(history[0].GetProperty("KeyId").GetString(), history[1].GetProperty("KeyId").GetString());
        Assert.Contains("BEGIN CERTIFICATE", history[1].GetProperty("Pem").GetString());
    }

    /// <summary>
    /// An existing RSA 2048 CA can be renewed past 2030, so that it stays in service while its
    /// replacement is prepared, but only once the administrator has acknowledged the warning.
    /// </summary>
    [Fact]
    public async Task An_rsa_2048_ca_is_renewed_past_2030_only_once_the_warning_is_acknowledged()
    {
        await using var bench = new Bench();
        var w = bench.World.W;
        var root = await w.Creation.CreateRootWithoutKeyRuleAsync("Old Rsa Root", "Acme", null, null, null, "US", "RSA", 2048, 2, null, w.SpaceId);
        var before = root.CertificateId;

        var refused = Assert.IsType<ConflictObjectResult>(await bench.RenewAsync(bench.Admin, root.Id, 20));

        var answer = JsonSerializer.SerializeToElement(refused.Value);
        Assert.True(answer.GetProperty("requiresAcknowledgement").GetBoolean());
        Assert.Equal(CaKeyPolicy.RsaBelow3072Past2030, answer.GetProperty("advisories")[0].GetProperty("Reason").GetString());
        Assert.Equal(before, bench.World.Ca(root.Id).CertificateId);

        var renewed = Json(await bench.RenewAsync(bench.Admin, root.Id, 20, acknowledge: [CaKeyPolicy.RsaBelow3072Past2030]));
        Assert.False(renewed.GetProperty("requiresCeremony").GetBoolean());
        Assert.Contains(renewed.GetProperty("advisories").EnumerateArray(), a => a.GetProperty("Reason").GetString() == CaKeyPolicy.RsaBelow3072Past2030);
        Assert.NotEqual(before, bench.World.Ca(root.Id).CertificateId);
    }

    /// <summary>Through a ceremony, the approvers read what the initiator was told and that the warning was acknowledged.</summary>
    [Fact]
    public async Task A_ceremony_for_an_rsa_2048_renewal_past_2030_shows_its_approvers_the_warning_and_the_acknowledgment()
    {
        await using var bench = new Bench();
        var w = bench.World.W;
        var strict = Guid.NewGuid();
        w.Db.Spaces.Add(new SpaceEntity { Id = strict, Name = "strict-rsa", Slug = "strict-rsa", RequireKeyCeremony = true, CeremonyRequiredApprovals = 1 });
        var creation = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateRootCA", Description = "seed", Status = "Approved", SpaceId = strict,
            RequiredApprovals = 1, CurrentApprovals = 1, ExpiresAt = DateTime.UtcNow.AddHours(1),
        };
        w.Db.KeyCeremonies.Add(creation);
        w.Db.SaveChanges();
        var root = await w.Creation.CreateRootWithoutKeyRuleAsync("Old Rsa Ceremony Root", "Acme", null, null, null, "US", "RSA", 2048, 2, null, strict, ceremonyId: creation.Id);

        // Not acknowledged: no ceremony is opened.
        Assert.IsType<ConflictObjectResult>(await bench.RenewAsync(bench.Admin, root.Id, 40));
        Assert.DoesNotContain(w.Db.KeyCeremonies.AsNoTracking().ToList(), c => c.OperationType == "RenewCaCertificate");

        var opened = Json(await bench.RenewAsync(bench.Admin, root.Id, 40, acknowledge: [CaKeyPolicy.RsaBelow3072Past2030]));

        var ceremony = w.Db.KeyCeremonies.AsNoTracking().Single(c => c.Id == opened.GetProperty("ceremonyId").GetGuid());
        var parameters = CeremonyParametersJson.Read<RenewCaCertificateCeremonyParameters>(ceremony.ParametersJson)!;
        Assert.Equal(new[] { CaKeyPolicy.RsaBelow3072Past2030 }, parameters.Acknowledged);
        Assert.Equal(new[] { CaKeyPolicy.RsaBelow3072Past2030, CaKeyPolicy.ValidityBeyondCommonPractice }, parameters.Advisories.Select(a => a.Reason).ToArray());
        var warning = parameters.Advisories[0];
        Assert.Equal(CaKeyAdvisory.Warning, warning.Severity);
        Assert.Contains("only through 2030", warning.Message);
        Assert.Equal(CaKeyAdvisory.Notice, parameters.Advisories[1].Severity);
        Assert.Contains("longer than common practice", parameters.Advisories[1].Message);

        // The signer's check of the ceremony is what it was: the approved ceremony executes.
        Assert.IsType<OkObjectResult>(await Bench.Call(bench.CeremonyController(bench.SecondAdmin), "Approve", ceremony.Id,
            bench.StepUp(bench.SecondAdmin, StepUpOps.ApproveCeremony, ceremony.Id.ToString())));
        var executed = Json(await Bench.Call(bench.CeremonyController(bench.Admin), "Execute", ceremony.Id,
            bench.StepUp(bench.Admin, StepUpOps.ExecuteCeremony, ceremony.Id.ToString())));
        Assert.Equal("Executed", executed.GetProperty("Status").GetString());
    }

    /// <summary>A validity longer than common practice is said and is no refusal.</summary>
    [Fact]
    public async Task A_root_renewed_for_more_than_twenty_five_years_is_told_so_and_renewed()
    {
        await using var bench = new Bench();
        var root = await bench.World.W.CreateRootAsync("Long Root", null, null);
        var before = root.CertificateId;

        var renewed = Json(await bench.RenewAsync(bench.Admin, root.Id, 40));

        Assert.Equal(CaKeyPolicy.ValidityBeyondCommonPractice, Assert.Single(renewed.GetProperty("advisories").EnumerateArray()).GetProperty("Reason").GetString());
        Assert.NotEqual(before, bench.World.Ca(root.Id).CertificateId);
    }

    [Fact]
    public async Task An_intermediate_asked_past_its_parent_is_shortened_and_says_so()
    {
        await using var bench = new Bench();
        var w = bench.World.W;
        var root = await w.CreateRootAsync("Endpoint Parent", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Endpoint Issuing", null, null);
        var parentEnd = bench.World.Certificate(root.CertificateId).NotAfter.ToUniversalTime();

        var answer = Json(await bench.RenewAsync(bench.Admin, issuing.Id, 30));

        Assert.True(answer.GetProperty("shortenedToParent").GetBoolean());
        Assert.Equal(parentEnd, answer.GetProperty("notAfter").GetDateTime().ToUniversalTime());
        Assert.Equal(parentEnd, bench.World.Certificate(bench.World.Ca(issuing.Id).CertificateId).NotAfter.ToUniversalTime());
    }

    [Fact]
    public async Task Where_the_scope_requires_a_ceremony_the_call_opens_one_and_the_renewal_happens_when_it_is_executed()
    {
        await using var bench = new Bench();
        var w = bench.World.W;
        var strict = Guid.NewGuid();
        w.Db.Spaces.Add(new SpaceEntity { Id = strict, Name = "strict", Slug = "strict", RequireKeyCeremony = true, CeremonyRequiredApprovals = 1 });
        var creation = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateRootCA", Description = "seed", Status = "Approved", SpaceId = strict,
            RequiredApprovals = 1, CurrentApprovals = 1, ExpiresAt = DateTime.UtcNow.AddHours(1),
        };
        w.Db.KeyCeremonies.Add(creation);
        w.Db.SaveChanges();
        var root = await w.Creation.CreateRootAsync("Ceremony Root", "Acme", null, null, null, "US", "ECDSA", 256, 5, null, strict, ceremonyId: creation.Id);
        var oldId = root.CertificateId;

        var opened = Json(await bench.RenewAsync(bench.Admin, root.Id, 20));

        Assert.True(opened.GetProperty("requiresCeremony").GetBoolean());
        var ceremonyId = opened.GetProperty("ceremonyId").GetGuid();
        Assert.Equal(oldId, bench.World.Ca(root.Id).CertificateId);       // nothing has changed yet
        w.Db.ChangeTracker.Clear();
        var ceremony = w.Db.KeyCeremonies.Single(c => c.Id == ceremonyId);
        Assert.Equal("RenewCaCertificate", ceremony.OperationType);
        Assert.Equal("Pending", ceremony.Status);
        Assert.Equal(root.Id.ToString(), ceremony.TargetEntityId);
        Assert.Equal(strict, ceremony.SpaceId);
        var parameters = CeremonyParametersJson.Read<RenewCaCertificateCeremonyParameters>(ceremony.ParametersJson)!;
        Assert.Equal(root.Id, parameters.CaId);
        Assert.Equal(oldId, parameters.CurrentCertificateId);
        Assert.Equal(opened.GetProperty("notAfter").GetDateTime().ToUniversalTime(), DateTime.SpecifyKind(parameters.NotAfter, DateTimeKind.Utc));

        // Not approved: the ceremony does not execute, and the initiator cannot approve it alone.
        var early = await Bench.Call(bench.CeremonyController(bench.Admin), "Execute", ceremonyId,
            bench.StepUp(bench.Admin, StepUpOps.ExecuteCeremony, ceremonyId.ToString()));
        Assert.Equal(409, Assert.IsAssignableFrom<ObjectResult>(early).StatusCode);
        await Assert.ThrowsAsync<InvalidOperationException>(() => new KeyCeremonyService(w.Db, bench.Audit).ApproveAsync(ceremonyId, bench.Admin, "first-admin"));

        Assert.IsType<OkObjectResult>(await Bench.Call(bench.CeremonyController(bench.SecondAdmin), "Approve", ceremonyId,
            bench.StepUp(bench.SecondAdmin, StepUpOps.ApproveCeremony, ceremonyId.ToString())));
        var executed = Json(await Bench.Call(bench.CeremonyController(bench.Admin), "Execute", ceremonyId,
            bench.StepUp(bench.Admin, StepUpOps.ExecuteCeremony, ceremonyId.ToString())));

        Assert.Equal("Executed", executed.GetProperty("Status").GetString());
        var renewedId = executed.GetProperty("certificateId").GetGuid();
        Assert.Equal(renewedId, bench.World.Ca(root.Id).CertificateId);
        Assert.NotEqual(oldId, renewedId);
        w.Db.ChangeTracker.Clear();
        Assert.Equal("Executed", w.Db.KeyCeremonies.Single(c => c.Id == ceremonyId).Status);
        Assert.Equal(ceremonyId, w.Db.CaCertificates.Single(h => h.CertificateId == renewedId).CeremonyId);
        Assert.Equal(DateTime.SpecifyKind(parameters.NotAfter, DateTimeKind.Utc), bench.World.Certificate(renewedId).NotAfter.ToUniversalTime());
        Assert.Contains(bench.Audit.Entries, e => e.Action == AuditActionType.CaCertificateRenewed);
        Assert.Contains(bench.Audit.Entries, e => e.Action == AuditActionType.KeyCeremonyExecuted);

        // Executed once: a second execute is refused.
        var again = await Bench.Call(bench.CeremonyController(bench.Admin), "Execute", ceremonyId,
            bench.StepUp(bench.Admin, StepUpOps.ExecuteCeremony, ceremonyId.ToString()));
        Assert.Equal(409, Assert.IsAssignableFrom<ObjectResult>(again).StatusCode);
    }

    [Fact]
    public async Task A_caller_without_the_right_is_refused_and_an_unknown_ca_is_not_found()
    {
        await using var bench = new Bench();
        var root = await bench.World.W.CreateRootAsync("Guarded Root", null, null);

        Assert.Equal(403, Assert.IsAssignableFrom<ObjectResult>(await bench.RenewAsync(bench.Nobody, root.Id, 20)).StatusCode);
        Assert.Equal(404, Assert.IsAssignableFrom<ObjectResult>(await bench.RenewAsync(bench.Admin, Guid.NewGuid(), 20)).StatusCode);
        Assert.Equal(root.CertificateId, bench.World.Ca(root.Id).CertificateId);
        Assert.Empty(bench.World.W.Db.KeyCeremonies);
    }

    [Theory]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.DisasterRecovery)]
    [InlineData(InstanceMode.Maintenance)]
    public async Task A_renewal_is_refused_outside_full_mode_below_the_request_filter_too(InstanceMode mode)
    {
        await using var bench = new Bench();
        var root = await bench.World.W.CreateRootAsync("Frozen Root", null, null);

        await Assert.ThrowsAnyAsync<Exception>(() => bench.RenewAsync(bench.Admin, root.Id, 20, new FixedModeGate(mode)));

        Assert.Equal(root.CertificateId, bench.World.Ca(root.Id).CertificateId);
        Assert.Equal(CaCertificateEntity.OriginInitial, Assert.Single(bench.World.W.Db.CaCertificates).Origin);
        Assert.IsType<OkObjectResult>(await bench.RenewAsync(bench.Admin, root.Id, 20, new FixedModeGate(InstanceMode.Full)));
    }

    /// <summary>The endpoint's own declarations: frozen outside full mode, step-up bound to the CA.</summary>
    [Fact]
    public void The_endpoint_is_frozen_outside_full_mode_and_needs_step_up_bound_to_the_ca()
    {
        var action = ApiAssembly.TypeNamed(Ns + "AdminCaController").GetMethod("RenewCertificate")!;

        var gate = action.GetCustomAttribute<ModeGateAttribute>()!;
        Assert.Equal(ModeOperation.Frozen, gate.Operation);
        Assert.Contains(action.GetCustomAttributes(), a => a.GetType().Name == "RequireStepUpAttribute");
        Assert.Contains(StepUpOps.RenewCaCertificate, StepUpOps.All);
    }
}
