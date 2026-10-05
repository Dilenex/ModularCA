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
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// With one administrator, every endpoint that would open a ceremony refuses instead (409, nothing
/// opened), because nobody else could approve it. Each path is driven through its controller with
/// the real <see cref="KeyCeremonyService"/>; with a second approver the same call opens the ceremony.
/// </summary>
public sealed class SingleAdministratorCeremonyTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static string StepUp(IDistributedCache cache, Guid actor, string op, Guid? target = null)
    {
        var token = Guid.NewGuid().ToString("N");
        cache.SetString(target == null ? $"mfa-stepup:{actor}:{op}" : $"mfa-stepup:{actor}:{op}:{target}", token);
        return token;
    }

    private static CaGroupAuthorizationService GroupAuth(SingleAdminWorld w)
        => new(w.Db, NullLogger<CaGroupAuthorizationService>.Instance);

    private static ControlledUserCeremonyService Controlled(SingleAdminWorld w)
        => new(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), null!, NullLogger<ControlledUserCeremonyService>.Instance);

    private static SpacePolicyChangeService PolicyChanges(SingleAdminWorld w)
        => new(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), NullLogger<SpacePolicyChangeService>.Instance);

    private static CaCreationService CaCreation(SingleAdminWorld w)
        => new(w.Db, null!, null!, null!, null!, new SystemConfig(), NullLogger<CaCreationService>.Instance, null!);

    /// <summary>The request services the refusal body reads: who is calling, and whether they are a super.</summary>
    private static IServiceProvider Services(SingleAdminWorld w, Guid actor)
        => new ServiceCollection()
            .AddSingleton<ICurrentUserService>(new CurrentUserStub(actor))
            .AddSingleton<IControlledUserCeremonyService>(Controlled(w))
            .BuildServiceProvider();

    private static object New(SingleAdminWorld w, string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
            RequestServices = Services(w, actor),
        };
        http.Items["IsSystemAdmin"] = true;
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType()
            .GetMethod(method, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.Invoke(controller, args)!;

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static object CaController(SingleAdminWorld w, Guid actor)
        => New(w, Ns + "AdminCaController", actor,
            null, new CurrentUserStub(actor), w.Db, new RecordingAuditService(), CaCreation(w), NewCache(), new RecordingAlertService(),
            GroupAuth(w), new KeyCeremonyService(w.Db, new RecordingAuditService()), null);

    private static object SshController(SingleAdminWorld w, Guid actor, IDistributedCache cache)
        => New(w, Ns + "AdminSshController", actor,
            null, new CurrentUserStub(actor), new RecordingAuditService(), w.Db, new SystemConfig(),
            new KeyCeremonyService(w.Db, new RecordingAuditService()), cache);

    private static object CeremonyController(SingleAdminWorld w, Guid actor, IDistributedCache cache)
    {
        var audit = new RecordingAuditService();
        return New(w, Ns + "AdminKeyCeremonyController", actor,
            new KeyCeremonyService(w.Db, audit), new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), CaCreation(w), w.Db,
            GroupAuth(w), null, null, PolicyChanges(w), Controlled(w));
    }

    private static SshCaKeyEntity SshCa(SingleAdminWorld w)
    {
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Ops SSH", Label = "ops-ssh", SpaceId = null, IsSshCa = true };
        var key = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "Ops SSH", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "unused", CertificateAuthorityId = ca.Id, IsEnabled = true };
        w.Db.CertificateAuthorities.Add(ca);
        w.Db.SshCaKeys.Add(key);
        w.Db.SaveChanges();
        return key;
    }

    /// <summary>The initiation paths a system administrator reaches, each as a call that opens a ceremony when it can.</summary>
    private static readonly Dictionary<string, Func<SingleAdminWorld, Guid, Task<IActionResult>>> Paths = new()
    {
        ["create-root"] = (w, actor) => Call(CaController(w, actor), "CreateRoot",
            Body("CreateRootCaRequest", ("SubjectCN", "Second Root"), ("SpaceId", (Guid?)w.Space))),
        ["create-root (instance)"] = (w, actor) => Call(CaController(w, actor), "CreateRoot",
            Body("CreateRootCaRequest", ("SubjectCN", "Instance Root"), ("Scope", "instance"))),
        ["create-intermediate"] = (w, actor) => Call(CaController(w, actor), "CreateIntermediate",
            Body("CreateIntermediateCaRequest", ("SubjectCN", "Issuing CA"), ("SpaceId", (Guid?)w.Space), ("ParentCaId", w.Ca))),
        ["ssh-ca create"] = (w, actor) =>
        {
            var cache = NewCache();
            return Call(SshController(w, actor, cache), "GenerateCaKey",
                Body("GenerateSshCaKeyRequest", ("Name", "Fleet SSH")), StepUp(cache, actor, StepUpOps.CreateSshCa));
        },
        ["ssh-ca delete"] = (w, actor) =>
        {
            var cache = NewCache();
            var key = SshCa(w);
            return Call(SshController(w, actor, cache), "DisableSshCaKey", key.Id, StepUp(cache, actor, StepUpOps.DisableSshCa, key.Id));
        },
        ["revoke-ca"] = async (w, actor) =>
        {
            var controller = New(w, Ns + "AdminRevocationController", actor,
                null, new CurrentUserStub(actor), new RecordingAuditService(), null, new RecordingAlertService(), w.Db,
                new KeyCeremonyService(w.Db, new RecordingAuditService()));
            var cert = await w.Db.Certificates.AsNoTracking().SingleAsync(c => c.CertificateId == w.CaCertificate);
            var gate = controller.GetType().GetMethod("TryCreateRevokeCaCeremonyAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
            return (await (Task<IActionResult?>)gate.Invoke(controller, [cert, RevocationReason.Superseded])!)!;
        },
    };

    public static TheoryData<string> PathNames() => new(Paths.Keys);

    [Theory]
    [MemberData(nameof(PathNames))]
    public async Task A_lone_administrator_is_refused_on_every_initiation_path(string path)
    {
        var w = new SingleAdminWorld();

        var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => Paths[path](w, w.Admin));

        Assert.Equal(409, ex.Status);
        Assert.Equal(ErrorCodes.CeremonyNoApprover, ex.Code);
        Assert.StartsWith("You're the only administrator who can approve this", ex.Message);
        Assert.NotNull(ex.RequirementScope);
        Assert.Empty(w.Db.KeyCeremonies);
        Assert.Single(w.Db.CertificateAuthorities.Where(c => !c.IsSshCa));
        Assert.False((await w.Db.Certificates.AsNoTracking().SingleAsync()).Revoked);
    }

    [Theory]
    [MemberData(nameof(PathNames))]
    public async Task A_second_approver_opens_the_ceremony_on_every_initiation_path(string path)
    {
        var w = new SingleAdminWorld();
        w.User("second", w.SystemOperatorGroup);

        var result = Assert.IsType<OkObjectResult>(await Paths[path](w, w.Admin));

        Assert.Contains("\"requiresCeremony\":true", JsonSerializer.Serialize(result.Value));
        var ceremony = await w.Db.KeyCeremonies.AsNoTracking().SingleAsync();
        Assert.Equal("Pending", ceremony.Status);
        Assert.Equal(w.Admin, ceremony.InitiatedByUserId);
    }

    /// <summary>
    /// The generic initiate endpoint catches everything, so it returns the refusal itself: the same
    /// body the middleware sends for the other paths, with the switch the caller may use.
    /// </summary>
    [Fact]
    public async Task The_generic_initiate_endpoint_answers_409_with_the_next_step()
    {
        var w = new SingleAdminWorld();
        var cache = NewCache();
        var request = Body("InitiateCeremonyRequest",
            ("OperationType", "CreateRootCA"), ("Description", "second root"),
            ("Parameters", new KeyCeremonyParameters { SubjectCN = "Second Root", KeyAlgorithm = "ECDSA", KeySize = 384, ValidityYears = 10, SpaceId = w.Space }));

        var result = await Call(CeremonyController(w, w.Admin, cache), "Initiate", request, StepUp(cache, w.Admin, StepUpOps.InitiateCeremony));

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(conflict.Value));
        Assert.Equal(ErrorCodes.CeremonyNoApprover, body.RootElement.GetProperty("code").GetString());
        Assert.StartsWith("You're the only administrator", body.RootElement.GetProperty("detail").GetString());
        Assert.Equal("CreateRootCA", body.RootElement.GetProperty("operationType").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("requiredApprovals").GetInt32());
        Assert.Equal(0, body.RootElement.GetProperty("eligibleApprovers").GetInt32());
        Assert.Equal("space", body.RootElement.GetProperty("requirementScope").GetString());
        Assert.Equal(w.Space, body.RootElement.GetProperty("spaceId").GetGuid());
        Assert.Equal("First", body.RootElement.GetProperty("spaceName").GetString());
        Assert.True(body.RootElement.GetProperty("canDisableRequirement").GetBoolean());
        Assert.Empty(w.Db.KeyCeremonies);

        w.User("second", w.SystemAdminGroup);
        Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "Initiate", request, StepUp(cache, w.Admin, StepUpOps.InitiateCeremony)));
        Assert.Single(w.Db.KeyCeremonies);
    }

    /// <summary>
    /// A system administrator who is not a super opens a policy-change ceremony to change the
    /// requirement. Alone, they are refused before anything is saved, the other fields included.
    /// </summary>
    [Fact]
    public async Task A_lone_non_super_is_refused_a_policy_change_and_nothing_is_saved()
    {
        var w = new SingleAdminWorld();
        var actor = w.User("sysadmin", w.SystemAdminGroup);
        // The super cannot sign in, so the system administrator is the only one who could approve.
        w.Db.Users.Single(u => u.Id == w.Admin).IsActive = false;
        w.Db.SaveChanges();
        var cache = NewCache();

        var instance = New(w, Ns + "AdminSecurityPolicyController", actor,
            w.Db, InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            new RecordingAuditService(), new CurrentUserStub(actor), Controlled(w), GroupAuth(w), PolicyChanges(w), cache);
        var instanceRequest = Body("SecurityPolicyUpdateRequest", ("RequireKeyCeremony", (bool?)false), ("LoginBanner", "after"));
        var ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(
            () => Call(instance, "Update", instanceRequest, StepUp(cache, actor, StepUpOps.UpdateConfig)));
        Assert.Equal(nameof(CeremonyType.InstancePolicyChange), ex.OperationType);
        Assert.Null(ex.RequirementScope);

        var space = New(w, Ns + "AdminSpaceController", actor,
            w.Db, new CurrentUserStub(actor), new RecordingAuditService(), cache, GroupAuth(w), PolicyChanges(w), Controlled(w), null);
        var spaceRequest = Body("UpdateSpaceRequest", ("Name", "Renamed"), ("RequireKeyCeremony", (bool?)false));
        ex = await Assert.ThrowsAsync<CeremonyQuorumUnreachableException>(() => Call(space, "Update", w.Space, spaceRequest, null));
        Assert.Equal(nameof(CeremonyType.SpacePolicyChange), ex.OperationType);

        w.Db.ChangeTracker.Clear();
        Assert.Empty(w.Db.KeyCeremonies);
        var policy = await w.Db.SecurityPolicies.AsNoTracking().SingleAsync();
        Assert.True(policy.RequireKeyCeremony);
        Assert.Null(policy.LoginBanner);
        var stored = await w.Db.Spaces.AsNoTracking().SingleAsync(s => s.Id == w.Space);
        Assert.Equal("First", stored.Name);
        Assert.True(stored.RequireKeyCeremony);
    }

    /// <summary>
    /// A ceremony already pending that nobody else can approve says so in its detail, and its
    /// initiator can cancel it. The approvers endpoint reports the same count for a scope.
    /// </summary>
    [Fact]
    public async Task A_stuck_pending_ceremony_is_reported_and_can_be_cancelled_by_its_initiator()
    {
        var w = new SingleAdminWorld();
        var ceremony = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateIntermediateCA", Description = "stuck", TargetEntityId = "",
            InitiatedByUserId = w.Admin, InitiatedByUsername = "superadmin", RequiredApprovals = 1, Status = "Pending",
            CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddHours(12), ParametersJson = SingleAdminWorld.Parameters(w.Space), ApprovalsJson = "[]", SpaceId = w.Space,
        };
        w.Db.KeyCeremonies.Add(ceremony);
        w.Db.SaveChanges();
        var cache = NewCache();

        var detail = Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "GetById", ceremony.Id));
        var json = JsonSerializer.Serialize(detail.Value);
        Assert.Contains("\"QuorumReachable\":false", json);
        Assert.Contains("\"EligibleApprovers\":0", json);
        Assert.Contains("\"ApprovalsStillNeeded\":1", json);

        var approvers = Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "Approvers", (Guid?)w.Space));
        Assert.Contains("\"eligibleApprovers\":0", JsonSerializer.Serialize(approvers.Value));
        Assert.Contains("\"reachable\":false", JsonSerializer.Serialize(approvers.Value));

        var second = w.User("second", w.SpaceOperatorGroup);
        detail = Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "GetById", ceremony.Id));
        Assert.Contains("\"QuorumReachable\":true", JsonSerializer.Serialize(detail.Value));
        approvers = Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "Approvers", (Guid?)w.Space));
        Assert.Contains("\"eligibleApprovers\":1", JsonSerializer.Serialize(approvers.Value));
        // The space operator holds nothing at instance scope.
        approvers = Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "Approvers", (Guid?)null));
        Assert.Contains("\"eligibleApprovers\":0", JsonSerializer.Serialize(approvers.Value));
        w.Db.Users.Single(u => u.Id == second).IsActive = false;
        w.Db.SaveChanges();

        Assert.IsType<OkObjectResult>(await Call(CeremonyController(w, w.Admin, cache), "Cancel", ceremony.Id, StepUp(cache, w.Admin, StepUpOps.CancelCeremony, ceremony.Id)));
        Assert.Equal("Cancelled", (await w.Db.KeyCeremonies.AsNoTracking().SingleAsync()).Status);
    }

    /// <summary>
    /// The paths that let the refusal propagate are answered by <c>RequestValidationMiddleware</c>:
    /// 409 problem+json with the code, the counts, the scope whose switch applies, and whether the
    /// caller (a system super-administrator only) may turn it off.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_middleware_renders_the_refusal_with_what_the_console_needs(bool callerIsSuper)
    {
        var w = new SingleAdminWorld();
        var caller = callerIsSuper ? w.Admin : w.User("sysadmin", w.SystemAdminGroup);
        var refusal = new CeremonyQuorumUnreachableException("RevokeCa", 2, callerIsSuper ? 0 : 1, CeremonyQuorumUnreachableException.InstanceScope);

        var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.RequestValidationMiddleware");
        var logger = typeof(NullLogger<>).MakeGenericType(type).GetField("Instance")!.GetValue(null);
        RequestDelegate next = _ => throw refusal;
        var middleware = Activator.CreateInstance(type, next, logger)!;
        var http = new DefaultHttpContext { RequestServices = Services(w, caller) };
        http.Response.Body = new MemoryStream();

        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [http])!;

        Assert.Equal(409, http.Response.StatusCode);
        Assert.Equal("application/problem+json", http.Response.ContentType);
        http.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(http.Response.Body);
        var root = body.RootElement;
        Assert.Equal(409, root.GetProperty("status").GetInt32());
        Assert.Equal(callerIsSuper ? ErrorCodes.CeremonyNoApprover : ErrorCodes.CeremonyQuorumUnreachable, root.GetProperty("code").GetString());
        Assert.StartsWith(callerIsSuper ? "You're the only administrator who can approve this" : "This needs 2 approvals and only 1 other administrator can approve",
            root.GetProperty("detail").GetString());
        Assert.Equal("RevokeCa", root.GetProperty("operationType").GetString());
        Assert.Equal(2, root.GetProperty("requiredApprovals").GetInt32());
        Assert.Equal(callerIsSuper ? 0 : 1, root.GetProperty("eligibleApprovers").GetInt32());
        Assert.Equal("instance", root.GetProperty("requirementScope").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("spaceId").ValueKind);
        Assert.Equal(callerIsSuper, root.GetProperty("canDisableRequirement").GetBoolean());
        Assert.Contains(callerIsSuper ? "turn the key ceremony requirement off" : "Ask a system super-administrator", root.GetProperty("remediation").GetString());
    }

    /// <summary>A ceremony no switch governs offers none, whoever asks.</summary>
    [Fact]
    public async Task A_refusal_no_requirement_governs_offers_no_switch()
    {
        var w = new SingleAdminWorld();
        var refusal = new CeremonyQuorumUnreachableException("ControlledUserChange", 1, 0);
        var body = await (Task<object>)ApiAssembly.TypeNamed("ModularCA.API.Services.CeremonyRefusalResponse")
            .GetMethod("BuildAsync")!.Invoke(null, [new DefaultHttpContext { RequestServices = Services(w, w.Admin) }, refusal, null])!;

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(body));
        Assert.False(json.RootElement.GetProperty("canDisableRequirement").GetBoolean());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("requirementScope").ValueKind);
        Assert.Contains("ask a system super-administrator", json.RootElement.GetProperty("remediation").GetString());
    }
}
