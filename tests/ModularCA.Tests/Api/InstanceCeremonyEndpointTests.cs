using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// An instance CA (no space: the system signing CA, SSH CAs) is held to the instance's
/// RequireKeyCeremony. Before the fold a null space read as "no policy", so revoking the system
/// signing CA or disabling an SSH CA skipped its ceremony.
/// </summary>
public sealed class InstanceCeremonyEndpointTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static object New(string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        http.Items["IsSystemAdmin"] = true;
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Revoking_the_system_signing_ca_follows_the_instance_policy(bool instanceRequiresCeremony)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = instanceRequiresCeremony, CeremonyRequiredApprovals = 3 });
        var cert = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "01", SubjectDN = "CN=System Signing CA", Issuer = "CN=System Signing CA", Pem = "x", IsCA = true };
        db.Certificates.Add(cert);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", SpaceId = null, CertificateId = cert.CertificateId });
        await db.SaveChangesAsync();
        var actor = Guid.NewGuid();
        var controller = New(Ns + "AdminRevocationController", actor,
            null, new CurrentUserStub(actor), new RecordingAuditService(), null, new RecordingAlertService(), db,
            new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard()));

        var gate = controller.GetType().GetMethod("TryCreateRevokeCaCeremonyAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var result = await (Task<IActionResult?>)gate.Invoke(controller, [cert, RevocationReason.Superseded])!;

        if (instanceRequiresCeremony)
        {
            Assert.NotNull(result);
            var ceremony = await db.KeyCeremonies.AsNoTracking().SingleAsync();
            Assert.Equal("RevokeCa", ceremony.OperationType);
            Assert.Null(ceremony.SpaceId);
            Assert.Equal(3, ceremony.RequiredApprovals);
        }
        else
        {
            Assert.Null(result);
            Assert.Empty(db.KeyCeremonies);
        }
    }

    [Fact]
    public async Task Disabling_an_ssh_ca_needs_a_ceremony_when_the_instance_requires_one()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 2 });
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Ops SSH", Label = "ops-ssh", SpaceId = null, IsSshCa = true };
        var key = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "Ops SSH", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "unused", CertificateAuthorityId = ca.Id, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        db.SshCaKeys.Add(key);
        await db.SaveChangesAsync();
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.DisableSshCa}:{key.Id}", token);
        var controller = New(Ns + "AdminSshController", actor,
            null, new CurrentUserStub(actor), db, new SystemConfig(),
            new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard()), cache, null, null, null);

        var result = await (Task<IActionResult>)controller.GetType().GetMethod("DisableSshCaKey")!.Invoke(controller, [key.Id, token])!;

        Assert.IsType<OkObjectResult>(result);
        var ceremony = await db.KeyCeremonies.AsNoTracking().SingleAsync();
        Assert.Equal("DeleteSshCa", ceremony.OperationType);
        Assert.Null(ceremony.SpaceId);
        Assert.Equal(2, ceremony.RequiredApprovals);
        Assert.True((await db.SshCaKeys.AsNoTracking().SingleAsync()).IsEnabled);
    }

    /// <summary>
    /// A system-super turning the instance's ceremony requirement off directly is KC-07, as it was
    /// on the former system tenant: the save needs the disable-ceremony-requirement step-up (an
    /// update-config token does not do), and the audit record carries the
    /// CeremonyRequirementDisabled marker.
    /// </summary>
    [Fact]
    public async Task A_super_disabling_the_instance_ceremony_requirement_needs_its_own_step_up_and_is_marked()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true });
        await db.SaveChangesAsync();
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var audit = new RecordingAuditService();
        var controller = New(Ns + "AdminSecurityPolicyController", actor,
            db, Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            audit, new CurrentUserStub(actor),
            Fake<ModularCA.Auth.Authorization.IControlledUserCeremonyService>.Create(),
            Fake<ModularCA.Auth.Authorization.ICaGroupAuthorizationService>.Create(),
            Fake<ISpacePolicyChangeService>.Create(), cache);
        var requestType = ApiAssembly.TypeNamed(Ns + "SecurityPolicyUpdateRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("RequireKeyCeremony")!.SetValue(request, false);
        var update = controller.GetType().GetMethod("Update")!;

        var configToken = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.UpdateConfig}", configToken);
        var refused = Assert.IsType<ObjectResult>(await (Task<IActionResult>)update.Invoke(controller, [request, configToken])!);
        Assert.Equal(403, refused.StatusCode);
        Assert.Contains(StepUpOps.DisableCeremonyRequirement, System.Text.Json.JsonSerializer.Serialize(refused.Value));
        Assert.True((await db.SecurityPolicies.AsNoTracking().SingleAsync()).RequireKeyCeremony);
        Assert.Empty(audit.Entries);

        var disableToken = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.DisableCeremonyRequirement}", disableToken);
        Assert.IsType<OkObjectResult>(await (Task<IActionResult>)update.Invoke(controller, [request, disableToken])!);
        Assert.False((await db.SecurityPolicies.AsNoTracking().SingleAsync()).RequireKeyCeremony);
        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.SecurityPolicyUpdated, entry.Action);
        Assert.Contains("\"CeremonyRequirementDisabled\":true", System.Text.Json.JsonSerializer.Serialize(entry.Details));
    }

    /// <summary>
    /// A non-super's ceremony-gated change is opened as a ceremony before anything is saved.
    /// With one already pending the answer is 409 and nothing changes, the other fields included,
    /// and nothing is audited; otherwise the other fields are saved and the audit lists the gated
    /// change as proposed by the ceremony, not applied.
    /// </summary>
    [Fact]
    public async Task A_gated_instance_policy_change_saves_nothing_when_a_ceremony_is_already_pending()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 2, LoginBanner = "before" });
        var pending = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = nameof(CeremonyType.InstancePolicyChange), CeremonyType = CeremonyType.InstancePolicyChange,
            Status = "Pending", SpaceId = null, Description = "pending", RequiredApprovals = 2, ExpiresAt = DateTime.UtcNow.AddHours(1),
        };
        db.KeyCeremonies.Add(pending);
        await db.SaveChangesAsync();
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var audit = new RecordingAuditService();
        var controller = New(Ns + "AdminSecurityPolicyController", actor,
            db, Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            audit, new CurrentUserStub(actor),
            NotSuper<ModularCA.Auth.Authorization.IControlledUserCeremonyService>.Create(),
            Fake<ModularCA.Auth.Authorization.ICaGroupAuthorizationService>.Create(),
            new SpacePolicyChangeService(db, new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard()), Microsoft.Extensions.Logging.Abstractions.NullLogger<SpacePolicyChangeService>.Instance),
            cache);
        var requestType = ApiAssembly.TypeNamed(Ns + "SecurityPolicyUpdateRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("RequireKeyCeremony")!.SetValue(request, false);
        requestType.GetProperty("LoginBanner")!.SetValue(request, "after");
        var update = controller.GetType().GetMethod("Update")!;
        string Token()
        {
            var token = Guid.NewGuid().ToString("N");
            cache.SetString($"mfa-stepup:{actor}:{StepUpOps.UpdateConfig}", token);
            return token;
        }

        Assert.IsType<ConflictObjectResult>(await (Task<IActionResult>)update.Invoke(controller, [request, Token()])!);
        db.ChangeTracker.Clear();
        var unchanged = await db.SecurityPolicies.AsNoTracking().SingleAsync();
        Assert.Equal("before", unchanged.LoginBanner);
        Assert.True(unchanged.RequireKeyCeremony);
        Assert.Empty(audit.Entries);
        Assert.Single(db.KeyCeremonies);

        db.KeyCeremonies.Remove(await db.KeyCeremonies.SingleAsync());
        await db.SaveChangesAsync();
        Assert.IsType<AcceptedResult>(await (Task<IActionResult>)update.Invoke(controller, [request, Token()])!);
        var saved = await db.SecurityPolicies.AsNoTracking().SingleAsync();
        Assert.Equal("after", saved.LoginBanner);
        Assert.True(saved.RequireKeyCeremony);
        var opened = await db.KeyCeremonies.AsNoTracking().SingleAsync();
        Assert.Equal(CeremonyType.InstancePolicyChange, opened.CeremonyType);
        using var details = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(Assert.Single(audit.Entries).Details));
        var changes = details.RootElement.GetProperty("Changes");
        Assert.Equal("after", changes.GetProperty("LoginBanner").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, changes.GetProperty("RequireKeyCeremony").ValueKind);
        Assert.False(details.RootElement.GetProperty("ProposedByCeremony").GetProperty("RequireKeyCeremony").GetBoolean());
        Assert.Equal(opened.Id, details.RootElement.GetProperty("CeremonyId").GetGuid());
    }

    /// <summary>A stand-in whose every boolean answer is false: a caller who is not a system-super.</summary>
    public class NotSuper<T> : DispatchProxy where T : class
    {
        public static T Create() => Create<T, NotSuper<T>>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var type = targetMethod!.ReturnType;
            if (type == typeof(Task<bool>)) return Task.FromResult(false);
            if (type == typeof(bool)) return false;
            if (type == typeof(Task)) return Task.CompletedTask;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
            {
                var inner = type.GetGenericArguments()[0];
                var value = inner.IsValueType ? Activator.CreateInstance(inner) : null;
                return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(inner).Invoke(null, [value]);
            }
            return type == typeof(void) ? null : type.IsValueType ? Activator.CreateInstance(type) : null;
        }
    }

    /// <summary>
    /// Creating a CA names its scope: a space, or scope "instance". A body with neither (a
    /// missing or empty space id), both, or an unknown scope is a 400 before anything else runs,
    /// so an omitted space can no longer make an instance CA by accident.
    /// </summary>
    [Theory]
    [InlineData("CreateRoot", "CreateRootCaRequest")]
    [InlineData("CreateIntermediate", "CreateIntermediateCaRequest")]
    public async Task A_ca_create_that_does_not_name_its_scope_is_refused(string action, string requestTypeName)
    {
        var actor = Guid.NewGuid();
        var controller = New(Ns + "AdminCaController", actor,
            null, new CurrentUserStub(actor), null, null, null, null, null, null, null, null, null);
        var requestType = ApiAssembly.TypeNamed(Ns + requestTypeName);

        foreach (var (spaceId, scope) in new (Guid?, string?)[] { (null, null), (Guid.Empty, null), (Guid.NewGuid(), "instance"), (null, "global") })
        {
            var request = Activator.CreateInstance(requestType)!;
            requestType.GetProperty("SubjectCN")!.SetValue(request, "Scoped CA");
            requestType.GetProperty("SpaceId")!.SetValue(request, spaceId);
            requestType.GetProperty("Scope")!.SetValue(request, scope);
            var result = await (Task<IActionResult>)controller.GetType().GetMethod(action)!.Invoke(controller, [request])!;
            var bad = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("scope", System.Text.Json.JsonSerializer.Serialize(bad.Value), StringComparison.OrdinalIgnoreCase);
        }

        Assert.Null(ModularCA.Shared.Models.KeyCeremonyParameters.ScopeError(Guid.NewGuid(), null));
        Assert.Null(ModularCA.Shared.Models.KeyCeremonyParameters.ScopeError(null, "instance"));
        Assert.Null(ModularCA.Shared.Models.KeyCeremonyParameters.ScopeError(null, "Instance"));
        Assert.NotNull(ModularCA.Shared.Models.KeyCeremonyParameters.ScopeError(null, null));
    }

    /// <summary>
    /// A stand-in for a service interface: every boolean answer is true, every other answer its
    /// type's default, and void calls do nothing.
    /// </summary>
    public class Fake<T> : DispatchProxy where T : class
    {
        public static T Create() => Create<T, Fake<T>>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var type = targetMethod!.ReturnType;
            if (type == typeof(void)) return null;
            if (type == typeof(Task)) return Task.CompletedTask;
            if (type == typeof(Task<bool>)) return Task.FromResult(true);
            if (type == typeof(bool)) return true;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
            {
                var inner = type.GetGenericArguments()[0];
                var value = inner.IsValueType ? Activator.CreateInstance(inner) : null;
                return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(inner).Invoke(null, [value]);
            }
            return type.IsValueType ? Activator.CreateInstance(type) : null;
        }
    }
}
