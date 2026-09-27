using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the key-ceremony endpoints the way a request reaches them. There is no
/// WebApplicationFactory for this host, so each call first evaluates the endpoint's authorization
/// metadata through the real policy set, <see cref="CaGroupAuthorizationHandler"/> and the
/// fallback policy, pins that the endpoints carry no action filter a direct call would skip, and
/// then invokes the action with an HttpContext whose token carries the worn badge. The badge flows
/// through <see cref="AccessBadgeContext"/> into both the authorization resolver and the
/// controlled-user service, as in production. Step-up tokens are seeded in the cache the actions read.
/// </summary>
public sealed class CeremonyEndpointPipelineTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminKeyCeremonyController";

    private sealed class CurrentUserStub(Guid id) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>A ceremony world: the controlled-user fixtures plus the services the controller takes.</summary>
    private sealed class World
    {
        public ControlledUserWorld W { get; } = new();
        public ModularCADbContext Db => W.Db;
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public KeyCeremonyService Ceremonies { get; }
        public Func<IControlledUserCeremonyService, IControlledUserCeremonyService> Decorate { get; set; } = s => s;

        public World() => Ceremonies = new KeyCeremonyService(Db, Audit);

        /// <summary>A badge for <paramref name="userId"/> that keeps only <paramref name="groups"/>.</summary>
        public Guid Badge(Guid userId, params CaGroupEntity[] groups)
        {
            var badge = new AccessBadgeEntity { UserId = userId, Name = $"badge-{Guid.NewGuid():N}" };
            foreach (var g in groups)
                badge.Sources.Add(new AccessBadgeSourceEntity { BadgeId = badge.Id, Kind = AccessBadgeSourceKind.Group, SourceId = g.Id });
            Db.AccessBadges.Add(badge);
            Db.SaveChanges();
            return badge.Id;
        }

        /// <summary>Opens a controlled-user ceremony granting system.manage on CA A1 to <paramref name="target"/>.</summary>
        public Guid GrantOnA1(Guid target, Guid initiator)
        {
            var svc = new ControlledUserCeremonyService(Db, Ceremonies, null!, NullLogger<ControlledUserCeremonyService>.Instance);
            var minted = svc.ClassifyCapabilityGrant(Capabilities.SystemManage, W.CaA1)!.Value;
            return svc.InitiateCapabilityGrantAsync(target, "target", Capabilities.SystemManage, null, W.CaA1, null, null,
                minted, initiator, "initiator").GetAwaiter().GetResult();
        }

        public void Approve(Guid ceremonyId, Guid approver)
            => Ceremonies.ApproveAsync(ceremonyId, approver, "approver").GetAwaiter().GetResult();

        public string StepUp(Guid actor, string op, Guid? target = null)
        {
            var token = Guid.NewGuid().ToString("N");
            Cache.SetString(target == null ? $"mfa-stepup:{actor}:{op}" : $"mfa-stepup:{actor}:{op}:{target}", token);
            return token;
        }

        /// <summary>
        /// Sends <paramref name="action"/> as <paramref name="actor"/>, optionally wearing
        /// <paramref name="badge"/>: 403 when the endpoint's authorization policy refuses, otherwise
        /// the action's own result.
        /// </summary>
        public async Task<IActionResult> Send(Guid actor, Guid? badge, string action, params object?[] args)
        {
            var claims = new List<Claim> { new("sub", actor.ToString()), new(ClaimTypes.NameIdentifier, actor.ToString()) };
            if (badge != null) claims.Add(new Claim(AccessBadgeContext.BadgeClaim, badge.Value.ToString()));
            var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
            http.Request.Method = HttpMethods.Post;
            var accessor = new HttpContextAccessor { HttpContext = http };

            var badges = new AccessBadgeContext(Db, accessor);
            var groupAuth = new CaGroupAuthorizationService(Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor, badges);
            var controlled = Decorate(new ControlledUserCeremonyService(Db, Ceremonies, null!, NullLogger<ControlledUserCeremonyService>.Instance, badges));

            var type = ApiAssembly.TypeNamed(ControllerName);
            var method = type.GetMethod(action)!;
            if (!await PolicyAllows(type, method, http, groupAuth, accessor))
                return new StatusCodeResult(403);

            var controller = Activator.CreateInstance(type,
                Ceremonies, new CurrentUserStub(actor), Audit, Cache, new RecordingAlertService(), null, Db, groupAuth, null, null, null, controlled)!;
            type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });
            return await (Task<IActionResult>)method.Invoke(controller, args)!;
        }

        private async Task<bool> PolicyAllows(Type controller, MethodInfo action, HttpContext http, CaGroupAuthorizationService groupAuth, IHttpContextAccessor accessor)
        {
            var attributes = controller.GetCustomAttributes(true).Concat(action.GetCustomAttributes(true)).ToList();
            if (attributes.OfType<IAllowAnonymous>().Any()) return true;

            var services = new ServiceCollection().AddLogging().AddAuthorizationCore(options =>
            {
                options.AddPolicy("SystemAdmin", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.SystemManage, isSystemOnly: true)));
                options.AddPolicy("SystemOperator", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.CaManage, isSystemOnly: true)));
                options.AddPolicy("SystemAuditor", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.AuditView, isSystemOnly: true)));
                options.AddPolicy("CaAdmin", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.CaManage)));
                options.AddPolicy("CaOperator", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.CertRevoke)));
                options.AddPolicy("CaAuditor", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.CertView)));
                options.AddPolicy("CaUser", p => p.Requirements.Add(new CaGroupRequirement(Capabilities.CertRequest)));
                options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            });
            services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, Db, NullLogger<CaGroupAuthorizationHandler>.Instance));
            var sp = services.BuildServiceProvider();

            var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
            var policy = await AuthorizationPolicy.CombineAsync(provider, attributes.OfType<IAuthorizeData>())
                         ?? await provider.GetFallbackPolicyAsync();
            var result = await sp.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, http, policy!);
            return result.Succeeded;
        }
    }

    private static int? Status(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    private static List<Guid> Ids(IActionResult result)
        => ((System.Collections.IEnumerable)((ObjectResult)result).Value!).Cast<object>()
            .Select(o => (Guid)o.GetType().GetProperty("Id")!.GetValue(o)!).ToList();

    [Fact]
    public void Ceremony_endpoints_carry_no_action_filter_a_direct_call_would_skip()
    {
        // [ApiController] contributes only automatic model-state validation, which grants nothing.
        static IEnumerable<string> Filters(MemberInfo m) => m.GetCustomAttributes(true).OfType<IFilterMetadata>()
            .Where(f => f is not Microsoft.AspNetCore.Mvc.Infrastructure.IApiBehaviorMetadata)
            .Select(f => f.GetType().Name);
        var type = ApiAssembly.TypeNamed(ControllerName);
        Assert.Empty(Filters(type));
        foreach (var name in new[] { "Initiate", "List", "GetById", "Approve", "Reject", "Cancel", "Execute" })
            Assert.Empty(Filters(type.GetMethod(name)!));
    }

    [Fact]
    public async Task A_plain_user_and_a_ca_auditor_see_nothing_and_can_act_on_nothing()
    {
        var w = new World();
        var auditorGroup = w.W.Group("org_a1_auditor", w.W.TenantA, w.W.CaA1, "Auditor");
        var caAuditor = w.W.User("a1-auditor", auditorGroup);
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(w.W.Plain, initiator);
        w.Approve(id, w.W.A1AdminUser);

        foreach (var user in new[] { w.W.Plain, caAuditor })
        {
            Assert.Empty(Ids(await w.Send(user, null, "List", (string?)null)));
            Assert.Equal(403, Status(await w.Send(user, null, "GetById", id)));
            Assert.Equal(403, Status(await w.Send(user, null, "Approve", id, w.StepUp(user, StepUpOps.ApproveCeremony, id))));
            Assert.Equal(403, Status(await w.Send(user, null, "Reject", id, w.StepUp(user, StepUpOps.RejectCeremony, id))));
            Assert.Equal(403, Status(await w.Send(user, null, "Execute", id, w.StepUp(user, StepUpOps.ExecuteCeremony, id))));
        }
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
    }

    [Fact]
    public async Task A_badge_that_leaves_out_the_admin_group_closes_the_ceremony()
    {
        var w = new World();
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var pending = w.GrantOnA1(w.W.Plain, initiator);
        var approved = w.GrantOnA1(w.W.Plain, initiator);
        w.Approve(approved, w.W.A1AdminUser);

        // The CA's admin and a system admin, each also a requester, wear a requester-only badge.
        var a1Admin = w.W.User("a1-admin-2", w.W.A1Admin, w.W.A1Requester);
        w.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = w.W.A1Requester.Id, UserId = w.W.SystemAdmin });
        w.Db.SaveChanges();

        foreach (var user in new[] { a1Admin, w.W.SystemAdmin })
        {
            var badge = w.Badge(user, w.W.A1Requester);
            Assert.DoesNotContain(pending, Ids(await w.Send(user, badge, "List", (string?)null)));
            Assert.Equal(403, Status(await w.Send(user, badge, "GetById", pending)));
            Assert.Equal(403, Status(await w.Send(user, badge, "Approve", pending, w.StepUp(user, StepUpOps.ApproveCeremony, pending))));
            Assert.Equal(403, Status(await w.Send(user, badge, "Reject", pending, w.StepUp(user, StepUpOps.RejectCeremony, pending))));
            Assert.Equal(403, Status(await w.Send(user, badge, "Execute", approved, w.StepUp(user, StepUpOps.ExecuteCeremony, approved))));

            // Badgeless, the same user reaches it.
            Assert.Equal(200, Status(await w.Send(user, null, "GetById", pending)));
        }

        // A badge that keeps the admin group keeps the tier path.
        var keeps = w.Badge(a1Admin, w.W.A1Admin);
        Assert.Equal(200, Status(await w.Send(a1Admin, keeps, "GetById", pending)));

        // The initiator may not execute under a badge that drops their dominating tier.
        w.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = w.W.A1Requester.Id, UserId = initiator });
        w.Db.SaveChanges();
        var narrowed = w.Badge(initiator, w.W.A1Requester);
        Assert.Equal(403, Status(await w.Send(initiator, narrowed, "Execute", approved, w.StepUp(initiator, StepUpOps.ExecuteCeremony, approved))));
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == approved).Status);
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == pending).Status);
    }

    [Fact]
    public async Task The_target_cannot_reject_even_as_a_system_admin()
    {
        var w = new World();
        var targetAdmin = w.W.User("sysadmin-2", w.W.SystemAdminGroup);
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(targetAdmin, initiator);

        Assert.Equal(403, Status(await w.Send(targetAdmin, null, "Reject", id, w.StepUp(targetAdmin, StepUpOps.RejectCeremony, id))));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);

        // An eligible approver may reject it.
        Assert.Equal(200, Status(await w.Send(w.W.A1AdminUser, null, "Reject", id, w.StepUp(w.W.A1AdminUser, StepUpOps.RejectCeremony, id))));
        Assert.Equal("Rejected", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
    }

    [Fact]
    public async Task A_tenant_wide_ca_manage_holder_who_does_not_dominate_neither_sees_nor_rejects_it()
    {
        var w = new World();
        var operatorGroup = w.W.Group("tenant-a-ca-operator", w.W.TenantA, null, null);
        w.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = operatorGroup.Id, Capability = Capabilities.CaManage });
        w.Db.SaveChanges();
        var orgOperator = w.W.User("tenant-a-operator", operatorGroup);

        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(w.W.Plain, initiator);
        var other = await w.Ceremonies.InitiateAsync("CreateRootCA", "root", string.Empty, initiator, "initiator",
            $"{{\"TenantId\":\"{w.W.TenantA}\"}}");

        var listed = Ids(await w.Send(orgOperator, null, "List", (string?)null));
        Assert.DoesNotContain(id, listed);
        Assert.Contains(other.Id, listed);
        Assert.Equal(403, Status(await w.Send(orgOperator, null, "GetById", id)));
        Assert.Equal(403, Status(await w.Send(orgOperator, null, "Reject", id, w.StepUp(orgOperator, StepUpOps.RejectCeremony, id))));
        Assert.Equal(200, Status(await w.Send(orgOperator, null, "GetById", other.Id)));
        Assert.Equal("Pending", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);

        // A system operator (system-wide ca.manage, no tier) likewise loses the controlled-user row only.
        var sysListed = Ids(await w.Send(w.W.Operator, null, "List", (string?)null));
        Assert.DoesNotContain(id, sysListed);
        Assert.Contains(other.Id, sysListed);
    }

    [Fact]
    public async Task A_second_execute_is_a_conflict_and_the_change_applies_once()
    {
        var w = new World();
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(w.W.Plain, initiator);
        w.Approve(id, w.W.A1AdminUser);

        Assert.Equal(200, Status(await w.Send(initiator, null, "Execute", id, w.StepUp(initiator, StepUpOps.ExecuteCeremony, id))));
        Assert.Equal(409, Status(await w.Send(w.W.A1AdminUser, null, "Execute", id, w.StepUp(w.W.A1AdminUser, StepUpOps.ExecuteCeremony, id))));

        Assert.Equal("Executed", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
        Assert.Single(w.Db.UserCapabilityGrants.Where(g => g.UserId == w.W.Plain && g.Capability == Capabilities.SystemManage));
        Assert.Single(w.Audit.Entries.Where(e => e.Action == AuditActionType.ControlledUserChangeApplied));
    }

    [Fact]
    public async Task An_apply_that_read_the_ceremony_before_a_concurrent_execute_committed_is_refused()
    {
        var name = $"race-{Guid.NewGuid():N}";
        var w = new ControlledUserWorld(InMemoryDbContextFactory.Create(name));
        var first = new KeyCeremonyService(w.Db, new RecordingAuditService());
        var svc1 = new ControlledUserCeremonyService(w.Db, first, null!, NullLogger<ControlledUserCeremonyService>.Instance);
        var initiator = w.User("a1-initiator", w.A1Admin);
        var minted = svc1.ClassifyCapabilityGrant(Capabilities.SystemManage, w.CaA1)!.Value;
        var id = await svc1.InitiateCapabilityGrantAsync(w.Plain, "plain", Capabilities.SystemManage, null, w.CaA1, null, null, minted, initiator, "i");
        await first.ApproveAsync(id, w.A1AdminUser, "a1admin");

        // The second request has already loaded the ceremony as Approved when the first one applies.
        using var db2 = InMemoryDbContextFactory.Create(name);
        Assert.Equal("Approved", (await db2.KeyCeremonies.FindAsync(id))!.Status);
        var svc2 = new ControlledUserCeremonyService(db2, new KeyCeremonyService(db2, new RecordingAuditService()), null!,
            NullLogger<ControlledUserCeremonyService>.Instance);

        await svc1.ApplyApprovedAsync(id);
        var refused = await Assert.ThrowsAsync<CeremonyNotExecutableException>(() => svc2.ApplyApprovedAsync(id));
        Assert.Equal("Executed", refused.Status);
        Assert.Single(db2.UserCapabilityGrants.Where(g => g.UserId == w.Plain && g.Capability == Capabilities.SystemManage));
    }

    [Fact]
    public async Task An_effectively_identical_grant_is_not_inserted_again()
    {
        var w = new World();
        // Already held on CA A1, recorded with the CA's tenant; the ceremony names the CA only.
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
        {
            UserId = w.W.Plain, Capability = Capabilities.SystemManage, TenantId = w.W.TenantA, CertificateAuthorityId = w.W.CaA1,
        });
        w.Db.SaveChanges();
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(w.W.Plain, initiator);
        w.Approve(id, w.W.A1AdminUser);

        Assert.Equal(200, Status(await w.Send(initiator, null, "Execute", id, w.StepUp(initiator, StepUpOps.ExecuteCeremony, id))));
        Assert.Single(w.Db.UserCapabilityGrants.Where(g => g.UserId == w.W.Plain && g.Capability == Capabilities.SystemManage));
    }

    [Theory]
    [InlineData("ControlledUserChange")]
    [InlineData("TenantPolicyChange")]
    [InlineData("RevokeCa")]
    [InlineData("CreateSshCa")]
    [InlineData("DeleteSshCa")]
    [InlineData("createrootca")]
    [InlineData("Unknown")]
    public async Task Generic_initiate_refuses_types_with_a_dedicated_path(string operationType)
    {
        var w = new World();
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.InitiateCeremonyRequest"))!;
        body.GetType().GetProperty("OperationType")!.SetValue(body, operationType);
        body.GetType().GetProperty("Parameters")!.SetValue(body, new KeyCeremonyParameters { TenantId = w.W.TenantA });

        var result = await w.Send(w.W.SystemAdmin, null, "Initiate", body, w.StepUp(w.W.SystemAdmin, StepUpOps.InitiateCeremony));
        Assert.Equal(400, Status(result));
        Assert.Empty(w.Db.KeyCeremonies);
    }

    [Fact]
    public async Task A_last_dominator_refusal_is_audited_as_a_refusal_and_leaves_the_ceremony_approved()
    {
        var w = new World();
        w.Decorate = inner => RefusingProxy.Wrap(inner);
        var initiator = w.W.User("a1-initiator", w.W.A1Admin);
        var id = w.GrantOnA1(w.W.Plain, initiator);
        w.Approve(id, w.W.A1AdminUser);

        Assert.Equal(409, Status(await w.Send(initiator, null, "Execute", id, w.StepUp(initiator, StepUpOps.ExecuteCeremony, id))));
        Assert.Equal("Approved", w.Db.KeyCeremonies.Single(c => c.Id == id).Status);
        Assert.Contains(w.Audit.Entries, e => e.Action == AuditActionType.ControlledUserChangeRefused && e.TargetId == id.ToString());
        Assert.DoesNotContain(w.Audit.Entries, e => e.Action == AuditActionType.KeyCeremonyRejected);
    }

    /// <summary>Forwards to the real service but refuses every apply as a last-dominator refusal would.</summary>
    public class RefusingProxy : DispatchProxy
    {
        private IControlledUserCeremonyService _inner = null!;

        public static IControlledUserCeremonyService Wrap(IControlledUserCeremonyService inner)
        {
            var proxy = Create<IControlledUserCeremonyService, RefusingProxy>();
            ((RefusingProxy)(object)proxy)._inner = inner;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == nameof(IControlledUserCeremonyService.ApplyApprovedAsync))
                return Task.FromException<ControlledUserChangeResult>(new ControlledUserChangeRefusedException(
                    "Refusing this change: it would remove the last controlled user of this scope.", ceremonyExpired: false));
            try
            {
                return targetMethod.Invoke(_inner, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }
    }
}
