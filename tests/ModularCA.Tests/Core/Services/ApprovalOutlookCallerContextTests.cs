using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The approval outlook says who else could approve a request. It evaluates those other accounts on
/// their own grants: the caller's worn badge does not filter them, and the hypothetical evaluation
/// writes no audit rows. Drives the real <c>AdminCertSignRequestController</c> with the
/// request-scoped authorization service it gets in production.
/// </summary>
public sealed class ApprovalOutlookCallerContextTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminCertSignRequestController";

    private sealed class CurrentUserStub(UserEntity user) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => user.Id;
        public UserEntity? User => user;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class PolicyOf(SecurityPolicyEntity policy) : ISecurityPolicyService
    {
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(policy);
        public void InvalidateCache() { }
    }

    private sealed class World
    {
        public SingleAdminWorld W { get; } = new(requireCeremony: false);
        public SigningProfileEntity Signing { get; }
        public RequestProfileEntity Gated { get; }
        public Guid Caller { get; }
        public Guid CallerBadge { get; } = Guid.NewGuid();
        public RecordingAuditService Audit { get; } = new();

        public World()
        {
            Signing = new SigningProfileEntity { Name = "Root signing", IssuerId = W.CaCertificate };
            Gated = new RequestProfileEntity { Name = "Gated", RequireApproval = true, RequiredApprovalCount = 2 };
            W.Db.SigningProfiles.Add(Signing);
            W.Db.RequestProfiles.Add(Gated);
            W.Db.SaveChanges();

            var callerGroup = OperatorGroup("caller");
            Caller = W.User("caller", callerGroup);
            W.Db.AccessBadges.Add(new AccessBadgeEntity
            {
                Id = CallerBadge, UserId = Caller, Name = "Operator only",
                Sources = { new AccessBadgeSourceEntity { Kind = AccessBadgeSourceKind.Group, SourceId = callerGroup.Id } },
            });
            W.Db.SaveChanges();
        }

        /// <summary>A space operator group that may also use the signing profile.</summary>
        public CaGroupEntity OperatorGroup(string name)
        {
            var group = W.Group($"{name}-group", W.Space, null, Capabilities.OperatorTemplate);
            W.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = Capabilities.ProfileUse, ResourceType = "SigningProfile" });
            W.Db.SaveChanges();
            return group;
        }

        /// <summary>Asks for the outlook of a request the caller is about to make, as the caller.</summary>
        public async Task<JsonElement> SubmissionOutlookAsync(bool wearBadge)
        {
            var claims = new List<Claim> { new("sub", Caller.ToString()) };
            if (wearBadge) claims.Add(new Claim(AccessBadgeContext.BadgeClaim, CallerBadge.ToString()));
            var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
            var accessor = new HttpContextAccessor { HttpContext = http };

            // The request-scoped resolver as production builds it: the caller's badge and audit.
            var auth = new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance,
                Audit, accessor, new AccessBadgeContext(W.Db, accessor));
            var callerUser = W.Db.Users.Single(u => u.Id == Caller);

            var type = ApiAssembly.TypeNamed(ControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                W.Db, auth, Audit, new CurrentUserStub(callerUser), new PolicyOf(W.Db.SecurityPolicies.Single()),
                new ProfileResolutionService(W.Db, NullLogger<ProfileResolutionService>.Instance), new SystemConfig(),
            };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });

            var result = await (Task<IActionResult>)type.GetMethod("GetSubmissionApprovalOutlook")!
                .Invoke(controller, new object?[] { Gated.Id, Signing.Id, null })!;
            return JsonSerializer.SerializeToElement(Assert.IsType<OkObjectResult>(result).Value);
        }
    }

    [Fact]
    public async Task A_badge_the_caller_wears_does_not_hide_other_approvers()
    {
        var w = new World();
        w.W.User("first", w.OperatorGroup("first"));
        w.W.User("second", w.OperatorGroup("second"));

        // Two operators and the setup administrator can approve. The caller's badge narrows the
        // caller; applied to other accounts it named nothing they hold and counted none of them.
        var outlook = await w.SubmissionOutlookAsync(wearBadge: true);

        Assert.Equal(3, outlook.GetProperty("OthersWhoCanApprove").GetInt32());
        Assert.True(outlook.GetProperty("CanComplete").GetBoolean());
    }

    [Fact]
    public async Task Evaluating_other_accounts_writes_no_audit_rows()
    {
        var w = new World();
        var sysadmin = w.W.User("sysadmin");
        w.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = sysadmin, Capability = Capabilities.SystemManage });
        w.W.Db.SaveChanges();

        // A system administrator by direct grant, in none of the CA's groups, besides the setup
        // administrator. Evaluating them recorded SystemAdminElevatedAccess as if they had reached
        // into the CA on this request, under the caller's address and path.
        var outlook = await w.SubmissionOutlookAsync(wearBadge: false);

        Assert.Equal(2, outlook.GetProperty("OthersWhoCanApprove").GetInt32());
        Assert.DoesNotContain(w.Audit.Entries, e => e.Action == AuditActionType.SystemAdminElevatedAccess);
    }
}
