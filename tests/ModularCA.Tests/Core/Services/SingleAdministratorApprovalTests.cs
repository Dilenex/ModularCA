using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A single administrator can complete a request whose profile requires approval by approving it
/// themselves, when the policy allows it; and the console can tell, before and after a request is
/// made, whether anyone can approve it.
/// </summary>
public class SingleAdministratorApprovalTests
{
    private sealed class World
    {
        public SingleAdminWorld W { get; } = new(requireCeremony: false);
        public SigningProfileEntity Signing { get; }
        public RequestProfileEntity Gated { get; }
        public CaGroupAuthorizationService Auth { get; }

        public World(bool selfApproval)
        {
            W.Db.SecurityPolicies.Local.Single().AllowSystemSuperSelfApproval = selfApproval;
            Signing = new SigningProfileEntity { Name = "Root signing", IssuerId = W.CaCertificate };
            Gated = new RequestProfileEntity { Name = "Gated", RequireApproval = true, RequiredApprovalCount = 2 };
            W.Db.SigningProfiles.Add(Signing);
            W.Db.RequestProfiles.Add(Gated);
            W.Db.SaveChanges();
            Auth = new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance);
        }

        public SecurityPolicyEntity Policy => W.Db.SecurityPolicies.Single();

        public Task<ApprovalOutlook> OutlookAsync(Guid requester, params Guid[] approvedBy)
            => RequestApprovers.OutlookAsync(W.Db, Auth, Policy, 2, Signing.Id, null, requester, approvedBy);

        public Guid Operator(string name)
        {
            var group = W.Group($"{name}-group", W.Space, null, Capabilities.OperatorTemplate);
            W.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = Capabilities.ProfileUse, ResourceType = "SigningProfile" });
            W.Db.SaveChanges();
            return W.User(name, group);
        }
    }

    [Fact]
    public async Task A_request_needs_its_profile_s_approval_count_and_at_least_one()
    {
        var w = new World(selfApproval: false);
        var profiles = new ProfileResolutionService(w.W.Db, NullLogger<ProfileResolutionService>.Instance);
        var none = new RequestProfileEntity { Name = "None", RequireApproval = true, RequiredApprovalCount = 0 };
        w.W.Db.RequestProfiles.Add(none);
        await w.W.Db.SaveChangesAsync();

        Assert.Equal(2, await RequestApprovals.RequiredCountAsync(w.W.Db, profiles, new CertRequestEntity { RequestProfileId = w.Gated.Id }));
        Assert.Equal(1, await RequestApprovals.RequiredCountAsync(w.W.Db, profiles, new CertRequestEntity { RequestProfileId = none.Id }));
        Assert.Equal(1, await RequestApprovals.RequiredCountAsync(w.W.Db, profiles, new CertRequestEntity()));
    }

    [Fact]
    public async Task Only_a_system_super_may_approve_their_own_request_and_only_when_the_policy_allows_it()
    {
        var allowed = new World(selfApproval: true);
        var operatorId = allowed.Operator("operator");
        Assert.True(await RequestApprovals.MaySelfApproveAsync(allowed.W.Db, allowed.Policy, allowed.W.Admin));
        Assert.False(await RequestApprovals.MaySelfApproveAsync(allowed.W.Db, allowed.Policy, operatorId));

        var refused = new World(selfApproval: false);
        Assert.False(await RequestApprovals.MaySelfApproveAsync(refused.W.Db, refused.Policy, refused.W.Admin));
    }

    [Fact]
    public async Task A_lone_administrator_s_request_can_complete_only_by_their_own_approval()
    {
        var allowed = new World(selfApproval: true);
        var outlook = await allowed.OutlookAsync(allowed.W.Admin);
        Assert.Equal(0, outlook.OthersWhoCanApprove);
        Assert.True(outlook.RequesterMaySelfApprove);
        Assert.True(outlook.CanComplete);

        var refused = new World(selfApproval: false);
        outlook = await refused.OutlookAsync(refused.W.Admin);
        Assert.Equal(0, outlook.OthersWhoCanApprove);
        Assert.False(outlook.RequesterMaySelfApprove);
        Assert.False(outlook.CanComplete);
    }

    [Fact]
    public async Task Other_approvers_are_counted_once_and_not_after_they_approve()
    {
        var w = new World(selfApproval: false);
        var first = w.Operator("first");
        w.Operator("second");

        var outlook = await w.OutlookAsync(w.W.Admin);
        Assert.Equal(2, outlook.OthersWhoCanApprove);
        Assert.True(outlook.CanComplete);

        outlook = await w.OutlookAsync(w.W.Admin, first);
        Assert.Equal(1, outlook.ApprovalCount);
        Assert.Equal(1, outlook.OthersWhoCanApprove);
        Assert.True(outlook.CanComplete);
    }

    [Fact]
    public async Task An_operator_without_profile_use_on_the_signing_profile_cannot_approve()
    {
        var w = new World(selfApproval: false);
        w.W.User("no-profile", w.W.Group("bare", w.W.Space, null, Capabilities.OperatorTemplate));
        var outlook = await w.OutlookAsync(w.W.Admin);
        Assert.Equal(0, outlook.OthersWhoCanApprove);
    }
}
