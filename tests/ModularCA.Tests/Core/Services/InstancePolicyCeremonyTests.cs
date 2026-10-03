using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The instance's own CA policy after 0.4.0 S3: a ceremony on an instance CA takes the instance's
/// quorum (never a fallback of 1), the instance's policy changes through an InstancePolicyChange
/// ceremony that writes the security policy row and nothing else, and a quorum no one can meet is
/// reported at start.
/// </summary>
public class InstancePolicyCeremonyTests
{
    [Theory]
    [InlineData("RevokeCa")]
    [InlineData("CreateRootCA")]
    [InlineData("CreateSshCa")]
    [InlineData("DeleteSshCa")]
    [InlineData("InstancePolicyChange")]
    [InlineData("SpacePolicyChange")]
    public async Task A_ceremony_with_no_space_takes_the_instance_quorum(string operation)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { CeremonyRequiredApprovals = 3 });
        var space = new SpaceEntity { Name = "Acme", Slug = "acme", CeremonyRequiredApprovals = 2 };
        db.Spaces.Add(space);
        await db.SaveChangesAsync();
        var ceremonies = new KeyCeremonyService(db, new RecordingAuditService());

        var instance = await ceremonies.InitiateAsync(operation, "x", "", Guid.NewGuid(), "op", JsonSerializer.Serialize(new { SpaceId = (Guid?)null }));
        var spaced = await ceremonies.InitiateAsync(operation, "x", "", Guid.NewGuid(), "op", JsonSerializer.Serialize(new { SpaceId = space.Id }));

        Assert.Equal(3, instance.RequiredApprovals);
        Assert.Null(instance.SpaceId);
        Assert.Equal(2, spaced.RequiredApprovals);
        Assert.Equal(space.Id, spaced.SpaceId);
    }

    [Fact]
    public void An_empty_space_id_in_stored_parameters_reads_as_the_instance()
    {
        var parameters = JsonSerializer.Deserialize<KeyCeremonyParameters>($"{{\"SpaceId\":\"{Guid.Empty}\",\"SubjectCN\":\"x\"}}")!;
        Assert.Null(parameters.SpaceId);
        Assert.Null(JsonSerializer.Deserialize<RevokeCaCeremonyParameters>($"{{\"SpaceId\":\"{Guid.Empty}\"}}")!.SpaceId);
        Assert.Null(ModularCA.Shared.Models.CeremonyParametersJson.ReadSpaceId($"{{\"SpaceId\":\"{Guid.Empty}\"}}"));
        var space = Guid.NewGuid();
        Assert.Equal(space, JsonSerializer.Deserialize<SshKeyCeremonyParameters>($"{{\"SpaceId\":\"{space}\"}}")!.SpaceId);
    }

    [Fact]
    public async Task Instance_ceremonies_are_listed_only_when_asked_for()
    {
        using var db = InMemoryDbContextFactory.Create();
        var space = Guid.NewGuid();
        db.KeyCeremonies.AddRange(
            new KeyCeremonyEntity { OperationType = "RevokeCa", Status = "Pending", SpaceId = null, ExpiresAt = DateTime.UtcNow.AddHours(1) },
            new KeyCeremonyEntity { OperationType = "RevokeCa", Status = "Pending", SpaceId = space, ExpiresAt = DateTime.UtcNow.AddHours(1) });
        await db.SaveChangesAsync();
        var ceremonies = new KeyCeremonyService(db, new RecordingAuditService());

        Assert.Equal([space], (await ceremonies.ListBySpacesAsync([space])).Select(c => c.SpaceId!.Value));
        Assert.Equal(2, (await ceremonies.ListBySpacesAsync([space], includeInstance: true)).Count);
        Assert.Single(await ceremonies.ListBySpacesAsync([], includeInstance: true));
    }

    [Fact]
    public async Task An_instance_policy_change_writes_the_security_policy_row_and_nothing_else()
    {
        var name = $"instance-policy-{Guid.NewGuid():N}";
        using var db = InMemoryDbContextFactory.Create(name);
        var policy = new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 3, UserCeremonyRequiredApprovals = null };
        db.SecurityPolicies.Add(policy);
        var space = new SpaceEntity { Name = "Acme", Slug = "acme", RequireKeyCeremony = true, CeremonyRequiredApprovals = 2 };
        db.Spaces.Add(space);
        var instanceCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Ops SSH", Label = "ops-ssh", SpaceId = null };
        var spaceCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Acme Root", Label = "acme-root", SpaceId = space.Id };
        db.CertificateAuthorities.AddRange(instanceCa, spaceCa);
        await db.SaveChangesAsync();
        var ceremonies = new KeyCeremonyService(db, new RecordingAuditService());
        var changes = new SpacePolicyChangeService(db, ceremonies, NullLogger<SpacePolicyChangeService>.Instance);

        var id = await changes.InitiateChangeAsync(null, false, 1, Guid.NewGuid(), "admin",
            userQuorumIncluded: true, proposedUserQuorum: 2,
            caUserQuorums: [new CaUserQuorumChange { CaId = instanceCa.Id, ProposedQuorum = 1 }, new CaUserQuorumChange { CaId = spaceCa.Id, ProposedQuorum = 1 }]);

        var ceremony = await db.KeyCeremonies.AsNoTracking().SingleAsync(c => c.Id == id);
        Assert.Equal(CeremonyType.InstancePolicyChange, ceremony.CeremonyType);
        Assert.Equal("InstancePolicyChange", ceremony.OperationType);
        Assert.Null(ceremony.SpaceId);
        Assert.Equal(3, ceremony.RequiredApprovals);
        // One pending at a time.
        await Assert.ThrowsAsync<InvalidOperationException>(() => changes.InitiateChangeAsync(null, false, null, Guid.NewGuid(), "admin"));

        var tracked = await db.KeyCeremonies.SingleAsync(c => c.Id == id);
        tracked.Status = "Approved";
        await db.SaveChangesAsync();
        var result = await changes.ApplyApprovedChangeAsync(id);

        Assert.Null(result.SpaceId);
        using var check = InMemoryDbContextFactory.Create(name);
        var after = await check.SecurityPolicies.SingleAsync();
        Assert.False(after.RequireKeyCeremony);
        Assert.Equal(1, after.CeremonyRequiredApprovals);
        Assert.Equal(2, after.UserCeremonyRequiredApprovals);
        var spaceAfter = await check.Spaces.SingleAsync();
        Assert.True(spaceAfter.RequireKeyCeremony);
        Assert.Equal(2, spaceAfter.CeremonyRequiredApprovals);
        Assert.Equal(1, (await check.CertificateAuthorities.SingleAsync(c => c.Id == instanceCa.Id)).UserCeremonyRequiredApprovals);
        // A CA outside the scope was dropped at initiation, never changed.
        Assert.Null((await check.CertificateAuthorities.SingleAsync(c => c.Id == spaceCa.Id)).UserCeremonyRequiredApprovals);
    }

    [Fact]
    public async Task A_space_ceremony_cannot_be_applied_to_the_instance()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity());
        await db.SaveChangesAsync();
        var parameters = JsonSerializer.Serialize(new SpacePolicyChangeCeremonyParameters
        {
            SpaceId = null, CurrentRequireKeyCeremony = true, CurrentCeremonyRequiredApprovals = 2, ProposedRequireKeyCeremony = false,
        });
        var ceremony = new KeyCeremonyEntity { OperationType = "SpacePolicyChange", CeremonyType = CeremonyType.SpacePolicyChange, Status = "Approved", ParametersJson = parameters, ExpiresAt = DateTime.UtcNow.AddHours(1) };
        db.KeyCeremonies.Add(ceremony);
        await db.SaveChangesAsync();
        var changes = new SpacePolicyChangeService(db, new KeyCeremonyService(db, new RecordingAuditService()), NullLogger<SpacePolicyChangeService>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => changes.ApplyApprovedChangeAsync(ceremony.Id));
        Assert.True((await db.SecurityPolicies.AsNoTracking().SingleAsync()).RequireKeyCeremony);
    }

    [Theory]
    [InlineData(2, 3, false)]
    [InlineData(2, 2, true)]
    [InlineData(1, 1, true)]
    [InlineData(0, 2, false)]
    public void A_quorum_no_one_can_meet_is_warned_about(int required, int eligible, bool warns)
    {
        var warning = InstanceQuorumCheck.Warning(required, eligible);
        Assert.Equal(warns, warning != null);
        if (warns) Assert.Contains("initiator never counts", warning);
    }

    [Fact]
    public async Task The_start_up_check_counts_system_scoped_approvers()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = true, CeremonyRequiredApprovals = 2 });
        var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-operator", IsSystemGroup = true, SpaceId = null };
        db.CaGroups.Add(group);
        db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = ModularCA.Shared.Authorization.Capabilities.CaManage });
        foreach (var n in new[] { "a", "b" })
        {
            var user = new UserEntity { Id = Guid.NewGuid(), Username = n, Email = $"{n}@x", IsActive = true };
            db.Users.Add(user);
            db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = user.Id });
        }
        await db.SaveChangesAsync();

        Assert.NotNull(await InstanceQuorumCheck.WarningAsync(db));

        var third = new UserEntity { Id = Guid.NewGuid(), Username = "c", Email = "c@x", IsActive = true };
        db.Users.Add(third);
        db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = third.Id });
        await db.SaveChangesAsync();
        Assert.Null(await InstanceQuorumCheck.WarningAsync(db));
    }
}
