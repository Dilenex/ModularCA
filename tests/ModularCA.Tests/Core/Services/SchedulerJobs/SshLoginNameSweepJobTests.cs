using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// The scheduled SSH login name sweep (<c>docs/architecture/ssh-login-names.md</c>, "The sweep"):
/// what the job writes when a pass revoked something and when it did not, and how it is named,
/// scheduled and registered. Which certificates a sweep revokes and leaves is pinned in
/// <see cref="SshLoginNameTests"/>.
/// </summary>
public class SshLoginNameSweepJobTests
{
    private static SshLoginNameSweepJob Build(SshNode node, SystemConfig? config = null)
    {
        config ??= new SystemConfig();
        var sp = new ServiceCollection().BuildServiceProvider();
        return new SshLoginNameSweepJob(NullLogger<SshLoginNameSweepJob>.Instance, node.Audit, config, node.LoginNames, sp,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test"));
    }

    private static Task<SshCertificateEntity> SignFor(SshNode node, SshCaKeyEntity ca, UserEntity user)
        => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(user.Id), [user.Username], 1, null, node.Actor);

    [Fact]
    public async Task A_pass_that_revokes_writes_one_completed_entry_with_the_counts_and_names_the_scheduler()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var alices = await SignFor(node, ca, alice);
        var bobs = await SignFor(node, ca, bob);
        // Disabled with no hook run, as a node that stopped after saving the change leaves it.
        alice.IsActive = false;
        node.Db.SaveChanges();

        var result = await Build(node).RunOnceAsync(CancellationToken.None);

        Assert.Equal(new SshLoginNameSweep(UserNotActive: 1, UserDeleted: 0, LoginNameLost: 0), result);
        using (var db = node.Reopen())
        {
            Assert.True(db.SshCertificates.Single(c => c.Id == alices.Id).IsRevoked);
            Assert.False(db.SshCertificates.Single(c => c.Id == bobs.Id).IsRevoked);
        }
        var revoked = Assert.Single(node.Audit.Of(AuditActionType.SshCertRevoked));
        Assert.Equal(alices.Id.ToString(), revoked.TargetId);
        Assert.Equal("scheduler", revoked.Actor);
        Assert.Null(revoked.ActorId);
        var completed = Assert.Single(node.Audit.Of(AuditActionType.SshLoginNameSweepCompleted));
        Assert.Equal("scheduler", completed.Actor);
        Assert.Equal("{\"UserNotActive\":1,\"UserDeleted\":0,\"UserRenamed\":0,\"RequestRightLost\":0,\"LoginNameLost\":0}", JsonSerializer.Serialize(completed.Details));
    }

    [Fact]
    public async Task A_pass_with_nothing_to_do_writes_no_audit_entry()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var alices = await SignFor(node, ca, alice);
        var entries = node.Audit.Entries.Count;

        var result = await Build(node).RunOnceAsync(CancellationToken.None);

        Assert.Equal(0, result.Total);
        Assert.Equal(entries, node.Audit.Entries.Count);
        using var db = node.Reopen();
        Assert.False(db.SshCertificates.Single(c => c.Id == alices.Id).IsRevoked);
    }

    [Fact]
    public async Task The_job_runs_every_fifteen_minutes_by_default_and_is_registered_with_no_enabled_switch()
    {
        using var node = new SshNode();
        var config = new SystemConfig();
        var registry = new SchedulerJobRegistry(new ServiceCollection().BuildServiceProvider(), NullLogger<SchedulerJobRegistry>.Instance, config);

        Assert.Equal("SshLoginNameSweep", Build(node, config).Name);
        Assert.Equal("*/15 * * * *", config.SshLoginNameSweep.Schedule);
        Assert.Equal(config.ProtocolCleanup.Schedule, config.SshLoginNameSweep.Schedule);
        Assert.Contains("SshLoginNameSweep", registry.JobNames);
        Assert.True(registry.IsRegistered("SshLoginNameSweep"));
        Assert.Equal("*/15 * * * *", registry.GetCron("SshLoginNameSweep"));
        Assert.Equal(120, registry.GetTimeoutSeconds("SshLoginNameSweep"));
        Assert.Equal(120, config.Scheduler.JobTimeouts["SshLoginNameSweep"]);
        Assert.True(await registry.GetEnabledAsync("SshLoginNameSweep"));
        Assert.False(registry.SetEnabled("SshLoginNameSweep", false));
        Assert.True(await registry.GetEnabledAsync("SshLoginNameSweep"));

        Assert.True(registry.SetCron("SshLoginNameSweep", "*/5 * * * *"));
        Assert.Equal("*/5 * * * *", config.SshLoginNameSweep.Schedule);
    }
}
