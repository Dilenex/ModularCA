using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// <c>SshCertificates.RevokedAt</c> (<c>docs/architecture/ssh-krl-delivery.md</c>, "When a
/// certificate was revoked"): every way a certificate is revoked records when, through the one
/// method that can mark it, and a certificate that is not revoked has no time. The KRL's
/// generation time and ETag are read from these times.
/// </summary>
public class SshRevocationTimeTests
{
    private static Task<SshCertificateEntity> SignFor(SshNode node, SshCaKeyEntity ca, UserEntity user, params string[] principals)
        => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(user.Id), principals.ToList(), 1, null, node.Actor);

    private static SshCertificateEntity Row(SshNode node, SshCertificateEntity certificate)
    {
        using var db = node.Reopen();
        return db.SshCertificates.Single(c => c.Id == certificate.Id);
    }

    /// <summary>Asserts the certificate is revoked at a UTC time between <paramref name="from"/> and now, and returns it.</summary>
    private static DateTime AssertRevokedSince(SshNode node, SshCertificateEntity certificate, DateTime from)
    {
        var row = Row(node, certificate);
        Assert.True(row.IsRevoked);
        var at = Assert.NotNull(row.RevokedAt);
        Assert.InRange(at, from, DateTime.UtcNow);
        return at;
    }

    private static void AssertNotRevoked(SshNode node, SshCertificateEntity certificate)
    {
        var row = Row(node, certificate);
        Assert.False(row.IsRevoked);
        Assert.Null(row.RevokedAt);
    }

    /// <summary>
    /// The compiler holds a fourth place to the rule: nothing outside the entity can set the
    /// flag or the time, so a certificate is revoked only through <c>Revoke</c>, which sets both.
    /// </summary>
    [Fact]
    public void A_certificate_is_marked_revoked_only_through_the_method_that_records_when()
    {
        foreach (var name in new[] { nameof(SshCertificateEntity.IsRevoked), nameof(SshCertificateEntity.RevokedAt) })
        {
            var setter = typeof(SshCertificateEntity).GetProperty(name)!.SetMethod;
            Assert.True(setter != null && setter.IsPrivate, $"{name} must have a private setter");
        }

        var certificate = new SshCertificateEntity();
        Assert.False(certificate.IsRevoked);
        Assert.Null(certificate.RevokedAt);

        var first = new DateTime(2026, 10, 8, 9, 0, 0, DateTimeKind.Unspecified);
        Assert.True(certificate.Revoke(first));
        Assert.True(certificate.IsRevoked);
        Assert.Equal(first, certificate.RevokedAt);
        Assert.Equal(DateTimeKind.Utc, certificate.RevokedAt!.Value.Kind);

        // A revocation is not undone and its time does not move.
        Assert.False(certificate.Revoke(first.AddHours(3)));
        Assert.Equal(first, certificate.RevokedAt);

        var local = new SshCertificateEntity();
        var localTime = new DateTime(2026, 10, 8, 9, 0, 0, DateTimeKind.Local);
        Assert.True(local.Revoke(localTime));
        Assert.Equal(localTime.ToUniversalTime(), local.RevokedAt);
        Assert.Equal(DateTimeKind.Utc, local.RevokedAt!.Value.Kind);
    }

    [Fact]
    public async Task An_administrator_s_revocation_records_when_and_asking_again_keeps_that_time()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var revoked = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        var standing = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host1"], 1, node.Actor);
        var before = DateTime.UtcNow;

        Assert.True(await node.Service.RevokeCertificateAsync(revoked.Id, ca.Id, node.Actor));

        var at = AssertRevokedSince(node, revoked, before);
        AssertNotRevoked(node, standing);

        await Task.Delay(20);
        Assert.True(await node.Service.RevokeCertificateAsync(revoked.Id, ca.Id, node.Actor));
        Assert.Equal(at, Row(node, revoked).RevokedAt);
    }

    [Fact]
    public async Task Disabling_an_ssh_ca_key_revokes_its_certificates_at_one_time_and_leaves_an_earlier_revocation_its_own()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var other = await node.CreateCaAsync("Other SSH");
        var earlier = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        var user = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["bob"], 1, null, node.Actor);
        var host = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host1"], 1, node.Actor);
        var elsewhere = await node.Service.SignUserKeyAsync(other.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        Assert.True(await node.Service.RevokeCertificateAsync(earlier.Id, ca.Id, node.Actor));
        var first = Row(node, earlier).RevokedAt;
        await Task.Delay(20);
        var before = DateTime.UtcNow;

        await node.Service.DisableAsync(ca.Id, node.Actor);

        var at = AssertRevokedSince(node, user, before);
        Assert.Equal(at, AssertRevokedSince(node, host, before));
        Assert.Equal(first, Row(node, earlier).RevokedAt);
        Assert.True(first < at);
        AssertNotRevoked(node, elsewhere);
        Assert.Equal(at, (await node.Service.GetKrlStateAsync(ca.Id)).LastRevokedAt);
    }

    /// <summary>The hooks of the login name rule: a grant removed, and a user disabled.</summary>
    [Fact]
    public async Task The_login_name_reconciliation_records_when_it_revoked()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var root = (await node.LoginNames.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["root"], alice.Id, null, null, null, null), node.Actor)).Single();
        var withRoot = await SignFor(node, ca, alice, "alice", "root");
        var ownOnly = await SignFor(node, ca, alice, "alice");
        var bobs = await SignFor(node, ca, bob, "bob");
        var before = DateTime.UtcNow;

        Assert.Equal(1, await node.LoginNames.RemoveGrantAsync(ca.Id, root.Id, node.Actor));

        var lostName = AssertRevokedSince(node, withRoot, before);
        AssertNotRevoked(node, ownOnly);
        AssertNotRevoked(node, bobs);

        await Task.Delay(20);
        var disabledAfter = DateTime.UtcNow;
        var users = new UserManagementService(node.Db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!, null!, node.LoginNames);
        Assert.True(await users.UpdateUser(alice.Id, new UpdateUserRequest { IsActive = false }));

        AssertRevokedSince(node, ownOnly, disabledAfter);
        Assert.Equal(lostName, Row(node, withRoot).RevokedAt);
        AssertNotRevoked(node, bobs);

        var bobsBefore = DateTime.UtcNow;
        var revocation = await node.LoginNames.RevokeCertificatesOfUserAsync(bob.Id, [ca.Id], node.Actor);
        Assert.Equal(1, revocation.Revoked);
        AssertRevokedSince(node, bobs, bobsBefore);
    }

    /// <summary>The periodic sweep, which revokes what a lost hook left live: every rule records when.</summary>
    [Fact]
    public async Task The_sweep_records_when_it_revoked()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var carol = node.AddUser("carol", node.GroupOf(ca, "user").Id);
        var dave = node.AddUser("dave", node.GroupOf(ca, "user").Id);
        var erin = node.AddUser("erin", node.GroupOf(ca, "user").Id);
        var root = (await node.LoginNames.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["root"], alice.Id, null, null, null, null), node.Actor)).Single();
        var lostName = await SignFor(node, ca, alice, "alice", "root");
        var ofDisabled = await SignFor(node, ca, bob, "bob");
        var ofDeleted = await SignFor(node, ca, carol, "carol");
        var ofNoRight = await SignFor(node, ca, dave, "dave");
        var held = await SignFor(node, ca, erin, "erin");

        // Each change made past its hook, as a node that stopped after saving it leaves the rows.
        node.Db.SshLoginNameGrants.RemoveRange(node.Db.SshLoginNameGrants.Where(g => g.Id == root.Id));
        bob.IsActive = false;
        node.Db.SshCertificates.Single(c => c.Id == ofDeleted.Id).SubjectUserId = null;
        node.Db.CaGroupMembers.RemoveRange(node.Db.CaGroupMembers.Where(m => m.UserId == dave.Id));
        node.Db.SaveChanges();
        var before = DateTime.UtcNow;

        var swept = await node.LoginNames.SweepAsync(new SshCaActor(null, "scheduler"));

        Assert.Equal(new SshLoginNameSweep(UserNotActive: 1, UserDeleted: 1, LoginNameLost: 1, RequestRightLost: 1), swept);
        foreach (var certificate in new[] { lostName, ofDisabled, ofDeleted, ofNoRight })
            AssertRevokedSince(node, certificate, before);
        AssertNotRevoked(node, held);

        var times = new[] { lostName, ofDisabled, ofDeleted, ofNoRight }.ToDictionary(c => c.Id, c => Row(node, c).RevokedAt);
        await Task.Delay(20);
        Assert.Equal(0, (await node.LoginNames.SweepAsync(new SshCaActor(null, "scheduler"))).Total);
        Assert.All(times, t => Assert.Equal(t.Value, Row(node, new SshCertificateEntity { Id = t.Key }).RevokedAt));
        Assert.Equal(times.Values.Max(), (await node.Service.GetKrlStateAsync(ca.Id)).LastRevokedAt);
    }
}
