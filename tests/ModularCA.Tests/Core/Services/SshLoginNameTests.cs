using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// SSH login names (<c>docs/architecture/ssh-login-names.md</c>): the grammar, the key id the CA
/// writes, who holds which name, what a held name allows a certificate, the grants, and the
/// reconciliation that revokes a certificate whose subject no longer holds one of its names.
/// </summary>
public class SshLoginNameTests
{
    private static readonly DateTime Now = new(2026, 10, 7, 12, 0, 0, DateTimeKind.Utc);

    private static List<string> Strings(string json) => JsonSerializer.Deserialize<List<string>>(json)!;

    // ---- Grammar -----------------------------------------------------------------------------

    [Theory]
    [InlineData("alice")]
    [InlineData("_svc")]
    [InlineData("9lives")]
    [InlineData("deploy.web-01_a+b@example")]
    [InlineData("A")]
    public void A_login_name_starts_with_a_letter_digit_or_underscore_and_goes_on_with_those_and_five_marks(string name)
    {
        Assert.True(SshLoginNameRules.IsValid(name));
        Assert.Null(SshLoginNameRules.Error(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".hidden")]
    [InlineData("-flag")]
    [InlineData("@host")]
    [InlineData("+plus")]
    [InlineData("ro ot")]
    [InlineData("dev;ops")]
    [InlineData("svc:deploy")]
    [InlineData("häns")]
    [InlineData("a,b")]
    [InlineData("tab\tname")]
    public void Anything_else_is_not_a_login_name(string name)
    {
        Assert.False(SshLoginNameRules.IsValid(name));
        Assert.NotNull(SshLoginNameRules.Error(name));
    }

    [Fact]
    public void A_login_name_is_at_most_128_characters_and_null_is_none()
    {
        Assert.True(SshLoginNameRules.IsValid(new string('a', 128)));
        Assert.False(SshLoginNameRules.IsValid(new string('a', 129)));
        Assert.False(SshLoginNameRules.IsValid(null));
        Assert.DoesNotContain("\t", SshLoginNameRules.Error("a\tb"));
    }

    // ---- Key ids -----------------------------------------------------------------------------

    [Fact]
    public void The_key_id_of_a_user_is_the_username_of_a_service_identity_svc_and_its_label_and_of_a_host_its_first_hostname()
    {
        Assert.Equal("alice", SshKeyIds.ForUser("alice"));
        Assert.Equal("Alice.Smith", SshKeyIds.ForUser("Alice.Smith"));
        Assert.Equal("svc:deploy-bot_1.a", SshKeyIds.ForService("deploy-bot_1.a"));
        Assert.Equal("web01.example.com", SshKeyIds.ForHost(["web01.example.com", "web01"]));
        Assert.Equal(string.Empty, SshKeyIds.ForHost([]));
        Assert.Equal("deploy", SshKeyIds.ServiceLabelOf("svc:deploy"));
        Assert.Null(SshKeyIds.ServiceLabelOf("alice"));
        Assert.Null(SshKeyIds.ServiceLabelOf("svc:"));
    }

    /// <summary>
    /// A username made under the console's rule has no colon, so it is never <c>svc:</c> and a
    /// label. One made under a looser rule (a service identity's, a directory's) could have one,
    /// and is refused, so the two forms never meet.
    /// </summary>
    [Theory]
    [InlineData("svc:deploy")]
    [InlineData("SVC:deploy")]
    [InlineData("svc:")]
    public void A_key_id_that_begins_with_svc_is_never_written_for_a_user(string username)
    {
        var ex = Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForUser(username));
        Assert.Contains("svc:", ex.Message);
    }

    [Fact]
    public void No_service_label_can_make_a_key_id_a_console_username_can_equal()
    {
        foreach (var label in new[] { "a", "deploy", "A.b-c_d", new string('x', 64) })
        {
            var keyId = SshKeyIds.ForService(label);
            Assert.Contains(':', keyId);
            Assert.DoesNotMatch("^[A-Za-z0-9._-]{1,64}$", keyId);
            Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForUser(keyId));
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("a:b")]
    [InlineData("svc:x")]
    [InlineData("naïve")]
    public void A_service_label_is_1_to_64_letters_digits_dots_underscores_and_dashes(string label)
    {
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForService(label));
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForService(new string('x', 65)));
    }

    [Fact]
    public void A_key_id_with_a_control_character_or_over_255_characters_is_refused()
    {
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForUser("ali\nce"));
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForUser(new string('u', 256)));
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForHost(["host\u0007"]));
        Assert.Throws<InvalidRequestException>(() => SshKeyIds.ForUser(null));
    }

    // ---- Holding, as a rule ------------------------------------------------------------------

    private static readonly Guid Alice = Guid.NewGuid();
    private static readonly Guid Ops = Guid.NewGuid();
    private static readonly Guid Dba = Guid.NewGuid();

    private static SshLoginNameGrantRow ToUser(string name, int? hours = null, DateTime? ends = null, Guid? user = null)
        => new(Guid.NewGuid(), name, user ?? Alice, null, null, hours, ends, null, "edward");

    private static SshLoginNameGrantRow ToGroup(string name, Guid group, int? hours = null, DateTime? ends = null)
        => new(Guid.NewGuid(), name, null, group, group == Ops ? "web-ops" : "dba", hours, ends, null, "edward");

    private static string[] Names(IEnumerable<SshLoginNameGround> grounds) => grounds.Select(g => $"{g.Name}:{g.Source}").OrderBy(n => n, StringComparer.Ordinal).ToArray();

    [Fact]
    public void A_user_holds_their_own_username_only_where_the_key_allows_it_and_only_when_it_is_a_login_name()
    {
        Assert.Equal(new[] { "alice:own" }, Names(SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid>(), [], Now)));
        Assert.Empty(SshLoginNameHolding.Grounds(Alice, "alice", false, new HashSet<Guid>(), [], Now));
        Assert.Empty(SshLoginNameHolding.Grounds(Alice, "alice smith", true, new HashSet<Guid>(), [], Now));
        Assert.Empty(SshLoginNameHolding.Grounds(Alice, "svc:alice", true, new HashSet<Guid>(), [], Now));
    }

    [Fact]
    public void A_user_holds_the_names_granted_to_them_and_to_the_groups_they_are_in_now_and_no_others()
    {
        var grants = new[]
        {
            ToUser("root"), ToUser("postgres", user: Guid.NewGuid()),
            ToGroup("deploy", Ops), ToGroup("backup", Dba),
        };

        var member = SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid> { Ops }, grants, Now);
        var left = SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid>(), grants, Now);

        Assert.Equal(new[] { "alice:own", "deploy:group", "root:user" }, Names(member));
        Assert.Equal(new[] { "alice:own", "root:user" }, Names(left));
        var deploy = member.Single(g => g.Name == "deploy");
        Assert.Equal(Ops, deploy.GroupId);
        Assert.Equal("web-ops", deploy.GroupName);
        Assert.Equal("edward", deploy.GrantedByUsername);
        Assert.NotNull(deploy.GrantId);
    }

    [Fact]
    public void A_grant_that_has_ended_gives_nothing_and_one_that_ends_later_still_does()
    {
        var grants = new[] { ToUser("root", ends: Now), ToUser("deploy", ends: Now.AddSeconds(1)), ToUser("backup", ends: Now.AddDays(-1)) };

        Assert.Equal(new[] { "deploy:user" }, Names(SshLoginNameHolding.Grounds(Alice, "alice", false, new HashSet<Guid>(), grants, Now)));
    }

    [Fact]
    public void Of_several_grounds_for_one_name_the_one_that_allows_the_latest_end_counts()
    {
        var start = Now;
        // Two hours with no end, against a day that ends in three hours: the second allows the later end.
        var short_ = ToUser("deploy", hours: 2);
        var endsSoon = ToGroup("deploy", Ops, hours: 24, ends: Now.AddHours(3));
        var held = SshLoginNameHolding.Held(
            SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid> { Ops }, [short_, endsSoon], Now), 48, start);

        var deploy = held.Single(h => h.Name == "deploy");
        Assert.Equal(SshLoginNameSources.Group, deploy.Ground.Source);
        Assert.Equal(24, deploy.MaxValidityHours);
        Assert.Equal(Now.AddHours(3), deploy.ExpiresAt);
        Assert.Equal(2, deploy.Grounds.Count);

        // One hour to its end, against two hours with no end: now the first is the later.
        var endsSooner = ToGroup("deploy", Ops, hours: 24, ends: Now.AddHours(1));
        var again = SshLoginNameHolding.Held(
            SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid> { Ops }, [short_, endsSooner], Now), 48, start).Single(h => h.Name == "deploy");
        Assert.Equal(SshLoginNameSources.User, again.Ground.Source);
        Assert.Equal(2, again.MaxValidityHours);
        Assert.Null(again.ExpiresAt);

        // The same end either way: one's own username before a grant, a grant to the user before one to a group.
        var own = SshLoginNameHolding.Held(
            SshLoginNameHolding.Grounds(Alice, "alice", true, new HashSet<Guid> { Ops }, [ToUser("alice"), ToGroup("alice", Ops)], Now), 48, start).Single();
        Assert.Equal(SshLoginNameSources.Own, own.Ground.Source);
        Assert.Equal(3, own.Grounds.Count);
    }

    [Fact]
    public void A_grant_s_limit_is_never_over_the_key_s_maximum_and_none_means_that_maximum()
    {
        Assert.Equal(24, SshLoginNameHolding.HoursOf(new SshLoginNameGround { Name = "a", MaxValidityHours = 100 }, 24));
        Assert.Equal(8, SshLoginNameHolding.HoursOf(new SshLoginNameGround { Name = "a", MaxValidityHours = 8 }, 24));
        Assert.Equal(24, SshLoginNameHolding.HoursOf(new SshLoginNameGround { Name = "a" }, 24));
    }

    // ---- What held names allow ---------------------------------------------------------------

    private static SshLoginNameIssuance Names(params (string Name, int Hours, DateTime? Ends)[] names)
        => SshLoginNameHolding.Issuance(
            names.Select(n => new SshHeldLoginName(n.Name, new SshLoginNameGround { Name = n.Name, Source = SshLoginNameSources.User, ExpiresAt = n.Ends },
                n.Hours, n.Ends, [])).ToList(),
            names.Select(n => n.Name).ToList());

    [Fact]
    public void Issuance_refuses_a_name_that_is_not_held_and_names_it()
    {
        var held = new List<SshHeldLoginName> { new("alice", new SshLoginNameGround { Name = "alice", Source = SshLoginNameSources.Own }, 24, null, []) };

        var ex = Assert.Throws<InvalidRequestException>(() => SshLoginNameHolding.Issuance(held, ["alice", "root"]));

        Assert.Equal(400, ex.Status);
        Assert.Contains("'root'", ex.Message);
        Assert.DoesNotContain("'alice'", ex.Message);
        Assert.Throws<InvalidRequestException>(() => SshLoginNameHolding.Issuance(held, ["Alice"]));
        Assert.Single(SshLoginNameHolding.Issuance(held, ["alice"]).Grounds);
    }

    [Fact]
    public void With_no_validity_asked_a_certificate_lasts_as_long_as_the_smallest_limit_allows()
    {
        Assert.Equal(Now.AddHours(8), SshLoginNameHolding.ValidBefore(Now, null, 24, Names(("alice", 720, null), ("root", 8, null))));
        Assert.Equal(Now.AddHours(24), SshLoginNameHolding.ValidBefore(Now, null, 24, Names(("alice", 720, null))));
        Assert.Equal(Now.AddHours(24), SshLoginNameHolding.ValidBefore(Now, null, 24, null));
    }

    [Fact]
    public void A_validity_asked_over_a_login_name_s_limit_is_refused_naming_the_name_and_the_limit()
    {
        var names = Names(("alice", 720, null), ("root", 8, null), ("deploy", 24, null));

        Assert.Equal(Now.AddHours(8), SshLoginNameHolding.ValidBefore(Now, 8, 24, names));
        Assert.Equal(Now.AddHours(1), SshLoginNameHolding.ValidBefore(Now, 1, 24, names));
        var ex = Assert.Throws<InvalidRequestException>(() => SshLoginNameHolding.ValidBefore(Now, 9, 24, names));
        Assert.Equal(400, ex.Status);
        Assert.Contains("'root'", ex.Message);
        Assert.Contains("at most 8 hours", ex.Message);
    }

    [Fact]
    public void A_certificate_never_ends_after_the_earliest_end_among_its_grounds()
    {
        var ends = Now.AddHours(3).AddMinutes(20).AddMilliseconds(250);
        var names = Names(("alice", 720, null), ("root", 8, ends), ("deploy", 24, Now.AddDays(7)));

        // None asked: to the second the grant ends, not to the hour.
        Assert.Equal(Now.AddHours(3).AddMinutes(20), SshLoginNameHolding.ValidBefore(Now, null, 24, names));
        // Asked and within it: as asked.
        Assert.Equal(Now.AddHours(3), SshLoginNameHolding.ValidBefore(Now, 3, 24, names));
        // Asked and past it: refused, naming the name and how long it can be.
        var ex = Assert.Throws<InvalidRequestException>(() => SshLoginNameHolding.ValidBefore(Now, 4, 24, names));
        Assert.Contains("'root'", ex.Message);
        Assert.Contains("at most 3 hours", ex.Message);
    }

    [Fact]
    public void A_validity_asked_over_the_key_s_or_the_profiles_limit_is_cut_to_it_as_before()
    {
        Assert.Equal(Now.AddHours(6), SshLoginNameHolding.ValidBefore(Now, 100, 6, null));
        Assert.Equal(Now.AddHours(6), SshLoginNameHolding.ValidBefore(Now, 100, 6, Names(("alice", 6, null))));
    }

    [Fact]
    public void A_name_is_held_through_a_moment_when_a_ground_has_no_end_or_ends_at_or_after_it()
    {
        var through = Now.AddHours(4);
        SshLoginNameGround Ground(DateTime? ends) => new() { Name = "root", Source = SshLoginNameSources.User, ExpiresAt = ends };

        Assert.True(SshLoginNameHolding.HeldThrough([Ground(null)], through));
        Assert.True(SshLoginNameHolding.HeldThrough([Ground(through)], through));
        Assert.True(SshLoginNameHolding.HeldThrough([Ground(Now.AddHours(1)), Ground(Now.AddHours(5))], through));
        Assert.False(SshLoginNameHolding.HeldThrough([Ground(through.AddSeconds(-1))], through));
        Assert.False(SshLoginNameHolding.HeldThrough([], through));
    }

    [Fact]
    public void Grounds_are_stored_and_read_back_under_fixed_names()
    {
        var grant = Guid.NewGuid();
        var stored = SshLoginNameHolding.Serialize(
        [
            new SshLoginNameGround { Name = "alice", Source = SshLoginNameSources.Own },
            new SshLoginNameGround { Name = "deploy", Source = SshLoginNameSources.Group, GrantId = grant, GroupId = Ops, GroupName = "web-ops", GrantedByUsername = "edward", MaxValidityHours = 24, ExpiresAt = Now },
        ]);

        Assert.Equal("[{\"name\":\"alice\",\"source\":\"own\"},{\"name\":\"deploy\",\"source\":\"group\",\"grantId\":\"" + grant + "\",\"groupId\":\"" + Ops
            + "\",\"groupName\":\"web-ops\",\"grantedByUsername\":\"edward\",\"maxValidityHours\":24,\"expiresAt\":\"2026-10-07T12:00:00Z\"}]", stored);
        var read = SshLoginNameHolding.Parse(stored)!;
        Assert.Equal(grant, read[1].GrantId);
        Assert.Equal(Now, read[1].ExpiresAt);
        Assert.Null(SshLoginNameHolding.Parse(null));
        Assert.Null(SshLoginNameHolding.Parse("not json"));
    }

    // ---- Issuance through the service --------------------------------------------------------

    private static Task<SshCertificateEntity> SignFor(SshNode node, SshCaKeyEntity ca, UserEntity user, int? hours, params string[] principals)
        => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(user.Id), principals.ToList(), hours, null, node.Actor);

    private static SshLoginNameGrantRequest Grant(UserEntity user, int? hours, DateTime? ends, params string[] names) => new(names, user.Id, null, hours, ends, null);

    private static SshLoginNameGrantRequest Grant(CaGroupEntity group, int? hours, DateTime? ends, params string[] names) => new(names, null, group.Id, hours, ends, null);

    private static bool Revoked(SshNode node, SshCertificateEntity certificate)
    {
        using var db = node.Reopen();
        return db.SshCertificates.Single(c => c.Id == certificate.Id).IsRevoked;
    }

    [Fact]
    public async Task A_certificate_for_a_user_carries_the_username_as_its_key_id_and_records_who_it_is_for_and_why()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var ops = node.AddGroup("web-ops");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, ops.Id);
        var root = (await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 8, null, "root"), node.Actor)).Single();
        var deploy = (await node.LoginNames.GrantAsync(ca.Id, Grant(ops, null, null, "deploy"), node.Actor)).Single();

        var row = await SignFor(node, ca, alice, 2, "alice", "deploy", "root");

        var certificate = SshCertificate.ParseOpenSsh(row.SignedCertificate);
        Assert.True(certificate.VerifySignature());
        Assert.Equal("alice", certificate.Fields.KeyId);
        Assert.Equal(new[] { "alice", "deploy", "root" }, certificate.Fields.Principals);
        Assert.Equal(alice.Id, row.SubjectUserId);
        Assert.Equal(node.Actor.UserId, row.IssuedByUserId);

        var grounds = SshLoginNameHolding.Parse(row.LoginNameGrounds)!;
        Assert.Equal(new[] { "own", "group", "user" }, grounds.Select(g => g.Source).ToArray());
        Assert.Equal(deploy.Id, grounds[1].GrantId);
        Assert.Equal(ops.Id, grounds[1].GroupId);
        Assert.Equal("web-ops", grounds[1].GroupName);
        Assert.Equal(root.Id, grounds[2].GrantId);
        Assert.Equal("ssh-operator", grounds[2].GrantedByUsername);
        Assert.Equal(8, grounds[2].MaxValidityHours);

        var audit = node.Audit.Of(AuditActionType.SshCertIssued).Single();
        var details = JsonSerializer.Serialize(audit.Details);
        Assert.Contains(alice.Id.ToString(), details);
        Assert.Contains("\"SubjectUsername\":\"alice\"", details);

        // The grants say how many live certificates name them.
        var list = (await node.LoginNames.ListAsync(ca.Id))!;
        Assert.All(list.Grants, g => Assert.Equal(1, g.LiveCertificates));
        Assert.Equal(1, list.Grants.Single(g => g.LoginName == "deploy").Group!.MemberCount);
    }

    [Fact]
    public async Task A_name_the_subject_does_not_hold_is_refused_by_name_and_the_failure_entry_names_no_principal()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        node.AddUser("bob", node.GroupOf(ca, "user").Id);

        var root = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 1, "alice", "root"));
        var colleague = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 1, "bob"));

        Assert.Equal(400, root.Status);
        Assert.Contains("'root'", root.Message);
        Assert.Contains("'bob'", colleague.Message);
        Assert.Empty(node.Relay.SshSigned);
        using var db = node.Reopen();
        Assert.Empty(db.SshCertificates);
        var failures = node.Audit.Of(AuditActionType.SshCertIssued);
        Assert.Equal(2, failures.Count);
        Assert.All(failures, f =>
        {
            Assert.False(f.Success);
            Assert.DoesNotContain("root", f.Error);
            Assert.DoesNotContain("bob", f.Error);
            var details = JsonSerializer.Serialize(f.Details);
            Assert.DoesNotContain("root", details);
            Assert.DoesNotContain("bob", details);
            Assert.Contains("\"SubjectUsername\":\"alice\"", details);
            Assert.Contains("PrincipalCount", details);
        });
    }

    [Fact]
    public async Task One_s_own_username_is_held_only_while_the_key_allows_it()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);

        Assert.Equal("alice", (await SignFor(node, ca, alice, 1, "alice")).KeyId);
        await node.LoginNames.SetOwnUsernameAsync(ca.Id, false, node.Actor);

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 1, "alice"));
        Assert.Contains("'alice'", ex.Message);
        Assert.Empty(await node.LoginNames.HeldAsync(alice.Id, ca.Id));
    }

    [Fact]
    public async Task A_subject_that_is_unknown_inactive_or_out_of_the_ssh_ca_s_scope_gets_no_certificate()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var inactive = node.AddUser("idle", node.GroupOf(ca, "user").Id);
        inactive.IsActive = false;
        node.Db.SaveChanges();
        var stranger = node.AddUser("stranger");

        var unknown = await Assert.ThrowsAsync<InvalidRequestException>(() => node.Service.SignUserKeyAsync(
            ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(Guid.NewGuid()), ["ghost"], 1, null, node.Actor));
        var idle = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, inactive, 1, "idle"));
        var outside = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, stranger, 1, "stranger"));

        Assert.Equal(unknown.Message, idle.Message);
        Assert.Equal(unknown.Message, outside.Message);
        Assert.Empty(node.Relay.SshSigned);
        Assert.False(await node.LoginNames.MayReferenceUserAsync(ca.Id, stranger.Id));
        Assert.True(await node.LoginNames.MayReferenceUserAsync(ca.Id, inactive.Id));
    }

    [Fact]
    public async Task A_user_whose_username_begins_with_svc_gets_no_certificate()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var odd = node.AddUser("svc:deploy", node.GroupOf(ca, "user").Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(odd, null, null, "deploy"), node.Actor);

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, odd, 1, "deploy"));

        Assert.Contains("svc:", ex.Message);
        Assert.Empty(node.Relay.SshSigned);
        Assert.Equal("svc:deploy", (await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForService("deploy"), ["deploy"], 1, null, node.Actor)).KeyId);
    }

    [Fact]
    public async Task The_validity_of_a_user_s_certificate_is_held_to_its_login_names()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 48);
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 2, null, "root"), node.Actor);
        var ends = DateTime.UtcNow.AddMinutes(90);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, ends, "deploy"), node.Actor);

        // Over the limit of a name: refused, naming it.
        var over = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 3, "alice", "root"));
        Assert.Contains("'root'", over.Message);
        Assert.Contains("at most 2 hours", over.Message);

        // None asked: the most allowed, which is the name's two hours and not the key's 48.
        var most = SshCertificate.ParseOpenSsh((await SignFor(node, ca, alice, null, "alice", "root")).SignedCertificate);
        Assert.Equal(2UL * 3600, most.Fields.ValidBefore - most.Fields.ValidAfter);
        var own = SshCertificate.ParseOpenSsh((await SignFor(node, ca, alice, null, "alice")).SignedCertificate);
        Assert.Equal(48UL * 3600, own.Fields.ValidBefore - own.Fields.ValidAfter);

        // Past the end of a grant: refused when asked, and cut to the second when not.
        var past = await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 2, "deploy"));
        Assert.Contains("'deploy'", past.Message);
        Assert.Contains("at most 1 hours", past.Message);
        var cut = await SignFor(node, ca, alice, null, "deploy");
        Assert.Equal(new DateTime(ends.Ticks - ends.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc), cut.ValidBefore);
        var hour = SshCertificate.ParseOpenSsh((await SignFor(node, ca, alice, 1, "deploy")).SignedCertificate);
        Assert.Equal(1UL * 3600, hour.Fields.ValidBefore - hour.Fields.ValidAfter);

        // A profile's limit still binds, below the name's.
        var profiled = SshCertificate.ParseOpenSsh((await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(),
            SshCertificateSubject.ForUser(alice.Id), ["alice"], null, null, node.Actor, profileMaxValidityHours: 5)).SignedCertificate);
        Assert.Equal(5UL * 3600, profiled.Fields.ValidBefore - profiled.Fields.ValidAfter);
    }

    // ---- Grants ------------------------------------------------------------------------------

    [Fact]
    public async Task Granting_makes_one_grant_per_name_and_audits_each()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 48);
        var ops = node.AddGroup("web-ops");
        node.AddUser("alice", ops.Id);
        var ends = DateTime.UtcNow.AddDays(7);

        var made = await node.LoginNames.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["deploy", "deployers"], null, ops.Id, 24, ends, " for the web tier "), node.Actor);

        Assert.Equal(new[] { "deploy", "deployers" }, made.Select(g => g.LoginName).ToArray());
        Assert.All(made, g =>
        {
            Assert.Equal(ops.Id, g.Group!.Id);
            Assert.Equal("web-ops", g.Group.Name);
            Assert.Equal(1, g.Group.MemberCount);
            Assert.Null(g.User);
            Assert.Equal(24, g.MaxValidityHours);
            Assert.Equal(ends, g.ExpiresAt);
            Assert.False(g.Ended);
            Assert.Equal("for the web tier", g.Note);
            Assert.Equal("ssh-operator", g.GrantedBy.Username);
            Assert.Equal(node.Actor.UserId, g.GrantedBy.Id);
            Assert.Equal(0, g.LiveCertificates);
            Assert.Equal(ca.Id, g.SshCaKey.Id);
        });
        var audits = node.Audit.Of(AuditActionType.SshLoginNameGranted);
        Assert.Equal(2, audits.Count);
        Assert.All(audits, a =>
        {
            Assert.Equal(node.Actor.UserId, a.ActorId);
            Assert.Equal(ca.CertificateAuthorityId, a.CaId);
            var details = JsonSerializer.Serialize(a.Details);
            Assert.Contains(ca.Id.ToString(), details);
            Assert.Contains("web-ops", details);
        });
        Assert.Contains("\"LoginName\":\"deploy\"", JsonSerializer.Serialize(audits[0].Details));

        var list = (await node.LoginNames.ListAsync(ca.Id))!;
        Assert.True(list.AllowOwnUsername);
        Assert.Equal(48, list.MaxValidityHours);
        Assert.Equal(2, list.Grants.Count);
        Assert.Null(await node.LoginNames.ListAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task A_name_the_target_already_has_is_a_conflict_that_names_it_and_writes_nothing()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var other = await node.CreateCaAsync("Lab SSH");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, node.GroupOf(other, "user").Id);
        var ops = node.AddGroup("web-ops");
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "root"), node.Actor);

        var ex = await Assert.ThrowsAsync<ResourceConflictException>(
            () => node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "deploy", "root", "backup"), node.Actor));

        Assert.Equal(409, ex.Status);
        Assert.Contains("'root'", ex.Message);
        Assert.DoesNotContain("'deploy'", ex.Message);
        using (var db = node.Reopen())
            Assert.Equal(1, db.SshLoginNameGrants.Count());

        // The same name to a group, or on another key, is another grant.
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, null, null, "root"), node.Actor);
        await node.LoginNames.GrantAsync(other.Id, Grant(alice, null, null, "root"), node.Actor);
        using (var db = node.Reopen())
            Assert.Equal(3, db.SshLoginNameGrants.Count());
    }

    [Fact]
    public async Task A_grant_is_refused_for_a_bad_name_target_limit_end_or_note()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 24);
        var hostOnly = await node.Service.GenerateKeyPairAsync("Hosts Only", "ed25519", isUserCa: false, isHostCa: true, 24);
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var stranger = node.AddUser("stranger");
        var ops = node.AddGroup("web-ops");
        var spaceGroup = new CaGroupEntity { Id = Guid.NewGuid(), Name = "space-ops", DisplayName = "Space ops", SpaceId = Guid.NewGuid() };
        node.Db.CaGroups.Add(spaceGroup);
        node.Db.SaveChanges();

        async Task<string> Refused(SshLoginNameGrantRequest request, Guid? key = null)
            => (await Assert.ThrowsAsync<InvalidRequestException>(() => node.LoginNames.GrantAsync(key ?? ca.Id, request, node.Actor))).Message;

        Assert.Contains("'ro ot'", await Refused(Grant(alice, null, null, "deploy", "ro ot")));
        Assert.Contains("at least one", await Refused(Grant(alice, null, null)));
        Assert.Contains("twice", await Refused(Grant(alice, null, null, "deploy", "deploy")));
        Assert.Contains("exactly one", await Refused(new SshLoginNameGrantRequest(["deploy"], null, null, null, null, null)));
        Assert.Contains("exactly one", await Refused(new SshLoginNameGrantRequest(["deploy"], alice.Id, ops.Id, null, null, null)));
        Assert.Contains("between 1 and 24", await Refused(Grant(alice, 25, null, "deploy")));
        Assert.Contains("between 1 and 24", await Refused(Grant(alice, 0, null, "deploy")));
        Assert.Contains("in the past", await Refused(Grant(alice, null, DateTime.UtcNow.AddMinutes(-1), "deploy")));
        Assert.Contains("256", await Refused(new SshLoginNameGrantRequest(["deploy"], alice.Id, null, null, null, new string('n', 257))));
        Assert.Contains("scope", await Refused(Grant(stranger, null, null, "deploy")));
        Assert.Equal(await Refused(Grant(stranger, null, null, "deploy")),
            await Refused(new SshLoginNameGrantRequest(["deploy"], Guid.NewGuid(), null, null, null, null)));
        Assert.Contains("another scope", await Refused(Grant(spaceGroup, null, null, "deploy")));
        Assert.Contains("another scope", await Refused(new SshLoginNameGrantRequest(["deploy"], null, Guid.NewGuid(), null, null, null)));
        Assert.Contains("no user certificates", await Refused(Grant(alice, null, null, "deploy"), hostOnly.Id));
        await Assert.ThrowsAsync<ResourceNotFoundException>(() => node.LoginNames.GrantAsync(Guid.NewGuid(), Grant(alice, null, null, "deploy"), node.Actor));

        using var db = node.Reopen();
        Assert.Empty(db.SshLoginNameGrants);
        Assert.Empty(node.Audit.Of(AuditActionType.SshLoginNameGranted));
    }

    // ---- Reconciliation ----------------------------------------------------------------------

    [Fact]
    public async Task Removing_a_grant_revokes_the_certificates_that_carried_its_name_and_no_others()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var root = (await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "root"), node.Actor)).Single();
        await node.LoginNames.GrantAsync(ca.Id, Grant(bob, null, null, "root"), node.Actor);
        var withRoot = await SignFor(node, ca, alice, 1, "alice", "root");
        var ownOnly = await SignFor(node, ca, alice, 1, "alice");
        var bobs = await SignFor(node, ca, bob, 1, "root");
        var typed = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["root"], 1, null, node.Actor);
        var host = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["root"], 1, node.Actor);

        var revoked = await node.LoginNames.RemoveGrantAsync(ca.Id, root.Id, node.Actor);

        Assert.Equal(1, revoked);
        Assert.True(Revoked(node, withRoot));
        Assert.False(Revoked(node, ownOnly));
        Assert.False(Revoked(node, bobs));
        Assert.False(Revoked(node, typed));
        Assert.False(Revoked(node, host));
        using (var db = node.Reopen())
            Assert.Equal(1, db.SshLoginNameGrants.Count());

        var why = node.Audit.Of(AuditActionType.SshCertRevoked).Single();
        Assert.Equal(withRoot.Id.ToString(), why.TargetId);
        Assert.Equal(node.Actor.UserId, why.ActorId);
        var details = JsonSerializer.Serialize(why.Details);
        Assert.Contains("was removed", details);
        Assert.Contains("\"LoginName\":\"root\"", details);
        Assert.Single(node.Audit.Of(AuditActionType.SshLoginNameGrantRemoved));
        Assert.Null(await node.LoginNames.RemoveGrantAsync(ca.Id, root.Id, node.Actor));
    }

    [Fact]
    public async Task A_name_still_held_on_another_ground_keeps_its_certificate()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var ops = node.AddGroup("web-ops");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, ops.Id);
        var direct = (await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "deploy"), node.Actor)).Single();
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, null, null, "deploy"), node.Actor);
        var certificate = await SignFor(node, ca, alice, 1, "deploy");

        Assert.Equal(0, await node.LoginNames.RemoveGrantAsync(ca.Id, direct.Id, node.Actor));

        Assert.False(Revoked(node, certificate));
    }

    [Fact]
    public async Task Moving_a_grant_s_end_before_a_certificate_s_end_revokes_it_and_lowering_its_limit_revokes_nothing()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 48);
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var grant = (await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 24, null, "root"), node.Actor)).Single();
        var twoHours = await SignFor(node, ca, alice, 2, "root");
        var day = await SignFor(node, ca, alice, 24, "root");

        // A lower limit, a note, an end after both: nothing is revoked.
        var lowered = (await node.LoginNames.ChangeGrantAsync(ca.Id, grant.Id, new SshLoginNameGrantChange(1, DateTime.UtcNow.AddDays(3), "tightened"), node.Actor))!;
        Assert.Equal(0, lowered.RevokedCertificates);
        Assert.Equal(1, lowered.Grant.MaxValidityHours);
        Assert.Equal("tightened", lowered.Grant.Note);
        Assert.Equal(2, lowered.Grant.LiveCertificates);
        Assert.False(Revoked(node, twoHours) || Revoked(node, day));

        // An end between the two: the longer certificate outlives the grant and goes.
        var earlier = (await node.LoginNames.ChangeGrantAsync(ca.Id, grant.Id, new SshLoginNameGrantChange(1, DateTime.UtcNow.AddHours(6), null), node.Actor))!;
        Assert.Equal(1, earlier.RevokedCertificates);
        Assert.Null(earlier.Grant.Note);
        Assert.False(Revoked(node, twoHours));
        Assert.True(Revoked(node, day));
        Assert.Contains("ends earlier", JsonSerializer.Serialize(node.Audit.Of(AuditActionType.SshCertRevoked).Single().Details));
        Assert.Equal(2, node.Audit.Of(AuditActionType.SshLoginNameGrantChanged).Count);

        // No end at all again, and the limit cleared: null clears, and nothing more is revoked.
        var cleared = (await node.LoginNames.ChangeGrantAsync(ca.Id, grant.Id, new SshLoginNameGrantChange(null, null, null), node.Actor))!;
        Assert.Null(cleared.Grant.MaxValidityHours);
        Assert.Null(cleared.Grant.ExpiresAt);
        Assert.Equal(0, cleared.RevokedCertificates);

        await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.LoginNames.ChangeGrantAsync(ca.Id, grant.Id, new SshLoginNameGrantChange(null, DateTime.UtcNow.AddMinutes(-5), null), node.Actor));
        await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.LoginNames.ChangeGrantAsync(ca.Id, grant.Id, new SshLoginNameGrantChange(49, null, null), node.Actor));
        Assert.Null(await node.LoginNames.ChangeGrantAsync(ca.Id, Guid.NewGuid(), new SshLoginNameGrantChange(null, null, null), node.Actor));
    }

    [Fact]
    public async Task Turning_own_usernames_off_revokes_the_certificates_that_carried_one()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var other = await node.CreateCaAsync("Lab SSH");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, node.GroupOf(other, "user").Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "root"), node.Actor);
        var own = await SignFor(node, ca, alice, 1, "alice", "root");
        var granted = await SignFor(node, ca, alice, 1, "root");
        var elsewhere = await SignFor(node, other, alice, 1, "alice");

        Assert.Equal(0, await node.LoginNames.SetOwnUsernameAsync(ca.Id, true, node.Actor));
        Assert.Equal(1, await node.LoginNames.SetOwnUsernameAsync(ca.Id, false, node.Actor));

        Assert.True(Revoked(node, own));
        Assert.False(Revoked(node, granted));
        Assert.False(Revoked(node, elsewhere));
        using (var db = node.Reopen())
            Assert.False(db.SshCaKeys.Single(k => k.Id == ca.Id).AllowOwnUsername);
        var changes = node.Audit.Of(AuditActionType.SshOwnUsernameChanged);
        Assert.Equal(2, changes.Count);
        Assert.Contains("\"RevokedCertificates\":1", JsonSerializer.Serialize(changes[1].Details));
        Assert.Null(await node.LoginNames.SetOwnUsernameAsync(Guid.NewGuid(), false, node.Actor));

        // A granted own name is a grant: turning the switch off does not touch it.
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "alice"), node.Actor);
        Assert.Equal("user", SshLoginNameHolding.Parse((await SignFor(node, ca, alice, 1, "alice")).LoginNameGrounds)!.Single().Source);
    }

    private static UserManagementService Users(SshNode node)
        => new(node.Db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!, null!, node.LoginNames);

    [Fact]
    public async Task Leaving_a_group_revokes_the_certificates_that_carried_a_name_held_through_it()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var ops = node.AddGroup("web-ops");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, ops.Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id, ops.Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, null, null, "deploy"), node.Actor);
        var alices = await SignFor(node, ca, alice, 1, "alice", "deploy");
        var aliceOwn = await SignFor(node, ca, alice, 1, "alice");
        var bobs = await SignFor(node, ca, bob, 1, "deploy");

        Assert.True(await Users(node).RemoveUserFromGroup(alice.Id, ops.Id));

        Assert.True(Revoked(node, alices));
        Assert.False(Revoked(node, aliceOwn));
        Assert.False(Revoked(node, bobs));
        var why = JsonSerializer.Serialize(node.Audit.Of(AuditActionType.SshCertRevoked).Single().Details);
        Assert.Contains("left a group", why);
        Assert.Contains("\"LoginName\":\"deploy\"", why);
        await Assert.ThrowsAsync<InvalidRequestException>(() => SignFor(node, ca, alice, 1, "deploy"));
    }

    [Fact]
    public async Task Deleting_a_group_removes_its_grants_and_revokes_its_members_certificates_that_carried_them()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var ops = node.AddGroup("web-ops");
        var dba = node.AddGroup("dba");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, ops.Id, dba.Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, null, null, "deploy", "deployers"), node.Actor);
        await node.LoginNames.GrantAsync(ca.Id, Grant(dba, null, null, "backup"), node.Actor);
        var deploy = await SignFor(node, ca, alice, 1, "deploy");
        var backup = await SignFor(node, ca, alice, 1, "backup");

        Assert.Equal(1, await node.LoginNames.GroupDeletingAsync(ops.Id, node.Actor));

        Assert.True(Revoked(node, deploy));
        Assert.False(Revoked(node, backup));
        using var db = node.Reopen();
        Assert.Equal("backup", db.SshLoginNameGrants.Single().LoginName);
        Assert.Equal(2, node.Audit.Of(AuditActionType.SshLoginNameGrantRemoved).Count);
        Assert.Contains("group was deleted", JsonSerializer.Serialize(node.Audit.Of(AuditActionType.SshLoginNameGrantRemoved)[0].Details));
    }

    /// <summary>A certificate as an install from before login names holds one: a subject where the upgrade found it, and no grounds.</summary>
    private static SshCertificateEntity SeedOlder(SshNode node, SshCaKeyEntity ca, Guid? subject, params string[] principals)
    {
        var row = new SshCertificateEntity
        {
            Id = Guid.NewGuid(), SshCaKeyId = ca.Id, CertificateType = "user", KeyId = "whatever-was-typed", SerialNumber = Random.Shared.NextInt64(1, int.MaxValue),
            Principals = JsonSerializer.Serialize(principals), ValidAfter = DateTime.UtcNow.AddHours(-1), ValidBefore = DateTime.UtcNow.AddHours(5),
            SubjectUserId = subject, IssuedByUserId = subject,
        };
        node.Db.SshCertificates.Add(row);
        node.Db.SaveChanges();
        return row;
    }

    [Fact]
    public async Task Disabling_a_user_revokes_every_live_certificate_issued_for_them_older_ones_included()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var current = await SignFor(node, ca, alice, 1, "alice");
        var older = SeedOlder(node, ca, alice.Id, "root");
        var bobs = await SignFor(node, ca, bob, 1, "bob");
        var expired = SeedOlder(node, ca, alice.Id, "alice");
        expired.ValidBefore = DateTime.UtcNow.AddMinutes(-1);
        node.Db.SaveChanges();

        Assert.True(await Users(node).UpdateUser(alice.Id, new UpdateUserRequest { IsActive = false }));

        Assert.True(Revoked(node, current));
        Assert.True(Revoked(node, older));
        Assert.False(Revoked(node, bobs));
        Assert.False(Revoked(node, expired));
        var audits = node.Audit.Of(AuditActionType.SshCertRevoked);
        Assert.Equal(2, audits.Count);
        Assert.All(audits, a => Assert.Contains("was disabled", JsonSerializer.Serialize(a.Details)));

        // Enabling again brings nothing back, and locking is not disabling.
        Assert.True(await Users(node).UpdateUser(alice.Id, new UpdateUserRequest { IsActive = true }));
        Assert.True(Revoked(node, current));
        Assert.True(await Users(node).UpdateUser(bob.Id, new UpdateUserRequest { IsLocked = true }));
        Assert.False(Revoked(node, bobs));
    }

    [Fact]
    public async Task Deleting_a_user_revokes_their_certificates_and_removes_their_grants()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "root"), node.Actor);
        await node.LoginNames.GrantAsync(ca.Id, Grant(bob, null, null, "root"), node.Actor);
        var current = await SignFor(node, ca, alice, 1, "alice", "root");
        var older = SeedOlder(node, ca, alice.Id, "deploy");

        Assert.True(await Users(node).DeleteUser(alice.Id));

        Assert.True(Revoked(node, current));
        Assert.True(Revoked(node, older));
        using var db = node.Reopen();
        Assert.Equal(bob.Id, db.SshLoginNameGrants.Single().UserId);
        Assert.False(db.Users.Any(u => u.Id == alice.Id));
        Assert.All(node.Audit.Of(AuditActionType.SshCertRevoked), a => Assert.Contains("was deleted", JsonSerializer.Serialize(a.Details)));
        Assert.Single(node.Audit.Of(AuditActionType.SshLoginNameGrantRemoved));
    }

    [Fact]
    public async Task Renaming_a_user_revokes_every_live_certificate_issued_for_them_since_their_key_id_is_the_old_username()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, null, null, "root"), node.Actor);
        var own = await SignFor(node, ca, alice, 1, "alice");
        var granted = await SignFor(node, ca, alice, 1, "root");
        var bobs = await SignFor(node, ca, bob, 1, "bob");

        Assert.True(await Users(node).UpdateUser(alice.Id, new UpdateUserRequest { Username = "alice2" }));

        Assert.True(Revoked(node, own));
        Assert.True(Revoked(node, granted));
        Assert.False(Revoked(node, bobs));
        Assert.All(node.Audit.Of(AuditActionType.SshCertRevoked), a => Assert.Contains("was renamed", JsonSerializer.Serialize(a.Details)));
        Assert.Equal("alice2", (await SignFor(node, ca, alice, 1, "alice2", "root")).KeyId);
    }

    [Fact]
    public async Task Reconciliation_leaves_older_certificates_service_identities_and_host_certificates_alone()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var older = SeedOlder(node, ca, alice.Id, "root", "anything");
        var typed = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["root"], 1, null, node.Actor);
        var host = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["web01"], 1, node.Actor);
        var held = await SignFor(node, ca, alice, 1, "alice");

        Assert.Equal(0, await node.LoginNames.ReconcileKeyAsync(ca.Id, "a check", node.Actor));
        Assert.Equal(0, await node.LoginNames.ReconcileUsersAsync([alice.Id], "a check", node.Actor));
        Assert.Equal(0, await node.LoginNames.ReconcileUsersAsync([], "a check", node.Actor));

        Assert.False(Revoked(node, older) || Revoked(node, typed) || Revoked(node, host) || Revoked(node, held));
        Assert.Empty(node.Audit.Of(AuditActionType.SshCertRevoked));
    }

    [Fact]
    public async Task A_service_identity_that_is_a_user_is_reconciled_as_one_when_it_is_disabled_leaves_a_group_or_is_deleted()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var admins = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-super", DisplayName = "System super", IsSystemGroup = true, IsSystemTierSuper = true };
        node.Db.CaGroups.Add(admins);
        foreach (var capability in ModularCA.Shared.Authorization.Capabilities.AdministratorTemplate)
            node.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = admins.Id, Capability = capability });
        var admin = node.AddUser("root-admin", admins.Id);
        UserEntity Identity(string name)
        {
            var identity = node.AddUser(name, node.GroupOf(ca, "user").Id);
            identity.IsServiceIdentity = true;
            node.Db.SaveChanges();
            return identity;
        }
        var disabled = Identity("deploy-bot");
        var deleted = Identity("backup-bot");
        await node.LoginNames.GrantAsync(ca.Id, Grant(deleted, null, null, "backup"), node.Actor);
        var first = await SignFor(node, ca, disabled, 1, "deploy-bot");
        var second = await SignFor(node, ca, deleted, 1, "backup");
        var identities = new ServiceIdentityService(node.Db, new CaGroupAuthorizationService(node.Db, NullLogger<CaGroupAuthorizationService>.Instance), null, node.LoginNames);

        await identities.UpdateAsync(admin.Id, disabled.Id, null, null, isActive: false);
        await identities.DeleteAsync(admin.Id, deleted.Id);

        Assert.True(Revoked(node, first));
        Assert.True(Revoked(node, second));
        using var db = node.Reopen();
        Assert.Empty(db.SshLoginNameGrants);
    }

    // ---- What the routes read ----------------------------------------------------------------

    [Fact]
    public async Task A_user_s_login_names_are_listed_per_key_with_every_ground_and_which_one_counts()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 720);
        var lab = await node.CreateCaAsync("Lab SSH", maxValidityHours: 168);
        var hostOnly = await node.Service.GenerateKeyPairAsync("Hosts Only", "ed25519", isUserCa: false, isHostCa: true, 24);
        var ops = node.AddGroup("web-ops");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, node.GroupOf(lab, "user").Id, ops.Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, 24, null, "deploy"), node.Actor);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 8, null, "deploy"), node.Actor);
        var ends = DateTime.UtcNow.AddDays(7);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 8, ends, "root"), node.Actor);

        var names = await node.LoginNames.NamesOfUserAsync(alice.Id, [ca.Id, lab.Id, hostOnly.Id]);

        Assert.Equal(new[]
        {
            "Fleet SSH alice own 720 True True", "Fleet SSH deploy group 24 False True", "Fleet SSH deploy user 8 False False",
            "Fleet SSH root user 8 False True", "Lab SSH alice own 168 True True",
        }, names.Select(n => $"{n.SshCaKey.Name} {n.LoginName} {n.Source} {n.MaxValidityHours} {n.LimitIsKeyMaximum} {n.Effective}").ToArray());
        Assert.Equal(ends, names.Single(n => n.LoginName == "root").ExpiresAt);
        Assert.Equal("web-ops", names.Single(n => n.Source == "group").GroupName);
        Assert.Equal(new[] { "Lab SSH" }, (await node.LoginNames.NamesOfUserAsync(alice.Id, [lab.Id])).Select(n => n.SshCaKey.Name).ToArray());
        Assert.Empty(await node.LoginNames.NamesOfUserAsync(alice.Id, []));

        var ofGroup = await node.LoginNames.GrantsOfGroupAsync(ops.Id, [ca.Id, lab.Id]);
        Assert.Equal("deploy", ofGroup.Single().LoginName);
        Assert.Empty(await node.LoginNames.GrantsOfGroupAsync(ops.Id, [lab.Id]));
    }

    [Fact]
    public async Task A_certificate_says_who_it_is_for_who_issued_it_and_why_its_subject_held_each_name()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id);
        var admin = new UserEntity { Id = node.Actor.UserId!.Value, Username = "ssh-operator", Email = "op@example.test", PasswordHash = "x" };
        node.Db.Users.Add(admin);
        node.Db.SaveChanges();
        var byAdmin = await SignFor(node, ca, alice, 1, "alice");
        var self = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(alice.Id), ["alice"], 1, null,
            new SshCaActor(alice.Id, "alice", "198.51.100.9"));
        var service = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["deploy"], 1, null, node.Actor);
        var host = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["web01.example.com"], 1, node.Actor);
        var older = SeedOlder(node, ca, null, "root");
        older.IssuedByUserId = alice.Id;
        node.Db.SaveChanges();

        var views = (await node.LoginNames.DescribeAsync([byAdmin, self, service, host, older])).ToList();

        Assert.Equal(new SshCertificateSubjectView("user", alice.Id, "alice", null), views[0].Subject);
        Assert.Equal(new SshCertificateIssuerView(admin.Id, "ssh-operator", false, "192.0.2.7"), views[0].IssuedBy);
        Assert.Equal("own", views[0].LoginNameGrounds!.Single().Source);
        Assert.Equal(new SshCertificateIssuerView(alice.Id, "alice", true, "198.51.100.9"), views[1].IssuedBy);
        Assert.Equal(new SshCertificateSubjectView("service", null, null, "ci"), views[2].Subject);
        Assert.Equal("typed", views[2].LoginNameGrounds!.Single().Source);
        Assert.Equal(new SshCertificateSubjectView("host", null, null, null), views[3].Subject);
        Assert.Null(views[3].LoginNameGrounds);
        Assert.Equal(new SshCertificateSubjectView("unknown", null, null, null), views[4].Subject);
        Assert.Null(views[4].LoginNameGrounds);
        Assert.All(views, v =>
        {
            Assert.Equal("active", v.Status);
            Assert.Equal(ca.Id, v.SshCaKey!.Id);
            Assert.Equal(SshPublicKey.ParseAuthorizedKey(ca.PublicKey).Fingerprint, v.SshCaKey.Fingerprint);
        });
        Assert.Equal(SshPublicKey.ParseAuthorizedKey(byAdmin.PublicKey).Fingerprint, views[0].KeyFingerprint);
        Assert.Equal(byAdmin.Principals, views[0].Principals);

        // Once the user is gone, the key id the CA wrote still names the subject.
        Assert.True(await Users(node).DeleteUser(alice.Id));
        using var db = node.Reopen();
        var after = (await node.LoginNames.DescribeAsync([db.SshCertificates.AsNoTracking().Single(c => c.Id == byAdmin.Id)])).Single();
        Assert.Equal("revoked", after.Status);
        Assert.Equal("user", after.Subject.Kind);
    }

    [Fact]
    public async Task A_certificate_is_found_by_its_serial_narrowed_by_the_ca_fingerprint_and_the_key_id()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var lab = await node.CreateCaAsync("Lab SSH");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, node.GroupOf(lab, "user").Id);
        var wanted = await SignFor(node, ca, alice, 1, "alice");
        var sameSerialElsewhere = SeedOlder(node, lab, alice.Id, "alice");
        sameSerialElsewhere.SerialNumber = wanted.SerialNumber;
        node.Db.SaveChanges();
        var fingerprint = SshPublicKey.ParseAuthorizedKey(ca.PublicKey).Fingerprint;

        var bySerial = await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, null, null, [ca.Id, lab.Id]);
        var byCa = await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, fingerprint, null, [ca.Id, lab.Id]);
        var byKeyId = await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, null, "alice", [ca.Id, lab.Id]);

        Assert.Equal(2, bySerial.Count);
        Assert.Equal(wanted.Id, byCa.Single().Id);
        Assert.Equal(fingerprint, byCa.Single().SshCaKey!.Fingerprint);
        Assert.Equal("Fleet SSH", byCa.Single().SshCaKey!.Name);
        Assert.Equal(wanted.Id, byKeyId.Single().Id);
        Assert.Equal(wanted.Id, (await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, fingerprint["SHA256:".Length..], null, [ca.Id, lab.Id])).Single().Id);
        Assert.Empty(await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, fingerprint, null, [lab.Id]));
        Assert.Empty(await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, "SHA256:nothing", null, [ca.Id, lab.Id]));
        Assert.Empty(await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber + 1, null, null, [ca.Id, lab.Id]));
        Assert.Empty(await node.LoginNames.FindCertificatesAsync(wanted.SerialNumber, null, null, []));
    }

    [Fact]
    public async Task Revoking_a_user_s_certificates_covers_the_keys_the_caller_may_revoke_on_and_counts_the_rest()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var lab = await node.CreateCaAsync("Lab SSH");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, node.GroupOf(lab, "user").Id);
        var bob = node.AddUser("bob", node.GroupOf(ca, "user").Id);
        var mine = await SignFor(node, ca, alice, 1, "alice");
        var older = SeedOlder(node, ca, alice.Id, "root");
        var theirs = await SignFor(node, lab, alice, 1, "alice");
        var bobs = await SignFor(node, ca, bob, 1, "bob");

        Assert.Equal(3, (await node.LoginNames.CertificatesOfUserAsync(alice.Id, [ca.Id, lab.Id], liveOnly: true)).Count);
        var result = await node.LoginNames.RevokeCertificatesOfUserAsync(alice.Id, [ca.Id], node.Actor);

        Assert.Equal(new SshSubjectRevocation(2, 1), result);
        Assert.True(Revoked(node, mine) && Revoked(node, older));
        Assert.False(Revoked(node, theirs) || Revoked(node, bobs));
        Assert.Equal(theirs.Id, (await node.LoginNames.CertificatesOfUserAsync(alice.Id, [ca.Id, lab.Id], liveOnly: true)).Single().Id);
        Assert.Equal(3, (await node.LoginNames.CertificatesOfUserAsync(alice.Id, [ca.Id, lab.Id], liveOnly: false)).Count);
        Assert.Equal(2, (await node.LoginNames.CertificatesOfUserAsync(alice.Id, [ca.Id], liveOnly: false)).Count);
        Assert.All(node.Audit.Of(AuditActionType.SshCertRevoked), a => Assert.Equal(node.Actor.UserId, a.ActorId));
    }

    [Fact]
    public async Task The_request_options_list_the_caller_s_names_and_the_profile_combinations_that_can_carry_them()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 720);
        var lab = await node.CreateCaAsync("Lab SSH", maxValidityHours: 168);
        var ops = node.AddGroup("web-ops");
        var alice = node.AddUser("alice", node.GroupOf(ca, "user").Id, ops.Id);
        await node.LoginNames.GrantAsync(ca.Id, Grant(ops, 24, null, "deploy"), node.Actor);
        await node.LoginNames.GrantAsync(ca.Id, Grant(alice, 8, null, "root"), node.Actor);
        var signing = node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == ca.Id && p.AllowUserCerts);
        var open = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "any account", AllowedPrincipalPatterns = "[]", MaxPrincipals = 5, MaxValidityHours = 12 };
        var noRoot = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "no root", AllowedPrincipalPatterns = "[\"^(?!root$)[a-z]+$\"]", MaxPrincipals = 3, MaxValidityHours = 720 };
        var unlisted = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "unlisted", AllowedPrincipalPatterns = "[]" };
        node.Db.SshCertProfiles.AddRange(open, noRoot, unlisted);
        node.Db.SshRequestProfiles.AddRange(
            new SshRequestProfileEntity
            {
                Id = Guid.NewGuid(), Name = "self-service", MaxValidityHours = 48, CertificateAuthorityId = ca.CertificateAuthorityId,
                AllowedSshSigningProfileIds = JsonSerializer.Serialize(new[] { signing.Id }), AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { open.Id, noRoot.Id }),
            },
            new SshRequestProfileEntity { Id = Guid.NewGuid(), Name = "needs approval", RequireApproval = true, CertificateAuthorityId = ca.CertificateAuthorityId });
        node.Db.SaveChanges();

        var options = await node.LoginNames.RequestOptionsAsync(alice.Id, [ca.CertificateAuthorityId]);

        Assert.Equal("alice", options.KeyId);
        var key = options.CaKeys.Single();
        Assert.Equal(ca.Id, key.Id);
        Assert.Equal(720, key.MaxValidityHours);
        Assert.True(key.AllowOwnUsername);
        Assert.Equal(new[] { "alice own 720", "deploy group 24", "root user 8" }, key.LoginNames.Select(n => $"{n.Name} {n.Source} {n.MaxValidityHours}").ToArray());
        Assert.Equal("web-ops", key.LoginNames.Single(n => n.Name == "deploy").GroupName);
        Assert.Equal(new[] { "self-service/any account 12 5 []", "self-service/no root 24 3 [root]" },
            key.Profiles.Select(p => $"{p.RequestProfileName}/{p.CertProfileName} {p.MaxValidityHours} {p.MaxPrincipals} [{string.Join(",", p.UnavailableLoginNames)}]").ToArray());
        Assert.All(key.Profiles, p => Assert.Equal(signing.Id, p.SigningProfileId));
        Assert.Empty((await node.LoginNames.RequestOptionsAsync(alice.Id, [])).CaKeys);
    }

    // ---- Upgrade check -----------------------------------------------------------------------

    [Fact]
    public void The_upgrade_check_says_what_changes_and_counts_the_live_certificates_that_carry_another_name()
    {
        var live = new[]
        {
            new SshUpgradeUserCertificate("alice", "[\"alice\"]"),
            new SshUpgradeUserCertificate("alice", "[\"alice\",\"root\"]"),
            new SshUpgradeUserCertificate("laptop", "[\"bob\"]"),
            new SshUpgradeUserCertificate("carol", "not json"),
        };

        var before = SshUpgradeCheck.LoginNamesNote(2, live)!;
        var after = SshUpgradeCheck.LoginNamesNote(2, live, beforeUpgrade: false)!;

        Assert.Contains("2 of 4 live user certificate(s) carry a name other than their key id", before);
        Assert.Contains("may only name the requester's own username and the login names granted to them", before);
        Assert.Contains("for a user, who must hold the names, or for a service identity", before);
        Assert.Contains("stay valid until they expire", before);
        Assert.StartsWith("After this upgrade", before);
        Assert.DoesNotContain("After this upgrade", after);
        Assert.Contains("0 of 0 live user certificate(s)", SshUpgradeCheck.LoginNamesNote(1, [])!);
        Assert.Null(SshUpgradeCheck.LoginNamesNote(0, live));
    }
}
