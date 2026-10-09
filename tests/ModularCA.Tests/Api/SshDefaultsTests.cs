using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The default SSH CA setup (<c>docs/architecture/ssh-defaults.md</c>; owner, 2026-10-08). Each
/// decided number and list has a test here that fails when it is changed back: what a new key's
/// maximum is, what its signing profiles take, what a new install is seeded with, and the
/// advisory review date, which reminds and never acts.
/// </summary>
public sealed class SshDefaultsTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.";
    private const string Admin = Ns + "Admin.AdminSshController";
    private const string Self = Ns + "User.UserSshController";
    private const string Public = Ns + "Public.PublicSshController";

    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static readonly string[] FivePermits =
        ["permit-pty", "permit-agent-forwarding", "permit-port-forwarding", "permit-X11-forwarding", "permit-user-rc"];

    private sealed class CurrentUserStub(UserEntity user) : ICurrentUserService
    {
        public Guid? UserId => user.Id;
        public UserEntity? User { get; } = user;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static object New(string typeName, UserEntity caller, bool instanceScope, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", caller.Id.ToString()) }, "test")),
        };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: instanceScope));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static JsonElement Json(IActionResult result)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value, Wire)).RootElement;

    private static string Error(IActionResult result)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<BadRequestObjectResult>(result).Value, Wire)).RootElement.GetProperty("error").GetString()!;

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static object AdminController(SshNode node, UserEntity caller, bool instanceScope = true, IDistributedCache? cache = null)
        => New(Admin, caller, instanceScope, node.Service, new CurrentUserStub(caller), node.Db, new SystemConfig(),
            new KeyCeremonyService(node.Db, new RecordingAuditService()), cache ?? NewCache(), node.Relay, new SshKeyImportState(), node.LoginNames);

    private static object SelfController(SshNode node, UserEntity caller)
        => New(Self, caller, true, node.Db, node.Service, new CurrentUserStub(caller), new RecordingAuditService(),
            new CaGroupAuthorizationService(node.Db, NullLogger<CaGroupAuthorizationService>.Instance), node.LoginNames);

    private static List<string> Strings(string json) => JsonSerializer.Deserialize<List<string>>(json)!;

    private static SshCertificate Certificate(JsonElement answer) => SshCertificate.ParseOpenSsh(answer.GetProperty("signedCertificate").GetString()!);

    private static string[] ExtensionsOf(SshCertificate certificate) => certificate.Fields.Extensions.Select(e => e.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();

    // ---- A. Creating an SSH CA key -----------------------------------------------------------

    [Fact]
    public void A_key_that_signs_user_certificates_defaults_to_24_hours_and_a_host_only_key_to_one_year()
    {
        Assert.Equal(24, SshCaKeyDefaults.UserMaxValidityHours);
        Assert.Equal(8760, SshCaKeyDefaults.HostMaxValidityHours);

        Assert.Equal(24, SshCaKeyDefaults.MaxValidityHours(isUserCa: true, isHostCa: false));
        Assert.Equal(24, SshCaKeyDefaults.MaxValidityHours(isUserCa: true, isHostCa: true));
        Assert.Equal(8760, SshCaKeyDefaults.MaxValidityHours(isUserCa: false, isHostCa: true));
        Assert.Equal(24, SshCaKeyDefaults.MaxValidityHours(isUserCa: false, isHostCa: false));
    }

    [Fact]
    public async Task The_create_route_takes_the_default_for_the_type_when_the_maximum_is_omitted_and_still_accepts_both_flags()
    {
        using var node = new SshNode();
        var caller = node.AddUser("edward");

        async Task<SshCaKeyEntity> CreateAsync(string name, bool? user, bool? host, int? hours)
        {
            var cache = NewCache();
            var token = Guid.NewGuid().ToString("N");
            cache.SetString($"mfa-stepup:{caller.Id}:{StepUpOps.CreateSshCa}", token);
            var answer = Json(await Call(AdminController(node, caller, cache: cache), "GenerateCaKey",
                Body("Admin.GenerateSshCaKeyRequest", ("Name", name), ("IsUserCa", user), ("IsHostCa", host), ("MaxValidityHours", hours)), token));
            using var db = node.Reopen();
            var row = db.SshCaKeys.Single(k => k.Id == answer.GetProperty("id").GetGuid());
            Assert.Equal(row.MaxValidityHours, answer.GetProperty("maxValidityHours").GetInt32());
            return row;
        }

        var neitherSaid = await CreateAsync("Plain SSH", null, null, null);
        Assert.True(neitherSaid.IsUserCa);
        Assert.False(neitherSaid.IsHostCa);
        Assert.Equal(24, neitherSaid.MaxValidityHours);

        Assert.Equal(24, (await CreateAsync("Users SSH", true, false, null)).MaxValidityHours);
        Assert.Equal(8760, (await CreateAsync("Hosts SSH", false, true, null)).MaxValidityHours);

        var both = await CreateAsync("Both SSH", true, true, null);
        Assert.True(both.IsUserCa && both.IsHostCa);
        Assert.Equal(24, both.MaxValidityHours);

        Assert.Equal(100, (await CreateAsync("Long users SSH", true, false, 100)).MaxValidityHours);
        Assert.Equal(48, (await CreateAsync("Short hosts SSH", false, true, 48)).MaxValidityHours);
    }

    [Fact]
    public async Task A_ceremony_for_a_new_key_records_the_default_for_its_type()
    {
        using var node = new SshNode(requireKeyCeremony: true);
        var admins = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-admin", DisplayName = "System administrators", IsSystemGroup = true };
        node.Db.CaGroups.Add(admins);
        foreach (var capability in Capabilities.AdministratorTemplate)
            node.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = admins.Id, Capability = capability });
        node.Db.SaveChanges();
        var caller = node.AddUser("edward", admins.Id);
        node.AddUser("second-admin", admins.Id);

        async Task<int> RecordedAsync(string name, bool user, bool host)
        {
            var cache = NewCache();
            var token = Guid.NewGuid().ToString("N");
            cache.SetString($"mfa-stepup:{caller.Id}:{StepUpOps.CreateSshCa}", token);
            var answer = Json(await Call(AdminController(node, caller, cache: cache), "GenerateCaKey",
                Body("Admin.GenerateSshCaKeyRequest", ("Name", name), ("IsUserCa", (bool?)user), ("IsHostCa", (bool?)host)), token));
            Assert.True(answer.GetProperty("requiresCeremony").GetBoolean());
            using var db = node.Reopen();
            var ceremony = db.KeyCeremonies.Single(c => c.Id == answer.GetProperty("ceremonyId").GetGuid());
            return ModularCA.Shared.Models.CeremonyParametersJson.Read<ModularCA.Shared.Models.SshKeyCeremonyParameters>(ceremony.ParametersJson)!.MaxValidityHours;
        }

        Assert.Equal(24, await RecordedAsync("Users SSH", user: true, host: false));
        Assert.Equal(24, await RecordedAsync("Both SSH", user: true, host: true));
        Assert.Equal(8760, await RecordedAsync("Hosts SSH", user: false, host: true));
        Assert.Empty(node.Db.SshCaKeys);
    }

    // ---- B. The signing profiles created with a key ------------------------------------------

    [Fact]
    public async Task Both_signing_profiles_created_with_a_key_take_the_key_s_own_maximum()
    {
        using var node = new SshNode();

        var both = await node.Service.GenerateKeyPairAsync("Both SSH", "ed25519", isUserCa: true, isHostCa: true, 720);
        var user = await node.Service.GenerateKeyPairAsync("Users SSH", "ed25519", isUserCa: true, isHostCa: false, 24);
        var shortUser = await node.Service.GenerateKeyPairAsync("Short SSH", "ed25519", isUserCa: true, isHostCa: false, 8);
        var host = await node.Service.GenerateKeyPairAsync("Hosts SSH", "ed25519", isUserCa: false, isHostCa: true, 8760);

        using var db = node.Reopen();
        List<SshSigningProfileEntity> Of(SshCaKeyEntity key) => db.SshSigningProfiles.Where(p => p.SshCaKeyId == key.Id).OrderBy(p => p.Name).ToList();

        // The user profile is no longer capped at 24 hours: the key holds the ceiling.
        Assert.Equal(new[] { "Both SSH - Host Signing 720", "Both SSH - User Signing 720" }, Of(both).Select(p => $"{p.Name} {p.MaxValidityHours}").ToArray());
        Assert.Equal(new[] { "Users SSH - User Signing 24" }, Of(user).Select(p => $"{p.Name} {p.MaxValidityHours}").ToArray());
        Assert.Equal(new[] { "Short SSH - User Signing 8" }, Of(shortUser).Select(p => $"{p.Name} {p.MaxValidityHours}").ToArray());
        Assert.Equal(new[] { "Hosts SSH - Host Signing 8760" }, Of(host).Select(p => $"{p.Name} {p.MaxValidityHours}").ToArray());
    }

    [Fact]
    public async Task The_user_signing_profile_created_with_a_key_permits_a_terminal_and_no_forwarding()
    {
        Assert.Equal(new[] { "permit-pty" }, SshCaKeyDefaults.UserSigningDefaultExtensions);

        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var userProfile = node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == ca.Id && p.AllowUserCerts);
        var hostProfile = node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == ca.Id && p.AllowHostCerts);

        Assert.Equal("[\"permit-pty\"]", userProfile.DefaultExtensions);
        Assert.Equal("[]", hostProfile.DefaultExtensions);
        Assert.DoesNotContain("forwarding", userProfile.DefaultExtensions);

        // A certificate signed through it with no extension asked carries the terminal and nothing else.
        var open = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "any account", AllowedPrincipalPatterns = "[]", MaxPrincipals = 5, MaxValidityHours = 24 };
        node.Db.SshCertProfiles.Add(open);
        node.Db.SaveChanges();
        var signed = Json(await Call(AdminController(node, node.AddUser("edward")), "SignUserKey", ca.Id, Body("Admin.SignSshUserKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("ServiceLabel", "ci"), ("Principals", new List<string> { "deploy" }), ("ValidityHours", (int?)1),
            ("SshSigningProfileId", userProfile.Id), ("SshCertProfileId", open.Id))));
        Assert.Equal(new[] { "permit-pty" }, ExtensionsOf(Certificate(signed)));
    }

    // ---- C. The seeded profiles --------------------------------------------------------------

    [Fact]
    public void A_new_install_is_seeded_with_the_decided_ssh_profiles()
    {
        using var db = InMemoryDbContextFactory.Create($"ssh-seed-{Guid.NewGuid():N}");
        BootstrapProfileSeeder.SeedDefaultSshProfiles(db);

        var certProfiles = db.SshCertProfiles.OrderBy(p => p.Name).ToList();
        Assert.Equal(new[] { "SSH Host Cert - Standard", "SSH User Cert - Forwarding", "SSH User Cert - Standard" }, certProfiles.Select(p => p.Name).ToArray());
        var host = certProfiles[0];
        var forwarding = certProfiles[1];
        var standard = certProfiles[2];

        const string loginNameGrammar = "^[A-Za-z0-9_][A-Za-z0-9._@+-]{0,127}$";
        Assert.Equal(loginNameGrammar, SshLoginNameRules.Pattern);

        Assert.Equal($"[\"{loginNameGrammar}\"]", standard.AllowedPrincipalPatterns);
        Assert.Equal(3, standard.MaxPrincipals);
        Assert.Equal(new[] { "permit-pty", "permit-user-rc" }, Strings(standard.AllowedExtensions));
        Assert.Empty(Strings(standard.RequiredExtensions));
        Assert.Equal(24, standard.MaxValidityHours);

        Assert.Equal(standard.AllowedPrincipalPatterns, forwarding.AllowedPrincipalPatterns);
        Assert.Equal(3, forwarding.MaxPrincipals);
        Assert.Equal(FivePermits.OrderBy(p => p, StringComparer.Ordinal), Strings(forwarding.AllowedExtensions).OrderBy(p => p, StringComparer.Ordinal));
        Assert.Equal(new[] { "permit-agent-forwarding", "permit-port-forwarding" }, Strings(forwarding.RequiredExtensions).OrderBy(p => p, StringComparer.Ordinal));
        Assert.Equal(24, forwarding.MaxValidityHours);

        Assert.Equal("[\"^[a-z0-9][a-z0-9.-]+$\"]", host.AllowedPrincipalPatterns);
        Assert.Equal(10, host.MaxPrincipals);
        Assert.Equal(8760, host.MaxValidityHours);

        var requestProfiles = db.SshRequestProfiles.OrderBy(p => p.Name).ToList();
        Assert.Equal(new[] { "SSH Host Request - Default", "SSH User Request - Default" }, requestProfiles.Select(p => p.Name).ToArray());
        Assert.Equal(8760, requestProfiles[0].MaxValidityHours);
        Assert.Equal(12, requestProfiles[1].MaxValidityHours);
        Assert.All(requestProfiles, p => Assert.False(p.RequireApproval));

        // Forwarding is attached to no request profile: an administrator adds it where it is wanted.
        Assert.Equal(new[] { standard.Id }, JsonSerializer.Deserialize<List<Guid>>(requestProfiles[1].AllowedSshCertProfileIds));
        Assert.Equal(new[] { host.Id }, JsonSerializer.Deserialize<List<Guid>>(requestProfiles[0].AllowedSshCertProfileIds));
        Assert.All(requestProfiles, p => Assert.DoesNotContain(forwarding.Id.ToString(), p.AllowedSshCertProfileIds));

        // No signing profile is seeded: those are created with each key.
        Assert.Empty(db.SshSigningProfiles);
    }

    [Fact]
    public void An_install_that_has_an_ssh_certificate_profile_is_seeded_nothing_and_keeps_its_rows()
    {
        var name = $"ssh-seed-{Guid.NewGuid():N}";
        using (var db = InMemoryDbContextFactory.Create(name))
        {
            // What an install seeded before this change holds.
            db.SshCertProfiles.Add(new SshCertProfileEntity
            {
                Name = "SSH User Cert - Standard", AllowedPrincipalPatterns = "[\"^[a-z_][a-z0-9_-]{0,31}$\"]", MaxPrincipals = 5,
                AllowedExtensions = JsonSerializer.Serialize(FivePermits), RequiredExtensions = "[]", MaxValidityHours = 24,
            });
            db.SshRequestProfiles.Add(new SshRequestProfileEntity { Name = "SSH User Request - Default", MaxValidityHours = 24 });
            db.SaveChanges();

            BootstrapProfileSeeder.SeedDefaultSshProfiles(db);
        }

        using var after = InMemoryDbContextFactory.Create(name);
        var profile = Assert.Single(after.SshCertProfiles);
        Assert.Equal("[\"^[a-z_][a-z0-9_-]{0,31}$\"]", profile.AllowedPrincipalPatterns);
        Assert.Equal(5, profile.MaxPrincipals);
        Assert.Equal(5, Strings(profile.AllowedExtensions).Count);
        Assert.Equal(24, Assert.Single(after.SshRequestProfiles).MaxValidityHours);
    }

    [Fact]
    public void Seeding_twice_seeds_once()
    {
        using var db = InMemoryDbContextFactory.Create($"ssh-seed-{Guid.NewGuid():N}");
        BootstrapProfileSeeder.SeedDefaultSshProfiles(db);
        BootstrapProfileSeeder.SeedDefaultSshProfiles(db);

        Assert.Equal(3, db.SshCertProfiles.Count());
        Assert.Equal(2, db.SshRequestProfiles.Count());
    }

    /// <summary>
    /// The seeded pattern and <see cref="SshLoginNameRules.IsValid"/> say the same of every
    /// name, so the Standard profile refuses no name a grant allows. The one string they differ
    /// on in .NET, a name with a final line feed, is refused by the rule and by the signer.
    /// </summary>
    [Fact]
    public void The_seeded_principal_pattern_is_the_login_name_grammar()
    {
        var names = new List<string> { string.Empty, "root", "Deploy", "svc.backup", "ops@corp", "9lives", "a+b", "_apt", "web-01", "-dash", ".dot", "@at", "+plus", "a b", "a\tb", "a/b", "a:b", "a,b" };
        for (var c = 0; c < 0x300; c++)
        {
            var ch = ((char)c).ToString();
            if (ch == "\n")
                continue;
            names.Add(ch);
            names.Add("a" + ch);
            names.Add(ch + "a");
            names.Add("a" + ch + "a");
        }
        // Beyond the loop: a CJK letter, a line separator and a full-width letter.
        foreach (var c in new[] { 0x540D, 0x2028, 0xFF41 })
        {
            names.Add(((char)c).ToString());
            names.Add("a" + (char)c);
        }
        foreach (var length in new[] { 1, 2, 127, 128, 129, 200 })
        {
            names.Add(new string('a', length));
            names.Add("_" + new string('9', length - 1));
        }

        Assert.All(names, name => Assert.True(
            SshLoginNameRules.IsValid(name) == ProfileRegex.IsMatch(name, SshLoginNameRules.Pattern),
            $"The rule and the pattern disagree on '{name}' ({string.Join(' ', name.Select(c => ((int)c).ToString("x4")))})."));

        // Names a grant allows that the lower-case POSIX pattern seeded before refused.
        Assert.All(new[] { "Deploy", "svc.backup", "ops@corp", "9lives", "a+b", new string('a', 128) }, name =>
        {
            Assert.True(ProfileRegex.IsMatch(name, SshLoginNameRules.Pattern), name);
            Assert.False(ProfileRegex.IsMatch(name, "^[a-z_][a-z0-9_-]{0,31}$"), name);
        });

        Assert.False(SshLoginNameRules.IsValid("deploy\n"));
        Assert.NotNull(SshCertificateRules.CheckPrincipals(["deploy\n"]));
    }

    /// <summary>
    /// A fresh install with one user key: the seeded profiles, the key's own signing profile and
    /// two people. What a request through the Standard profile gets and is refused, and what
    /// choosing the Forwarding profile yields once an administrator has attached it.
    /// </summary>
    private sealed class FreshInstall : IDisposable
    {
        public SshNode Node { get; } = new();
        public SshCaKeyEntity Ca { get; }
        public UserEntity Operator { get; }
        public UserEntity Alice { get; }
        public Guid SigningProfile { get; }
        public SshCertProfileEntity Standard { get; }
        public SshCertProfileEntity Forwarding { get; }
        public SshRequestProfileEntity UserRequest { get; }

        public FreshInstall()
        {
            BootstrapProfileSeeder.SeedDefaultSshProfiles(Node.Db);
            Ca = Node.Service.GenerateKeyPairAsync("Users SSH", "ed25519", isUserCa: true, isHostCa: false,
                SshCaKeyDefaults.MaxValidityHours(true, false), actor: Node.Actor).GetAwaiter().GetResult();
            Operator = Node.AddUser("edward", Node.GroupOf(Ca, "admin").Id);
            Alice = Node.AddUser("alice", Node.GroupOf(Ca, "user").Id);
            SigningProfile = Node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == Ca.Id && p.AllowUserCerts).Id;
            Standard = Node.Db.SshCertProfiles.Single(p => p.Name == BootstrapProfileSeeder.SshUserCertStandardName);
            Forwarding = Node.Db.SshCertProfiles.Single(p => p.Name == BootstrapProfileSeeder.SshUserCertForwardingName);
            UserRequest = Node.Db.SshRequestProfiles.Single(p => p.Name == BootstrapProfileSeeder.SshUserRequestDefaultName);
        }

        public object SelfRequest(Guid? certProfile, int? hours, params string[] extensions) => Body("User.UserSshSignRequest",
            ("PublicKey", SshNode.SubjectKey()), ("Principals", new List<string> { "alice" }), ("ValidityHours", hours),
            ("Extensions", extensions.Length == 0 ? null : extensions.ToList()),
            ("SshRequestProfileId", UserRequest.Id), ("SshSigningProfileId", (Guid?)SigningProfile), ("SshCertProfileId", certProfile));

        public object AdminRequest(Guid certProfile, List<string>? extensions, params string[] principals) => Body("Admin.SignSshUserKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("ServiceLabel", "ci"), ("Principals", principals.ToList()), ("ValidityHours", (int?)1),
            ("Extensions", extensions), ("SshSigningProfileId", SigningProfile), ("SshCertProfileId", certProfile));

        public void AttachForwarding()
        {
            UserRequest.AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { Standard.Id, Forwarding.Id });
            Node.Db.SaveChanges();
        }

        public void Dispose() => Node.Dispose();
    }

    [Fact]
    public async Task A_request_through_the_standard_profile_gets_a_terminal_for_12_hours_and_is_refused_forwarding()
    {
        using var w = new FreshInstall();
        var self = SelfController(w.Node, w.Alice);

        var plain = Certificate(Json(await Call(self, "SignUserKey", w.SelfRequest(null, null))));
        Assert.Equal(new[] { "permit-pty" }, ExtensionsOf(plain));
        Assert.Equal(new[] { "alice" }, plain.Fields.Principals);
        // The request profile holds the everyday number; the key (24) and the profiles between are the ceiling.
        Assert.Equal(12UL * 3600, plain.Fields.ValidBefore - plain.Fields.ValidAfter);

        Assert.Contains("request profile maximum of 12 hours", Error(await Call(self, "SignUserKey", w.SelfRequest(null, 13))));

        foreach (var forwarding in new[] { "permit-agent-forwarding", "permit-port-forwarding", "permit-X11-forwarding" })
            Assert.Equal($"Extension '{forwarding}' is not allowed by the cert profile", Error(await Call(self, "SignUserKey", w.SelfRequest(null, 1, forwarding))));
        Assert.Contains("not allowed by the cert profile", Error(await Call(self, "SignUserKey", w.SelfRequest(null, 1, "permit-pty", "permit-agent-forwarding"))));

        // What the profile does allow can be asked for.
        Assert.Equal(new[] { "permit-pty", "permit-user-rc" }, ExtensionsOf(Certificate(Json(await Call(self, "SignUserKey", w.SelfRequest(null, 1, "permit-pty", "permit-user-rc"))))));

        // The administrator's route holds the profile to the same list.
        var admin = AdminController(w.Node, w.Operator);
        Assert.Equal("Extension 'permit-agent-forwarding' is not allowed by the cert profile",
            Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Standard.Id, ["permit-pty", "permit-agent-forwarding"], "deploy"))));
        Assert.Equal(new[] { "permit-pty" }, ExtensionsOf(Certificate(Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Standard.Id, null, "deploy"))))));

        Assert.Equal(3, w.Node.Relay.SshSigned.Count);
    }

    [Fact]
    public async Task The_standard_profile_takes_any_valid_login_name_and_at_most_three()
    {
        using var w = new FreshInstall();
        var admin = AdminController(w.Node, w.Operator);

        var three = Certificate(Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Standard.Id, null, "Deploy", "svc.backup", "ops@corp"))));
        Assert.Equal(new[] { "Deploy", "svc.backup", "ops@corp" }, three.Fields.Principals);

        Assert.Equal("Too many principals (4); cert profile allows max 3",
            Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Standard.Id, null, "a", "b", "c", "d"))));
        Assert.Equal("Principal 'not a name' does not match any allowed pattern",
            Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Standard.Id, null, "not a name"))));
    }

    [Fact]
    public async Task The_forwarding_profile_is_not_offered_until_attached_and_then_yields_both_forwardings_and_a_terminal()
    {
        using var w = new FreshInstall();
        var self = SelfController(w.Node, w.Alice);

        Assert.Equal("The chosen cert profile is not allowed by this request profile",
            Error(await Call(self, "SignUserKey", w.SelfRequest(w.Forwarding.Id, 1))));
        Assert.Empty(w.Node.Relay.SshSigned);

        w.AttachForwarding();

        var forwarded = Certificate(Json(await Call(self, "SignUserKey", w.SelfRequest(w.Forwarding.Id, null))));
        Assert.Equal(new[] { "permit-agent-forwarding", "permit-port-forwarding", "permit-pty" }, ExtensionsOf(forwarded));
        Assert.Equal(12UL * 3600, forwarded.Fields.ValidBefore - forwarded.Fields.ValidAfter);

        // Standard is still there beside it, and still permits no forwarding.
        Assert.Equal(new[] { "permit-pty" }, ExtensionsOf(Certificate(Json(await Call(self, "SignUserKey", w.SelfRequest(w.Standard.Id, 1))))));
        Assert.Contains("not allowed by the cert profile", Error(await Call(self, "SignUserKey", w.SelfRequest(w.Standard.Id, 1, "permit-port-forwarding"))));

        // Through the administrator's route the Forwarding profile yields the same three.
        var admin = AdminController(w.Node, w.Operator);
        Assert.Equal(new[] { "permit-agent-forwarding", "permit-port-forwarding", "permit-pty" },
            ExtensionsOf(Certificate(Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Forwarding.Id, null, "deploy"))))));
    }

    // ---- D. The advisory review date ---------------------------------------------------------

    [Fact]
    public void A_key_is_due_for_review_two_years_on_when_it_signs_user_certificates_and_five_when_it_signs_hosts_only()
    {
        Assert.Equal(2, SshCaKeyDefaults.UserReviewYears);
        Assert.Equal(5, SshCaKeyDefaults.HostReviewYears);
        Assert.Equal(90, SshCaKeyDefaults.ReviewWarningDays);
        Assert.Equal(10, SshCaKeyDefaults.MaxReviewYearsAhead);

        var created = new DateTime(2026, 10, 8, 9, 30, 0, DateTimeKind.Utc);
        Assert.Equal(new DateTime(2028, 10, 8, 9, 30, 0, DateTimeKind.Utc), SshCaKeyDefaults.ReviewBy(created, isUserCa: true, isHostCa: false));
        Assert.Equal(new DateTime(2028, 10, 8, 9, 30, 0, DateTimeKind.Utc), SshCaKeyDefaults.ReviewBy(created, isUserCa: true, isHostCa: true));
        Assert.Equal(new DateTime(2031, 10, 8, 9, 30, 0, DateTimeKind.Utc), SshCaKeyDefaults.ReviewBy(created, isUserCa: false, isHostCa: true));
        Assert.Equal(DateTimeKind.Utc, SshCaKeyDefaults.ReviewBy(DateTime.SpecifyKind(created, DateTimeKind.Unspecified), true, false).Kind);
        Assert.Equal(new DateTime(2026, 2, 28, 0, 0, 0, DateTimeKind.Utc), SshCaKeyDefaults.ReviewBy(new DateTime(2024, 2, 29, 0, 0, 0, DateTimeKind.Utc), true, false));
    }

    [Fact]
    public void A_key_is_due_from_90_days_before_its_review_date_and_stays_due_after_it()
    {
        var now = new DateTime(2026, 10, 8, 12, 0, 0, DateTimeKind.Utc);
        Assert.False(SshCaKeyDefaults.ReviewIsDue(null, now));
        Assert.False(SshCaKeyDefaults.ReviewIsDue(now.AddDays(90).AddSeconds(1), now));
        Assert.True(SshCaKeyDefaults.ReviewIsDue(now.AddDays(90), now));
        Assert.True(SshCaKeyDefaults.ReviewIsDue(now.AddDays(1), now));
        Assert.True(SshCaKeyDefaults.ReviewIsDue(now, now));
        Assert.True(SshCaKeyDefaults.ReviewIsDue(now.AddYears(-3), now));
    }

    [Fact]
    public async Task A_new_key_is_given_its_review_date_and_the_creation_is_audited_with_it()
    {
        using var node = new SshNode();
        var user = await node.Service.GenerateKeyPairAsync("Users SSH", "ed25519", isUserCa: true, isHostCa: false, 24, actor: node.Actor);
        var both = await node.Service.GenerateKeyPairAsync("Both SSH", "ed25519", isUserCa: true, isHostCa: true, 24, actor: node.Actor);
        var host = await node.Service.GenerateKeyPairAsync("Hosts SSH", "ed25519", isUserCa: false, isHostCa: true, 8760, actor: node.Actor);

        using var db = node.Reopen();
        SshCaKeyEntity Row(SshCaKeyEntity key) => db.SshCaKeys.Single(k => k.Id == key.Id);
        Assert.Equal(Row(user).CreatedAt.AddYears(2), Row(user).ReviewBy);
        Assert.Equal(Row(both).CreatedAt.AddYears(2), Row(both).ReviewBy);
        Assert.Equal(Row(host).CreatedAt.AddYears(5), Row(host).ReviewBy);
        Assert.InRange(Row(user).ReviewBy!.Value, DateTime.UtcNow.AddYears(2).AddMinutes(-5), DateTime.UtcNow.AddYears(2));

        Assert.All(node.Audit.Of(AuditActionType.SshCaKeyCreated), a => Assert.Contains("\"ReviewBy\":\"20", JsonSerializer.Serialize(a.Details)));
    }

    /// <summary>One SSH CA with certificates issued, its administrator, and a requester.</summary>
    private sealed class Reviewed : IDisposable
    {
        public SshNode Node { get; } = new();
        public SshCaKeyEntity Ca { get; }
        public UserEntity Operator { get; }
        public UserEntity Alice { get; }

        public Reviewed()
        {
            Ca = Node.CreateCaAsync().GetAwaiter().GetResult();
            Operator = Node.AddUser("edward", Node.GroupOf(Ca, "admin").Id);
            Alice = Node.AddUser("alice", Node.GroupOf(Ca, "user").Id);
        }

        public object MoveTo(DateTime? reviewBy) => Body("Admin.SetSshCaKeyReviewByRequest", ("ReviewBy", reviewBy));

        /// <summary>Every column of the key row but the review date, and every row that hangs off the key.</summary>
        public string EverythingButTheReviewDate()
        {
            using var db = Node.Reopen();
            var key = db.SshCaKeys.AsNoTracking().Single(k => k.Id == Ca.Id);
            var ca = db.CertificateAuthorities.AsNoTracking().Single(c => c.Id == key.CertificateAuthorityId);
            return JsonSerializer.Serialize(new
            {
                key.Id, key.Name, key.KeyType, key.KeySize, key.PublicKey, key.PrivateKeyPath, key.KeyStorage, key.CertificateAuthorityId,
                key.IsUserCa, key.IsHostCa, key.MaxValidityHours, key.AllowOwnUsername, key.IsEnabled, key.CreatedAt,
                Ca = new { ca.IsEnabled, ca.IsDeleted, ca.Name, ca.Label },
                SigningProfiles = db.SshSigningProfiles.AsNoTracking().Where(p => p.SshCaKeyId == key.Id).OrderBy(p => p.Name)
                    .Select(p => new { p.Name, p.MaxValidityHours, p.DefaultExtensions, p.AllowUserCerts, p.AllowHostCerts }).ToList(),
                Certificates = db.SshCertificates.AsNoTracking().Where(c => c.SshCaKeyId == key.Id).OrderBy(c => c.SerialNumber)
                    .Select(c => new { c.SerialNumber, c.IsRevoked, c.RevokedAt, c.ValidAfter, c.ValidBefore, c.SignedCertificate }).ToList(),
                Grants = db.SshLoginNameGrants.AsNoTracking().Where(g => g.SshCaKeyId == key.Id).OrderBy(g => g.LoginName)
                    .Select(g => new { g.LoginName, g.UserId, g.GroupId, g.MaxValidityHours, g.ExpiresAt }).ToList(),
            });
        }

        public DateTime? ReviewBy()
        {
            using var db = Node.Reopen();
            return db.SshCaKeys.AsNoTracking().Single(k => k.Id == Ca.Id).ReviewBy;
        }

        public void Dispose() => Node.Dispose();
    }

    [Fact]
    public void The_review_route_asks_ca_manage_on_the_key_s_ca_and_no_step_up()
    {
        var method = ApiAssembly.TypeNamed(Admin).GetMethod("SetReviewBy")!;
        var attributes = method.GetCustomAttributes(inherit: true);
        var http = attributes.OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>().Single();

        Assert.Equal("PUT", http.HttpMethods.Single());
        Assert.Equal("ca-keys/{caKeyId:guid}/review-by", http.Template);
        Assert.Equal("api/v1/admin/ssh", ApiAssembly.TypeNamed(Admin).GetCustomAttributes(true).OfType<RouteAttribute>().Single().Template);
        Assert.Equal("CaAdmin", attributes.OfType<IAuthorizeData>().Select(a => a.Policy).Single(p => p != null));
        Assert.Equal(Capabilities.CaManage, PolicyDefinitions.All["CaAdmin"].Capability);
        Assert.False(PolicyDefinitions.All["CaAdmin"].SystemOnly);
        Assert.DoesNotContain(attributes, a => a.GetType().Name == "RequireStepUpAttribute");
    }

    [Fact]
    public async Task The_roles_of_an_ssh_ca_decide_who_may_move_its_review_date()
    {
        using var w = new Reviewed();
        var auth = new CaGroupAuthorizationService(w.Node.Db, NullLogger<CaGroupAuthorizationService>.Instance);

        Assert.True(await auth.HasCaCapabilityAsync(w.Operator.Id, w.Ca.CertificateAuthorityId, Capabilities.CaManage));
        Assert.False(await auth.HasCaCapabilityAsync(w.Alice.Id, w.Ca.CertificateAuthorityId, Capabilities.CaManage));
    }

    [Fact]
    public async Task Moving_the_review_date_changes_that_date_and_nothing_else_and_is_audited()
    {
        using var w = new Reviewed();
        await w.Node.LoginNames.GrantAsync(w.Ca.Id, new SshLoginNameGrantRequest(["deploy"], w.Alice.Id, null, 4, null, null), new SshCaActor(w.Operator.Id, w.Operator.Username));
        var live = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice", "deploy"], 1, null, w.Node.Actor);
        var revoked = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["ci"], 1, null, w.Node.Actor);
        Assert.True(await w.Node.Service.RevokeCertificateAsync(revoked.Id, w.Ca.Id, w.Node.Actor));

        var before = w.EverythingButTheReviewDate();
        var krlBefore = await w.Node.Service.BuildKrlAsync(w.Ca.Id);
        var was = w.ReviewBy();
        var auditsBefore = w.Node.Audit.Entries.Count;
        var signedBefore = w.Node.Relay.SshSigned.Count;

        var admin = AdminController(w.Node, w.Operator);
        var to = DateTime.UtcNow.AddYears(3);
        var answer = Json(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(to)));

        Assert.Equal(w.Ca.Id, answer.GetProperty("id").GetGuid());
        Assert.Equal(to, answer.GetProperty("reviewBy").GetDateTime().ToUniversalTime());
        Assert.Equal(to, w.ReviewBy());

        Assert.Equal(before, w.EverythingButTheReviewDate());
        var krlAfter = await w.Node.Service.BuildKrlAsync(w.Ca.Id);
        Assert.Equal(krlBefore.Bytes, krlAfter.Bytes);
        Assert.Equal(krlBefore.State!.ETag, krlAfter.State!.ETag);
        Assert.Equal(signedBefore, w.Node.Relay.SshSigned.Count);
        using (var db = w.Node.Reopen())
            Assert.False(db.SshCertificates.Single(c => c.Id == live.Id).IsRevoked);

        // One audit entry, for this, naming who, the key, its CA, the new date and the one before.
        Assert.Equal(auditsBefore + 1, w.Node.Audit.Entries.Count);
        var audit = Assert.Single(w.Node.Audit.Of(AuditActionType.SshCaKeyReviewDateChanged));
        Assert.True(audit.Success);
        Assert.Equal(w.Operator.Id, audit.ActorId);
        Assert.Equal("edward", audit.Actor);
        Assert.Equal("SshCaKey", audit.TargetType);
        Assert.Equal(w.Ca.Id.ToString(), audit.TargetId);
        Assert.Equal(w.Ca.CertificateAuthorityId, audit.CaId);
        var details = JsonDocument.Parse(JsonSerializer.Serialize(audit.Details)).RootElement;
        Assert.Equal("Fleet SSH", details.GetProperty("SshCaKeyName").GetString());
        Assert.Equal(to, details.GetProperty("ReviewBy").GetDateTime().ToUniversalTime());
        Assert.Equal(was, details.GetProperty("Was").GetDateTime().ToUniversalTime());

        // The admin key list answers the date; the public list says nothing of it.
        var listed = Json(await Call(admin, "GetCaKeys")).EnumerateArray().Single(k => k.GetProperty("id").GetGuid() == w.Ca.Id);
        Assert.Equal(to, listed.GetProperty("reviewBy").GetDateTime().ToUniversalTime());
        var publicList = JsonSerializer.Serialize(Assert.IsAssignableFrom<ObjectResult>(
            await Call(New(Public, w.Operator, true, w.Node.Service, new SystemConfig()), "ListCaKeys")).Value);
        Assert.DoesNotContain("review", publicList, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_review_date_in_the_past_too_far_ahead_or_missing_is_400_and_changes_nothing()
    {
        using var w = new Reviewed();
        var admin = AdminController(w.Node, w.Operator);
        var was = w.ReviewBy();
        var auditsBefore = w.Node.Audit.Entries.Count;

        Assert.Equal("The review date must be in the future.", Error(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.UtcNow.AddDays(-1)))));
        Assert.Equal("The review date must be in the future.", Error(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.UtcNow.AddSeconds(-1)))));
        Assert.Equal("The review date can be at most 10 years ahead.", Error(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.UtcNow.AddYears(10).AddDays(1)))));
        Assert.Equal("The review date can be at most 10 years ahead.", Error(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.MaxValue))));
        Assert.Contains("reviewBy", Error(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(null))));

        Assert.Equal(was, w.ReviewBy());
        Assert.Equal(auditsBefore, w.Node.Audit.Entries.Count);

        // The service holds the same line for a caller that is not the route.
        Assert.Equal(400, (await Assert.ThrowsAsync<InvalidRequestException>(() => w.Node.Service.SetReviewByAsync(w.Ca.Id, DateTime.UtcNow.AddMinutes(-1)))).Status);
        Assert.Equal(400, (await Assert.ThrowsAsync<InvalidRequestException>(() => w.Node.Service.SetReviewByAsync(w.Ca.Id, DateTime.UtcNow.AddYears(11)))).Status);
        Assert.Equal(was, w.ReviewBy());
        Assert.Empty(w.Node.Audit.Of(AuditActionType.SshCaKeyReviewDateChanged));

        // The edges that are allowed: tomorrow, and a day short of ten years.
        Assert.IsType<OkObjectResult>(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.UtcNow.AddDays(1))));
        Assert.IsType<OkObjectResult>(await Call(admin, "SetReviewBy", w.Ca.Id, w.MoveTo(DateTime.UtcNow.AddYears(10).AddDays(-1))));
        Assert.Equal(2, w.Node.Audit.Of(AuditActionType.SshCaKeyReviewDateChanged).Count);
    }

    [Fact]
    public async Task A_key_outside_the_caller_s_fence_or_unknown_is_not_found_and_keeps_its_review_date()
    {
        using var w = new Reviewed();
        var was = w.ReviewBy();
        var to = DateTime.UtcNow.AddYears(1);

        Assert.IsType<NotFoundResult>(await Call(AdminController(w.Node, w.Operator, instanceScope: false), "SetReviewBy", w.Ca.Id, w.MoveTo(to)));
        Assert.IsType<NotFoundResult>(await Call(AdminController(w.Node, w.Operator), "SetReviewBy", Guid.NewGuid(), w.MoveTo(to)));
        Assert.Null(await w.Node.Service.SetReviewByAsync(Guid.NewGuid(), to));

        Assert.Equal(was, w.ReviewBy());
        Assert.Empty(w.Node.Audit.Of(AuditActionType.SshCaKeyReviewDateChanged));
    }

    /// <summary>
    /// The date reminds and never acts: a key whose review date passed years ago signs user and
    /// host certificates, revokes, serves its KRL and is listed exactly as one whose date is
    /// years away.
    /// </summary>
    [Fact]
    public async Task A_key_past_its_review_date_signs_revokes_and_serves_its_krl_as_before()
    {
        using var w = new Reviewed();
        var subjectKey = SshNode.SubjectKey();

        async Task<string> EverythingTheKeyDoesAsync()
        {
            var user = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, subjectKey, SshCertificateSubject.ForUser(w.Alice.Id), ["alice"], null, ["permit-pty"], w.Node.Actor, profileMaxValidityHours: 12);
            var host = await w.Node.Service.SignHostKeyAsync(w.Ca.Id, subjectKey, ["host1.example.com"], null, w.Node.Actor);
            var userCert = SshCertificate.ParseOpenSsh(user.SignedCertificate);
            var hostCert = SshCertificate.ParseOpenSsh(host.SignedCertificate);
            Assert.True(userCert.VerifySignature() && hostCert.VerifySignature());
            Assert.True(await w.Node.Service.RevokeCertificateAsync(host.Id, w.Ca.Id, w.Node.Actor));
            var krl = await w.Node.Service.BuildKrlAsync(w.Ca.Id);
            Assert.NotEmpty(krl.Bytes);

            var listed = Json(await Call(AdminController(w.Node, w.Operator), "GetCaKeys")).EnumerateArray().Single(k => k.GetProperty("id").GetGuid() == w.Ca.Id);
            using var db = w.Node.Reopen();
            var row = db.SshCaKeys.Single(k => k.Id == w.Ca.Id);
            return string.Join(" | ",
                $"user {(userCert.Fields.ValidBefore - userCert.Fields.ValidAfter) / 3600}h {string.Join(",", ExtensionsOf(userCert))}",
                $"host {(hostCert.Fields.ValidBefore - hostCert.Fields.ValidAfter) / 3600}h",
                $"enabled {row.IsEnabled} max {row.MaxValidityHours} own {row.AllowOwnUsername}",
                $"listed enabled {listed.GetProperty("isEnabled").GetBoolean()} state {listed.GetProperty("signerState").GetString()}",
                $"ca enabled {db.CertificateAuthorities.Single(c => c.Id == row.CertificateAuthorityId).IsEnabled}");
        }

        void SetReviewBy(DateTime? at)
        {
            var row = w.Node.Db.SshCaKeys.Single(k => k.Id == w.Ca.Id);
            row.ReviewBy = at;
            w.Node.Db.SaveChanges();
        }

        SetReviewBy(DateTime.UtcNow.AddYears(4));
        var wellBefore = await EverythingTheKeyDoesAsync();
        SetReviewBy(DateTime.UtcNow.AddDays(30));
        var withinTheWarning = await EverythingTheKeyDoesAsync();
        SetReviewBy(DateTime.UtcNow.AddYears(-3));
        var longPast = await EverythingTheKeyDoesAsync();
        SetReviewBy(null);
        var noDate = await EverythingTheKeyDoesAsync();

        Assert.Equal("user 12h permit-pty | host 48h | enabled True max 48 own True | listed enabled True state held | ca enabled True", wellBefore);
        Assert.Equal(wellBefore, withinTheWarning);
        Assert.Equal(wellBefore, longPast);
        Assert.Equal(wellBefore, noDate);

        using var after = w.Node.Reopen();
        Assert.Equal(4, after.SshCertificates.Count(c => c.SshCaKeyId == w.Ca.Id && !c.IsRevoked));
        Assert.Equal(4, after.SshCertificates.Count(c => c.SshCaKeyId == w.Ca.Id && c.IsRevoked));
    }

    /// <summary>
    /// Nothing but the route, the creation, the reminder job and the pages reads the review
    /// date: no source file that signs, checks or revokes names it.
    /// </summary>
    [Fact]
    public void Nothing_that_signs_checks_or_revokes_reads_the_review_date()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "ModularCA.sln")))
            root = root.Parent;
        Assert.NotNull(root);

        var allowed = new[]
        {
            Path.Combine("ModularCA.Shared", "Entities", "SshCaKeyEntity.cs"),
            Path.Combine("ModularCA.Shared", "Utils", "SshCaKeyDefaults.cs"),
            Path.Combine("ModularCA.Shared", "Interfaces", "ISshCaService.cs"),
            Path.Combine("ModularCA.Core", "Services", "SshCaService.cs"),
            Path.Combine("ModularCA.Core", "Services", "SchedulerJobs", "CertExpiryNotificationJob.cs"),
            Path.Combine("ModularCA.API", "Controllers", "v1", "Admin", "AdminSshController.cs"),
        };
        var projects = new[] { "ModularCA.API", "ModularCA.Auth", "ModularCA.Bootstrap", "ModularCA.Core", "ModularCA.Keystore", "ModularCA.Shared", "ModularCA.Signer", "ModularCA.Ssh" };
        var readers = projects
            .Select(p => Path.Combine(root!.FullName, p))
            .Where(Directory.Exists)
            .SelectMany(p => Directory.EnumerateFiles(p, "*.cs", SearchOption.AllDirectories))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .Where(f => File.ReadAllText(f).Contains("ReviewBy", StringComparison.Ordinal))
            .Select(f => Path.GetRelativePath(root!.FullName, f))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(allowed.OrderBy(f => f, StringComparer.Ordinal), readers);

        // In the service, the date is written at creation and by the one method that moves it.
        var service = File.ReadAllText(Path.Combine(root!.FullName, allowed[3]));
        var sign = service[service.IndexOf("private async Task<SshCertificateEntity> SignAsync(", StringComparison.Ordinal)..];
        Assert.DoesNotContain("ReviewBy", sign);
    }

    // ---- The reminder ------------------------------------------------------------------------

    private sealed class RecordingNotifications : NoopNotificationService
    {
        public List<(string EventType, string Message)> Sent { get; } = [];

        public override Task NotifyAsync(string eventType, string message)
        {
            Sent.Add((eventType, message));
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Administrators_are_reminded_once_per_key_and_review_date_from_90_days_ahead_and_nothing_is_changed()
    {
        var dbName = $"ssh-review-{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(opts => opts.UseInMemoryDatabase(dbName).ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning)));
        var sp = services.BuildServiceProvider();
        var config = new SystemConfig();
        config.CertExpiryNotification.Enabled = true;
        config.Email.Enabled = true;

        var now = new DateTimeOffset(2026, 10, 8, 6, 0, 0, TimeSpan.Zero);
        var time = new QueueTimeProvider([now]);
        var notifications = new RecordingNotifications();
        using var scope = sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var job = new CertExpiryNotificationJob(sp, db, notifications, new RecordingAlertService(), config, NullLogger<CertExpiryNotificationJob>.Instance,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test", time), timeProvider: time);

        SshCaKeyEntity Key(string name, DateTime? reviewBy, bool enabled = true, bool user = true, bool host = false) => new()
        {
            Id = Guid.NewGuid(), Name = name, KeyType = "ed25519", PublicKey = "ssh-ed25519 AAAA", CertificateAuthorityId = Guid.NewGuid(),
            IsUserCa = user, IsHostCa = host, IsEnabled = enabled, ReviewBy = reviewBy,
        };
        var at = now.UtcDateTime;
        var later = Key("Later SSH", at.AddDays(91));
        var soon = Key("Soon SSH", at.AddDays(90));
        var past = Key("Past SSH", at.AddYears(-1), user: false, host: true);
        var disabled = Key("Disabled SSH", at.AddYears(-1), enabled: false);
        var undated = Key("Undated SSH", null);
        db.SshCaKeys.AddRange(later, soon, past, disabled, undated);
        db.SaveChanges();

        Assert.Equal(2, await job.ProcessSshCaKeyReviewsAsync(CancellationToken.None));
        Assert.Equal(new[] { "Past SSH", "Soon SSH" }, notifications.Sent.Select(s => s.Message.Split('\'')[1]).OrderBy(n => n).ToArray());
        Assert.All(notifications.Sent, s =>
        {
            Assert.Equal("SshCaKeyReviewDue", s.EventType);
            Assert.Contains("This is a reminder only. The key keeps signing", s.Message);
        });
        Assert.Contains("(host certificates) was due for review on", notifications.Sent.Single(s => s.Message.Contains("Past SSH")).Message);
        Assert.Contains("(user certificates) is due for review on", notifications.Sent.Single(s => s.Message.Contains("Soon SSH")).Message);

        // A second run the same day, and every run after, says nothing again.
        Assert.Equal(0, await job.ProcessSshCaKeyReviewsAsync(CancellationToken.None));
        Assert.Equal(2, notifications.Sent.Count);

        // Moving the date out of the window stops the reminder; a new date inside it is reminded once.
        db.SshCaKeys.Single(k => k.Id == past.Id).ReviewBy = at.AddYears(2);
        db.SshCaKeys.Single(k => k.Id == soon.Id).ReviewBy = at.AddDays(30);
        db.SaveChanges();
        Assert.Equal(1, await job.ProcessSshCaKeyReviewsAsync(CancellationToken.None));
        Assert.Contains("Soon SSH", notifications.Sent[^1].Message);
        Assert.Equal(0, await job.ProcessSshCaKeyReviewsAsync(CancellationToken.None));

        // The job wrote its log and nothing else: every key is as it was.
        using var verify = sp.CreateScope();
        var rows = verify.ServiceProvider.GetRequiredService<ModularCADbContext>();
        Assert.Equal(3, rows.NotificationLogs.Count(n => n.EventType == "SshCaKeyReviewDue"));
        Assert.Equal(new[] { "Disabled SSH False", "Later SSH True", "Past SSH True", "Soon SSH True", "Undated SSH True" },
            rows.SshCaKeys.OrderBy(k => k.Name).Select(k => k.Name + " " + k.IsEnabled).ToArray());
        Assert.Empty(rows.SshCertificates);
    }
}
